#!/usr/bin/env bash
# tests/guard-netns.sh — guard в netns-стенде: gcli (клиент) ⇄ veth ⇄ gsrv (сервер; XDP + tc на gsrv0).
#   raw   — объекты BPF собираются и цепляются напрямую (bpftool / ip / tc), без guard.sh
#   guard — modules/guard.sh целиком (on/off/reattach/allow/hook), GUARD_NO_SYSTEMD=1, --iface gsrv0
# Запуск от root: sudo bash tests/guard-deps.sh && sudo bash tests/guard-netns.sh raw|guard
#   → последняя строка GUARD-NETNS OK (rc 0), иначе GUARD-NETNS FAIL (rc 1); неизвестный режим — rc 2.
# Ядро без kfunc bpf_sk_assign_tcp_reqsk: cookie-кейсы — SKIP + ::warning:: (компиляция и загрузка
# tc-объекта проверяются и тогда); ND_GUARD_REQUIRE_KFUNC=1 (CI) — вместо SKIP провал.
#
# Устройство (новый режим — функция mode_<имя>; переиспользуется всё, кроме raw_*):
#   net_up/net_down, srv_start 4|6, cli_echo, held_ss — сеть, эхо-сервер на :443 в gsrv, клиент в gcli;
#   stats/st/delta — счётчики guard_ctrl.py stats по $MAPS (карты guard: XDP пинит, tc переиспользует);
#   set_cookies/state_until (ключ $KEY), bad_ack — управление режимом и «чужой» ACK;
#   case_* (список COOKIE_CASES, запуск — run_cookie_cases) — кейсы, каждый печатает ok/bad.
# Команды в netns идут через nsenter --net (in_srv/in_cli), а не `ip netns exec`: тот перемонтирует
# /sys, и bpffs с pin'ами (/sys/fs/bpf) внутри не виден.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

fail=0
ok()   { echo "  ✓ $*"; }
bad()  { echo "  ✗ $*"; fail=1; }
skip() { echo "  ~ SKIP $*"; }

SRV_NS=gsrv CLI_NS=gcli SRV_IF=gsrv0 CLI_IF=gcli0
SRV4=10.200.0.1 CLI4=10.200.0.2 SRV6=fd00:200::1 CLI6=fd00:200::2
PORT=443
PIN=/sys/fs/bpf/nd-guard-netns
MAPS="$PIN/maps"
BPFTOOL="${BPFTOOL:-bpftool}"
COOKIE_CASES=(cookie_handshake_v4 cookie_handshake_v6 dualstack_listener_v4_cookie
              cookie_ts_from_ack no_timestamps_keeps_wscale bad_cookie_ack_fails_open cookie_modes)
# режим guard: «чужие» (не из гео-фикстуры 10.200.0.0/25, fd00:200::/120) адреса клиента
FOREIGN4=10.200.0.200 FOREIGN6=fd00:200::200
GUARD_CASES=(geo_unavailable_refuses ssh_port_refused variant1_geo_drop xdp_mode_veth allowlist_bypasses_geo
             notrack_no_conntrack_entries icmp_errors_not_invalid variant2_cookies_always
             tc_load_fail_degrades reapply_no_stacking
             shaper_survives_guard shaper_legacy_filters_removed certbot_hooks_toggle_geo_80 reattach_restores_from_disk
             reattach_unconfirmed_rolls_back off_cleans_everything)
TMP=""
KEY=""
SRV_PID=""
SHAPE_TOUCHED=0

in_srv() { nsenter --net="/var/run/netns/$SRV_NS" "$@"; }
in_cli() { nsenter --net="/var/run/netns/$CLI_NS" "$@"; }
# фоновый процесс в netns: у `in_srv … &` в $! был бы PID подоболочки, и kill не задел бы сам
# процесс; здесь nsenter делает exec, поэтому $! — PID процесса. bg_in NS КОМАНДА…
bg_in() {
    local ns="$1"
    shift
    nsenter --net="/var/run/netns/$ns" "$@" &
}

# ── сеть и процессы ──

# процессы, оставшиеся в netns (прерванный прогон), гасятся до удаления netns
net_down() {
    local ns
    for ns in "$SRV_NS" "$CLI_NS"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
        ip netns del "$ns" 2>/dev/null
    done
    return 0
}

net_up() {
    net_down
    ip netns add "$SRV_NS" && ip netns add "$CLI_NS" \
        && ip link add "$SRV_IF" netns "$SRV_NS" type veth peer name "$CLI_IF" netns "$CLI_NS" \
        && in_srv ip addr add "$SRV4/24" dev "$SRV_IF" \
        && in_srv ip addr add "$SRV6/64" dev "$SRV_IF" nodad \
        && in_cli ip addr add "$CLI4/24" dev "$CLI_IF" \
        && in_cli ip addr add "$CLI6/64" dev "$CLI_IF" nodad \
        && in_srv ip link set lo up && in_cli ip link set lo up \
        && in_srv ip link set "$SRV_IF" up && in_cli ip link set "$CLI_IF" up
}

# kill + wait без «Terminated» в выводе
reap() {
    [ -n "$1" ] || return 0
    kill "$1" 2>/dev/null
    wait "$1" 2>/dev/null
    return 0
}

srv_stop() { reap "$SRV_PID"; SRV_PID=""; }

# srv_start 6 — dual-stack [::]:443 (IPV6_V6ONLY=0); srv_start 4 — 0.0.0.0:443
srv_start() {
    srv_stop
    bg_in "$SRV_NS" python3 "$TMP/echo.py" "$1" >>"$TMP/echo.log" 2>&1
    SRV_PID=$!
    for _ in $(seq 50); do
        [ -n "$(in_srv ss -"$1"ltnH "sport = :$PORT")" ] && return 0
        sleep 0.1
    done
    return 1
}

# семейства сокетов, слушающих :443 в gsrv: "4", "6" или "46"
listener_fams() {
    local f=""
    [ -n "$(in_srv ss -4ltnH "sport = :$PORT")" ] && f="4"
    [ -n "$(in_srv ss -6ltnH "sport = :$PORT")" ] && f="${f}6"
    echo "$f"
}

# cli_echo ADDR — connect (таймаут 3 с), b"ping" → b"ping"; ошибка клиента — в stdout
cli_echo() { in_cli python3 "$TMP/client.py" "$1" 2>&1; }

cleanup() {
    srv_stop
    # прерванный shaper_survives_guard: настоящий shape off, пока gsrv (его default route) жив
    [ "$SHAPE_TOUCHED" = 1 ] && in_srv bash modules/shape.sh off >/dev/null 2>&1
    net_down
    rm -rf "$PIN" "$PIN-new"
    [ -n "$TMP" ] && rm -rf "$TMP"
}

write_helpers() {
    cat >"$TMP/echo.py" <<'EOF'
import socket, sys, threading
v6 = sys.argv[1] == "6"
s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
if v6:
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::" if v6 else "0.0.0.0", 443))
s.listen(64)


def serve(c):
    with c:
        while True:
            d = c.recv(4096)
            if not d:
                return
            c.sendall(d)


while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
EOF
    # client.py ADDR [HOLD [SRC]] — эхо; с HOLD > 0 печатает "up <локальный порт>" и держит
    # соединение HOLD с; SRC — адрес источника (по умолчанию выбирает ядро)
    cat >"$TMP/client.py" <<'EOF'
import socket, sys, time
addr = sys.argv[1]
hold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0
src = (sys.argv[3], 0) if len(sys.argv) > 3 else None
try:
    s = socket.create_connection((addr, 443), timeout=3, source_address=src)
    s.sendall(b"ping")
    got = b""
    while len(got) < 4:
        d = s.recv(4 - len(got))
        if not d:
            break
        got += d
except OSError as e:
    print("клиент %s: %s" % (addr, e))
    sys.exit(1)
if got != b"ping":
    print("клиент %s: эхо %r" % (addr, got))
    sys.exit(1)
if hold:
    print("up %d" % s.getsockname()[1], flush=True)
    time.sleep(hold)
s.close()
EOF
    # badack.py SRC DST — голый ACK со случайными seq/ack_seq на DST:443 raw-сокетом;
    # rc 0 — ядро сервера ответило RST (пакет не дропнут), 2 — RST не пришёл за 3 с
    cat >"$TMP/badack.py" <<'EOF'
import random, socket, struct, sys, time
src, dst = sys.argv[1], sys.argv[2]


def csum(b):
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


sport = random.randint(20000, 29999)   # вне ip_local_port_range — не задевает живые соединения
hdr = struct.pack("!HHIIBBHHH", sport, 443, random.getrandbits(32), random.getrandbits(32),
                  5 << 4, 0x10, 65535, 0, 0)
ph = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr))
hdr = hdr[:16] + struct.pack("!H", csum(ph + hdr)) + hdr[18:]
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.bind((src, 0))
s.settimeout(0.2)
s.sendto(hdr, (dst, 0))
end = time.time() + 3
while time.time() < end:
    try:
        pkt, peer = s.recvfrom(2048)
    except socket.timeout:
        continue
    ihl = (pkt[0] & 0xF) * 4
    sp, dp = struct.unpack("!HH", pkt[ihl:ihl + 4])
    if peer[0] == dst and sp == 443 and dp == sport and pkt[ihl + 13] & 0x04:
        sys.exit(0)
sys.exit(2)
EOF
    # icmperr.py 4|6 SRC DST — ICMP-ошибка (v4 frag-needed, v6 packet-too-big, MTU 1400) о сегменте
    # DST:443 → SRC:40000, будто ответ ноды не пролез; raw-сокетом из SRC. Чексумму ICMPv6 считает ядро
    cat >"$TMP/icmperr.py" <<'EOF'
import socket, struct, sys
fam, src, dst = sys.argv[1:4]


def csum(b):
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


tcp8 = struct.pack("!HHI", 443, 40000, 1)
if fam == "4":
    inner = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0x4000, 64, 6, 0,
                        socket.inet_aton(dst), socket.inet_aton(src)) + tcp8
    icmp = struct.pack("!BBHHH", 3, 4, 0, 0, 1400) + inner
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
else:
    inner = struct.pack("!IHBB16s16s", 6 << 28, 20, 6, 64, socket.inet_pton(socket.AF_INET6, dst),
                        socket.inet_pton(socket.AF_INET6, src)) + tcp8
    icmp = struct.pack("!BBHI", 2, 0, 0, 1400) + inner
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
s.bind((src, 0))
s.sendto(icmp, (dst, 0))
EOF
}

# ── BPF и карты ──

bpf_cc() {   # SRC OUT [флаги clang]
    local src="$1" out="$2" inc=()
    shift 2
    [ -d "/usr/include/$(uname -m)-linux-gnu" ] && inc=(-I"/usr/include/$(uname -m)-linux-gnu")
    clang -O2 -g -Wall -target bpf "${inc[@]}" "$@" -c "$src" -o "$out"
}

ctrl()  { python3 modules/guard_ctrl.py --pin-dir "$MAPS" "$@"; }
stats() { ctrl stats; }
st() {   # st NAME "строка stats" → значение (-1 — нет такого)
    local kv
    for kv in $2; do
        [ "${kv%%=*}" = "$1" ] && { echo "${kv#*=}"; return 0; }
    done
    echo -1
}
delta() { echo $(( $(st "$1" "$3") - $(st "$1" "$2") )); }   # delta NAME ДО ПОСЛЕ

# set_cookies off|auto|always [порог SYN/с] — cfg с ключом $KEY, гео выкл.
set_cookies() { ctrl set-cfg --geo 0 --cookies "$1" --syn-threshold "${2:-10000}" --key-file "$KEY"; }

# state_until NS — guard_state_map[0] = {окна SYN нет, attack_until_ns = NS} (0 — «атаки не было»)
state_until() {
    local v=()
    read -ra v < <(python3 -c 'import struct, sys
print(" ".join("%02x" % b for b in struct.pack("=QQQ", 0, 0, int(sys.argv[1]))))' "$1")
    "$BPFTOOL" map update pinned "$MAPS/guard_state_map" key hex 00 00 00 00 value hex "${v[@]}"
}

mono_ns() { ctrl state | sed -n 's/.*now_ns=\([0-9]*\).*/\1/p'; }   # CLOCK_MONOTONIC, как у BPF

# bad_ack — голый ACK со случайным ack_seq из gcli; rc 0 — ядро сервера ответило RST
bad_ack() { in_cli python3 "$TMP/badack.py" "$CLI4" "$SRV4"; }

has_kfunc() {
    "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format raw 2>/dev/null \
        | grep -F "'bpf_sk_assign_tcp_reqsk'" >/dev/null
}

# tc-программа держит те же карты, что XDP (переиспользование по pin'ам, а не копии)
maps_shared() {
    python3 - "$BPFTOOL" "$PIN/progs/nd_guard_tc" "$MAPS" <<'EOF'
import json, subprocess, sys
bt, prog, maps = sys.argv[1:4]


def j(*a):
    return json.loads(subprocess.run([bt, "-j", *a], capture_output=True, text=True, check=True).stdout)


ids = set(j("prog", "show", "pinned", prog).get("map_ids", []))
miss = [m for m in ("guard_cfg_map", "guard_state_map", "guard_ports_map", "guard_stats_map")
        if j("map", "show", "pinned", maps + "/" + m)["id"] not in ids]
if miss:
    print(" ".join(miss))
    sys.exit(1)
EOF
}

# ── кейсы (общие для режимов) ──

# cookie_echo ADDR — эхо через cookie-путь; печатает причины провала (пусто — всё в порядке):
# эхо прошло, cookie_sent и cookie_ok выросли, assign_err = 0
cookie_echo() {
    local s0 s1 out why=""
    s0=$(stats)
    out=$(cli_echo "$1") || why="эхо не прошло ($out);"
    s1=$(stats)
    [ "$(delta cookie_sent "$s0" "$s1")" -ge 1 ] || why="$why cookie_sent не вырос;"
    [ "$(delta cookie_ok "$s0" "$s1")" -ge 1 ] || why="$why cookie_ok не вырос;"
    [ "$(st assign_err "$s1")" = 0 ] || why="$why assign_err=$(st assign_err "$s1");"
    [ -z "$why" ] || echo "$why [$s1]"
}

case_cookie_handshake_v4() {
    local why
    why=$(cookie_echo "$SRV4")
    if [ -z "$why" ]; then ok "cookie_handshake_v4"; else bad "cookie_handshake_v4: $why"; fi
}

case_cookie_handshake_v6() {
    local why
    why=$(cookie_echo "$SRV6")
    if [ -z "$why" ]; then ok "cookie_handshake_v6"; else bad "cookie_handshake_v6: $why"; fi
}

# IPv4-клиент через cookie-путь к dual-stack [::]:443 (как xray), затем к 0.0.0.0:443
case_dualstack_listener_v4_cookie() {
    local why fams
    fams=$(listener_fams)
    if [ "$fams" != 6 ]; then
        bad "dualstack_listener_v4_cookie: слушает не один dual-stack [::]:$PORT (семейства: '$fams')"
        return
    fi
    why=$(cookie_echo "$SRV4")
    if [ -n "$why" ]; then
        bad "dualstack_listener_v4_cookie: [::]:$PORT: $why"
        return
    fi
    if srv_start 4 && [ "$(listener_fams)" = 4 ]; then
        why=$(cookie_echo "$SRV4")
    else
        why="0.0.0.0:$PORT не поднялся ($(tail -n 3 "$TMP/echo.log" | tr '\n' ' '))"
    fi
    srv_start 6 || why="$why; dual-stack [::]:$PORT не вернулся"
    if [ -z "$why" ]; then
        ok "dualstack_listener_v4_cookie ([::]:$PORT и 0.0.0.0:$PORT)"
    else
        bad "dualstack_listener_v4_cookie: 0.0.0.0:$PORT: $why"
    fi
}

# held_ss ADDR — соединение к ADDR:443, которое клиент держит открытым; печатает в одну строку
# `ss -tinoH` сервера именно для него (пусто — не установлено; вывод клиента — в $TMP/hold.out).
# -o обязателен: без него ss (iproute2 6.1) не печатает токены опций ts/sack вовсе, и проверка
# «нет ts» прошла бы вхолостую.
held_ss() {
    local port="" line="" pid
    bg_in "$CLI_NS" python3 "$TMP/client.py" "$1" 10 >"$TMP/hold.out" 2>&1
    pid=$!
    for _ in $(seq 50); do
        port=$(sed -n 's/^up \([0-9][0-9]*\)$/\1/p' "$TMP/hold.out")
        [ -n "$port" ] && break
        sleep 0.1
    done
    [ -n "$port" ] && line=$(in_srv ss -tinoH state established "( sport = :$PORT and dport = :$port )")
    reap "$pid"
    [ -n "$line" ] && printf '%s\n' "$line" | tr -s '\t\n' '  '
    return 0
}

ss_tok()    { printf '%s\n' "$1" | grep -qE "(^|[[:space:]])$2([[:space:]]|\$)"; }   # ss_tok LINE TOKEN
ss_wscale() { printf '%s\n' "$1" | grep -o 'wscale:[0-9]*,[0-9]*' | head -n 1; }       # wscale:N,M

# held_check ADDR ts|nots — held_ss через cookie-путь; печатает причины провала (пусто — ок):
# соединение есть, wscale клиента N>0, sack есть, ts — как ожидается, cookie_ok вырос, assign_err=0
held_check() {
    local s0 s1 line ws n why=""
    s0=$(stats)
    line=$(held_ss "$1")
    s1=$(stats)
    if [ -z "$line" ]; then
        why="соединение не установлено ($(tr '\n' ' ' <"$TMP/hold.out"));"
    else
        ws=$(ss_wscale "$line")
        n=${ws#wscale:}
        n=${n%%,*}
        { [ -n "$ws" ] && [ "$n" -gt 0 ]; } || why="нет wscale клиента;"
        ss_tok "$line" sack || why="$why нет sack;"
        if [ "$2" = ts ]; then
            ss_tok "$line" ts || why="$why нет ts;"
        else
            ss_tok "$line" ts && why="$why ts включены;"
        fi
    fi
    [ "$(delta cookie_ok "$s0" "$s1")" -ge 1 ] || why="$why cookie_ok не вырос;"
    [ "$(st assign_err "$s1")" = 0 ] || why="$why assign_err=$(st assign_err "$s1");"
    [ -z "$why" ] || echo "$why [ss: $line] [$s1]"
}

# (сверх брифа) клиент с timestamps: TS из ACK доходят до ядра (tstamp_ok), SACK и WS — из cookie
case_cookie_ts_from_ack() {
    local why
    why=$(held_check "$SRV4" ts)
    if [ -z "$why" ]; then ok "cookie_ts_from_ack (ts, sack, wscale)"; else bad "cookie_ts_from_ack: $why"; fi
}

# клиент без TCP timestamps (Windows): window scaling клиента сохраняется (у штатных
# syncookies ядра он живёт в TS и без TS теряется); проверка — на стороне сервера
case_no_timestamps_keeps_wscale() {
    local why
    in_cli sysctl -qw net.ipv4.tcp_timestamps=0
    why=$(held_check "$SRV4" nots)
    in_cli sysctl -qw net.ipv4.tcp_timestamps=1
    if [ -z "$why" ]; then ok "no_timestamps_keeps_wscale (wscale клиента > 0, без ts)"; else bad "no_timestamps_keeps_wscale: $why"; fi
}

# ACK со случайным ack_seq: cookie_bad, но не дроп — ядро само отвечает RST (D9);
# после этого обычное соединение по-прежнему работает
case_bad_cookie_ack_fails_open() {
    local s0 s1 rc why=""
    s0=$(stats)
    bad_ack
    rc=$?
    s1=$(stats)
    [ "$(delta cookie_bad "$s0" "$s1")" -ge 1 ] || why="cookie_bad не вырос;"
    [ "$(st assign_err "$s1")" = 0 ] || why="$why assign_err=$(st assign_err "$s1");"
    [ "$rc" = 0 ] || why="$why ядро не ответило RST (rc $rc) — ACK не дошёл до стека;"
    s0=$(cookie_echo "$SRV4")
    [ -z "$s0" ] || why="$why следующее соединение: $s0"
    if [ -z "$why" ]; then
        ok "bad_cookie_ack_fails_open (cookie_bad, RST от ядра, следующее соединение ок)"
    else
        bad "bad_cookie_ack_fails_open: $why [$s1]"
    fi
}

# (сверх брифа) ранние выходы tc по режиму cookies: off и auto вне атаки — ACK не трогается
# (cookie_bad не растёт, RST от ядра есть); auto под атакой (порог 0) — cookie-путь работает;
# auto через 1 с после атаки — tc ещё проверяет cookie (граница attack_until + 2·2^36).
# «Вне атаки» = now > attack_until + 2·2^36 нс; при attack_until = 0 это требует CLOCK_MONOTONIC
# > ~137 с: недостающие ≤ 60 с кейс выжидает (свежий CI runner), иначе часть не проверяется
# (видно в выводе).
case_cookie_modes() {
    local s0 s1 rc now wait_s=0 why="" idle need=$(( (2 << 36) + 3000000000 ))
    set_cookies off >/dev/null || why="set-cfg off;"
    s0=$(stats); bad_ack; rc=$?; s1=$(stats)
    [ "$(delta cookie_bad "$s0" "$s1")" = 0 ] || why="$why off: tc проверял cookie;"
    [ "$rc" = 0 ] || why="$why off: нет RST;"

    set_cookies auto 0 >/dev/null || why="$why set-cfg auto 0;"
    s0=$(cookie_echo "$SRV4")
    [ -z "$s0" ] || why="$why auto под атакой: $s0;"

    # атака кончилась 1 с назад: XDP cookie уже не выдаёт, но выданные живы 2 слота — tc проверяет
    set_cookies auto >/dev/null || why="$why set-cfg auto;"
    now=$(mono_ns)
    now=${now:-0}
    state_until $(( now > 1000000000 ? now - 1000000000 : 0 )) >/dev/null || why="$why state;"
    s0=$(stats); bad_ack; rc=$?; s1=$(stats)
    [ "$(delta cookie_bad "$s0" "$s1")" -ge 1 ] || why="$why auto сразу после атаки: tc не проверял cookie;"
    [ "$rc" = 0 ] || why="$why auto сразу после атаки: нет RST;"

    state_until 0 >/dev/null || why="$why сброс state;"
    now=$(mono_ns)
    now=${now:-0}
    if [ "$now" -le "$need" ] && [ $(( need - now )) -le 60000000000 ]; then
        wait_s=$(( (need - now) / 1000000000 + 1 ))
        sleep "$wait_s"
        now=$(( now + wait_s * 1000000000 ))
    fi
    if [ "$now" -gt "$need" ]; then
        s0=$(stats); bad_ack; rc=$?; s1=$(stats)
        [ "$(delta cookie_bad "$s0" "$s1")" = 0 ] || why="$why auto вне атаки: tc проверял cookie;"
        [ "$rc" = 0 ] || why="$why auto вне атаки: нет RST;"
        idle="auto вне атаки"
        [ "$wait_s" = 0 ] || idle="$idle, ждал ${wait_s} с"
    else
        idle="auto вне атаки НЕ проверен: CLOCK_MONOTONIC $now нс < 2·2^36 + 3 с"
    fi

    set_cookies always >/dev/null || why="$why возврат always;"
    if [ -z "$why" ]; then
        ok "cookie_modes (off, auto под атакой, auto сразу после атаки, $idle)"
    else
        bad "cookie_modes: $why [$s1]"
    fi
}

run_cookie_cases() {
    local c
    if has_kfunc; then
        for c in "${COOKIE_CASES[@]}"; do "case_$c"; done
    elif [ "${ND_GUARD_REQUIRE_KFUNC:-0}" = 1 ]; then
        bad "ядро $(uname -r) без bpf_sk_assign_tcp_reqsk, а ND_GUARD_REQUIRE_KFUNC=1 — cookie-кейсы не проверены"
    else
        for c in "${COOKIE_CASES[@]}"; do skip "$c — ядро без bpf_sk_assign_tcp_reqsk"; done
        echo "::warning::ядро $(uname -r) без bpf_sk_assign_tcp_reqsk"
    fi
}

# ── режим raw: объекты цепляются напрямую ──

raw_build() {
    bpf_cc modules/nd-guard-xdp.bpf.c "$TMP/nd-guard-xdp.bpf.o" \
        && bpf_cc modules/nd-guard-tc.bpf.c "$TMP/nd-guard-tc.bpf.o"
}

# XDP пинит карты; tc грузится с переиспользованием 4 общих карт по имени
raw_load() {
    local m reuse=()
    rm -rf "$PIN" && mkdir -p "$PIN" || return 1
    "$BPFTOOL" prog loadall "$TMP/nd-guard-xdp.bpf.o" "$PIN/progs" type xdp pinmaps "$MAPS" || return 1
    for m in guard_cfg_map guard_state_map guard_ports_map guard_stats_map; do
        reuse+=(map name "$m" pinned "$MAPS/$m")
    done
    "$BPFTOOL" prog loadall "$TMP/nd-guard-tc.bpf.o" "$PIN/progs" type classifier "${reuse[@]}"
}

# R5: на ядре без kfunc объект обязан грузиться — имя kfunc подменяется на несуществующее
raw_load_without_kfunc() {
    bpf_cc modules/nd-guard-tc.bpf.c "$TMP/nd-guard-tc-nokf.bpf.o" \
        -Dbpf_sk_assign_tcp_reqsk=nd_guard_no_such_kfunc \
        && "$BPFTOOL" prog loadall "$TMP/nd-guard-tc-nokf.bpf.o" "$PIN/nokf" type classifier \
        && rm -rf "$PIN/nokf"
}

raw_attach() {
    in_srv ip link set dev "$SRV_IF" xdpgeneric pinned "$PIN/progs/nd_guard_xdp" \
        && in_srv tc qdisc add dev "$SRV_IF" clsact \
        && in_srv tc filter add dev "$SRV_IF" ingress pref 10 bpf direct-action pinned "$PIN/progs/nd_guard_tc"
}

raw_cfg() {
    head -c 16 /dev/urandom >"$KEY" && set_cookies always && ctrl set-port "$PORT" tcp
}

mode_raw() {
    local out
    echo "== raw: сборка и загрузка =="
    if out=$(raw_build 2>&1); then ok "сборка nd-guard-xdp.bpf.o и nd-guard-tc.bpf.o"; else bad "сборка: $out"; return; fi
    if out=$(raw_load 2>&1); then ok "загрузка: XDP + tc с картами XDP"; else bad "загрузка: $out"; return; fi
    if out=$(maps_shared 2>&1); then ok "tc и XDP делят guard_cfg/state/ports/stats_map"; else bad "карты не общие: $out"; fi
    if out=$(raw_load_without_kfunc 2>&1); then
        ok "tc-объект грузится и без kfunc (__weak + bpf_ksym_exists)"
    else
        bad "без kfunc tc-объект не грузится: $out"
    fi

    echo "== raw: стенд gsrv ⇄ gcli =="
    if ! out=$(net_up 2>&1); then bad "netns/veth: $out"; return; fi
    if ! srv_start 6; then bad "эхо-сервер [::]:$PORT не поднялся: $(cat "$TMP/echo.log")"; return; fi
    if out=$(cli_echo "$SRV4") && out=$(cli_echo "$SRV6"); then
        ok "связность без guard (v4 и v6)"
    else
        bad "связность без guard: $out"
        return
    fi
    if out=$(raw_attach 2>&1); then ok "XDP (xdpgeneric) и tc ingress pref 10 на $SRV_IF"; else bad "attach: $out"; return; fi
    if out=$(raw_cfg 2>&1); then ok "cfg: cookies always, гео выкл., $PORT:tcp"; else bad "guard_ctrl: $out"; return; fi

    echo "== raw: cookie-кейсы (ядро $(uname -r)) =="
    run_cookie_cases
}

# ── режим guard: modules/guard.sh целиком ──
# Окружение (guard_env): GUARD_NO_SYSTEMD=1 (без юнитов, dead-man и хуков), GUARD_DIR во временном
# каталоге, GUARD_PIN=$PIN (карты — те же $MAPS, что читают stats/ctrl), гео-фикстура — RIPE JSON с
# 10.200.0.0/25 и fd00:200::/120 по file://, db-ip недоступен (список собирается из одного источника),
# пороги здравости снижены. guard.sh в gsrv — через in_srv (nsenter --net: pin'ы на bpffs видны).

guard_env() {
    export GUARD_DIR="$TMP/guard" GUARD_PIN="$PIN" GUARD_NO_SYSTEMD=1 \
        ND_STATE_DIR="$TMP/state" FIX_LOG="$TMP/fix.log" \
        GUARD_GEO_RIPE_URL="file://$TMP/ripe.json" GUARD_GEO_DBIP_URL=file:///nonexistent \
        GUARD_GEO_MIN_V4_ADDRS=1 GUARD_GEO_MIN_V4_PREFIXES=1 GUARD_GEO_MIN_V6_PREFIXES=1
    printf '%s\n' '{"data": {"resources": {"ipv4": ["10.200.0.0/25"], "ipv6": ["fd00:200::/120"]}}, "status": "ok"}' \
        >"$TMP/ripe.json"
}

# сеть + «чужие» адреса на gcli0. На gcli0 своей XDP-программы нет — как у eth0 контейнера LXC, чей
# peer на хосте: guard сам выбирает generic при cookies (R11). default route в gsrv — shape.sh берёт
# интерфейс из default_iface; ct-правило включает conntrack в gsrv (R6: без него проверка NOTRACK
# была бы холостой)
guard_setup() {
    net_up \
        && in_cli ip addr add "$FOREIGN4/24" dev "$CLI_IF" \
        && in_cli ip addr add "$FOREIGN6/64" dev "$CLI_IF" nodad \
        && in_srv ip route add default via "$CLI4" dev "$SRV_IF" \
        && in_srv nft -f - <<'EOF'
table inet nd_test_ct {
	chain in {
		type filter hook input priority filter; policy accept;
		ct state established counter
	}
}
EOF
}

guard() { in_srv bash modules/guard.sh "$@" 2>&1; }
g_on()  { guard on "$@" --iface "$SRV_IF" --confirm; }
shape() { in_srv bash modules/shape.sh "$@" 2>&1; }
tail3() { printf '%s\n' "$1" | tail -n 3 | tr '\n' ' '; }

cli_from() { in_cli python3 "$TMP/client.py" "$2" 0 "$1" 2>&1; }   # cli_from SRC DST — эхо с адреса SRC
srv_xdp()  { in_srv ip -d link show dev "$SRV_IF" | grep -oE 'prog/xdp[a-z]* id [0-9]+ name [^ ]+'; }
srv_xdp_kind() { in_srv ip link show dev "$SRV_IF" | head -n 1 | grep -oE ' xdp[a-z]* ' | tr -d ' '; }
tc_has()   { in_srv tc filter show dev "$SRV_IF" ingress pref "$1" 2>/dev/null | grep -q handle; }
nft_has()  { in_srv nft list table inet nd_guard >/dev/null 2>&1; }
pin_empty() { [ -z "$(ls -A "$PIN" 2>/dev/null)" ] && [ ! -e "$PIN-new" ]; }
# R11: XDP на veth gsrv0 — generic, если работает cookie-путь (tc), иначе drv. xdp_mode_why MODE:
# пусто — guard.conf XDP_MODE и вид XDP в ip link (drv → «xdp», generic → «xdpgeneric») совпали
xdp_mode_why() {
    local c k want=xdp
    [ "$1" = generic ] && want=xdpgeneric
    c=$(sed -n 's/^XDP_MODE=//p' "$GUARD_DIR/guard.conf" 2>/dev/null)
    k=$(srv_xdp_kind)
    [ "$c" = "$1" ] || printf ' guard.conf XDP_MODE=%s, а не %s;' "${c:-?}" "$1"
    [ "$k" = "$want" ] || printf ' ip link: %s, а не %s;' "${k:-нет XDP}" "$want"
    return 0
}
cookie_xdp_mode() { if has_kfunc; then echo generic; else echo drv; fi; }   # режим при cookies ≠ off
# записи conntrack на :443 (v4 и v6)
ct_443() {
    { in_srv conntrack -L -p tcp --orig-port-dst "$PORT"; in_srv conntrack -L -f ipv6 -p tcp --orig-port-dst "$PORT"; } \
        2>/dev/null | grep -c "dport=$PORT"
}

verdict() { if [ -z "$2" ]; then ok "$1"; else bad "${1%% (*}: $2"; fi; }   # verdict "кейс (детали)" ПРИЧИНЫ

need_kfunc() {   # need_kfunc КЕЙС — rc 1 (SKIP, при ND_GUARD_REQUIRE_KFUNC=1 — провал), если ядро без kfunc
    has_kfunc && return 0
    if [ "${ND_GUARD_REQUIRE_KFUNC:-0}" = 1 ]; then
        bad "$1: ядро $(uname -r) без bpf_sk_assign_tcp_reqsk, а ND_GUARD_REQUIRE_KFUNC=1"
    else
        skip "$1 — ядро без bpf_sk_assign_tcp_reqsk"
    fi
    return 1
}

# Review Focus 1: оба источника гео недоступны, кеша нет → отказ; ничего не прицеплено
case_geo_unavailable_refuses() {
    local out rc why=""
    out=$(GUARD_GEO_RIPE_URL=file:///nonexistent g_on --geo ru)
    rc=$?
    [ "$rc" != 0 ] || why="rc 0;"
    printf '%s\n' "$out" | grep -q 'гео-список не получен' || why="$why нет отказа «гео-список не получен»;"
    [ -z "$(srv_xdp)" ] || why="$why на $SRV_IF висит XDP;"
    nft_has && why="$why есть таблица nd_guard;"
    tc_has 10 && why="$why есть tc pref 10;"
    pin_empty || why="$why pin'ы в $PIN;"
    [ -z "$why" ] || why="$why [$(tail3 "$out")]"
    verdict "geo_unavailable_refuses (rc $rc, хост не тронут)" "$why"
}

# F4/D10: порт SSH в --ports → rc 2 до любых изменений (SSH guard не трогает)
case_ssh_port_refused() {
    local out rc ssh why=""
    ssh=$(in_srv bash -c 'source lib/common.sh; detect_ssh_port')
    out=$(g_on --ports "443,$ssh")
    rc=$?
    [ "$rc" = 2 ] || why="rc $rc, а не 2;"
    printf '%s\n' "$out" | grep -q "SSH на порту $ssh" || why="$why нет отказа «SSH на порту $ssh»;"
    [ -z "$(srv_xdp)" ] || why="$why на $SRV_IF висит XDP;"
    nft_has && why="$why есть таблица nd_guard;"
    pin_empty || why="$why pin'ы в $PIN;"
    [ -z "$why" ] || why="$why [$(tail3 "$out")]"
    verdict "ssh_port_refused (--ports 443,$ssh → rc $rc, хост не тронут)" "$why"
}

# вариант 1: RU-клиент проходит, «чужой» — DROP в XDP (таймаут); v4 и v6, geo_drop растёт
case_variant1_geo_drop() {
    local out s0 s1 why=""
    if ! out=$(g_on --geo ru --cookies off); then bad "variant1_geo_drop: guard on: $(tail3 "$out")"; return; fi
    s0=$(stats)
    out=$(cli_from "$CLI4" "$SRV4") || why="RU v4 не прошёл ($out);"
    out=$(cli_from "$CLI6" "$SRV6") || why="$why RU v6 не прошёл ($out);"
    cli_from "$FOREIGN4" "$SRV4" >/dev/null && why="$why чужой v4 прошёл;"
    cli_from "$FOREIGN6" "$SRV6" >/dev/null && why="$why чужой v6 прошёл;"
    s1=$(stats)
    [ "$(delta geo_drop "$s0" "$s1")" -ge 2 ] || why="$why geo_drop не вырос [$s1];"
    if ! out=$(guard status) || ! printf '%s\n' "$out" | grep -q 'только Россия'; then
        why="$why status: нет «только Россия» [$(tail3 "$out")];"
    fi
    why="$why$(xdp_mode_why drv)"   # D12: только гео (DROP/PASS) — native и на veth
    verdict "variant1_geo_drop (RU v4/v6 эхо, чужие v4/v6 — таймаут, geo_drop +$(delta geo_drop "$s0" "$s1"), XDP drv)" "$why"
}

# R11/D12 на veth: с cookies (auto) — generic с объяснением (native XDP_TX не доходит до peer'а без
# его XDP-программы — SYN-ACK с cookie пропадали бы молча); снова без cookies — обратно drv, одна
# программа. Ядро без kfunc: cookies выключены — drv в обоих случаях
case_xdp_mode_veth() {
    local out m why=""
    m=$(cookie_xdp_mode)
    if ! out=$(g_on --geo ru); then bad "xdp_mode_veth: on --geo ru: $(tail3 "$out")"; return; fi
    why="$(xdp_mode_why "$m")"
    if [ "$m" = generic ] && ! printf '%s\n' "$out" | grep -q 'veth'; then
        why="$why on не объяснил generic на veth [$(tail3 "$out")];"
    fi
    out=$(cli_from "$CLI4" "$SRV4") || why="$why RU v4 при cookies auto ($out);"
    if ! out=$(g_on --geo ru --cookies off); then bad "xdp_mode_veth: on --cookies off: $(tail3 "$out")"; return; fi
    why="$why$(xdp_mode_why drv)"
    [ "$(srv_xdp | wc -l)" = 1 ] || why="$why XDP-программ на $SRV_IF: $(srv_xdp | wc -l);"
    verdict "xdp_mode_veth (cookies auto → XDP $m, cookies off → drv)" "$why"
}

# D8: allowlist обходит гео; запись в allow.list и обратно
case_allowlist_bypasses_geo() {
    local out why=""
    out=$(guard allow "$FOREIGN4") || why="allow: $(tail3 "$out");"
    out=$(cli_from "$FOREIGN4" "$SRV4") || why="$why чужой v4 из allowlist не прошёл ($out);"
    grep -qx "$FOREIGN4/32" "$GUARD_DIR/allow.list" 2>/dev/null || why="$why нет $FOREIGN4/32 в allow.list;"
    out=$(guard unallow "$FOREIGN4") || why="$why unallow: $(tail3 "$out");"
    cli_from "$FOREIGN4" "$SRV4" >/dev/null && why="$why после unallow чужой v4 прошёл;"
    grep -qx "$FOREIGN4/32" "$GUARD_DIR/allow.list" 2>/dev/null && why="$why $FOREIGN4/32 остался в allow.list;"
    verdict "allowlist_bypasses_geo (allow → проходит, unallow → таймаут)" "$why"
}

# R6: conntrack в gsrv включён ct-правилом (nd_test_ct); контроль — без guard записи на :443 есть
case_notrack_no_conntrack_entries() {
    local out n0 n1 why=""
    out=$(guard off) || why="off: $(tail3 "$out");"
    in_srv conntrack -F >/dev/null 2>&1
    out=$(cli_from "$CLI4" "$SRV4") || why="$why эхо без guard ($out);"
    n0=$(ct_443)
    [ "$n0" -gt 0 ] || why="$why контроль: без guard записей на :$PORT нет — conntrack в gsrv не работает;"
    out=$(g_on --geo ru --cookies off) || why="$why on: $(tail3 "$out");"
    in_srv conntrack -F >/dev/null 2>&1
    out=$(cli_from "$CLI4" "$SRV4") || why="$why эхо v4 с guard ($out);"
    out=$(cli_from "$CLI6" "$SRV6") || why="$why эхо v6 с guard ($out);"
    n1=$(ct_443)
    [ "$n1" = 0 ] || why="$why с guard записей на :$PORT: $n1;"
    verdict "notrack_no_conntrack_entries (без guard: $n0, с guard: $n1)" "$why"
}

# F5: ICMP-ошибка о потоке guard (node:443 → клиент) — у потока под NOTRACK нет записи conntrack,
# и без guard-правила она попадала бы в ct state invalid (drop в protect/ufw раньше accept ICMP —
# чёрная дыра PMTU). Контроль без guard: invalid; с guard: untracked, не invalid. Счётчики — в gsrv
icmp_cnt() { in_srv nft list counter inet nd_test_icmp "$1" 2>/dev/null | sed -n 's/.*packets \([0-9]*\).*/\1/p'; }
icmp_send() {   # → «inv4 unt4 inv6 unt6» — прирост счётчиков после frag-needed (v4) и packet-too-big (v6)
    local c b=() a=()
    for c in inv4 unt4 inv6 unt6; do b+=("$(icmp_cnt "$c")"); done
    in_cli python3 "$TMP/icmperr.py" 4 "$CLI4" "$SRV4"
    in_cli python3 "$TMP/icmperr.py" 6 "$CLI6" "$SRV6"
    sleep 0.2
    for c in inv4 unt4 inv6 unt6; do a+=("$(icmp_cnt "$c")"); done
    echo "$((a[0] - b[0])) $((a[1] - b[1])) $((a[2] - b[2])) $((a[3] - b[3]))"
}
case_icmp_errors_not_invalid() {
    local out d0 d1 why=""
    if ! in_srv nft -f - <<'EOF'
table inet nd_test_icmp {
	counter inv4 {}
	counter unt4 {}
	counter inv6 {}
	counter unt6 {}
	chain in {
		type filter hook input priority filter; policy accept;
		icmp type destination-unreachable ct state invalid counter name inv4
		icmp type destination-unreachable ct state untracked counter name unt4
		icmpv6 type packet-too-big ct state invalid counter name inv6
		icmpv6 type packet-too-big ct state untracked counter name unt6
	}
}
EOF
    then
        bad "icmp_errors_not_invalid: тестовая таблица nft не встала"
        return
    fi
    out=$(guard off) || why="off: $(tail3 "$out");"
    d0=$(icmp_send)
    [ "$d0" = "1 0 1 0" ] || why="$why контроль без guard: «inv4 unt4 inv6 unt6» = $d0, а не «1 0 1 0»;"
    out=$(g_on --geo ru --cookies off) || why="$why on: $(tail3 "$out");"
    d1=$(icmp_send)
    [ "$d1" = "0 1 0 1" ] || why="$why с guard: «inv4 unt4 inv6 unt6» = $d1, а не «0 1 0 1»;"
    in_srv nft delete table inet nd_test_icmp 2>/dev/null
    verdict "icmp_errors_not_invalid (без guard — invalid: $d0; с guard — untracked: $d1)" "$why"
}

# вариант 2, cookies always: и RU, и «чужие» проходят через cookie-путь (XDP → tc → kfunc)
case_variant2_cookies_always() {
    local out s0 s1 why=""
    need_kfunc variant2_cookies_always || return
    out=$(guard off) || why="off: $(tail3 "$out");"
    if ! out=$(g_on --cookies always); then bad "variant2_cookies_always: on: $(tail3 "$out")"; return; fi
    tc_has 10 || why="$why нет tc pref 10;"
    why="$why$(xdp_mode_why generic)"   # R11: cookie-путь на veth — generic
    s0=$(stats)
    out=$(cli_from "$CLI4" "$SRV4") || why="$why RU v4 ($out);"
    out=$(cli_from "$FOREIGN4" "$SRV4") || why="$why чужой v4 ($out);"
    out=$(cli_from "$FOREIGN6" "$SRV6") || why="$why чужой v6 ($out);"
    s1=$(stats)
    [ "$(delta cookie_ok "$s0" "$s1")" -ge 3 ] || why="$why cookie_ok +$(delta cookie_ok "$s0" "$s1") < 3;"
    [ "$(delta geo_drop "$s0" "$s1")" = 0 ] || why="$why geo_drop вырос;"
    [ "$(st assign_err "$s1")" = 0 ] || why="$why assign_err=$(st assign_err "$s1");"
    [ -z "$why" ] || why="$why [$s1]"
    verdict "variant2_cookies_always (RU и чужие v4/v6, cookie_ok +$(delta cookie_ok "$s0" "$s1"), XDP generic)" "$why"
}

# F2: tc-объект не загрузился (битый .o новее исходников — _guard_compile его не пересобирает) — как
# отказ tc attach (D9): вариант 1 не отказывает, а ставит XDP для гео без cookies (drv, без pref 10);
# вариант 2 без гео — только NOTRACK. Потом .o удаляется — следующий on соберёт его заново
case_tc_load_fail_degrades() {
    local out obj="$GUARD_DIR/nd-guard-tc.bpf.o" why=""
    need_kfunc tc_load_fail_degrades || return
    printf 'не ELF\n' >"$obj"
    if out=$(g_on --geo ru --cookies always); then
        printf '%s\n' "$out" | grep -q 'tc-объект не загрузился' || why="нет предупреждения о tc-объекте;"
        why="$why$(xdp_mode_why drv)"
        tc_has 10 && why="$why есть tc pref 10;"
        grep -qx 'COOKIES=always' "$GUARD_DIR/guard.conf" 2>/dev/null || why="$why guard.conf не помнит cookies always;"
        out=$(cli_from "$CLI4" "$SRV4") || why="$why RU v4 ($out);"
        cli_from "$FOREIGN4" "$SRV4" >/dev/null && why="$why чужой v4 прошёл — гео не работает;"
    else
        why="вариант 1 отказал: $(tail3 "$out");"
    fi
    if out=$(g_on --cookies always); then
        [ -z "$(srv_xdp)" ] || why="$why вариант 2: XDP висит без дела;"
        tc_has 10 && why="$why вариант 2: есть tc pref 10;"
        nft_has || why="$why вариант 2: нет NOTRACK;"
        pin_empty || why="$why вариант 2: pin'ы не пусты;"
    else
        why="$why вариант 2 отказал: $(tail3 "$out");"
    fi
    rm -f "$obj"
    verdict "tc_load_fail_degrades (вариант 1: XDP drv для гео без cookies; вариант 2: только NOTRACK)" "$why"
}

# повторный on не плодит программ и pin'ов; on без работы для XDP (гео и cookies выкл.) снимает их
case_reapply_no_stacking() {
    local out ck=off want="nd_guard_xdp" ntc=0 progs why=""
    has_kfunc && { ck=always want="nd_guard_tc nd_guard_xdp" ntc=1; }
    out=$(g_on --geo ru --cookies "$ck") && out=$(g_on --geo ru --cookies "$ck") || why="on ×2: $(tail3 "$out");"
    [ "$(srv_xdp | wc -l)" = 1 ] || why="$why XDP-программ на $SRV_IF: $(srv_xdp | wc -l);"
    why="$why$(xdp_mode_why "$(cookie_xdp_mode)")"
    [ "$(in_srv tc filter show dev "$SRV_IF" ingress | grep -c 'handle.*nd_guard_tc')" = "$ntc" ] \
        || why="$why tc-фильтров nd_guard_tc не $ntc;"
    progs=$(ls "$PIN/progs" 2>/dev/null | tr '\n' ' ')
    [ "$progs" = "$want " ] || why="$why pin'ы программ: '$progs';"
    [ ! -e "$PIN-new" ] || why="$why остался $PIN-new;"
    out=$(g_on --cookies off) || why="$why on --cookies off: $(tail3 "$out");"
    [ -z "$(srv_xdp)" ] || why="$why после on --cookies off XDP висит;"
    tc_has 10 && why="$why после on --cookies off есть pref 10;"
    pin_empty || why="$why после on --cookies off pin'ы не пусты;"
    nft_has || why="$why после on --cookies off нет NOTRACK;"
    verdict "reapply_no_stacking (on ×2: 1 XDP, $ntc tc, pin'ы без дублей; без дела — XDP/tc сняты)" "$why"
}

# Review Focus 3 / D11: шейпер (pref 49200) и guard (pref 10) на одном clsact; выключение одного не
# ломает другой. shape.sh настоящий (on/off): интерфейс — из default route gsrv, состояние — в
# $ND_STATE_DIR; без systemd его юнит не ставится (на CI runner ставится и снимается shape off)
case_shaper_survives_guard() {
    local out why=""
    need_kfunc shaper_survives_guard || return
    if [ -e /sys/fs/bpf/nd-shaper ] || [ -e /etc/systemd/system/node-diagnostic-shaper.service ]; then
        skip "shaper_survives_guard — на хосте уже есть шейпер (не трогаю)"
        return
    fi
    out=$(guard off) || why="off: $(tail3 "$out");"
    SHAPE_TOUCHED=1
    if ! out=$(shape on) || ! tc_has 49200; then bad "shaper_survives_guard: shape on: $(tail3 "$out")"; return; fi
    out=$(g_on --cookies always) || why="$why on: $(tail3 "$out");"
    { tc_has 10 && tc_has 49200; } || why="$why guard on: нет pref 10 и 49200 вместе;"
    why="$why$(xdp_mode_why generic)"
    out=$(guard off) || why="$why off: $(tail3 "$out");"
    tc_has 49200 || why="$why guard off снял pref 49200 шейпера;"
    tc_has 10 && why="$why guard off не снял pref 10;"
    out=$(g_on --cookies always) || why="$why on №2: $(tail3 "$out");"
    out=$(shape off) || why="$why shape off: $(tail3 "$out");"
    SHAPE_TOUCHED=0
    tc_has 10 || why="$why shape off снял pref 10 guard;"
    tc_has 49200 && why="$why shape off не снял pref 49200;"
    out=$(cookie_echo "$SRV4")
    [ -z "$out" ] || why="$why cookie-путь после shape off: $out;"
    verdict "shaper_survives_guard (guard off → pref 49200 есть; shape off → pref 10 есть, cookie-эхо ок)" "$why"
}

# F6: обновление с версии шейпера без pref — её фильтры (авто-pref 49152…) на той же программе.
# shape on оставляет ровно один свой фильтр на направление (pref 49200), shape off — ни одного;
# чужой фильтр (matchall pref 20) и pref 10 guard не задеваются
shaper_n() { in_srv tc filter show dev "$SRV_IF" "$1" | grep -cE 'handle .*nd_shape_(up|down)'; }
shaper_legacy() {   # фильтры «прежней версии»: без pref, на текущих pin'ах
    in_srv tc filter add dev "$SRV_IF" ingress bpf direct-action pinned /sys/fs/bpf/nd-shaper/progs/nd_shape_up \
        && in_srv tc filter add dev "$SRV_IF" egress bpf direct-action pinned /sys/fs/bpf/nd-shaper/progs/nd_shape_down
}
case_shaper_legacy_filters_removed() {
    local out g10=0 why=""
    if [ -e /sys/fs/bpf/nd-shaper ] || [ -e /etc/systemd/system/node-diagnostic-shaper.service ]; then
        skip "shaper_legacy_filters_removed — на хосте уже есть шейпер (не трогаю)"
        return
    fi
    tc_has 10 && g10=1
    SHAPE_TOUCHED=1
    if ! out=$(shape on); then bad "shaper_legacy_filters_removed: shape on: $(tail3 "$out")"; return; fi
    in_srv tc filter add dev "$SRV_IF" ingress pref 20 matchall action pass || why="чужой matchall не встал;"
    shaper_legacy || why="$why фильтры без pref не встали;"
    [ "$(shaper_n ingress) $(shaper_n egress)" = "2 2" ] || why="$why до shape on своих фильтров не 2+2;"
    out=$(shape on) || why="$why shape on №2: $(tail3 "$out");"
    [ "$(shaper_n ingress) $(shaper_n egress)" = "1 1" ] \
        || why="$why после shape on своих фильтров $(shaper_n ingress)+$(shaper_n egress), а не 1+1;"
    tc_has 49200 || why="$why нет pref 49200;"
    shaper_legacy || why="$why фильтры без pref №2 не встали;"
    out=$(shape off) || why="$why shape off: $(tail3 "$out");"
    SHAPE_TOUCHED=0
    [ "$(shaper_n ingress) $(shaper_n egress)" = "0 0" ] \
        || why="$why после shape off своих фильтров $(shaper_n ingress)+$(shaper_n egress);"
    tc_has 20 || why="$why чужой pref 20 снят;"
    [ "$g10" = 0 ] || tc_has 10 || why="$why pref 10 guard снят;"
    in_srv tc filter del dev "$SRV_IF" ingress pref 20 2>/dev/null
    verdict "shaper_legacy_filters_removed (on: 1+1 на pref 49200; off: 0; pref 20 и guard pref 10 на месте)" "$why"
}

# Review Focus 4 / D7: certbot pre-хук снимает гео с порта 80, post — возвращает; 443 не трогается
case_certbot_hooks_toggle_geo_80() {
    local out p0 p1 p2 p443 why=""
    if ! out=$(g_on --geo ru --cookies off); then bad "certbot_hooks_toggle_geo_80: on: $(tail3 "$out")"; return; fi
    p0=$(ctrl get-port 80)
    out=$(guard hook pre) || why="hook pre: $(tail3 "$out");"
    p1=$(ctrl get-port 80)
    p443=$(ctrl get-port 443)
    out=$(guard hook post) || why="$why hook post: $(tail3 "$out");"
    p2=$(ctrl get-port 80)
    [ "$p0" = tcp,udp,geo ] || why="$why до хука 80: $p0;"
    [ "$p1" = tcp,udp ] || why="$why после pre 80: $p1;"
    [ "$p443" = tcp,udp,geo ] || why="$why pre задел 443: $p443;"
    [ "$p2" = tcp,udp,geo ] || why="$why после post 80: $p2;"
    verdict "certbot_hooks_toggle_geo_80 (pre: 80 → $p1, post: 80 → $p2)" "$why"
}

# имитация reboot: XDP/tc сняты, pin'ы и NOTRACK пропали (GUARD_DIR на диске — остался); rc 1 — не вышло
reboot_sim() {
    in_srv ip link set dev "$SRV_IF" xdpdrv off 2>/dev/null
    in_srv ip link set dev "$SRV_IF" xdpgeneric off 2>/dev/null
    in_srv tc filter del dev "$SRV_IF" ingress pref 10 2>/dev/null
    in_srv nft delete table inet nd_guard 2>/dev/null
    rm -rf "$PIN"
    [ -z "$(srv_xdp)" ] && ! tc_has 10 && ! nft_has
}

# reboot: XDP/tc сняты, pin'ы и NOTRACK пропали, сеть «недоступна» — reattach поднимает всё по
# guard.conf и гео-кешу (без скачиваний)
case_reattach_restores_from_disk() {
    local out why=""
    if ! out=$(g_on --geo ru); then bad "reattach_restores_from_disk: on: $(tail3 "$out")"; return; fi
    if ! reboot_sim; then bad "reattach_restores_from_disk: имитация reboot не удалась"; return; fi
    out=$(GUARD_GEO_RIPE_URL=file:///nonexistent guard reattach) || why="reattach rc≠0: $(tail3 "$out");"
    [ -n "$(srv_xdp)" ] || why="$why нет XDP;"
    why="$why$(xdp_mode_why "$(cookie_xdp_mode)")"   # reattach выбирает режим так же, как on (R11)
    nft_has || why="$why нет NOTRACK;"
    if has_kfunc; then tc_has 10 || why="$why нет tc pref 10;"; fi
    out=$(cli_from "$CLI4" "$SRV4") || why="$why RU v4 не прошёл ($out);"
    cli_from "$FOREIGN4" "$SRV4" >/dev/null && why="$why чужой v4 прошёл — гео не из кеша;"
    verdict "reattach_restores_from_disk (XDP $(cookie_xdp_mode), tc, NOTRACK и гео по кешу)" "$why"
}

# F3/D10: on без подтверждения оставляет метку unconfirmed (dead-man — таймер systemd-run, reboot его
# не переживает; GUARD_NO_SYSTEMD=1 → GUARD_FORCE_UNCONFIRMED=1). Reboot до подтверждения: reattach
# не поднимает guard, а снимает целиком, как dead-man (guard off), rc 0. guard confirm и on --confirm
# метку снимают — тогда reattach восстанавливает
case_reattach_unconfirmed_rolls_back() {
    local out rc mark="$GUARD_DIR/unconfirmed" why=""
    if ! out=$(GUARD_FORCE_UNCONFIRMED=1 guard on --geo ru --iface "$SRV_IF"); then
        bad "reattach_unconfirmed_rolls_back: on: $(tail3 "$out")"
        return
    fi
    [ -e "$mark" ] || why="on без --confirm не оставил метку;"
    if ! reboot_sim; then bad "reattach_unconfirmed_rolls_back: имитация reboot не удалась"; return; fi
    out=$(GUARD_GEO_RIPE_URL=file:///nonexistent guard reattach)
    rc=$?
    [ "$rc" = 0 ] || why="$why reattach rc $rc;"
    printf '%s\n' "$out" | grep -q 'не был подтверждён до перезагрузки' || why="$why нет сообщения об откате [$(tail3 "$out")];"
    why="$why$(gone)"
    [ ! -e "$GUARD_DIR/guard.conf" ] || why="$why guard.conf остался;"
    [ ! -e "$mark" ] || why="$why метка осталась;"
    # confirm снимает метку → reboot восстанавливает; on --confirm метку не ставит
    out=$(GUARD_FORCE_UNCONFIRMED=1 guard on --geo ru --iface "$SRV_IF") || why="$why on №2: $(tail3 "$out");"
    out=$(guard confirm) || why="$why confirm: $(tail3 "$out");"
    [ ! -e "$mark" ] || why="$why guard confirm не снял метку;"
    reboot_sim || why="$why имитация reboot №2;"
    out=$(GUARD_GEO_RIPE_URL=file:///nonexistent guard reattach) || why="$why reattach после confirm: $(tail3 "$out");"
    [ -n "$(srv_xdp)" ] || why="$why после confirm reattach не вернул XDP;"
    out=$(GUARD_FORCE_UNCONFIRMED=1 g_on --geo ru) || why="$why on --confirm: $(tail3 "$out");"
    [ ! -e "$mark" ] || why="$why on --confirm оставил метку;"
    verdict "reattach_unconfirmed_rolls_back (без подтверждения reboot → guard off, rc 0; confirm → reattach восстанавливает)" "$why"
}

# off --keep-config снимает рантайм, но оставляет guard.conf; off — и его. Ключ, гео-кеш и
# allow.list остаются всегда. Ни XDP, ни tc pref 10, ни nd_guard, pin'ы пусты; status работает
gone() {   # пусто — от guard в рантайме ничего не осталось
    [ -z "$(srv_xdp)" ] || printf ' XDP висит;'
    tc_has 10 && printf ' есть pref 10;'
    nft_has && printf ' есть nd_guard;'
    pin_empty || printf ' pin'"'"'ы не пусты;'
    return 0
}
kept() {   # пусто — ключ, гео-кеш и allow.list на месте
    [ -s "$GUARD_DIR/key" ] || printf ' нет key;'
    [ -s "$GUARD_DIR/geo/geo4.txt" ] || printf ' нет гео-кеша;'
    grep -qx 192.0.2.0/24 "$GUARD_DIR/allow.list" 2>/dev/null || printf ' нет allow.list;'
    return 0
}
case_off_cleans_everything() {
    local out why=""
    out=$(guard allow 192.0.2.0/24) || why="allow: $(tail3 "$out");"
    out=$(guard off --keep-config) || why="$why off --keep-config: $(tail3 "$out");"
    why="$why$(gone)$(kept)"
    [ -s "$GUARD_DIR/guard.conf" ] || why="$why off --keep-config удалил guard.conf;"
    out=$(guard reattach) || why="$why reattach после off --keep-config: $(tail3 "$out");"
    [ -n "$(srv_xdp)" ] || why="$why reattach не вернул XDP;"
    out=$(guard off) || why="$why off: $(tail3 "$out");"
    why="$why$(gone)$(kept)"
    [ ! -e "$GUARD_DIR/guard.conf" ] || why="$why off оставил guard.conf;"
    if ! out=$(guard status) || ! printf '%s\n' "$out" | grep -q 'выключен'; then
        why="$why status после off [$(tail3 "$out")];"
    fi
    verdict "off_cleans_everything (--keep-config: конфиг есть; off: нет XDP/pref 10/nd_guard/pin'ов; key, гео, allow.list — на месте)" "$why"
}

mode_guard() {
    local out c
    echo "== guard: стенд gsrv ⇄ gcli, modules/guard.sh --iface $SRV_IF =="
    guard_env
    if ! out=$(guard_setup 2>&1); then bad "стенд: $out"; return; fi
    ok "стенд: чужие $FOREIGN4/$FOREIGN6 на $CLI_IF (без XDP на peer, как в LXC), ct-правило в $SRV_NS"
    if ! srv_start 6; then bad "эхо-сервер [::]:$PORT не поднялся: $(cat "$TMP/echo.log")"; return; fi
    if out=$(cli_from "$CLI4" "$SRV4") && out=$(cli_from "$CLI6" "$SRV6") && out=$(cli_from "$FOREIGN4" "$SRV4"); then
        ok "связность без guard (RU v4/v6, чужой v4)"
    else
        bad "связность без guard: $out"
        return
    fi
    echo "== guard: кейсы (ядро $(uname -r)) =="
    for c in "${GUARD_CASES[@]}"; do "case_$c"; done
}

# ── main ──

case "${1:-}" in
raw) tools=() ;;
guard) tools=(nft conntrack ethtool curl) ;;   # curl: guard.sh качает гео-фикстуру по file://
*)
    echo "использование: $0 raw|guard" >&2
    exit 2
    ;;
esac
if [ "$(id -u)" != 0 ]; then
    echo "guard-netns: нужен root" >&2
    exit 1
fi
for t in clang "$BPFTOOL" ip tc ss nsenter python3 ${tools[@]+"${tools[@]}"}; do
    command -v "$t" >/dev/null 2>&1 || { echo "guard-netns: нет $t (tests/guard-deps.sh)" >&2; exit 1; }
done
grep -qs ' /sys/fs/bpf bpf ' /proc/mounts || { echo "guard-netns: bpffs не смонтирован на /sys/fs/bpf" >&2; exit 1; }

TMP=$(mktemp -d)
KEY="$TMP/key"
trap cleanup EXIT
trap 'exit 130' INT TERM
write_helpers

"mode_$1"

echo
if [ "$fail" = 0 ]; then echo "GUARD-NETNS OK"; exit 0; else echo "GUARD-NETNS FAIL"; exit 1; fi
