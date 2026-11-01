#!/usr/bin/env bash
# tests/guard-netns.sh — guard в netns-стенде: gcli (клиент) ⇄ veth ⇄ gsrv (сервер; XDP + tc на gsrv0).
#   raw — объекты BPF собираются и цепляются напрямую (bpftool / ip / tc), без guard.sh
# Запуск от root: sudo bash tests/guard-deps.sh && sudo bash tests/guard-netns.sh raw
#   → последняя строка GUARD-NETNS OK (rc 0), иначе GUARD-NETNS FAIL (rc 1); неизвестный режим — rc 2.
# Ядро без kfunc bpf_sk_assign_tcp_reqsk: cookie-кейсы — SKIP + ::warning:: (компиляция и загрузка
# tc-объекта проверяются и тогда); ND_GUARD_REQUIRE_KFUNC=1 (CI) — вместо SKIP провал.
#
# Устройство (новый режим — функция mode_<имя>; переиспользуется всё, кроме raw_*):
#   net_up/net_down, srv_start 4|6, cli_echo, held_ss — сеть, эхо-сервер на :443 в gsrv, клиент в gcli;
#   stats/st/delta — счётчики guard_ctrl.py stats по $MAPS (карты guard: XDP пинит, tc переиспользует);
#   set_cookies/state_reset (ключ $KEY), bad_ack — управление режимом и «чужой» ACK;
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
TMP=""
KEY=""
SRV_PID=""

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
    net_down
    rm -rf "$PIN"
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
    # client.py ADDR [HOLD] — эхо; с HOLD печатает "up <локальный порт>" и держит соединение HOLD с
    cat >"$TMP/client.py" <<'EOF'
import socket, sys, time
addr = sys.argv[1]
hold = float(sys.argv[2]) if len(sys.argv) > 2 else 0.0
try:
    s = socket.create_connection((addr, 443), timeout=3)
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

# guard_state_map[0] = 0: окна SYN нет, attack_until_ns = 0 («атаки не было»)
state_reset() {
    local z=()
    for _ in $(seq 24); do z+=(00); done
    "$BPFTOOL" map update pinned "$MAPS/guard_state_map" key hex 00 00 00 00 value hex "${z[@]}"
}

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
# (cookie_bad не растёт, RST от ядра есть); auto под атакой (порог 0) — cookie-путь работает.
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

    { set_cookies auto >/dev/null && state_reset >/dev/null; } || why="$why сброс в auto без атаки;"
    now=$(ctrl state | sed -n 's/.*now_ns=\([0-9]*\).*/\1/p')
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
        ok "cookie_modes (off, auto под атакой, $idle)"
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

# ── main ──

case "${1:-}" in
raw) ;;
*)
    echo "использование: $0 raw" >&2
    exit 2
    ;;
esac
if [ "$(id -u)" != 0 ]; then
    echo "guard-netns: нужен root" >&2
    exit 1
fi
for t in clang "$BPFTOOL" ip tc ss nsenter python3; do
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
