#!/usr/bin/env bash
# modules/guard.sh — защита ноды от DDoS на L3/L4 (IP/TCP; содержимое TLS/HTTP не разбирается).
# Опциональная, по умолчанию выключена. Состав:
#   NOTRACK — conntrack не ведёт порты ноды (nft, table inet nd_guard, priority raw);
#   XDP     — гео-DROP по LPM (вариант 1) и SYN-ACK с SYN-cookie (nd-guard-xdp.bpf.c);
#   tc      — ingress pref 10: ACK с cookie → bpf_sk_assign_tcp_reqsk, без conntrack (nd-guard-tc.bpf.c).
# Вариант 1 «только Россия»: guard on --geo ru.  Вариант 2 «весь мир»: guard on.
#
#   guard on [--geo ru|off] [--cookies auto|always|off] [--syn-threshold N] [--ports 443,80] [--iface IF] [--confirm]
#   guard off [--keep-config]          # без --keep-config ещё юниты, таймер, хуки и guard.conf
#   guard status
#   guard reattach                     # systemd на boot: из GUARD_DIR, без скачиваний
#   guard allow CIDR | unallow CIDR    # обход гео и cookies (+ GUARD_DIR/allow.list)
#   guard update-geo                   # таймер: обновить гео-список
#   guard confirm                      # снять dead-man и метку «не подтверждён» (иначе reboot откатит)
#   guard hook pre|post                # certbot: снять/вернуть гео на 80
# rc: 0 — ок, 1 — ошибка выполнения, 2 — неверные аргументы.
#
# Карты трогает только guard_ctrl.py; гео-список собирает guard_geo.py из файлов, которые качает
# этот модуль. Env для тестов: GUARD_DIR, GUARD_PIN, GUARD_NO_SYSTEMD=1 (без юнитов, таймера,
# dead-man и хуков), GUARD_FORCE_KFUNC=0|1, GUARD_FORCE_UNCONFIRMED=1 (метка без dead-man), GUARD_GEO_RIPE_URL,
# GUARD_GEO_DBIP_URL, GUARD_GEO_MIN_V4_ADDRS, GUARD_GEO_MIN_V4_PREFIXES, GUARD_GEO_MIN_V6_PREFIXES (→ guard_geo.py).
# Подключается через source (smoke): guard_main выполняется, только если файл запущен напрямую.
set -u
_guard_self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$_guard_self/../lib/common.sh" 2>/dev/null || { echo "guard: нет lib/common.sh" >&2; return 1 2>/dev/null || exit 1; }

GUARD_DIR="${GUARD_DIR:-/var/lib/node-diagnostic/guard}"   # D14: переживает reboot (не /run)
GUARD_PIN="${GUARD_PIN:-/sys/fs/bpf/nd-guard}"
BPFTOOL="${BPFTOOL:-bpftool}"
export BPFTOOL   # guard_ctrl.py берёт путь отсюда; рабочий bpftool — bpftool_find/ensure_bpftool (R14)
GUARD_CONF="$GUARD_DIR/guard.conf"
GUARD_KEY="$GUARD_DIR/key"
GUARD_GEO_CACHE="$GUARD_DIR/geo"                # принятый гео-список: geo4.txt, geo6.txt, geo.meta
GUARD_ALLOW="$GUARD_DIR/allow.list"
GUARD_LOADED="$GUARD_DIR/geo-loaded"            # что лежит в geo-картах (geo-sync --loaded-dir)
GUARD_UNCONFIRMED="$GUARD_DIR/unconfirmed"      # on без подтверждения: reattach на boot откатывает
GUARD_STAGE="$GUARD_PIN-new"                    # загрузка до attach; bpffs не принимает «.» в имени
GUARD_CTRL="$_guard_self/guard_ctrl.py"
GUARD_GEO_PY="$_guard_self/guard_geo.py"
GUARD_UNIT=node-diagnostic-guard
GUARD_GEO_UNIT=node-diagnostic-guard-geo
GUARD_DEADMAN=nd-guard-deadman
GUARD_DEADMAN_SEC=300
GUARD_HOOK=node-diagnostic-guard.sh
GUARD_XDP_PROG=nd_guard_xdp
GUARD_TC_PROG=nd_guard_tc
GUARD_RIPE_URL='https://stat.ripe.net/data/country-resource-list/data.json?resource=RU&v4_format=prefix'

# ── чистые функции (smoke через source) ──────────────────────────────

# PORT LOW → rc 0, если 1 <= PORT < LOW: порт ниже ip_local_port_range, NOTRACK и гео не заденут
# ответы на исходящие соединения ноды (D6)
_guard_port_ok() {
    case "$1" in '' | *[!0-9]*) return 1 ;; esac
    case "$2" in '' | *[!0-9]*) return 1 ;; esac
    [ "$((10#$1))" -ge 1 ] && [ "$((10#$1))" -lt "$((10#$2))" ]
}

# «ip -o link show IF» → rc 0, если у интерфейса Ethernet-заголовок (link/ether): XDP и tc guard
# разбирают Ethernet. tun/wg/ppp (link/none, link/ppp) guard молча пропускал бы, а status писал «вкл»
_guard_iface_ether() { case "$1" in *" link/ether "*) return 0 ;; *) return 1 ;; esac; }

# PORTS SSHPORTS → rc 0 и печать порта, если SSH (D10: guard его не трогает) попал в порты guard
_guard_ports_conflict_ssh() {
    local p s
    for p in ${1//,/ }; do
        case "$p" in '' | *[!0-9]*) continue ;; esac
        for s in ${2//,/ }; do
            case "$s" in '' | *[!0-9]*) continue ;; esac
            [ "$((10#$p))" = "$((10#$s))" ] && { echo "$((10#$s))"; return 0; }
        done
    done
    return 1
}

# BYTES → rcv_wscale, как в ядре (tcp_select_initial_window); вход — max(rmem_max, tcp_rmem[2])
_guard_rcv_wscale() {
    local space=$1 ws=0
    while [ "$space" -gt 65535 ] && [ "$ws" -lt 14 ]; do
        space=$((space >> 1))
        ws=$((ws + 1))
    done
    echo "$ws"
}

# GEO COOKIES HAS_KFUNC → rc 0, если XDP есть чем заняться (D2): гео или cookies при kfunc.
# Generic XDP без дела не вешаем: он линеаризует GRO-пакеты и съедает пропускную способность.
_guard_need_xdp() { [ "$1" = ru ] || { [ "$2" != off ] && [ "$3" = 1 ]; }; }

# COOKIES HAS_KFUNC → режим cookies с учётом ядра: без kfunc — off
_guard_effective_cookies() { if [ "$2" = 1 ]; then echo "$1"; else echo off; fi; }

# IFACE PORTS → ruleset NOTRACK; идиома protect.sh (table / delete table / table {}) — атомарная замена.
# ICMP-ошибки на потоки guard (frag-needed, packet-too-big…) — тоже мимо conntrack: записи потока нет,
# ошибка попала бы в ct state invalid, а его drop (protect, ufw before*.rules) стоит раньше accept ICMP —
# чёрная дыра PMTU. Внутренний sport — порт guard: ICMP 8 + IPv4 20 (IHL 5) = бит 224; ICMPv6 8 + 40 = 384
_guard_nft_render() {
    local set="${2//,/, }"
    cat <<EOF
table inet nd_guard
delete table inet nd_guard
table inet nd_guard {
	chain pre {
		type filter hook prerouting priority raw; policy accept;
		iifname "$1" tcp dport { $set } notrack
		iifname "$1" udp dport { $set } notrack
		iifname "$1" icmp type { destination-unreachable, time-exceeded, parameter-problem } @th,224,16 { $set } notrack
		iifname "$1" icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } @th,384,16 { $set } notrack
	}
	chain out {
		type filter hook output priority raw; policy accept;
		oifname "$1" tcp sport { $set } notrack
		oifname "$1" udp sport { $set } notrack
	}
}
EOF
}

# PORTS → rc 0 и имена контейнеров, публикующих порт через docker bridge: их DNAT держится на
# conntrack, с NOTRACK он ломается (D13). Нода с network_mode: host портов не публикует.
_guard_docker_conflict() {
    local name pp p hit=1
    have docker || return 1
    while read -r name pp; do
        for p in ${1//,/ }; do
            case "$pp" in *":$p->"*)
                echo "$name"
                hit=0
                break
                ;;
            esac
        done
    done < <(_guard_timeout docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null)
    return "$hit"
}

# rc 0 — в BTF ядра есть kfunc bpf_sk_assign_tcp_reqsk (D1: по BTF, а не по версии ядра)
_guard_has_kfunc() {
    case "${GUARD_FORCE_KFUNC:-}" in 1) return 0 ;; 0) return 1 ;; esac
    [ -r /sys/kernel/btf/vmlinux ] || return 1
    "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format raw 2>/dev/null \
        | grep -qF "'bpf_sk_assign_tcp_reqsk'"
}

# ── окружение ────────────────────────────────────────────────────────

_guard_timeout() { if have timeout; then timeout 15 "$@"; else "$@"; fi; }
# XDP-объект — глобальные функции с ctx-аргументом: без BTF ядра верификатор его не примет
_guard_btf_ok() { [ -r /sys/kernel/btf/vmlinux ]; }
_guard_systemd() { [ "${GUARD_NO_SYSTEMD:-0}" != 1 ] && have systemctl && [ -d /run/systemd/system ]; }
_guard_ctrl() { python3 "$GUARD_CTRL" --pin-dir "$GUARD_PIN/maps" "$@"; }
_guard_active() { [ -e "$GUARD_PIN/progs/$GUARD_XDP_PROG" ]; }   # XDP загружена, карты на месте
_guard_geo_cached() { [ -s "$GUARD_GEO_CACHE/geo4.txt" ] && [ -s "$GUARD_GEO_CACHE/geo6.txt" ]; }
_guard_badarg() {
    echo "guard: $*" >&2
    echo "  справка: guard help" >&2
    exit 2
}

_guard_kernel_ok() {   # ≥ 5.10
    local kv
    kv=$(uname -r | grep -oE '^[0-9]+\.[0-9]+' | head -n 1)
    awk -v v="$kv" 'BEGIN { split(v, a, "."); exit !(a[1] > 5 || (a[1] == 5 && a[2] >= 10)) }'
}

_guard_mtu() { ip -o link show dev "$1" 2>/dev/null | sed -n 's/.* mtu \([0-9][0-9]*\).*/\1/p'; }

_guard_rmem() {   # max(net.core.rmem_max, tcp_rmem[2]) — от этого ядро считает rcv_wscale
    local a b
    a=$(sysctl -n net.core.rmem_max 2>/dev/null)
    b=$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')
    case "$a" in '' | *[!0-9]*) a=0 ;; esac
    case "$b" in '' | *[!0-9]*) b=0 ;; esac
    if [ "$a" -gt "$b" ]; then echo "$a"; else echo "$b"; fi
}

_guard_u32() {   # целое 1…4294967295
    case "$1" in '' | *[!0-9]*) return 1 ;; esac
    [ "${#1}" -le 10 ] && [ "$1" -ge 1 ] && [ "$1" -le 4294967295 ]
}

_guard_ports_norm() {   # "443,80" → "443,80" без дублей; rc 1 — мусор
    local p out="" seen=","
    case "$1" in '' | *[!0-9,]*) return 1 ;; esac
    for p in ${1//,/ }; do
        p=$((10#$p))
        { [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; } || return 1
        case "$seen" in *",$p,"*) continue ;; esac
        seen="$seen$p,"
        out="${out:+$out,}$p"
    done
    [ -n "$out" ] && echo "$out"
}

_guard_cidr_norm() {   # IP|CIDR → сеть с префиксом (10.0.0.5 → 10.0.0.5/32); rc 1 — не адрес
    python3 -c 'import ipaddress, sys; print(ipaddress.ip_network(sys.argv[1].strip(), strict=False))' "$1" 2>/dev/null
}

# ── конфиг GUARD_DIR/guard.conf (600) ────────────────────────────────

_guard_defaults() {
    G_GEO=off G_COOKIES=auto G_THRESH=10000 G_HOLD=60 G_PORTS=443,80 G_IFACE="" G_XDP_MODE=none
    G_GRO_HW_RESTORE=0 G_CONFIRM=0
    G_GEO_RT=off G_EFF=off G_KFUNC=0 G_XDP_OK=0   # рантайм: гео, эффективные cookies, kfunc, XDP возможен
}

_guard_conf_load() {   # → G_*; rc 1 — файла нет или он битый
    local k v
    [ -r "$GUARD_CONF" ] || return 1
    while IFS='=' read -r k v; do
        case "$k" in
        GEO) G_GEO=$v ;;
        COOKIES) G_COOKIES=$v ;;
        SYN_THRESHOLD) G_THRESH=$v ;;
        HOLD) G_HOLD=$v ;;
        PORTS) G_PORTS=$v ;;
        IFACE) G_IFACE=$v ;;
        XDP_MODE) G_XDP_MODE=$v ;;
        GRO_HW_RESTORE) G_GRO_HW_RESTORE=$v ;;
        esac
    done <"$GUARD_CONF"
    case "$G_GEO" in ru | off) ;; *) return 1 ;; esac
    case "$G_COOKIES" in auto | always | off) ;; *) return 1 ;; esac
    _guard_u32 "$G_THRESH" && _guard_u32 "$G_HOLD" && [ -n "$G_IFACE" ] || return 1
    G_PORTS=$(_guard_ports_norm "$G_PORTS") || return 1
    case "$G_XDP_MODE" in drv | generic | none) ;; *) G_XDP_MODE=none ;; esac
    [ "$G_GRO_HW_RESTORE" = 1 ] || G_GRO_HW_RESTORE=0
}

_guard_conf_save() {
    (
        umask 077
        cat >"$GUARD_CONF.tmp" <<EOF
# node-diagnostic guard: пишут guard on/reattach, читает guard reattach (systemd на boot)
GEO=$G_GEO
COOKIES=$G_COOKIES
SYN_THRESHOLD=$G_THRESH
HOLD=$G_HOLD
PORTS=$G_PORTS
IFACE=$G_IFACE
XDP_MODE=$G_XDP_MODE
GRO_HW_RESTORE=$G_GRO_HW_RESTORE
EOF
    ) && chmod 600 "$GUARD_CONF.tmp" && mv -f "$GUARD_CONF.tmp" "$GUARD_CONF"
}

_guard_parse_on() {
    local opt val
    while [ $# -gt 0 ]; do
        case "$1" in
        --confirm)
            G_CONFIRM=1
            shift
            continue
            ;;
        --geo | --cookies | --syn-threshold | --ports | --iface)
            [ $# -ge 2 ] || _guard_badarg "$1: нужно значение"
            opt=$1 val=$2
            shift 2
            ;;
        --geo=* | --cookies=* | --syn-threshold=* | --ports=* | --iface=*)
            opt=${1%%=*} val=${1#*=}
            shift
            ;;
        *) _guard_badarg "on: неизвестный аргумент '$1'" ;;
        esac
        case "$opt" in
        --geo) case "$val" in ru | off) G_GEO=$val ;; *) _guard_badarg "--geo: ru|off, а не '$val'" ;; esac ;;
        --cookies) case "$val" in auto | always | off) G_COOKIES=$val ;; *) _guard_badarg "--cookies: auto|always|off, а не '$val'" ;; esac ;;
        --syn-threshold)
            _guard_u32 "$val" || _guard_badarg "--syn-threshold: целое 1…4294967295, а не '$val'"
            G_THRESH=$((10#$val))
            ;;
        --ports) G_PORTS=$(_guard_ports_norm "$val") || _guard_badarg "--ports: порты 1…65535 через запятую, а не '$val'" ;;
        --iface)
            case "$val" in '' | *[!A-Za-z0-9_.-]*) _guard_badarg "--iface: недопустимое имя '$val'" ;; esac
            G_IFACE=$val
            ;;
        esac
    done
}

# ── XDP, tc, rx-gro-hw ───────────────────────────────────────────────

# IF → «режим id имя» на каждую XDP-программу интерфейса (пусто — XDP нет); режим drv|generic|offload.
# Имя — из ip -d (iproute2 ≥ 5.x), иначе из bpftool.
_guard_xdp_list() {
    local out def tok id name m
    out=$(ip -d link show dev "$1" 2>/dev/null) || return 0
    case " ${out%%$'\n'*} " in
    *" xdpgeneric "*) def=generic ;;
    *" xdpoffload "*) def=offload ;;
    *) def=drv ;;
    esac
    printf '%s\n' "$out" | grep -oE 'prog/xdp[a-z]* id [0-9]+( name [^ ]+)?' \
        | while read -r tok _ id _ name; do
            case "$tok" in
            prog/xdpdrv) m=drv ;;
            prog/xdpgeneric) m=generic ;;
            prog/xdpoffload) m=offload ;;
            *) m=$def ;;
            esac
            [ -n "$name" ] || name=$("$BPFTOOL" prog show id "$id" 2>/dev/null | sed -n '1s/.* name \([^ ]*\).*/\1/p')
            echo "$m $id ${name:-?}"
        done
}

_guard_xdp_foreign() {   # IF → печатает чужую XDP-программу; rc 0 — она есть
    local m id name
    while read -r m id name; do
        [ "$name" = "$GUARD_XDP_PROG" ] && continue
        echo "$name (id $id, $m)"
        return 0
    done < <(_guard_xdp_list "$1")
    return 1
}

_guard_xdp_detach() {   # IF — снять только свою программу, в её режиме
    local m id name
    while read -r m id name; do
        [ "$name" = "$GUARD_XDP_PROG" ] || continue
        case "$m" in
        drv) ip link set dev "$1" xdpdrv off ;;
        generic) ip link set dev "$1" xdpgeneric off ;;
        offload) ip link set dev "$1" xdpoffload off ;;
        esac 2>/dev/null
    done < <(_guard_xdp_list "$1")
    return 0
}

_guard_gro_hw() { ethtool -k "$1" 2>/dev/null | awk '/^rx-gro-hw:/ { print ($3 == "[fixed]") ? "fixed" : $2; exit }'; }
_guard_gro_hw_set() { ethtool -K "$1" rx-gro-hw "$2" >/dev/null 2>&1; }

# R11: native XDP_TX на veth кладёт кадр в кольцо peer'а, но будит его (veth_xdp_flush), только если
# у peer'а своя XDP-программа. Peer eth0 контейнера LXC/Proxmox — на хосте, туда не поставить:
# SYN-ACK с cookie пропадали бы молча (чёрная дыра, не fail-open D9). XDP_DROP/XDP_PASS (гео) это не
# задевает. DRIVER COOKIES(0|1) → drv|generic
_guard_xdp_mode_plan() { if [ "$1" = veth ] && [ "$2" = 1 ]; then echo generic; else echo drv; fi; }

_guard_iface_driver() {   # IF → драйвер из ethtool -i; без ethtool veth узнаётся по типу ссылки (ip -d)
    local d
    d=$(ethtool -i "$1" 2>/dev/null | awk '/^driver:/ { print $2; exit }')
    if [ -z "$d" ] && ip -d -o link show dev "$1" 2>/dev/null | grep -q ' veth '; then d=veth; fi
    echo "$d"
}

# D12: native (xdpdrv); не встал и rx-gro-hw включён (virtio) — выключить и снова native, запомнив
# вернуть на off; иначе xdpgeneric с предупреждением. R11: veth с cookie-путём — сразу generic.
# IF PROG COOKIES(0|1) → G_XDP_MODE, G_GRO_HW_RESTORE.
_guard_xdp_attach() {
    local ifc="$1" prog="$2" log="$GUARD_DIR/xdp.log" plan
    plan=$(_guard_xdp_mode_plan "$(_guard_iface_driver "$ifc")" "$3")
    _guard_xdp_detach "$ifc"
    : >"$log"
    if [ "$plan" = generic ]; then
        msg_info "$ifc — veth: native XDP_TX не доходит до peer'а без его XDP-программы (peer на хосте), SYN-ACK с cookie терялись бы — XDP generic"
    else
        if ip link set dev "$ifc" xdpdrv pinned "$prog" 2>>"$log"; then
            G_XDP_MODE=drv
            return 0
        fi
        if [ "$(_guard_gro_hw "$ifc")" = on ] && _guard_gro_hw_set "$ifc" off; then
            if ip link set dev "$ifc" xdpdrv pinned "$prog" 2>>"$log"; then
                G_XDP_MODE=drv G_GRO_HW_RESTORE=1
                msg_info "rx-gro-hw на $ifc выключен ради native XDP (guard off вернёт)"
                return 0
            fi
            _guard_gro_hw_set "$ifc" on
        fi
    fi
    if [ "$G_GRO_HW_RESTORE" = 1 ]; then   # выключали раньше, а native сейчас не стоит
        _guard_gro_hw_set "$ifc" on
        G_GRO_HW_RESTORE=0
    fi
    if ip link set dev "$ifc" xdpgeneric pinned "$prog" 2>>"$log"; then
        G_XDP_MODE=generic
        [ "$plan" = drv ] && msg_warn "native XDP на $ifc не встал ($(tail -n 1 "$log")) — generic: работает, но медленнее"
        return 0
    fi
    G_XDP_MODE=none
    return 1
}

_guard_tc_ours() { tc filter show dev "$1" ingress pref "$ND_TC_PREF_GUARD" 2>/dev/null | grep -q "$GUARD_TC_PROG"; }

_guard_tc_attach() {   # IF PROG — pref 10 занят чужим фильтром → отказ (чужое не сносим)
    if [ -n "$(tc filter show dev "$1" ingress pref "$ND_TC_PREF_GUARD" 2>/dev/null)" ] && ! _guard_tc_ours "$1"; then
        echo "ingress pref $ND_TC_PREF_GUARD занят чужим фильтром" >"$GUARD_DIR/tc.log"
        return 1
    fi
    clsact_ensure "$1" \
        && tc_filter_put "$1" ingress "$ND_TC_PREF_GUARD" bpf direct-action pinned "$2" 2>"$GUARD_DIR/tc.log"
}

_guard_tc_detach() {   # IF — свой фильтр pref 10; clsact уходит, только если он опустел (D11)
    _guard_tc_ours "$1" || return 0
    tc filter del dev "$1" ingress pref "$ND_TC_PREF_GUARD" 2>/dev/null
    clsact_release "$1"
}

_guard_detach_iface() { _guard_xdp_detach "$1"; _guard_tc_detach "$1"; }

# всё своё из рантайма: XDP и tc (на всех интерфейсах — вдруг конфиг потерян), rx-gro-hw,
# NOTRACK, pin'ы. Интерфейсы — через ip (netlink текущего netns), не /sys/class/net.
_guard_runtime_down() {
    local ifc
    for ifc in $(ip -o link show 2>/dev/null | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }'); do
        _guard_detach_iface "$ifc"
    done
    [ "$G_GRO_HW_RESTORE" = 1 ] && [ -n "$G_IFACE" ] && _guard_gro_hw_set "$G_IFACE" on
    have nft && nft delete table inet nd_guard 2>/dev/null
    rm -rf "$GUARD_PIN" "$GUARD_STAGE" "$GUARD_LOADED" "$GUARD_LOADED.new" 2>/dev/null
    return 0
}

# ── сборка, загрузка, карты ──────────────────────────────────────────

_guard_newer() {   # OBJ SRC… → rc 0, если OBJ новее всех SRC
    local o="$1" s
    shift
    [ -f "$o" ] || return 1
    for s in "$@"; do [ "$o" -nt "$s" ] || return 1; done
}

_guard_compile() {   # → GUARD_DIR/nd-guard-{xdp,tc}.bpf.o; пропуск, если .o новее исходников
    local n src obj inc=()
    [ -d "/usr/include/$(uname -m)-linux-gnu" ] && inc=(-I"/usr/include/$(uname -m)-linux-gnu")
    for n in xdp tc; do
        src="$_guard_self/nd-guard-$n.bpf.c" obj="$GUARD_DIR/nd-guard-$n.bpf.o"
        [ -f "$src" ] || { msg_err "нет $src (нужен весь репозиторий)"; return 1; }
        _guard_newer "$obj" "$src" "$_guard_self/nd-guard.h" "$_guard_self/nd-guard-cookie.h" && continue
        have clang || { msg_err "нет clang — $obj не собрать"; return 1; }
        if ! clang -O2 -g -Wall -target bpf ${inc[@]+"${inc[@]}"} -c "$src" -o "$obj.tmp" >"$GUARD_DIR/clang-$n.log" 2>&1; then
            rm -f "$obj.tmp"
            msg_err "clang не собрал $src — смотри $GUARD_DIR/clang-$n.log (нет libbpf-dev/linux-libc-dev?)"
            return 1
        fi
        mv -f "$obj.tmp" "$obj"
    done
}

# WITH_TC → объекты в $GUARD_STAGE (живые pin'ы не тронуты до attach): XDP пинит карты, tc
# переиспользует 4 общие по имени. Повторный on не копит программы: живой каталог заменяется целиком.
# prog load с явным pin-путём (в каждом объекте одна программа), а не loadall: старый bpftool
# пинил loadall по секции (progs/xdp), и attach по progs/nd_guard_xdp не находил программу.
# rc 0 — всё загружено; 1 — XDP не загрузилась; 2 — XDP есть, tc-объект не загрузился (cookies — нет)
_guard_load() {
    local m reuse=() log="$GUARD_DIR/load.log"
    grep -qs ' /sys/fs/bpf bpf ' /proc/mounts || mount -t bpf bpf /sys/fs/bpf 2>/dev/null
    rm -rf "$GUARD_STAGE" "$GUARD_LOADED.new"
    mkdir -p "$GUARD_STAGE/progs" || return 1
    "$BPFTOOL" prog load "$GUARD_DIR/nd-guard-xdp.bpf.o" "$GUARD_STAGE/progs/$GUARD_XDP_PROG" type xdp \
        pinmaps "$GUARD_STAGE/maps" >"$log" 2>&1 || return 1
    [ "$1" = 1 ] || return 0
    for m in guard_cfg_map guard_state_map guard_ports_map guard_stats_map; do
        reuse+=(map name "$m" pinned "$GUARD_STAGE/maps/$m")
    done
    "$BPFTOOL" prog load "$GUARD_DIR/nd-guard-tc.bpf.o" "$GUARD_STAGE/progs/$GUARD_TC_PROG" type classifier \
        "${reuse[@]}" >>"$log" 2>&1 || return 2
}

_guard_stage_commit() {   # прицеплено из $GUARD_STAGE → он становится $GUARD_PIN
    rm -rf "$GUARD_PIN" "$GUARD_LOADED"
    mv "$GUARD_STAGE" "$GUARD_PIN" || { msg_warn "pin'ы остались в $GUARD_STAGE (mv не прошёл)"; return 1; }
    [ -d "$GUARD_LOADED.new" ] && mv "$GUARD_LOADED.new" "$GUARD_LOADED"
    return 0
}
_guard_stage_drop() { rm -rf "$GUARD_STAGE" "$GUARD_LOADED.new"; }

_guard_key() {   # D4: 16 байт из /dev/urandom, 600; существующий ключ остаётся
    [ "$(stat -c %s "$GUARD_KEY" 2>/dev/null)" = 16 ] && { chmod 600 "$GUARD_KEY"; return 0; }
    (
        umask 077
        head -c 16 /dev/urandom >"$GUARD_KEY.tmp"
    ) && mv -f "$GUARD_KEY.tmp" "$GUARD_KEY" && [ "$(stat -c %s "$GUARD_KEY" 2>/dev/null)" = 16 ]
}

_guard_set_cfg() {   # MAPS — guard_cfg_map[0] по G_GEO_RT, G_EFF, порогу и MTU интерфейса
    local geo=0 mtu
    [ "$G_GEO_RT" = ru ] && geo=1
    mtu=$(_guard_mtu "$G_IFACE")
    { [ -n "$mtu" ] && [ "$mtu" -ge 576 ] && [ "$mtu" -le 65535 ]; } || mtu=1500
    python3 "$GUARD_CTRL" --pin-dir "$1" set-cfg --geo "$geo" --cookies "$G_EFF" \
        --syn-threshold "$G_THRESH" --hold "$G_HOLD" --rcv-wscale "$(_guard_rcv_wscale "$(_guard_rmem)")" \
        --mss4 $((mtu - 40)) --mss6 $((mtu - 60)) --key-file "$GUARD_KEY"
}

# MAPS LOADED_DIR — cfg, порты (tcp,udp[,geo]), повтор allowlist, гео. geo-sync — только со списком,
# который принял guard_geo.py (кеш пишется лишь после rc 0): пустой файл дропнул бы всех.
_guard_maps() {
    local p fl=tcp,udp c out
    _guard_set_cfg "$1" || return 1
    [ "$G_GEO_RT" = ru ] && fl=tcp,udp,geo
    for p in ${G_PORTS//,/ }; do
        python3 "$GUARD_CTRL" --pin-dir "$1" set-port "$p" "$fl" || return 1
    done
    if [ -s "$GUARD_ALLOW" ]; then
        while read -r c _; do
            case "$c" in '' | '#'*) continue ;; esac
            python3 "$GUARD_CTRL" --pin-dir "$1" allow-add "$c" || msg_warn "allowlist: $c не добавлен"
        done <"$GUARD_ALLOW"
    fi
    [ "$G_GEO_RT" = ru ] || return 0
    _guard_geo_cached || return 1
    out=$(python3 "$GUARD_CTRL" --pin-dir "$1" geo-sync --v4 "$GUARD_GEO_CACHE/geo4.txt" \
        --v6 "$GUARD_GEO_CACHE/geo6.txt" --loaded-dir "$2") || return 1
    msg_info "гео в картах: $out"
}

_guard_nft_apply() { _guard_nft_render "$G_IFACE" "$G_PORTS" | nft -f - >"$GUARD_DIR/nft.log" 2>&1; }

# ── гео-список (D5) ──────────────────────────────────────────────────

_guard_geo_meta() {   # «v4 N · v6 M префиксов · ДАТА» из кеша
    local d
    d=$(sed -n 's/.*"date": *"\([^"]*\)".*/\1/p' "$GUARD_GEO_CACHE/geo.meta" 2>/dev/null)
    printf 'v4 %s · v6 %s префиксов · %s' "$(($(wc -l <"$GUARD_GEO_CACHE/geo4.txt")))" \
        "$(($(wc -l <"$GUARD_GEO_CACHE/geo6.txt")))" "${d:-дата неизвестна}"
}

# Скачать RIPEstat и db-ip (текущий месяц, иначе прошлый), собрать guard_geo.py во временный каталог
# и только при rc 0 заменить кеш целиком. Не скачался один источник — собираем из другого.
# rc 0 — новый список принят; иначе кеш не тронут (любой rc guard_geo.py ≠ 0 — провал).
_guard_geo_fetch() {
    local tmp src=() dbip=() mins=() u f y m rc
    mkdir -p "$GUARD_DIR" && chmod 700 "$GUARD_DIR" || return 1
    tmp=$(mktemp -d "$GUARD_DIR/geo-dl.XXXXXX") || return 1
    if download_file "${GUARD_GEO_RIPE_URL:-$GUARD_RIPE_URL}" "$tmp/ripe.json"; then
        src+=(--ripe "$tmp/ripe.json")
    else
        msg_warn "RIPEstat не скачался"
    fi
    if [ -n "${GUARD_GEO_DBIP_URL:-}" ]; then
        dbip=("$GUARD_GEO_DBIP_URL")
    else
        y=$(date -u +%Y) m=$((10#$(date -u +%m)))
        dbip=("https://download.db-ip.com/free/dbip-country-lite-$(printf '%04d-%02d' "$y" "$m").csv.gz")
        m=$((m - 1))
        [ "$m" = 0 ] && { m=12; y=$((y - 1)); }
        dbip+=("https://download.db-ip.com/free/dbip-country-lite-$(printf '%04d-%02d' "$y" "$m").csv.gz")
    fi
    for u in "${dbip[@]}"; do
        f="$tmp/dbip.csv"
        case "$u" in *.gz) f="$f.gz" ;; esac
        download_file "$u" "$f" && { src+=(--dbip "$f"); break; }
    done
    case " ${src[*]-} " in *" --dbip "*) ;; *) msg_warn "db-ip не скачался" ;; esac
    if [ "${#src[@]}" = 0 ]; then
        rm -rf "$tmp"
        return 1
    fi
    [ -n "${GUARD_GEO_MIN_V4_ADDRS:-}" ] && mins+=(--min-v4-addrs "$GUARD_GEO_MIN_V4_ADDRS")
    [ -n "${GUARD_GEO_MIN_V4_PREFIXES:-}" ] && mins+=(--min-v4-prefixes "$GUARD_GEO_MIN_V4_PREFIXES")
    [ -n "${GUARD_GEO_MIN_V6_PREFIXES:-}" ] && mins+=(--min-v6-prefixes "$GUARD_GEO_MIN_V6_PREFIXES")
    python3 "$GUARD_GEO_PY" build --cc RU --out-dir "$tmp/geo" "${src[@]}" ${mins[@]+"${mins[@]}"} >"$tmp/build.log" 2>&1
    rc=$?
    if [ "$rc" != 0 ] || [ ! -s "$tmp/geo/geo4.txt" ] || [ ! -s "$tmp/geo/geo6.txt" ]; then
        msg_warn "гео-список не принят (guard_geo.py rc $rc): $(tail -n 1 "$tmp/build.log")"
        rm -rf "$tmp"
        return 1
    fi
    msg_info "$(tail -n 1 "$tmp/build.log")"
    rm -rf "$GUARD_GEO_CACHE.old"
    if [ -d "$GUARD_GEO_CACHE" ] && ! mv "$GUARD_GEO_CACHE" "$GUARD_GEO_CACHE.old"; then
        rm -rf "$tmp"
        return 1
    fi
    if ! mv "$tmp/geo" "$GUARD_GEO_CACHE"; then
        [ -d "$GUARD_GEO_CACHE.old" ] && mv "$GUARD_GEO_CACHE.old" "$GUARD_GEO_CACHE"
        rm -rf "$tmp"
        return 1
    fi
    rm -rf "$GUARD_GEO_CACHE.old" "$tmp"
}

# ── systemd: юниты, таймер, certbot-хуки, dead-man ───────────────────

_guard_units_install() {
    local me="$_guard_self/guard.sh" d=/etc/systemd/system env h
    env="Environment=\"GUARD_DIR=$GUARD_DIR\" \"GUARD_PIN=$GUARD_PIN\""
    if _guard_systemd; then
        cat >"$d/$GUARD_UNIT.service" <<UNIT
[Unit]
Description=node-diagnostic guard (XDP + tc + NOTRACK)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
$env
ExecStart=/bin/bash "$me" reattach
ExecStop=/bin/bash "$me" off --keep-config
[Install]
WantedBy=multi-user.target
UNIT
        if [ "$G_GEO" = ru ]; then
            cat >"$d/$GUARD_GEO_UNIT.service" <<UNIT
[Unit]
Description=node-diagnostic guard: обновление гео-списка RU
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
$env
ExecStart=/bin/bash "$me" update-geo
UNIT
            cat >"$d/$GUARD_GEO_UNIT.timer" <<UNIT
[Unit]
Description=node-diagnostic guard: гео-список RU раз в неделю
[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
        else
            systemctl disable --now "$GUARD_GEO_UNIT.timer" >/dev/null 2>&1
            rm -f "$d/$GUARD_GEO_UNIT.service" "$d/$GUARD_GEO_UNIT.timer"
        fi
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable "$GUARD_UNIT.service" >/dev/null 2>&1
        if [ "$G_GEO" = ru ]; then
            systemctl enable --now "$GUARD_GEO_UNIT.timer" >/dev/null 2>&1
            msg_ok "$GUARD_UNIT.service (reattach на boot) и таймер гео-списка (раз в неделю)"
        else
            msg_ok "$GUARD_UNIT.service (reattach на boot)"
        fi
    elif [ "${GUARD_NO_SYSTEMD:-0}" != 1 ]; then
        msg_warn "нет systemd — guard не переживёт reboot (после загрузки: guard reattach)"
    fi
    # D7: certbot-хуки — на время продления HTTP-01 гео снимается с порта 80 (валидаторы LE не из РФ)
    [ "${GUARD_NO_SYSTEMD:-0}" = 1 ] && return 0
    for h in pre post; do
        if [ "$G_GEO" = ru ] && [ -d /etc/letsencrypt ]; then
            mkdir -p "/etc/letsencrypt/renewal-hooks/$h"
            cat >"/etc/letsencrypt/renewal-hooks/$h/$GUARD_HOOK" <<HOOK
#!/bin/sh
# node-diagnostic guard (D7): $h-хук certbot — гео-фильтр на порту 80 на время продления HTTP-01
export GUARD_DIR='$GUARD_DIR' GUARD_PIN='$GUARD_PIN'
exec /bin/bash '$me' hook $h
HOOK
            chmod 755 "/etc/letsencrypt/renewal-hooks/$h/$GUARD_HOOK"
        else
            rm -f "/etc/letsencrypt/renewal-hooks/$h/$GUARD_HOOK"
        fi
    done
    [ "$G_GEO" = ru ] && [ -d /etc/letsencrypt ] && msg_ok "certbot-хуки: на время продления гео с порта 80 снимается"
    return 0
}

_guard_units_remove() {   # off без --keep-config; boot — из ExecStart самого юнита guard (reattach)
    local d=/etc/systemd/system
    if _guard_systemd; then
        systemctl disable --now "$GUARD_GEO_UNIT.timer" >/dev/null 2>&1
        if [ "${1:-}" = boot ]; then
            # stop своего юнита из его же ExecStart ждал бы сам себя — только disable
            systemctl disable "$GUARD_UNIT.service" >/dev/null 2>&1
        else
            # stop запустит ExecStop (off --keep-config) — рантайм уже снят, он ничего не найдёт
            systemctl disable --now "$GUARD_UNIT.service" >/dev/null 2>&1
        fi
        rm -f "$d/$GUARD_UNIT.service" "$d/$GUARD_GEO_UNIT.service" "$d/$GUARD_GEO_UNIT.timer"
        systemctl daemon-reload >/dev/null 2>&1
    fi
    [ "${GUARD_NO_SYSTEMD:-0}" = 1 ] || rm -f "/etc/letsencrypt/renewal-hooks/pre/$GUARD_HOOK" \
        "/etc/letsencrypt/renewal-hooks/post/$GUARD_HOOK"
    return 0
}

_guard_deadman_armed() { _guard_systemd && systemctl is-active --quiet "$GUARD_DEADMAN.timer"; }

# F3/D10: таймер dead-man (systemd-run) reboot не переживает, а юнит guard включён — без метки
# перезагрузка в окне dead-man сделала бы неподтверждённый guard постоянным. Метка — в GUARD_DIR
# (переживает reboot); снимают её подтверждение (confirm, «y», on --confirm) и полный off.
_guard_unconfirmed_set() { mkdir -p "$GUARD_DIR" && : >"$GUARD_UNCONFIRMED"; }
_guard_unconfirmed_clear() { rm -f "$GUARD_UNCONFIRMED"; }

_guard_deadman_stop() {
    _guard_systemd || return 0
    systemctl stop "$GUARD_DEADMAN.timer" >/dev/null 2>&1
    systemctl reset-failed "$GUARD_DEADMAN.timer" "$GUARD_DEADMAN.service" >/dev/null 2>&1
    return 0
}

# D10: через GUARD_DEADMAN_SEC guard off сам — если клиенты отвалились, а подтверждения нет
_guard_deadman_arm() {
    if ! _guard_systemd; then
        [ "${GUARD_NO_SYSTEMD:-0}" = 1 ] || msg_warn "dead-man недоступен (нет systemd) — проверь клиентов сам; выключить: guard off"
        return 1
    fi
    _guard_deadman_stop
    if systemd-run --quiet --unit="$GUARD_DEADMAN" --on-active="$GUARD_DEADMAN_SEC" \
        --timer-property=AccuracySec=1s --setenv=GUARD_DIR="$GUARD_DIR" --setenv=GUARD_PIN="$GUARD_PIN" \
        /bin/bash "$_guard_self/guard.sh" off >/dev/null 2>&1; then
        msg_warn "dead-man: через $((GUARD_DEADMAN_SEC / 60)) мин guard выключится сам. Клиенты подключаются — guard confirm"
        return 0
    fi
    msg_warn "dead-man не взвёлся (systemd-run) — проверь клиентов сам; выключить: guard off"
    return 1
}

# ── шаги on/reattach ─────────────────────────────────────────────────

# шаг 8: инструменты (как shape._ensure_tools) + nftables, ethtool. G_XDP_OK=1 — XDP можно собрать
# и загрузить. Без BTF ядра XDP-объект не грузится: XDP и tc не ставим, NOTRACK — да (D9), а гео
# (вариант 1) невозможно — отказ, а не тихая работа без гео.
_guard_tools() {
    local miss=""
    G_XDP_OK=0
    ensure_pkg nft nftables nftables nftables >/dev/null 2>&1
    ensure_pkg ethtool ethtool ethtool ethtool >/dev/null 2>&1
    ensure_pkg tc iproute2 iproute iproute2 >/dev/null 2>&1
    have nft || die "нет nft (nftables) — без него NOTRACK не поставить"
    have tc || die "нет tc (iproute2)"
    have ethtool || msg_warn "нет ethtool — rx-gro-hw для native XDP не переключить"
    if ! _guard_btf_ok; then
        [ "$G_GEO" = ru ] && die "ядро без BTF (/sys/kernel/btf/vmlinux): XDP guard не загрузится — вариант 1 (гео) невозможен"
        msg_warn "ядро без BTF (/sys/kernel/btf/vmlinux) — XDP и tc не ставлю: только NOTRACK и syncookies ядра"
        return 0
    fi
    ensure_pkg clang clang clang clang >/dev/null 2>&1
    ensure_pkg python3 python3 python3 python3 >/dev/null 2>&1
    # R14: PATH → пакет bpftool → linux-tools Ubuntu → статический; libbpf ≥ 1.0 (lib/common.sh)
    if ensure_bpftool >/dev/null 2>&1; then
        [ "$ND_BPFTOOL_VIA" = found ] || msg_info "bpftool: $BPFTOOL ($ND_BPFTOOL_VIA)"
    fi
    [ -e /usr/include/bpf/bpf_helpers.h ] || pkg_install libbpf-dev libbpf-devel libbpf-dev >/dev/null 2>&1
    have clang || miss="$miss clang"
    bpftool_usable "$BPFTOOL" || miss="$miss bpftool (libbpf ≥ 1.0)"
    have python3 || miss="$miss python3"
    [ -e /usr/include/bpf/bpf_helpers.h ] || miss="$miss libbpf-dev"
    if [ -n "$miss" ]; then
        [ "$G_GEO" = ru ] && die "не хватает:$miss — вариант 1 (гео) без XDP невозможен"
        msg_warn "не хватает:$miss — XDP не ставлю: только NOTRACK и syncookies ядра"
        return 0
    fi
    G_XDP_OK=1
}

# шаг 9 → G_EFF. tcp_syncookies=0: ядро не смотрит в cookie_v4/v6_check и бросает request sock от
# kfunc (RST, хотя tc насчитал cookie_ok), и само не защищается — ставим 1. tcp_timestamps/sack/
# window_scaling = 0: kfunc отвергнет атрибуты из cookie — XDP-cookies выключаем.
_guard_sysctls() {
    local k
    if [ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = 0 ]; then
        if sysctl -qw net.ipv4.tcp_syncookies=1 >/dev/null 2>&1; then
            msg_warn "net.ipv4.tcp_syncookies был 0 — включил (1): без него ядро не примет cookie-ACK и не защитится само"
        else
            msg_warn "net.ipv4.tcp_syncookies=0, и включить не вышло — cookie-ACK ядро не примет"
        fi
    fi
    G_EFF=$(_guard_effective_cookies "$G_COOKIES" "$G_KFUNC")
    [ "$G_EFF" = off ] && return 0
    for k in tcp_timestamps tcp_sack tcp_window_scaling; do
        if [ "$(sysctl -n "net.ipv4.$k" 2>/dev/null)" = 0 ]; then
            msg_warn "net.ipv4.$k = 0 — XDP-cookies выключаю: kfunc отверг бы атрибуты из cookie"
            G_EFF=off
            return 0
        fi
    done
}

# Шаги 11–17, общие для on и reattach. $1 = on: если гео запрошено (вариант 1), XDP встаёт целиком,
# иначе отказ, и хост остаётся как был; reattach: каждая часть по возможности (D9: не встала XDP —
# NOTRACK всё равно ставится). Вход: G_* (аргументы/конфиг), G_GEO_RT, G_EFF, G_KFUNC, G_XDP_OK.
# Выход: G_XDP_MODE, G_GRO_HW_RESTORE, G_EFF; guard.conf записан.
_guard_apply() {
    local strict=0 need=0 tc=0 old_if="" old_gro=0 why="" lrc
    [ "$1" = on ] && [ "$G_GEO_RT" = ru ] && strict=1
    _guard_need_xdp "$G_GEO_RT" "$G_EFF" "$G_KFUNC" && need=1
    [ "$need" = 1 ] && [ "$G_EFF" != off ] && tc=1
    # прежний запуск: его интерфейс и выключенный нами rx-gro-hw (повторный on, смена --iface)
    if [ -r "$GUARD_CONF" ]; then
        old_if=$(sed -n 's/^IFACE=//p' "$GUARD_CONF" | head -n 1)
        old_gro=$(sed -n 's/^GRO_HW_RESTORE=//p' "$GUARD_CONF" | head -n 1)
    fi
    G_GRO_HW_RESTORE=0
    [ "$old_if" = "$G_IFACE" ] && [ "$old_gro" = 1 ] && G_GRO_HW_RESTORE=1
    mkdir -p "$GUARD_DIR" && chmod 700 "$GUARD_DIR" || die "не создать $GUARD_DIR"

    # 11 ключ, 12 сборка, 13 загрузка в $GUARD_STAGE, 14 карты — до любого attach
    if [ "$need" = 1 ]; then
        if [ "$G_XDP_OK" != 1 ]; then
            why="XDP недоступен (нет BTF ядра или инструментов)"
        elif ! _guard_key; then
            why="ключ $GUARD_KEY не создан"
        elif ! _guard_compile; then
            why="BPF не собрался"
        else
            _guard_load "$tc"
            lrc=$?
            if [ "$lrc" = 2 ]; then
                # как отказ tc attach (D9): cookies выключены, XDP остаётся для гео; без гео XDP без дела
                msg_warn "tc-объект не загрузился ($(tail -n 1 "$GUARD_DIR/load.log")) — XDP-cookies выключаю, работают syncookies ядра"
                tc=0 G_EFF=off
                if ! _guard_need_xdp "$G_GEO_RT" "$G_EFF" "$G_KFUNC"; then
                    _guard_stage_drop
                    need=0
                fi
            fi
            if [ "$lrc" = 1 ]; then
                why="BPF не загрузился ($(tail -n 1 "$GUARD_DIR/load.log"))"
            elif [ "$need" = 1 ] && ! _guard_maps "$GUARD_STAGE/maps" "$GUARD_LOADED.new"; then
                why="карты guard не настроились"
            fi
        fi
        if [ -n "$why" ]; then
            _guard_stage_drop
            [ "$strict" = 1 ] && die "$why — вариант 1 не включаю, хост не тронут"
            msg_warn "$why — XDP не ставлю, работает только NOTRACK (fail-open)"
            need=0 tc=0
        fi
    fi

    # 15 NOTRACK
    if _guard_nft_apply; then
        msg_ok "NOTRACK: порты $G_PORTS (tcp, udp) на $G_IFACE — мимо conntrack"
    else
        [ "$1" = on ] && { _guard_stage_drop; die "nft не поставил NOTRACK ($(tail -n 1 "$GUARD_DIR/nft.log")) — хост не тронут"; }
        msg_err "NOTRACK не встал: $(tail -n 1 "$GUARD_DIR/nft.log")"
    fi

    # 16 attach; со сменой интерфейса своё со старого снимается
    if [ -n "$old_if" ] && [ "$old_if" != "$G_IFACE" ]; then
        _guard_detach_iface "$old_if"
        [ "$old_gro" = 1 ] && _guard_gro_hw_set "$old_if" on
    fi
    if [ "$need" = 1 ]; then
        # tc раньше XDP: cookie-ответы XDP без tc ломали бы рукопожатия
        if [ "$tc" = 1 ] && ! _guard_tc_attach "$G_IFACE" "$GUARD_STAGE/progs/$GUARD_TC_PROG"; then
            msg_warn "tc ingress pref $ND_TC_PREF_GUARD не встал ($(tail -n 1 "$GUARD_DIR/tc.log" 2>/dev/null)) — XDP-cookies выключаю"
            tc=0 G_EFF=off
            _guard_set_cfg "$GUARD_STAGE/maps" || why="cookies в карте не выключились"
        fi
        [ "$tc" = 1 ] || _guard_tc_detach "$G_IFACE"
        if [ -z "$why" ] && _guard_xdp_attach "$G_IFACE" "$GUARD_STAGE/progs/$GUARD_XDP_PROG" "$tc"; then
            _guard_stage_commit
        else
            [ -n "$why" ] || why="XDP не прицепился к $G_IFACE ($(tail -n 1 "$GUARD_DIR/xdp.log" 2>/dev/null))"
            if [ "$strict" = 1 ]; then
                _guard_runtime_down
                die "$why — вариант 1 не включён, guard снят"
            fi
            msg_warn "$why — работает только NOTRACK (fail-open)"
            _guard_stage_drop
            need=0
        fi
    fi
    if [ "$need" = 0 ]; then
        _guard_detach_iface "$G_IFACE"
        [ "$G_GRO_HW_RESTORE" = 1 ] && _guard_gro_hw_set "$G_IFACE" on
        G_GRO_HW_RESTORE=0 G_XDP_MODE=none G_EFF=off
        rm -rf "$GUARD_PIN" "$GUARD_LOADED"
    else
        msg_ok "XDP ($G_XDP_MODE) на $G_IFACE$([ "$tc" = 1 ] && echo ", tc ingress pref $ND_TC_PREF_GUARD (cookies $G_EFF)")"
    fi

    # 17
    _guard_conf_save || msg_warn "$GUARD_CONF не записан — reattach на boot не сработает"
}

_guard_variant() { if [ "$G_GEO" = ru ]; then echo "1 «только Россия»"; else echo "2 «весь мир»"; fi; }

# ── команды ──────────────────────────────────────────────────────────

guard_on() {
    local low p c
    need_root || die "нужен root"                                              # 1
    _guard_defaults
    _guard_parse_on "$@"                                                       # 2
    # D10: SSH guard не трогает — его порт под NOTRACK/гео/cookies не берём (до любых изменений)
    if c=$(_guard_ports_conflict_ssh "$G_PORTS" "$(detect_ssh_port)"); then
        _guard_badarg "SSH на порту $c — guard его не трогает, убери из --ports"
    fi
    G_GEO_RT=$G_GEO
    _guard_kernel_ok || die "нужно ядро Linux ≥ 5.10; у тебя $(uname -r)"     # 3
    [ -n "$G_IFACE" ] || G_IFACE=$(default_iface)                             # 4
    [ -n "$G_IFACE" ] || die "не определён интерфейс (нет маршрута по умолчанию) — укажи --iface"
    ip link show dev "$G_IFACE" >/dev/null 2>&1 || die "нет интерфейса $G_IFACE"
    if ! _guard_iface_ether "$(ip -o link show dev "$G_IFACE" 2>/dev/null)"; then
        die "у $G_IFACE нет Ethernet-заголовка ($(ip -o link show dev "$G_IFACE" | grep -oE 'link/[a-z0-9]+' | head -n 1)): XDP и tc guard его не разберут — укажи --iface внешнего Ethernet-интерфейса"
    fi
    low=$(awk '{print $1}' /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null)   # 5
    for p in ${G_PORTS//,/ }; do
        _guard_port_ok "$p" "${low:-32768}" || die "порт $p не ниже начала ip_local_port_range (${low:-?}): NOTRACK и гео задели бы ответы на исходящие соединения ноды — подними диапазон (optimize ставит 10000) или убери порт из --ports"
    done
    if c=$(_guard_docker_conflict "$G_PORTS"); then                             # 6
        die "docker публикует порты guard через bridge ($(echo "$c" | tr '\n' ' ')): DNAT держится на conntrack, NOTRACK его сломает — нода с network_mode: host совместима"
    fi
    if c=$(_guard_xdp_foreign "$G_IFACE"); then                                 # 7
        die "на $G_IFACE уже висит чужая XDP-программа $c — guard поверх не ставлю"
    fi
    ui_head "Guard: включение" "вариант $(_guard_variant), $G_IFACE"
    _guard_tools                                                               # 8
    G_KFUNC=0
    [ "$G_XDP_OK" = 1 ] && _guard_has_kfunc && G_KFUNC=1
    if [ "$G_COOKIES" != off ] && [ "$G_XDP_OK" = 1 ] && [ "$G_KFUNC" = 0 ]; then
        msg_warn "ядро $(uname -r) без kfunc bpf_sk_assign_tcp_reqsk (нужно ≥ 6.9) — XDP-cookies выключены, SYN-флуд держат syncookies ядра. Свежее ядро: rr bbr3 --install (XanMod)"
    fi
    _guard_sysctls                                                             # 9
    if [ "$G_GEO" = ru ]; then                                                 # 10
        if _guard_geo_fetch; then
            msg_ok "гео-список RU: $(_guard_geo_meta)"
        elif _guard_geo_cached; then
            msg_warn "гео-список не обновился — работаю по кешу: $(_guard_geo_meta)"
        else
            die "гео-список не получен — вариант 1 не включаю: без списка дропнулись бы все"
        fi
    fi
    _guard_apply on                                                            # 11–17
    # F3: метка «не подтверждён» — до юнитов (18): reboot до подтверждения откатит guard в reattach.
    # GUARD_FORCE_UNCONFIRMED=1 — как с dead-man, но без systemd (netns-стенд)
    if [ "$G_CONFIRM" != 1 ] && { _guard_systemd || [ "${GUARD_FORCE_UNCONFIRMED:-0}" = 1 ]; }; then
        _guard_unconfirmed_set
    fi
    _guard_units_install                                                       # 18
    if [ "$G_CONFIRM" = 1 ]; then                                              # 19
        _guard_deadman_stop
        _guard_unconfirmed_clear
    elif _guard_deadman_arm; then
        if [ -t 0 ] && [ -t 1 ]; then
            echo
            if confirm "Клиенты подключаются?"; then
                _guard_deadman_stop
                _guard_unconfirmed_clear
                msg_ok "подтверждено — dead-man снят"
            else
                msg_warn "dead-man остаётся: через $((GUARD_DEADMAN_SEC / 60)) мин guard выключится, перезагрузка до подтверждения тоже откатит его. Оставить: guard confirm, снять сейчас: guard off"
            fi
        fi
    elif [ "${GUARD_FORCE_UNCONFIRMED:-0}" != 1 ]; then
        _guard_unconfirmed_clear   # dead-man не взвёлся (предупреждение уже было): метка — только при нём
    fi
    record_fix "guard on (geo=$G_GEO, cookies=$G_EFF, xdp=$G_XDP_MODE)"       # 20
    echo
    msg_ok "guard включён: вариант $(_guard_variant) · cookies $G_EFF · XDP $G_XDP_MODE · $G_IFACE"
}

guard_reattach() {   # systemd на boot: шаги 11–17 по guard.conf и гео-кешу, без скачиваний и установок
    local c
    need_root || die "нужен root"
    [ $# -eq 0 ] || _guard_badarg "reattach: лишние аргументы"
    if [ -e "$GUARD_UNCONFIRMED" ]; then   # F3: reboot в окне dead-man — откат, как сделал бы он сам
        ui_head "Guard: reattach" "откат"
        msg_warn "guard не был подтверждён до перезагрузки — откатываю (как dead-man: guard off)"
        _guard_down 0 boot
        record_fix "guard off (не подтверждён до перезагрузки)"
        msg_ok "guard снят; включить снова: guard on, затем guard confirm"
        return 0
    fi
    _guard_defaults
    _guard_conf_load || die "нет или битый $GUARD_CONF — guard не включался (guard on)"
    ip link show dev "$G_IFACE" >/dev/null 2>&1 || die "нет интерфейса $G_IFACE"
    ui_head "Guard: reattach" "вариант $(_guard_variant), $G_IFACE"
    G_GEO_RT=$G_GEO
    if ! _guard_btf_ok; then
        msg_warn "ядро без BTF — XDP и tc не ставлю"
    elif ! bpftool_find || ! have python3; then
        msg_warn "нет рабочего bpftool (libbpf ≥ 1.0) или python3 — XDP и tc не ставлю"
    elif c=$(_guard_xdp_foreign "$G_IFACE"); then
        msg_warn "на $G_IFACE чужая XDP-программа $c — XDP guard не ставлю"
    else
        G_XDP_OK=1
    fi
    [ "$G_XDP_OK" = 1 ] && _guard_has_kfunc && G_KFUNC=1
    _guard_sysctls
    if [ "$G_GEO" = ru ] && ! _guard_geo_cached; then
        msg_warn "нет гео-кеша $GUARD_GEO_CACHE — гео не включаю (без списка дропнулись бы все); вернуть: guard on --geo ru"
        G_GEO_RT=off
    fi
    _guard_apply reattach
    msg_ok "guard восстановлен: вариант $(_guard_variant) · cookies $G_EFF · XDP $G_XDP_MODE · $G_IFACE"
}

# KEEP(0|1) [boot] — рантайм и dead-man снять; KEEP=0 — ещё юниты, хуки, guard.conf и метку F3.
# off --keep-config (ExecStop юнита на shutdown) метку не трогает: иначе reboot в окне dead-man
# стирал бы её до reattach. boot — вызов из ExecStart юнита (reattach): свой юнит не останавливать
_guard_down() {
    _guard_defaults
    _guard_conf_load || true
    _guard_runtime_down
    _guard_deadman_stop
    if [ "$1" = 0 ]; then
        _guard_units_remove "${2:-}"
        rm -f "$GUARD_CONF"
        _guard_unconfirmed_clear
    fi
}

guard_off() {
    local keep=0
    need_root || die "нужен root"
    case "${1:-}" in
    "") ;;
    --keep-config) keep=1 ;;
    *) _guard_badarg "off: неизвестный аргумент '$1' (--keep-config)" ;;
    esac
    [ $# -le 1 ] || _guard_badarg "off: лишние аргументы"
    _guard_down "$keep"
    record_fix "guard off$([ "$keep" = 1 ] && echo " --keep-config")"
    if [ "$keep" = 1 ]; then
        msg_ok "guard снят (конфиг и юниты сохранены — guard reattach вернёт)"
    else
        msg_ok "guard снят (ключ, гео-кеш и allow.list остались в $GUARD_DIR)"
    fi
}

guard_allow() {
    local c
    need_root || die "нужен root"
    [ $# -eq 1 ] || _guard_badarg "allow: нужен один IP или CIDR"
    have python3 || die "нет python3"
    c=$(_guard_cidr_norm "$1") || _guard_badarg "allow: не IP/CIDR: '$1'"
    mkdir -p "$GUARD_DIR" && chmod 700 "$GUARD_DIR" || die "не создать $GUARD_DIR"
    touch "$GUARD_ALLOW" && chmod 600 "$GUARD_ALLOW"
    grep -qxF "$c" "$GUARD_ALLOW" || echo "$c" >>"$GUARD_ALLOW"
    if _guard_active; then
        _guard_ctrl allow-add "$c" || die "allow-add $c не прошёл"
        msg_ok "allowlist + $c (мимо гео и cookies)"
    else
        msg_ok "allowlist + $c — XDP guard не включена, применится при guard on"
    fi
}

guard_unallow() {
    local c
    need_root || die "нужен root"
    [ $# -eq 1 ] || _guard_badarg "unallow: нужен один IP или CIDR"
    have python3 || die "нет python3"
    c=$(_guard_cidr_norm "$1") || _guard_badarg "unallow: не IP/CIDR: '$1'"
    if [ -f "$GUARD_ALLOW" ]; then
        grep -vxF "$c" "$GUARD_ALLOW" >"$GUARD_ALLOW.tmp"
        chmod 600 "$GUARD_ALLOW.tmp" && mv -f "$GUARD_ALLOW.tmp" "$GUARD_ALLOW"
    fi
    if _guard_active; then
        _guard_ctrl allow-del "$c" || die "allow-del $c не прошёл"
    fi
    msg_ok "allowlist − $c"
}

guard_update_geo() {   # таймер: новый список принят → в карту (сначала новые префиксы, потом удаление)
    local out
    need_root || die "нужен root"
    [ $# -eq 0 ] || _guard_badarg "update-geo: лишние аргументы"
    have python3 || die "нет python3"
    _guard_defaults
    _guard_conf_load || true
    if ! _guard_geo_fetch; then
        if _guard_geo_cached; then
            msg_err "гео-список не обновлён — остаётся прежний: $(_guard_geo_meta)"
        else
            msg_err "гео-список не получен, кеша нет"
        fi
        return 1
    fi
    msg_ok "гео-список RU: $(_guard_geo_meta)"
    if [ "$G_GEO" = ru ] && _guard_active; then
        out=$(_guard_ctrl geo-sync --v4 "$GUARD_GEO_CACHE/geo4.txt" --v6 "$GUARD_GEO_CACHE/geo6.txt" \
            --loaded-dir "$GUARD_LOADED") || { msg_err "geo-sync не прошёл — в карте прежний список"; return 1; }
        msg_ok "карты: $out"
    fi
}

guard_confirm() {
    need_root || die "нужен root"
    [ $# -eq 0 ] || _guard_badarg "confirm: лишние аргументы"
    local had=0
    [ -e "$GUARD_UNCONFIRMED" ] && had=1
    _guard_unconfirmed_clear
    if _guard_deadman_armed; then
        _guard_deadman_stop
        msg_ok "dead-man снят — guard остаётся включённым"
    elif [ "$had" = 1 ]; then
        msg_ok "подтверждено — guard переживёт перезагрузку"
    else
        msg_info "dead-man не взведён"
    fi
}

guard_hook() {   # certbot pre|post (D7): только вариант 1 и только если 80 под guard
    need_root || die "нужен root"
    case "${1:-}" in pre | post) ;; *) _guard_badarg "hook: pre|post" ;; esac
    [ $# -eq 1 ] || _guard_badarg "hook: лишние аргументы"
    _guard_defaults
    _guard_conf_load || return 0
    [ "$G_GEO" = ru ] && _guard_active || return 0
    case ",$G_PORTS," in *,80,*) ;; *) return 0 ;; esac
    if [ "$1" = pre ]; then
        _guard_ctrl set-port 80 tcp,udp && msg_ok "гео с порта 80 снято на время продления"
    else
        _guard_ctrl set-port 80 tcp,udp,geo && msg_ok "гео на порту 80 возвращено"
    fi
}

guard_status() {
    local conf=0 root=0 ifc xm="" tcon=0 nft=0 v s n att now
    [ $# -eq 0 ] || _guard_badarg "status: лишние аргументы"
    _guard_defaults
    need_root && root=1
    _guard_conf_load && conf=1
    ifc=${G_IFACE:-$(default_iface)}
    if [ -n "$ifc" ]; then
        xm=$(_guard_xdp_list "$ifc" | awk -v p="$GUARD_XDP_PROG" '$3 == p { print $1; exit }')
        _guard_tc_ours "$ifc" && tcon=1
    fi
    have nft && nft list table inet nd_guard >/dev/null 2>&1 && nft=1
    ui_head "Guard" "защита от DDoS: XDP + tc + NOTRACK"
    box_top "GUARD"
    if [ -z "$xm" ] && [ "$tcon" = 0 ] && [ "$nft" = 0 ]; then
        box_kv "Состояние" "выключен"
        if [ "$conf" = 1 ]; then
            box_kv "" "конфиг сохранён — вернуть: guard reattach"
        else
            box_kv "Включить" "guard on (весь мир) · guard on --geo ru"
        fi
        [ "$root" = 1 ] || box_kv "" "без root таблицу nft и карты не видно"
        box_bottom
        return 0
    fi
    if [ "$conf" = 1 ]; then v="$(_guard_variant)"; else v="? (нет $GUARD_CONF)"; fi
    box_kv "Вариант" "$v"
    if [ -n "$xm" ]; then v="$ifc · XDP $xm"; else v="$ifc · без XDP (только NOTRACK)"; fi
    box_kv "Интерфейс" "$v"
    if [ "$tcon" = 1 ]; then
        v=$G_COOKIES
        [ "$v" = auto ] && v="auto: от $G_THRESH SYN/с, ещё $G_HOLD с"
    elif ! _guard_has_kfunc; then
        v="ядро без kfunc — работают syncookies ядра"
    elif [ "$G_COOKIES" = off ]; then
        v="off — работают syncookies ядра"
    else
        v="не активны — работают syncookies ядра"
    fi
    box_kv "Cookies" "$v"
    case "$v" in "ядро без kfunc"*) box_kv "" "XDP-cookies: ядро ≥ 6.9 — rr bbr3 --install" ;; esac
    if [ "$root" = 1 ] && _guard_active && s=$(_guard_ctrl state 2>/dev/null); then
        att=$(echo "$s" | sed -n 's/.*attack_until_ns=\([0-9]*\).*/\1/p')
        now=$(echo "$s" | sed -n 's/.*now_ns=\([0-9]*\).*/\1/p')
        if [ -n "$att" ] && [ -n "$now" ] && [ "$att" -gt "$now" ]; then
            v="атака до $(date -d "@$(($(date +%s) + (att - now) / 1000000000))" +%H:%M:%S 2>/dev/null)"
        else
            v="норма"
        fi
        box_kv "Состояние" "$v"
    fi
    if [ "$G_GEO" = ru ]; then
        if _guard_geo_cached; then v=$(_guard_geo_meta); else v="нет кеша — гео не работает"; fi
        box_kv "Гео-список" "$v"
    fi
    n=$(grep -c . "$GUARD_ALLOW" 2>/dev/null)
    box_kv "Allowlist" "${n:-0} $(plural_ru "${n:-0}" запись записи записей)"
    if [ "$nft" = 1 ]; then v="table inet nd_guard · порты $G_PORTS"; else v="нет таблицы nd_guard"; fi
    box_kv "NOTRACK" "$v"
    if [ -r /proc/sys/net/netfilter/nf_conntrack_count ]; then
        box_kv "conntrack" "$(cat /proc/sys/net/netfilter/nf_conntrack_count) / $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
    fi
    if [ "$root" = 1 ] && _guard_active && s=$(_guard_ctrl stats 2>/dev/null); then
        box_kv "Счётчики" "$(echo "$s" | cut -d' ' -f1-3)"
        box_kv "" "$(echo "$s" | cut -d' ' -f4-6)"
        box_kv "" "$(echo "$s" | cut -d' ' -f7-)"
    fi
    if _guard_deadman_armed; then
        box_kv "Dead-man" "взведён — подтвердить: guard confirm"
    elif [ -e "$GUARD_UNCONFIRMED" ]; then
        box_kv "Dead-man" "не подтверждён: reboot откатит — guard confirm"
    fi
    box_bottom
    return 0
}

_guard_usage() {
    cat <<'EOF'
guard — защита ноды от DDoS на L3/L4: XDP (гео, SYN-cookie) + tc + conntrack NOTRACK
  guard on [--geo ru|off] [--cookies auto|always|off] [--syn-threshold N] [--ports 443,80] [--iface IF] [--confirm]
        вариант 1 «только Россия»: guard on --geo ru · вариант 2 «весь мир»: guard on
        без --confirm взводится dead-man: через 5 мин guard off, если не подтвердить
  guard off [--keep-config]        снять (--keep-config: конфиг и юниты остаются для reattach)
  guard status
  guard allow CIDR | unallow CIDR  мимо гео и cookies (CDN, каскады, админ за рубежом)
  guard update-geo                 обновить гео-список RU (таймер раз в неделю)
  guard confirm                    снять dead-man
  guard reattach                   для systemd на boot
  guard hook pre|post              certbot: снять/вернуть гео на порту 80
EOF
}

guard_main() {
    local cmd="${1:-}"
    [ $# -gt 0 ] && shift
    # рабочий bpftool без установок (статический ND_BPFTOOL_LOCAL — не в PATH); on ставит сам
    case "$cmd" in "" | help | -h | --help) ;; *) bpftool_find >/dev/null 2>&1 ;; esac
    case "$cmd" in
    on) guard_on "$@" ;;
    off) guard_off "$@" ;;
    status) guard_status "$@" ;;
    reattach) guard_reattach "$@" ;;
    allow) guard_allow "$@" ;;
    unallow) guard_unallow "$@" ;;
    update-geo) guard_update_geo "$@" ;;
    confirm) guard_confirm "$@" ;;
    hook) guard_hook "$@" ;;
    "" | help | -h | --help) _guard_usage ;;
    *)
        echo "guard: неизвестная команда '$cmd'" >&2
        _guard_usage >&2
        return 2
        ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
    guard_main "$@"
fi
