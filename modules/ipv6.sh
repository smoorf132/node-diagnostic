#!/usr/bin/env bash
# modules/ipv6.sh — включение/отключение IPv6 на ноде (sysctl disable_ipv6) со статусом.
# Порт из eGamesAPI/remnawave-reverse-proxy (src/modules/ipv6.sh). Файл настройки тот же,
# что у апстрима (99-remnawave-ipv6.conf): на сервере после него две настройки не спорят.
# Не namespaced под node-diagnostic намеренно — rollback оптимизаций его не трогает.
#
# Standalone:  sudo bash modules/ipv6.sh [menu|status|on|off]

if [ -z "${ND_COMMON_LOADED:-}" ]; then
    _self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "$_self/../lib/common.sh" 2>/dev/null \
        || { echo "не найден lib/common.sh — нужен весь репозиторий (см. install.sh)" >&2; exit 1; }
fi

# Debian 13 не читает /etc/sysctl.conf при загрузке — только drop-in в sysctl.d
IPV6_SYSCTL_CONF="${IPV6_SYSCTL_CONF:-/etc/sysctl.d/99-remnawave-ipv6.conf}"

# интерфейс маршрута по умолчанию (на docker-хосте первый линк — часто docker0/veth)
ipv6_iface() {
    local i
    i=$(default_iface)
    [ -z "$i" ] || [ "$i" = lo ] && i=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -vE '^(lo|.*@)' | head -n1)
    [ -n "$i" ] && echo "$i"
}

# включён ли IPv6 и в all, и на аплинке: disable_ipv6=1 на интерфейсе глушит его даже при all=0
ipv6_enabled() {   # [iface]
    [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = 0 ] || return 1
    [ -z "${1:-}" ] && return 0
    [ "$(sysctl -n "net.ipv6.conf.$1.disable_ipv6" 2>/dev/null)" = 0 ]
}

ipv6_global_addr() {   # <iface>
    ip -6 addr show dev "$1" scope global 2>/dev/null | awk '/inet6/{print $2; exit}'
}

ipv6_status() {
    local i a
    i=$(ipv6_iface)
    # ipv6.disable=1 в cmdline ядра убирает всё дерево sysctl
    if [ ! -d /proc/sys/net/ipv6 ]; then
        echo -e "    ${R}${I_BAD}${NC} IPv6 выключен при загрузке ${DIM}(ipv6.disable=1 в параметрах ядра)${NC}"
        return 1
    fi
    if [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = 1 ]; then
        echo -e "    ${R}${I_BAD}${NC} IPv6 выключен"
        return 1
    fi
    if [ -n "$i" ] && [ "$(sysctl -n "net.ipv6.conf.$i.disable_ipv6" 2>/dev/null)" = 1 ]; then
        echo -e "    ${R}${I_BAD}${NC} IPv6 выключен на интерфейсе $i"
        return 1
    fi
    a=$(ipv6_global_addr "${i:-eth0}")
    if [ -n "$a" ]; then
        echo -e "    ${G}${I_OK}${NC} IPv6 включён ${DIM}($i: $a)${NC}"
    else
        echo -e "    ${Y}${I_WARN}${NC} IPv6 включён в ядре, но глобального адреса нет ${DIM}(${i:-?})${NC}"
    fi
    return 0
}

# значения в собственном drop-in; старые ключи из /etc/sysctl.conf вычищаем —
# там, где он ещё читается, они противоречили бы drop-in
ipv6_set_sysctl() {   # <0|1> <iface>
    local v=$1 i=$2 k
    if [ -f /etc/sysctl.conf ]; then
        for k in all default lo ${i:+"$i"}; do
            sed -i "\|net\.ipv6\.conf\.$k\.disable_ipv6|d" /etc/sysctl.conf
        done
    fi
    mkdir -p "$(dirname "$IPV6_SYSCTL_CONF")"
    {
        echo "# Managed by node-diagnostic ($ND_VERSION): rr ipv6 on|off"
        echo "net.ipv6.conf.all.disable_ipv6 = $v"
        echo "net.ipv6.conf.default.disable_ipv6 = $v"
        echo "net.ipv6.conf.lo.disable_ipv6 = $v"
        [ -n "$i" ] && echo "net.ipv6.conf.$i.disable_ipv6 = $v"
    } > "$IPV6_SYSCTL_CONF"
    sysctl -p "$IPV6_SYSCTL_CONF" >/dev/null 2>&1
}

ipv6_on() {
    local i
    i=$(ipv6_iface)
    if ipv6_enabled "$i"; then msg_ok "IPv6 уже включён"; return 0; fi
    if [ ! -d /proc/sys/net/ipv6 ]; then
        msg_err "IPv6 выключен в загрузчике: убери ipv6.disable=1 из GRUB_CMDLINE_LINUX (/etc/default/grub), update-grub, перезагрузка"
        return 1
    fi
    ipv6_set_sysctl 0 "$i"
    # sysctl молча не применяется, если IPv6 выключен в GRUB — проверяем, а не верим
    ipv6_enabled "$i" || { msg_err "sysctl не применился — проверь ipv6.disable=1 в /etc/default/grub"; return 1; }
    msg_ok "IPv6 включён ($IPV6_SYSCTL_CONF)"
    record_fix "ipv6 on ($IPV6_SYSCTL_CONF)"

    # адрес приходит после обновления сети; если уже есть — не трогаем
    [ -z "$i" ] || [ -n "$(ipv6_global_addr "$i")" ] && return 0
    msg_warn "у $i пока нет глобального IPv6-адреса"
    if ! confirm "Обновить сетевые настройки, чтобы получить адрес?"; then
        msg_info "пропущено — адрес может появиться после перезагрузки или netplan apply"
        return 0
    fi
    if [ -d /etc/netplan ]; then
        netplan apply 2>/dev/null
    elif [ -f /etc/network/interfaces ] || [ -d /etc/network/interfaces.d ]; then
        ifdown "$i" 2>/dev/null; ifup "$i" 2>/dev/null
    else
        systemctl restart systemd-networkd 2>/dev/null
    fi
    sleep 2   # DAD: сразу после ifup адрес ещё tentative
    if [ -n "$(ipv6_global_addr "$i")" ]; then
        msg_ok "глобальный IPv6: $(ipv6_global_addr "$i")"
        return 0
    fi
    msg_warn "ядро IPv6 включило, но адрес выдаёт хостер (RA) или он прописывается вручную:"
    if [ -d /etc/netplan ]; then
        msg_info "  /etc/netplan/*.yaml → ethernets: $i: accept-ra: true"
        msg_info "  или статикой: addresses: [2a0c:.../64], routes: - to: default via: 2a0c:...::1"
    else
        msg_info "  /etc/network/interfaces → iface $i inet6 static / address 2a0c:...  / netmask 64 / gateway 2a0c:...::1"
    fi
    msg_info "адрес, маска и шлюз — в панели хостера; если тариф без IPv6, он здесь не заработает"
}

ipv6_off() {
    if [ ! -d /proc/sys/net/ipv6 ] || [ "$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)" = 1 ]; then
        msg_ok "IPv6 уже выключен"; return 0
    fi
    local sip; sip=$(ssh_client_ip)
    if [[ "$sip" == *:* && "$sip" != ::ffff:* ]]; then
        msg_warn "ты подключён по IPv6 ($sip) — выключение оборвёт эту SSH-сессию"
        confirm "Всё равно выключить IPv6?" || { msg_info "отменено"; return 1; }
    fi
    ipv6_set_sysctl 1 "$(ipv6_iface)"
    msg_ok "IPv6 выключен ($IPV6_SYSCTL_CONF)"
    record_fix "ipv6 off ($IPV6_SYSCTL_CONF)"
}

ipv6_menu() {
    local c
    while true; do
        echo -e "  ${BOLD}IPv6${NC}"
        ipv6_status
        echo -e "    ${C}${BOLD}[1]${NC} Включить"
        echo -e "    ${C}${BOLD}[2]${NC} Выключить"
        echo -e "    ${C}${BOLD}[0]${NC} Назад"
        printf "  ${BOLD}Выбор${NC} ${DIM}[0-2]${NC}: "; read -r c || return 0; echo
        case "$c" in
            1) ipv6_on ;;
            2) ipv6_off ;;
            0|q|"") return 0 ;;
            *) msg_warn "нет такого пункта" ;;
        esac
        echo
    done
}

ipv6_main() {
    case "${1:-menu}" in
        status) ipv6_status; return ;;
        help|-h|--help) echo "ipv6: sudo bash node-diagnostic.sh ipv6 [menu|status|on|off]"; return 0 ;;
        menu|on|off) ;;
        *) echo "ipv6: неизвестная команда '$1' (menu|status|on|off)" >&2; return 2 ;;
    esac
    need_root || die "нужен root"
    case "${1:-menu}" in
        menu) [ -t 0 ] || die "меню — только в интерактивном терминале (есть: ipv6 status|on|off)"; ipv6_menu ;;
        on)   ipv6_on ;;
        off)  ipv6_off ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    ipv6_main "$@"
fi
