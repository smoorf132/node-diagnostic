#!/usr/bin/env bash
# modules/warp.sh — WARP Native (distillium/warp-native): WireGuard-интерфейс warp на ноде
# для outbound'а Xray (sockopt.interface = "warp"). Порт пункта WARP Native из
# eGamesAPI/remnawave-reverse-proxy — только установка и удаление: outbound в профиль
# Xray добавляется в панели (апстрим делает это через API панели, на ноде его нет).
#
# Standalone:  sudo bash modules/warp.sh [menu|install|uninstall|status]

if [ -z "${ND_COMMON_LOADED:-}" ]; then
    _self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "$_self/../lib/common.sh" 2>/dev/null \
        || { echo "не найден lib/common.sh — нужен весь репозиторий (см. install.sh)" >&2; exit 1; }
fi

WARP_SCRIPT_BASE="https://raw.githubusercontent.com/distillium/warp-native/main"
WARP_IFACE="warp"

warp_status_line() {
    if ip link show "$WARP_IFACE" >/dev/null 2>&1; then
        echo -e "    ${G}${I_OK}${NC} интерфейс $WARP_IFACE поднят ${DIM}($(ip -o -4 addr show dev "$WARP_IFACE" 2>/dev/null | awk '{print $4; exit}'))${NC}"
    elif [ -f /etc/wireguard/warp.conf ]; then
        echo -e "    ${Y}${I_WARN}${NC} WARP установлен, но интерфейс $WARP_IFACE не поднят ${DIM}(systemctl status wg-quick@warp)${NC}"
    else
        echo -e "    ${DIM}${I_INFO} WARP не установлен${NC}"
    fi
}

# Скрипт идёт под root — только при совпадении двух независимых источников
warp_run() {   # install.sh | uninstall.sh
    local f rc
    f=$(mktemp)
    msg_info "скачиваю distillium/warp-native/$1 (проверка по двум источникам)…"
    if ! download_verified "$WARP_SCRIPT_BASE/$1" "$f" /bin/bash; then
        rm -f "$f"
        msg_err "скрипт WARP не подтверждён двумя независимыми источниками (возможна подмена) — запуск отменён"
        return 1
    fi
    bash "$f"; rc=$?
    rm -f "$f"
    return "$rc"
}

warp_install() {
    ui_head "Установка WARP Native" "distillium/warp-native · интерфейс $WARP_IFACE"
    if ! grep -qs '^[[:space:]]*remnanode:' "$REMNANODE_DIR/docker-compose.yml" /opt/remnawave/docker-compose.yml; then
        msg_err "нода Remnawave не найдена ($REMNANODE_DIR/docker-compose.yml) — сначала установи ноду"
        return 1
    fi
    msg_info "интерактивный установщик из стороннего репозитория — задаст свои вопросы (язык, ключ WARP+)"
    confirm "Скачать и запустить установщик WARP?" || { msg_info "отменено"; return 1; }
    warp_run install.sh || { msg_err "установщик WARP завершился с ошибкой"; return 1; }
    record_fix "warp-native install"
    echo
    warp_status_line
    msg_info "в профиле Xray (панель) добавь outbound и правило для нужных доменов:"
    cat <<'EOF' | sed 's/^/      /'
{ "tag": "warp-out", "protocol": "freedom",
  "settings": { "domainStrategy": "UseIP" },
  "streamSettings": { "sockopt": { "interface": "warp", "tcpFastOpen": true } } }
routing.rules: { "domain": ["whoer.net", "browserleaks.com", "2ip.io", "2ip.ru"], "outboundTag": "warp-out" }
EOF
    msg_info "подробнее: https://wiki.egam.es/ru/configuration/warp-native"
}

warp_uninstall() {
    ui_head "Удаление WARP Native" "distillium/warp-native/uninstall.sh"
    confirm "Удалить WARP (интерфейс $WARP_IFACE, wgcf, watchdog)?" || { msg_info "отменено"; return 1; }
    warp_run uninstall.sh || { msg_err "удаление WARP завершилось с ошибкой"; return 1; }
    record_fix "warp-native uninstall"
    msg_info "убери outbound warp-out и его правило из профиля Xray в панели, иначе этот трафик не уйдёт"
}

warp_menu() {
    local c
    while true; do
        echo -e "  ${BOLD}WARP Native${NC} ${DIM}(Cloudflare WARP как outbound Xray)${NC}"
        warp_status_line
        echo -e "    ${C}${BOLD}[1]${NC} Установить"
        echo -e "    ${C}${BOLD}[2]${NC} Удалить"
        echo -e "    ${C}${BOLD}[0]${NC} Назад"
        printf "  ${BOLD}Выбор${NC} ${DIM}[0-2]${NC}: "; read -r c || return 0; echo
        case "$c" in
            1) warp_install ;;
            2) warp_uninstall ;;
            0|q|"") return 0 ;;
            *) msg_warn "нет такого пункта" ;;
        esac
        echo
    done
}

warp_main() {
    case "${1:-menu}" in
        status) warp_status_line; return 0 ;;
        help|-h|--help) echo "warp: sudo bash node-diagnostic.sh warp [menu|install|uninstall|status]"; return 0 ;;
        menu|install|uninstall) ;;
        *) echo "warp: неизвестная команда '$1' (menu|install|uninstall|status)" >&2; return 2 ;;
    esac
    need_root || die "нужен root"
    [ -t 0 ] || die "нужен интерактивный терминал — установщик WARP спрашивает ввод"
    case "${1:-menu}" in
        menu)      warp_menu ;;
        install)   warp_install ;;
        uninstall) warp_uninstall ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    warp_main "$@"
fi
