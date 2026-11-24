#!/usr/bin/env bash
# node-diagnostic.sh — точка входа модульного тулкита ноды (Remnawave / VPN / Linux).
# Диспетчер: интерактивное меню или прямой вызов модуля. Логика — в modules/, общее — в lib/common.sh.
# Источник: https://github.com/smoorf132/node-diagnostic
#
#   sudo bash node-diagnostic.sh                 # меню (или диагностика, если не TTY)
#   sudo bash node-diagnostic.sh diagnose -q     # только диагностика
#   sudo bash node-diagnostic.sh optimize --all  # тюнинг
#   sudo bash node-diagnostic.sh protect --panel-ip 1.2.3.4   # генерация защиты
#   sudo bash node-diagnostic.sh bbr3 --install  # XanMod (BBRv3)
#   sudo bash node-diagnostic.sh rollback        # откат оптимизаций

set -u
# ${BASH_SOURCE[0]:-$0}: при `curl … | bash` BASH_SOURCE пуст — без фоллбэка set -u
# роняет скрипт с «unbound variable» вместо внятного сообщения ниже
SELF="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
MOD="$SELF/modules"

# shellcheck source=lib/common.sh
if ! source "$SELF/lib/common.sh" 2>/dev/null; then
    echo "Ошибка: не найден lib/common.sh рядом со скриптом (запуск через pipe?)." >&2
    echo "Тулкит модульный — нужен весь репозиторий. Установка одной командой:" >&2
    echo "  curl -sSL https://raw.githubusercontent.com/smoorf132/node-diagnostic/main/install.sh | sudo bash" >&2
    echo "или вручную:" >&2
    echo "  git clone https://github.com/smoorf132/node-diagnostic && cd node-diagnostic && sudo bash node-diagnostic.sh" >&2
    exit 1
fi
export FINDINGS_FILE ND_STATE_DIR   # общий findings-файл между диагностикой и модулями
export ND_VERSION                   # единый источник версии (diagnose.sh печатает её)

run() { local m="$1"; shift; bash "$MOD/$m.sh" "$@"; }

banner() {
    echo
    echo -e "  ${C}${BOLD}NODE DIAGNOSTIC${NC}  ${DIM}v${ND_VERSION} · toolkit${NC}"
    ui_rule
    echo -e "  ${DIM}$(date -u +'%Y-%m-%d %H:%M UTC') · $(hostname) · $(detect_virt)${NC}"
}

usage() {
    cat <<HELP
node-diagnostic.sh v$ND_VERSION — модульный тулкит ноды (Remnawave / VPN / Linux).

Команды:
  diagnose [-q|-v|--no-net]      Диагностика ноды (27 чеков, дашборд, вердикт)
  optimize [--all|--from-findings|--sysctl|--limits|--rps|--nic|--mss|--irqbalance|--journald|--zram|--dry-run]
                                 Тюнинг: sysctl/BBR/FD-лимиты/RPS-RFS-XPS/NIC/MSS/irqbalance/journald
                                 --all включает irqbalance+journald; --zram (zram-swap) — только явно
                                 --from-findings — только фиксы по находкам последней диагностики
  protect  [--panel-ip IP] [--node-port N] [--ssh-from IP|CIDR] [--out DIR]
           [--hy2 y|n] [--trust IP|CIDR]... [--bridge-port N|off] [--bridge-from IP|CIDR]...
                                 Защита под Remnawave (firewall/SSH) — ГЕНЕРАЦИЯ, не применяет
                                 SSH по умолчанию: подсеть NetBird, если сессия через неё, иначе твой IP
  protect trust  {add|del IP|CIDR…|list}
  protect bridge {add|del IP|CIDR…|port N|off|list}
                                 На лету: trusted4/6 (443 мимо per-IP лимитов), порт мостов/балансеров
                                 и его пул bridge4/6 — conf, firewall.nft и живая таблица node_protect
  bbr3     [--status|--install|--dry-run|--yes]
                                 BBRv3 через XanMod-ядро (гейт контейнеров, без автоперезагрузки)
  rollback [--yes|--dry-run]     Откат наложенных оптимизаций (namespaced-артефакты)
  status                         Что наложено на систему, ядро, cc/qdisc
  install {node|warp|netbird|monitoring|crowdsec|balancer}
                                 Установка ноды Remnawave (nginx-selfsteal + сертификат) / WARP /
                                 NetBird / мониторинга / CrowdSec
  certs    [menu|renew|issue [ДОМЕН]|manual [ДОМЕН]]
                                 Сертификаты: продление, выпуск (Cloudflare/Gcore/Bunny/HTTP-01), свой
  warp     [menu|install|uninstall|status]
                                 WARP Native (distillium/warp-native) — интерфейс warp для outbound Xray
  ipv6     [menu|status|on|off]  Включить/выключить IPv6 (sysctl disable_ipv6)
  shape {on|off|status|rule …|wl IP}
                                 Per-IP шейпер полосы (eBPF/EDT) — лимит DL/UL на клиента
  guard  {on [--geo ru]|off|status|reattach|allow IP|unallow IP|update-geo|confirm}
                                 Защита от DDoS (XDP + tc + NOTRACK): вариант 1 — только Россия, вариант 2 — весь мир
  ssh-port [ПОРТ]                Смена SSH-порта без лок-аута (sshd + firewall, проверка входа, откат)
  balancer {install|add SNI HOST:PORT[,…]|del SNI|default SNI|list|status|apply}
                                 Балансер: nginx stable (nginx.org), SNI → upstream'ы нод с proxy-protocol
  menu                           Интерактивное меню (по умолчанию в TTY)
  help | --version

Без аргументов: меню в терминале, диагностика — если ввод не интерактивный (curl | bash).
После install.sh тулкит доступен командой rr (например: rr, rr certs renew, rr ipv6 status).
HELP
}

menu() {
    while true; do
        banner
        echo
        echo -e "    ${C}${BOLD}[1]${NC} Диагностика        ${DIM}27 чеков, дашборд, вердикт${NC}"
        echo -e "    ${C}${BOLD}[2]${NC} Оптимизация        ${DIM}sysctl/BBR/FD/RPS/NIC${NC}"
        echo -e "    ${C}${BOLD}[3]${NC} Защита ноды        ${DIM}firewall/SSH, trusted, мосты${NC}"
        echo -e "    ${C}${BOLD}[4]${NC} BBRv3-ядро         ${DIM}XanMod, нужен reboot${NC}"
        echo -e "    ${C}${BOLD}[5]${NC} Откат              ${DIM}снять наложенные оптимизации${NC}"
        echo -e "    ${C}${BOLD}[6]${NC} Статус             ${DIM}что применено, ядро, cc/qdisc${NC}"
        echo -e "    ${C}${BOLD}[7]${NC} Установка Remnanode ${DIM}нода+selfsteal/WARP/NetBird/мониторинг/CrowdSec${NC}"
        echo -e "    ${C}${BOLD}[8]${NC} Шейпер трафика     ${DIM}per-IP лимиты полосы (eBPF)${NC}"
        echo -e "    ${C}${BOLD}[9]${NC} SSH-порт           ${DIM}быстрая смена без лок-аута${NC}"
        echo -e "   ${C}${BOLD}[10]${NC} Сертификаты        ${DIM}продление/выпуск/свой${NC}"
        echo -e "   ${C}${BOLD}[11]${NC} IPv6               ${DIM}включить/выключить${NC}"
        echo -e "   ${C}${BOLD}[12]${NC} Защита от DDoS     ${DIM}XDP: только Россия / весь мир${NC}"
        echo -e "   ${C}${BOLD}[13]${NC} Балансер nginx     ${DIM}SNI → ноды, proxy-protocol${NC}"
        echo -e "    ${C}${BOLD}[0]${NC} Выход"
        echo
        printf "  ${BOLD}Выбор${NC} ${DIM}[0-13]${NC}: "
        local c; read -r c
        echo
        case "$c" in
            1) menu_diagnose ;;
            2) menu_optimize ;;
            3) menu_protect ;;
            4) run bbr3 ;;
            5) run rollback ;;
            6) show_status ;;
            7) menu_install ;;
            8) menu_shape ;;
            9) run sshport ;;
            10) run certs menu ;;
            11) run ipv6 menu ;;
            12) menu_guard ;;
            13) menu_balancer ;;
            0|q|"") echo -e "  ${DIM}выход${NC}"; return 0 ;;
            *) echo -e "  ${Y}нет такого пункта${NC}" ;;
        esac
        echo
        printf "  ${DIM}Enter — вернуться в меню…${NC}"; read -r _
    done
}

# Что тулкит наложил на систему + ключевое состояние сети (read-only)
show_status() {
    echo
    local cc qdisc cc_disp g_disp
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null)
    cc_disp="${cc:-?}"; [ -n "$qdisc" ] && cc_disp="$cc + $qdisc"
    box_top "СОСТОЯНИЕ НОДЫ"
    box_kv "Версия" "$ND_VERSION"
    box_kv "Ядро" "$(uname -r)"
    box_kv "Congestion" "$cc_disp"
    if [ -e /sys/fs/bpf/nd-guard/progs/nd_guard_xdp ]; then g_disp="включён (rr guard status)"
    elif [ -e /var/lib/node-diagnostic/guard/guard.conf ]; then g_disp="выключен, конфиг сохранён (rr guard reattach)"
    else g_disp="выключен"; fi
    box_kv "Guard (DDoS)" "$g_disp"
    box_bottom
    echo

    box_top "НАЛОЖЕННЫЕ АРТЕФАКТЫ"
    local found=0 f
    for f in /etc/sysctl.d/${ND_DROPIN_PREFIX}-*.conf \
             /etc/security/limits.d/99-node-diagnostic.conf \
             /etc/modules-load.d/${ND_DROPIN_PREFIX}.conf \
             /etc/systemd/journald.conf.d/99-node-diagnostic.conf \
             /etc/ssh/sshd_config.d/${ND_DROPIN_PREFIX}-port.conf \
             /etc/sysctl.d/99-remnawave-ipv6.conf; do
        [ -e "$f" ] && { box_row "${C_OK}${I_OK}${NC} ${f}"; found=1; }
    done
    for svc in node-diagnostic-rps node-diagnostic-nic node-diagnostic-zram; do
        [ -e "/etc/systemd/system/$svc.service" ] && { box_row "${C_OK}${I_OK}${NC} ${svc}.service"; found=1; }
    done
    if have iptables && iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
        box_row "${C_OK}${I_OK}${NC} iptables MSS clamp (OUTPUT)"; found=1
    fi
    [ "$found" = "0" ] && box_row "${DIM}ничего не наложено (optimize не запускался)${NC}"
    box_bottom
    echo

    if [ -f "$FIX_LOG" ]; then
        box_top "ЖУРНАЛ ПРИМЕНЁННОГО"
        tail -5 "$FIX_LOG" 2>/dev/null | while IFS= read -r line; do
            box_row "${DIM}$(ui_fit "$line" "$ND_BOX_W")${NC}"
        done
        box_bottom
    fi
}

menu_optimize() {
    if [ ! -t 0 ]; then run optimize --all; return; fi
    echo -e "  ${BOLD}Оптимизация${NC}"
    echo -e "    ${DIM}[a] всё   [f] по находкам   [z] zram-swap   [d] предпросмотр (dry-run)   [Enter] всё${NC}"
    printf "  выбор: "; local c; read -r c
    case "${c,,}" in
        f) run optimize --from-findings ;;
        z) run optimize --zram ;;
        d) run optimize --dry-run ;;
        *) run optimize --all ;;
    esac
}

menu_diagnose() {
    if [ ! -t 0 ]; then run diagnose; return; fi
    echo -e "  ${BOLD}Диагностика${NC}"
    echo -e "    ${DIM}[Enter] полная (~5 мин)   [q] быстрая (~1 мин, без долгих тестов)${NC}"
    printf "  выбор: "; local c; read -r c
    case "${c,,}" in
        q) run diagnose -q ;;
        *) run diagnose ;;
    esac
}

is_port() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

menu_protect() {
    if [ ! -t 0 ]; then run protect; return; fi
    echo -e "  ${BOLD}Защита ноды${NC}"
    echo -e "    ${C}${BOLD}[1]${NC} Сгенерировать firewall/SSH  ${DIM}ничего не применяет${NC}"
    echo -e "    ${C}${BOLD}[2]${NC} Доверенные IP (trusted)     ${DIM}443 мимо per-IP лимитов, на лету${NC}"
    echo -e "    ${C}${BOLD}[3]${NC} Мосты и балансеры           ${DIM}порт (8443) + пул IP, на лету${NC}"
    echo -e "    ${C}${BOLD}[0]${NC} Назад"
    printf "  ${BOLD}Выбор${NC} ${DIM}[0-3]${NC}: "; local c; read -r c; echo
    case "$c" in
        1) menu_protect_gen ;;
        2) menu_protect_nets trust ;;
        3) menu_protect_nets bridge ;;
        *) return 0 ;;
    esac
}

# список IP/подсетей через пробел (v4/v6) → массив _NETS; пустой ввод — пустой массив; rc 1 — мусор
_read_nets() {
    local line n; _NETS=()
    read -r line || return 0
    for n in $line; do
        net_norm "$n" >/dev/null || { echo -e "    ${Y}«${n}» — не IP/подсеть${NC}"; return 1; }
        _NETS+=("$n")
    done
}

menu_protect_gen() {
    echo -e "  ${BOLD}Генерация firewall/SSH${NC} ${DIM}(ничего не применяет)${NC}"
    local pip np sf nb hy bp="" yn n
    local -a args=() trust=() bridge=()
    while true; do
        printf "  IP панели Remnawave ${DIM}[Enter — оставить плейсхолдер <PANEL_IP>]${NC}: "
        read -r pip
        [ -z "$pip" ] || is_ipv4 "$pip" && break
        echo -e "    ${Y}это не IPv4-адрес${NC} ${DIM}(firewall.nft ждёт именно IPv4)${NC}"
    done
    while true; do
        printf "  NODE_PORT (панель→нода) ${DIM}[Enter — автодетект из .env/docker]${NC}: "
        read -r np
        [ -z "$np" ] || is_port "$np" && break
        echo -e "    ${Y}порт — это число 1-65535${NC}"
    done
    nb=$(netbird_cidr) && echo -e "    ${DIM}NetBird на ноде: подсеть $nb${NC}"
    while true; do
        printf "  SSH пускать с ${DIM}[Enter — авто: подсеть NetBird, если зашёл через неё, иначе твой IP]${NC}: "
        read -r sf
        [ -z "$sf" ] || ipv4_net "$sf" >/dev/null && break
        echo -e "    ${Y}нужен IPv4 или подсеть${NC} ${DIM}(напр. ${nb:-100.92.0.0/16})${NC}"
    done
    while true; do
        printf "  Hysteria2 (HY2/QUIC) на 443/udp есть? ${DIM}[y/n]${NC}: "
        read -r yn || return 0
        case "$yn" in y|Y|yes|д|да) hy=y; break ;; n|N|no|н|нет) hy=n; break ;; esac
        echo -e "    ${Y}ответь y или n${NC} ${DIM}(n — 443/udp будет закрыт)${NC}"
    done
    while true; do
        printf "  Доверенные IP/подсети мимо per-IP лимитов 443 ${DIM}[через пробел, Enter — нет]${NC}: "
        _read_nets && break
    done
    trust=("${_NETS[@]}")
    while true; do
        printf "  Открыть порт для мостов/балансеров (xray + proxy-protocol) только пулу IP? ${DIM}[y/n]${NC}: "
        read -r yn || return 0
        case "$yn" in y|Y|yes|д|да|n|N|no|н|нет|"") break ;; esac
        echo -e "    ${Y}ответь y или n${NC}"
    done
    if case "$yn" in y|Y|yes|д|да) true ;; *) false ;; esac; then
        while true; do
            printf "  Порт мостов ${DIM}[Enter — 8443]${NC}: "
            read -r bp; bp=${bp:-8443}
            is_port "$bp" && break
            echo -e "    ${Y}порт — это число 1-65535${NC}"
        done
        while true; do
            printf "  IP/подсети мостов и балансеров ${DIM}[через пробел; можно позже: rr protect bridge add]${NC}: "
            _read_nets && break
        done
        bridge=("${_NETS[@]}")
    fi
    [ -n "$pip" ] && args+=(--panel-ip "$pip")
    [ -n "$np" ]  && args+=(--node-port "$np")
    [ -n "$sf" ]  && args+=(--ssh-from "$sf")
    args+=(--hy2 "$hy")
    for n in ${trust[@]+"${trust[@]}"}; do args+=(--trust "$n"); done
    [ -n "$bp" ] && args+=(--bridge-port "$bp")
    for n in ${bridge[@]+"${bridge[@]}"}; do args+=(--bridge-from "$n"); done
    run protect "${args[@]}"
}

menu_protect_nets() {   # trust|bridge
    local k=$1 c p
    if [ "$k" = trust ]; then
        echo -e "  ${BOLD}Доверенные IP${NC} ${DIM}(set trusted4/6: 443 мимо per-IP лимитов)${NC}"
    else
        echo -e "  ${BOLD}Мосты и балансеры${NC} ${DIM}(порт мостов открыт только пулу bridge4/6)${NC}"
    fi
    run protect "$k" list
    echo
    echo -e "    ${C}${BOLD}[1]${NC} Добавить IP/подсети"
    echo -e "    ${C}${BOLD}[2]${NC} Удалить IP/подсети"
    [ "$k" = bridge ] && echo -e "    ${C}${BOLD}[3]${NC} Порт мостов ${DIM}(число или off)${NC}"
    echo -e "    ${C}${BOLD}[0]${NC} Назад"
    printf "  ${BOLD}Выбор${NC}: "; read -r c; echo
    case "$c" in
        1|2)
            while true; do
                printf "  IP/подсети через пробел ${DIM}(v4/v6)${NC}: "
                _read_nets && break
            done
            [ "${#_NETS[@]}" -gt 0 ] || return 0
            if [ "$c" = 1 ]; then run protect "$k" add "${_NETS[@]}"; else run protect "$k" del "${_NETS[@]}"; fi ;;
        3)
            [ "$k" = bridge ] || return 0
            printf "  Порт мостов ${DIM}[Enter — 8443, off — закрыть]${NC}: "; read -r p
            run protect bridge port "${p:-8443}" ;;
        *) return 0 ;;
    esac
}

menu_balancer() {
    if [ ! -t 0 ]; then run balancer status; return; fi
    echo -e "  ${BOLD}Балансер nginx${NC} ${DIM}(stream + ssl_preread: SNI → upstream'ы нод с proxy-protocol)${NC}"
    run balancer list
    echo
    echo -e "    ${C}${BOLD}[1]${NC} Установить / переустановить ${DIM}nginx stable с nginx.org + маршруты${NC}"
    echo -e "    ${C}${BOLD}[2]${NC} Добавить / изменить маршрут"
    echo -e "    ${C}${BOLD}[3]${NC} Удалить маршрут"
    echo -e "    ${C}${BOLD}[4]${NC} SNI по умолчанию"
    echo -e "    ${C}${BOLD}[5]${NC} Статус ${DIM}(nginx, доступность upstream'ов)${NC}"
    echo -e "    ${C}${BOLD}[0]${NC} Назад"
    printf "  ${BOLD}Выбор${NC} ${DIM}[0-5]${NC}: "; local c sni ups; read -r c; echo
    case "$c" in
        1) run balancer install ;;
        2) printf "  SNI (домен или *.домен): "; read -r sni
           printf "  upstream'ы (HOST:PORT через запятую, напр. 80.79.117.98:8443): "; read -r ups
           [ -n "$sni" ] && [ -n "$ups" ] && run balancer add "$sni" "$ups" ;;
        3) printf "  SNI: "; read -r sni; [ -n "$sni" ] && run balancer del "$sni" ;;
        4) printf "  SNI: "; read -r sni; [ -n "$sni" ] && run balancer default "$sni" ;;
        5) run balancer status ;;
        *) return 0 ;;
    esac
}

menu_install() {
    if [ ! -t 0 ]; then echo -e "  ${Y}установка доступна только в интерактивном режиме${NC}"; return 0; fi
    echo -e "  ${BOLD}Установка Remnanode${NC}"
    echo -e "    ${C}${BOLD}[1]${NC} Нода Remnawave     ${DIM}remnanode + nginx-selfsteal + сертификат${NC}"
    echo -e "    ${C}${BOLD}[2]${NC} WARP Native        ${DIM}интерфейс warp для outbound Xray${NC}"
    echo -e "    ${C}${BOLD}[3]${NC} NetBird            ${DIM}агент + setup-key${NC}"
    echo -e "    ${C}${BOLD}[4]${NC} Мониторинг         ${DIM}cAdvisor+node_exporter+vmagent${NC}"
    echo -e "    ${C}${BOLD}[5]${NC} CrowdSec           ${DIM}анти-брут SSH + nftables-bouncer${NC}"
    echo -e "    ${C}${BOLD}[0]${NC} Назад"
    printf "  ${BOLD}Выбор${NC} ${DIM}[0-5]${NC}: "; local c; read -r c; echo
    case "$c" in
        1) run install node ;;
        2) run warp menu ;;
        3) run install netbird ;;
        4) run install monitoring ;;
        5) run install crowdsec ;;
        0|q|"") return 0 ;;
        *) echo -e "  ${Y}нет такого пункта${NC}" ;;
    esac
}

menu_shape() {
    if [ ! -t 0 ]; then echo -e "  ${Y}шейпер доступен только в интерактивном режиме${NC}"; return 0; fi
    echo -e "  ${BOLD}Шейпер трафика${NC} ${DIM}(per-IP лимиты полосы, eBPF)${NC}"
    echo -e "    ${C}${BOLD}[1]${NC} Включить          ${DIM}собрать BPF + прицепить${NC}"
    echo -e "    ${C}${BOLD}[2]${NC} Правило           ${DIM}порты + лимит DL/UL на IP${NC}"
    echo -e "    ${C}${BOLD}[3]${NC} Whitelist +       ${DIM}IP без лимита${NC}"
    echo -e "    ${C}${BOLD}[4]${NC} Статус / правила"
    echo -e "    ${C}${BOLD}[5]${NC} Выключить"
    echo -e "    ${C}${BOLD}[0]${NC} Назад"
    printf "  ${BOLD}Выбор${NC} ${DIM}[0-5]${NC}: "; local c; read -r c; echo
    case "$c" in
        1) run shape on ;;
        2)
            local id ports dl ul
            printf "  ID правила (напр. 1): "; read -r id
            printf "  порты через запятую (или all): "; read -r ports
            printf "  лимит DL на IP (Mbit/s): "; read -r dl
            printf "  лимит UL на IP (Mbit/s): "; read -r ul
            if [ -n "$id" ] && [ -n "$ports" ] && [ -n "$dl" ] && [ -n "$ul" ]; then
                run shape rule "$id" "$ports" "$dl" "$ul"
            else echo -e "  ${Y}не все поля заданы${NC}"; fi
            ;;
        3) local ip; printf "  IP в whitelist: "; read -r ip; [ -n "$ip" ] && run shape wl "$ip" ;;
        4) run shape status ;;
        5) run shape off ;;
        0|q|"") return 0 ;;
        *) echo -e "  ${Y}нет такого пункта${NC}" ;;
    esac
}

menu_guard() {
    if [ ! -t 0 ]; then echo -e "  ${Y}guard доступен только в интерактивном режиме (в скриптах: rr guard on …)${NC}"; return 0; fi
    echo -e "  ${BOLD}Защита от DDoS${NC} ${DIM}(XDP + tc + NOTRACK; через 5 минут откатится без guard confirm)${NC}"
    echo -e "    ${C}${BOLD}[1]${NC} Вариант 1 — только Россия  ${DIM}guard on --geo ru${NC}"
    echo -e "    ${C}${BOLD}[2]${NC} Вариант 2 — весь мир       ${DIM}guard on${NC}"
    echo -e "    ${C}${BOLD}[3]${NC} Статус"
    echo -e "    ${C}${BOLD}[4]${NC} Allowlist +                ${DIM}IP/CIDR мимо гео (CDN, каскады, админы)${NC}"
    echo -e "    ${C}${BOLD}[5]${NC} Выключить"
    echo -e "    ${C}${BOLD}[0]${NC} Назад"
    printf "  ${BOLD}Выбор${NC} ${DIM}[0-5]${NC}: "; local c; read -r c; echo
    case "$c" in
        1) run guard on --geo ru ;;
        2) run guard on ;;
        3) run guard status ;;
        4) local ip; printf "  IP или CIDR в allowlist: "; read -r ip; [ -n "$ip" ] && run guard allow "$ip" ;;
        5) run guard off ;;
        0|q|"") return 0 ;;
        *) echo -e "  ${Y}нет такого пункта${NC}" ;;
    esac
}

# ── диспетчер ────────────────────────────────────────────────────────
cmd="${1:-}"; [ $# -gt 0 ] && shift || true
case "$cmd" in
    diagnose|diag)         run diagnose "$@" ;;
    optimize|opt|tune)     run optimize "$@" ;;
    protect|firewall|fw)   run protect "$@" ;;
    bbr3|kernel)           run bbr3 "$@" ;;
    rollback|revert)       run rollback "$@" ;;
    status|st)             show_status ;;
    install|setup)         run install "$@" ;;
    shape|shaper)          run shape "$@" ;;
    guard|ddos)            run guard "$@" ;;
    balancer|lb)           run balancer "$@" ;;
    ssh-port|sshport)      run sshport "$@" ;;
    certs|cert|ssl)        run certs "$@" ;;
    warp)                  run warp "$@" ;;
    ipv6)                  run ipv6 "$@" ;;
    menu)                  menu ;;
    help|-h|--help)        usage ;;
    --version|-V)          echo "node-diagnostic $ND_VERSION" ;;
    "")
        if [ -t 0 ]; then menu; else run diagnose; fi
        ;;
    *)
        echo "Неизвестная команда: $cmd (см. help)" >&2
        usage
        exit 2 ;;
esac
