#!/usr/bin/env bash
# modules/protect.sh — защита ноды под стек Remnawave. РЕЖИМ: только генерация.
# Пишет готовые артефакты (nftables/ufw firewall, SSH-хардненинг) в каталог
# и печатает пошаговую инструкцию по применению. САМ НИЧЕГО НЕ ПРИМЕНЯЕТ — фаервол на
# удалённой ноде может отрезать SSH, поэтому применяешь руками, сверив IP панели/SSH.
# Анти-брут SSH — CrowdSec, ставится отдельно: node-diagnostic.sh install crowdsec.
#
# Standalone:  sudo bash modules/protect.sh [--role node|balancer] [--panel-ip X.X.X.X] [--node-port N]
#              [--ssh-from IP|CIDR|any] [--out DIR]
#              [--hy2 y|n] [--trust IP|CIDR]... [--bridge-port N|off] [--bridge-from IP|CIDR]...
# На лету:     protect trust {add|del} IP|CIDR… | trust list
#              protect bridge {add|del} IP|CIDR… | bridge port N|off | bridge list
# SSH без --ssh-from: вся подсеть NetBird, если текущая сессия пришла через неё, иначе IP сессии.
# Как модуль:  source lib/common.sh; source modules/protect.sh; protect_generate

if [ -z "${ND_COMMON_LOADED:-}" ]; then
    _self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "$_self/../lib/common.sh" 2>/dev/null \
        || { echo "не найден lib/common.sh — нужен весь репозиторий (см. install.sh)" >&2; exit 1; }
fi

# ── детект параметров Remnawave-ноды ────────────────────────────────
detect_node_port() {
    local f v
    for f in "$REMNANODE_DIR/.env" /opt/remnanode/.env /root/remnanode/.env /opt/remnawave/node/.env ./.env; do
        [ -r "$f" ] || continue
        v=$(awk -F= '/^[[:space:]]*NODE_PORT[[:space:]]*=/{gsub(/[" ]/,"",$2);print $2;exit}' "$f")
        [ -n "$v" ] && { echo "$v"; return 0; }
    done
    # environment прямо в compose (установки remnawave-reverse-proxy):
    #   - NODE_PORT=2222   или   NODE_PORT: 2222
    for f in "$REMNANODE_DIR/docker-compose.yml" /opt/remnawave/docker-compose.yml; do
        [ -r "$f" ] || continue
        v=$(sed -nE 's/^[[:space:]]*-?[[:space:]]*"?NODE_PORT[=:][[:space:]]*"?([0-9]+).*/\1/p' "$f" | head -n1)
        [ -n "$v" ] && { echo "$v"; return 0; }
    done
    # из запущенного контейнера remnanode — ТОЛЬКО он: первый попавшийся published-порт
    # чужого контейнера (Caddy и т.п.) уехал бы в firewall как NODE_PORT.
    # Берём хостовую часть маппинга (куда реально стучится панель), не внутреннюю.
    if have docker; then
        v=$(docker ps --filter name=remnanode --format '{{.Ports}}' 2>/dev/null \
            | grep -oE ':[0-9]+->' | head -1 | tr -cd '0-9')
        [ -n "$v" ] && { echo "$v"; return 0; }
    fi
    return 1
}

# BAN_NETS="" из окружения значит «без бана», поэтому факт задания снимаем до дефолта ниже:
# окружение > protect.conf > дефолт
_BAN_FROM_ENV=${BAN_NETS+1}

PROTECT_OUT="${PROTECT_OUT:-}"
PANEL_IP="${PANEL_IP:-}"
NODE_PORT="${NODE_PORT:-}"
SSH_FROM="${SSH_FROM:-}"      # откуда пускать SSH: IP, CIDR или any (пусто — авто: NetBird / твой IP)
ROLE="${ROLE:-}"              # node (по умолчанию) | balancer — сервер балансера: без NODE_PORT/панели/мостов/HY2
HY2="${HY2:-}"                # Hysteria2/QUIC на 443/udp: y|n (пусто — из protect.conf, иначе y)
# доверенные (set trusted4/6): на 443 мимо per-IP лимитов — CGNAT-шлюзы, мосты, ходящие на 443
TRUST_NETS="${TRUST_NETS:-}"
# порт мостов/балансеров (xray + proxy-protocol, напр. 8443): открыт только пулу bridge4/6
BRIDGE_PORT="${BRIDGE_PORT:-}"    # пусто — из protect.conf; off — выключить
BRIDGE_NETS="${BRIDGE_NETS:-}"
# куда класть копию firewall.nft для автозагрузки; trust/bridge обновляют её, если она уже есть
PROTECT_PERSIST="${PROTECT_PERSIST:-/etc/nftables.d/node_protect.nft}"
# ключи <out>/protect.conf: параметры прошлой генерации, их берут повторный protect и trust/bridge
PROTECT_CONF_KEYS="GENERATED ROLE PANEL_IP NODE_PORT SSH_FROM HY2 TRUST_NETS BRIDGE_PORT BRIDGE_NETS BAN_NETS"
GENERATED=""

# per-IP лимиты в nft (из практики node-accelerator)
CONN_LIMIT="${CONN_LIMIT:-2048}"
SYN_RATE="${SYN_RATE:-200}"
UDP_RATE="${UDP_RATE:-200}"
ICMP_RATE="${ICMP_RATE:-10}"
SSH_RATE="${SSH_RATE:-6}"     # соединений/мин на IP
# per-IP лимиты живут в set'ах с size и timeout: v4 — до RL_SIZE4 адресов, v6 (по /64) — до RL_SIZE6
RL_SIZE4="${RL_SIZE4:-131072}"
RL_SIZE6="${RL_SIZE6:-65536}"
RL_TIMEOUT="${RL_TIMEOUT:-30s}"

# перманентный бан подсетей (set banned4, drop раньше любых accept). BAN_NETS="" — без бана
BAN_NETS="${BAN_NETS-185.224.228.0/22 195.209.120.0/22 212.192.156.0/23 212.192.158.0/24 194.165.22.0/23}"

# ── списки адресов (trusted/bridge): канон через net_norm, без дублей ──
# _nets_add "СПИСОК" NET… → СПИСОК + NET (уже нормализованные), порядок сохраняется
_nets_add() {
    local list=$1 n; shift
    for n in "$@"; do
        case " $list " in *" $n "*) ;; *) list="$list${list:+ }$n" ;; esac
    done
    echo "$list"
}
# _nets_del "СПИСОК" NET… → СПИСОК без NET
_nets_del() {
    local list=$1 n out=""; shift
    for n in $list; do
        case " $* " in *" $n "*) ;; *) out="$out${out:+ }$n" ;; esac
    done
    echo "$out"
}
# _nets_fam "СПИСОК" 4|6 → элементы семейства через «, » (для elements = { … })
_nets_fam() {
    local n out=""
    for n in $1; do
        case "$n" in *:*) [ "$2" = 6 ] || continue ;; *) [ "$2" = 4 ] || continue ;; esac
        out="$out${out:+, }$n"
    done
    echo "$out"
}
# _nets_clean "СПИСОК" ИМЯ → нормализованный список; мусор — предупреждение и пропуск
_nets_clean() {
    local n c out=""
    for n in $1; do
        c=$(net_norm "$n") || { msg_warn "$2: «${n}» не IP/подсеть — пропускаю" >&2; continue; }
        case "$c" in */0) msg_warn "$2: $c — весь интернет, пропускаю" >&2; continue ;; esac
        out=$(_nets_add "$out" "$c")
    done
    echo "$out"
}

# _net_wide_ok NET ЧТО — /0 не берём никогда (trusted /0 выключил бы лимиты всем, bridge /0 открыл
# бы порт с proxy-protocol всем — подмена IP клиента); короче /8 (v4) или /32 (v6) — только с
# подтверждением в терминале или ND_WIDE_OK=1. rc 1 — отказ
_net_wide_ok() {
    local p=${1#*/} min=8
    case "$1" in */*) ;; *) return 0 ;; esac
    case "$1" in *:*) min=32 ;; esac
    if [ "$p" -eq 0 ]; then
        msg_err "$2: $1 — это весь интернет, не беру" >&2; return 1
    fi
    [ "$p" -ge "$min" ] && return 0
    [ "${ND_WIDE_OK:-0}" = 1 ] && return 0
    if [ -t 0 ]; then
        confirm "$2: $1 — очень широкий префикс (/$p). Точно?" && return 0
        return 1
    fi
    msg_err "$2: $1 — очень широкий префикс (/$p); подтверди в терминале или задай ND_WIDE_OK=1" >&2
    return 1
}

# каталог артефактов (и protect.conf): --out / PROTECT_OUT, иначе /root/… под root, ./… без root
protect_out_dir() {
    if [ -n "$PROTECT_OUT" ]; then echo "$PROTECT_OUT"
    elif need_root; then echo /root/node-diagnostic-protect
    else echo "$PWD/node-diagnostic-protect"; fi
}

# protect_conf_load DIR → CONF_<КЛЮЧ> и CONF_PRESENT (« КЛЮЧ1 КЛЮЧ2 »); rc 1 — файла нет.
# Не source: файл в каталоге артефактов, строки с посторонними символами отбрасываются.
protect_conf_load() {
    local f="$1/protect.conf" line k v
    CONF_PRESENT=" "
    # shellcheck disable=SC2034  # часть читается только косвенно (${!v} в protect_live)
    CONF_GENERATED="" CONF_ROLE="" CONF_PANEL_IP="" CONF_NODE_PORT="" CONF_SSH_FROM="" CONF_HY2=""
    CONF_TRUST_NETS="" CONF_BRIDGE_PORT="" CONF_BRIDGE_NETS="" CONF_BAN_NETS=""
    [ -r "$f" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|\#*) continue ;; esac
        k=${line%%=*}; v=${line#*=}
        case " $PROTECT_CONF_KEYS " in *" $k "*) ;; *) continue ;; esac
        v=${v#\"}; v=${v%\"}
        case "$v" in *[!A-Za-z0-9.:/\ _-]*) continue ;; esac
        printf -v "CONF_$k" '%s' "$v"
        CONF_PRESENT="$CONF_PRESENT$k "
    done < "$f"
    return 0
}
# protect_conf_save DIR — текущие значения переменных PROTECT_CONF_KEYS (плейсхолдеры не пишем)
protect_conf_save() {
    local f="$1/protect.conf" k v
    mkdir -p "$1" || return 1
    {
        echo "# node-diagnostic protect: параметры генерации firewall. Читают повторный protect"
        echo "# и protect trust|bridge (они же его и правят)."
        for k in $PROTECT_CONF_KEYS; do
            v=${!k}
            case "$v" in *"<"*) v="" ;; esac
            printf '%s="%s"\n' "$k" "$v"
        done
    } > "$f.tmp" && chmod 600 "$f.tmp" && mv -f "$f.tmp" "$f"
}

# yes/no → y|n; rc 1 — ни то, ни другое
_yn() { case "$1" in y|Y|yes|Yes|YES|д|Д|да|Да) echo y ;; n|N|no|No|NO|н|Н|нет|Нет) echo n ;; *) return 1 ;; esac; }

protect_generate() {
    local ssh_port ssh_ip ssh_src nb_addr nb="" out
    out=$(protect_out_dir)
    ssh_port=$(detect_ssh_port)
    ssh_ip=$(ssh_client_ip)
    nb_addr=$(netbird_addr) && nb=$(ipv4_net "$nb_addr")

    # прошлая генерация: пустые параметры добираем из protect.conf, списки — объединяем
    protect_conf_load "$out" || true
    [ -z "$PANEL_IP" ]  && PANEL_IP=$CONF_PANEL_IP
    [ -z "$NODE_PORT" ] && NODE_PORT=$CONF_NODE_PORT
    [ -z "$SSH_FROM" ]  && SSH_FROM=$CONF_SSH_FROM
    [ -z "$ROLE" ]      && ROLE=$CONF_ROLE
    case "${ROLE:-node}" in node|balancer) ROLE=${ROLE:-node} ;; *) die "protect: --role ждёт node или balancer, получено: $ROLE" ;; esac
    [ -z "$HY2" ]       && HY2=$CONF_HY2
    [ -z "$BRIDGE_PORT" ] && BRIDGE_PORT=$CONF_BRIDGE_PORT
    if [ -z "$_BAN_FROM_ENV" ]; then
        case "$CONF_PRESENT" in *" BAN_NETS "*) BAN_NETS=$CONF_BAN_NETS ;; esac
    fi
    HY2=$(_yn "${HY2:-y}") || die "protect: --hy2 ждёт y или n, получено: $HY2"
    [ "$BRIDGE_PORT" = off ] && BRIDGE_PORT=""
    if [ "$ROLE" = balancer ]; then
        # балансер — nginx stream по TCP: ни UDP, ни порта мостов, ни канала панели
        HY2=n; PANEL_IP=""; NODE_PORT=""
        [ -n "$BRIDGE_PORT" ] && { msg_warn "балансер: порт мостов не нужен — пропускаю $BRIDGE_PORT"; BRIDGE_PORT=""; }
    fi
    TRUST_NETS=$(_nets_clean "$CONF_TRUST_NETS $TRUST_NETS" TRUST_NETS)
    BRIDGE_NETS=$(_nets_clean "$CONF_BRIDGE_NETS $BRIDGE_NETS" BRIDGE_NETS)
    [ "$ROLE" = node ] && [ -z "$NODE_PORT" ] && NODE_PORT=$(detect_node_port || echo "")
    if [ -n "$BRIDGE_PORT" ]; then
        [[ "$BRIDGE_PORT" =~ ^[0-9]+$ ]] && [ "$BRIDGE_PORT" -ge 1 ] && [ "$BRIDGE_PORT" -le 65535 ] \
            || die "protect: порт мостов — число 1-65535 или off, получено: $BRIDGE_PORT"
        case "$BRIDGE_PORT" in 443|80|"$ssh_port"|"$NODE_PORT")
            die "protect: порт мостов $BRIDGE_PORT занят под 443/80/SSH/NODE_PORT — выбери другой (напр. 8443)" ;;
        esac
    fi
    # откуда пускать SSH: явный --ssh-from → вся подсеть NetBird, если текущая сессия
    # пришла через неё (админ ходит по NetBird) → IP текущей сессии
    if [ "$SSH_FROM" = any ]; then
        ssh_src=any
    elif [ -n "$SSH_FROM" ]; then
        ssh_src="$SSH_FROM"
        case "$ssh_src" in */*) ssh_src=$(ipv4_net "$ssh_src" || echo "$ssh_src") ;; esac
    elif [ -n "$nb" ] && [ -n "$ssh_ip" ] && ip_in_cidr "$ssh_ip" "$nb"; then
        ssh_src="$nb"
        msg_info "SSH-сессия идёт через NetBird ($ssh_ip) — SSH открывается всей подсети $nb"
    else
        ssh_src="$ssh_ip"
    fi
    # dual-stack: nft-шаблон сам подставит ip6 saddr / ipv6_addr по семейству адреса
    case "$ssh_src"  in *:*) msg_info "SSH-источник IPv6 ($ssh_src) — правила будут на ip6 saddr" ;; esac
    case "$PANEL_IP" in *:*) msg_info "IP панели IPv6 ($PANEL_IP) — set panel_ip будет типа ipv6_addr" ;; esac
    mkdir -p "$out" || die "не создал каталог $out"

    local ph_panel="$PANEL_IP" ph_ssh="$ssh_src"
    [ -z "$ph_panel" ] && ph_panel="<PANEL_IP>"
    [ -z "$ph_ssh" ]   && ph_ssh="<YOUR_SSH_IP>"

    echo
    if [ "$ROLE" = balancer ]; then
        ui_head "Генерация защиты балансера" "nginx stream · только генерация файлов"
    else
        ui_head "Генерация защиты ноды" "Remnawave · только генерация файлов"
    fi
    echo -e "    ${DIM}SSH-порт:${NC} $ssh_port   ${DIM}SSH разрешён с:${NC} $([ "$ph_ssh" = any ] && echo "любого адреса (только rate-limit)" || echo "$ph_ssh")"
    [ -n "$nb" ] && echo -e "    ${DIM}NetBird:${NC} ${nb_addr%/*} ${DIM}(подсеть $nb)${NC}"
    if [ "$ROLE" = node ]; then
        echo -e "    ${DIM}NODE_PORT (control-API):${NC} ${NODE_PORT:-<не найден, укажи --node-port>}"
        echo -e "    ${DIM}IP панели:${NC} $ph_panel"
        if [ "$HY2" = y ]; then echo -e "    ${DIM}HY2/QUIC:${NC} да ${DIM}(443/udp открыт)${NC}"
        else echo -e "    ${DIM}HY2/QUIC:${NC} нет ${DIM}(443/udp закрыт)${NC}"; fi
    fi
    [ -n "$TRUST_NETS" ] && echo -e "    ${DIM}trusted (443 мимо per-IP лимитов):${NC} $TRUST_NETS"
    if [ -n "$BRIDGE_PORT" ]; then
        echo -e "    ${DIM}порт мостов/балансеров:${NC} $BRIDGE_PORT ${DIM}← только${NC} ${BRIDGE_NETS:-${Y}пул пуст — порт закрыт для всех${NC}}"
    fi
    echo -e "    ${DIM}каталог:${NC} $out"
    echo
    if [ "$ROLE" = node ]; then
        [ "$ph_panel" = "<PANEL_IP>" ] && msg_warn "IP панели не задан — в правилах плейсхолдер <PANEL_IP>, подставь перед применением (--panel-ip)"
        [ -z "$NODE_PORT" ] && msg_warn "NODE_PORT не найден — плейсхолдер <NODE_PORT>, подставь (--node-port)"
    fi
    # SSH-источник внутри NetBird (пир/подсеть) или накрывает её (100.64.0.0/10)
    local via_nb=0
    if [ -n "$nb" ] && { ip_in_cidr "${ph_ssh%/*}" "$nb" || ip_in_cidr "${nb_addr%/*}" "$ph_ssh"; }; then
        via_nb=1
    fi
    if [ "$ph_ssh" = any ]; then
        msg_warn "SSH открыт с любого адреса — защита: rate-limit ${SSH_RATE}/мин на IP, CrowdSec, вход только по ключу (sshd-hardening.conf)"
    elif [ "$ph_ssh" = "<YOUR_SSH_IP>" ]; then
        msg_warn "SSH-IP не определён (не по SSH?) — подставь свой IP вручную или задай --ssh-from (any — без ограничения)"
    elif [ "$via_nb" = "1" ]; then
        msg_warn "SSH будет открыт ТОЛЬКО из NetBird ($ph_ssh) — упадёт NetBird на ноде, вход останется только через VNC-консоль хостера"
    else
        msg_warn "SSH будет открыт ТОЛЬКО с $ph_ssh — если это домашний/динамический IP, после его смены SSH отрежет (детали в APPLY.txt)"
        [ -n "$nb" ] && msg_info "SSH только через NetBird: перегенерируй с --ssh-from $nb (и зайди через NetBird)"
    fi
    # текущая сессия вне разрешённого источника — firewall её оборвёт (IPv6 не сверяем)
    case "$ssh_ip$ph_ssh" in *:*|*"<"*|*any) ;; *)
        [ -n "$ssh_ip" ] && ! ip_in_cidr "$ssh_ip" "$ph_ssh" \
            && msg_warn "текущая сессия ($ssh_ip) не входит в $ph_ssh — firewall её оборвёт: перед применением зайди через NetBird"
    esac
    # бан-подсети: v4 → banned4, v6 → banned6, хост-биты обнуляются; свой SSH/панель в бане = лок-аут
    local n n2 bn ban="" ban6=""
    for n in $BAN_NETS; do
        bn=$(net_norm "$n") || { msg_warn "BAN_NETS: «${n}» не IP-подсеть — пропускаю"; continue; }
        case "$bn" in *:*) ban6="$ban6${ban6:+, }$bn"; continue ;; esac
        ban="$ban${ban:+, }$bn"
        ip_in_cidr "${ph_ssh%/*}" "$bn" && msg_warn "SSH-источник $ph_ssh в забаненной подсети $bn — firewall отрежет SSH"
        ip_in_cidr "$ph_panel" "$bn" && msg_warn "IP панели $ph_panel в забаненной подсети $bn — нода потеряет панель"
        for n2 in $TRUST_NETS $BRIDGE_NETS; do
            case "$n2" in *:*) continue ;; esac
            ip_in_cidr "${n2%/*}" "$bn" && msg_warn "$n2 (trusted/мост) в забаненной подсети $bn — бан сильнее, адрес будет отрезан"
        done
    done
    [ -n "$BRIDGE_PORT" ] && [ -z "$BRIDGE_NETS" ] \
        && msg_warn "порт мостов $BRIDGE_PORT без пула — закрыт для всех; добавить: protect bridge add <IP>"

    _gen_nft   "$out" "$ssh_port" "$ph_ssh" "$ph_panel" "${NODE_PORT:-<NODE_PORT>}" "$ban" "$ban6"
    _gen_ufw   "$out" "$ssh_port" "$ph_ssh" "$ph_panel" "${NODE_PORT:-<NODE_PORT>}"
    _gen_sshd  "$out"
    _gen_apply "$out" "$ssh_port" "$ph_ssh" "$via_nb" "$nb_addr"

    # параметры этой генерации — для повторного protect и для protect trust|bridge
    GENERATED=1
    case "$ph_ssh" in *"<"*) SSH_FROM="" ;; *) SSH_FROM=$ph_ssh ;; esac
    protect_conf_save "$out" || msg_warn "не записал $out/protect.conf"

    echo
    echo -e "  ${G}${BOLD}✓ Сгенерировано в $out${NC}"
    ls -1 "$out" | sed 's/^/      /'
    echo
    echo -e "  ${Y}${BOLD}Ничего не применено.${NC} ${DIM}Открой ${BOLD}$out/APPLY.txt${NC}${DIM} — там пошагово, с защитой от лок-аута.${NC}"
    record_fix "protect artifacts generated -> $out"
}

# _nft_set ИМЯ ТИП "ЭЛЕМЕНТЫ" — interval-set с auto-merge (пустой set валиден, пустой «elements = { }» — нет)
_nft_set() {
    printf '    set %s {\n        type %s\n        flags interval\n        auto-merge\n' "$1" "$2"
    [ -n "$3" ] && printf '        elements = { %s }\n' "$3"
    printf '    }\n'
}

# _nft_dset ИМЯ ТИП РАЗМЕР [TIMEOUT] — динамический set для per-IP лимитов. С timeout записи
# истекают сами; size явный: у meter'а без них set забивался (65535 записей навсегда), а на полном
# set'е update не срабатывает — лимит молча выключался для новых адресов (fail-open).
_nft_dset() {
    if [ -n "${4:-}" ]; then
        printf '    set %s { type %s; size %s; flags dynamic,timeout; timeout %s; }\n' "$1" "$2" "$3" "$4"
    else
        printf '    set %s { type %s; size %s; flags dynamic; }\n' "$1" "$2" "$3"
    fi
}

# Глобалы (их готовит protect_generate): ROLE node|balancer, HY2 y|n, TRUST_NETS, BRIDGE_PORT,
# BRIDGE_NETS. Правила trusted/bridge помечены comment "nd:trusted" / "nd:bridge" — по ним
# protect trust|bridge находит и правит их в живой таблице.
# Ключ IPv6-лимитов — /64 (K6): у клиента обычно целая /64, по /128 лимит обходится перебором адресов.
_gen_nft() {
    local out=$1 ssh_port=$2 ssh_ip=$3 panel=$4 node_port=$5 ban=$6 ban6=$7
    local K6="ip6 saddr and ffff:ffff:ffff:ffff::"

    # семейство адреса → правильный синтаксис saddr (dual-stack: v6 больше не игнорируется)
    local ssh_saddr="ip saddr" ssh_set=ssh_rate4 ssh_key="ip saddr" panel_type="ipv4_addr" panel_saddr="ip saddr"
    case "$ssh_ip" in *:*) ssh_saddr="ip6 saddr"; ssh_set=ssh_rate6; ssh_key=$K6 ;; esac
    case "$panel"  in *:*) panel_type="ipv6_addr"; panel_saddr="ip6 saddr" ;; esac

    local ports="443/tcp (VLESS/Reality)" ssh_rules udp_rules="" trusted_udp="" bridge_rules="" panel_rules=""
    local what="Remnawave-ноды"
    if [ "$ROLE" = balancer ]; then
        what="балансера (nginx stream: SNI → ноды)"; ports="443/tcp (SNI → upstream'ы нод)"
    else
        ports="$ports, NODE_PORT (control-API) — только с IP панели"
        panel_rules="
        # NODE_PORT — канал панель->нода, ТОЛЬКО с IP панели
        tcp dport $node_port $panel_saddr @panel_ip accept
"
    fi
    if [ "$ssh_ip" = any ]; then
        ssh_rules="        # SSH — с любого адреса (protect --ssh-from any): только rate-limit; брут режут CrowdSec и вход по ключу
        tcp dport $ssh_port ct state new meta nfproto ipv4 \\
            update @ssh_rate4 { ip saddr limit rate over ${SSH_RATE}/minute } counter drop
        tcp dport $ssh_port ct state new meta nfproto ipv6 \\
            update @ssh_rate6 { $K6 limit rate over ${SSH_RATE}/minute } counter drop
        tcp dport $ssh_port accept"
    else
        ssh_rules="        # SSH — только с $ssh_ip (IP или подсеть, напр. NetBird) + анти-брут по скорости соединений
        tcp dport $ssh_port $ssh_saddr $ssh_ip ct state new \\
            update @$ssh_set { $ssh_key limit rate over ${SSH_RATE}/minute } counter drop
        tcp dport $ssh_port $ssh_saddr $ssh_ip accept"
    fi
    if [ "$HY2" = y ]; then
        ports="$ports, 443/udp (HY2/QUIC)"
        trusted_udp="
        ip saddr @trusted4 udp dport 443 counter accept comment \"nd:trusted\"
        ip6 saddr @trusted6 udp dport 443 counter accept comment \"nd:trusted\""
        # без guard лимит видит только новые потоки (дальше — established). Под guard (NOTRACK) поток
        # untracked: лимит на каждый пакет срезал бы HY2 до ~2 Мбит/с на IP, поэтому считаем только
        # QUIC Long Header (старший бит первого байта — рукопожатие), 1-RTT Short Header идёт мимо.
        udp_rules="
        # 443/udp — Hysteria2/QUIC (protect --hy2 y): новые потоки; под guard — только QUIC Long Header
        udp dport 443 meta nfproto ipv4 ct state new \\
            update @udp443_4 { ip saddr limit rate over ${UDP_RATE}/second } counter drop
        udp dport 443 meta nfproto ipv6 ct state new \\
            update @udp443_6 { $K6 limit rate over ${UDP_RATE}/second } counter drop
        udp dport 443 meta nfproto ipv4 ct state untracked @th,64,1 1 \\
            update @udp443_4 { ip saddr limit rate over ${UDP_RATE}/second } counter drop
        udp dport 443 meta nfproto ipv6 ct state untracked @th,64,1 1 \\
            update @udp443_6 { $K6 limit rate over ${UDP_RATE}/second } counter drop
        udp dport 443 accept"
    fi
    if [ -n "$BRIDGE_PORT" ]; then
        ports="$ports, $BRIDGE_PORT/tcp (мосты/балансеры — только пул bridge4/6)"
        bridge_rules="
        # $BRIDGE_PORT — мосты и балансеры (xray + proxy-protocol): ТОЛЬКО пул bridge4/6, лимитов нет —
        # за одним IP балансера идут все его клиенты. Пул: protect bridge add|del <IP|CIDR>.
        # Порт идёт через conntrack (guard его не берёт): nf_conntrack_max масштабирует optimize
        tcp dport $BRIDGE_PORT ip saddr @bridge4 counter accept comment \"nd:bridge\"
        tcp dport $BRIDGE_PORT ip6 saddr @bridge6 counter accept comment \"nd:bridge\"
"
    fi

    {
    cat <<EOF
#!/usr/sbin/nft -f
# node-diagnostic: firewall $what. Своя таблица, ruleset не флашится (уживается с Docker).
# Применить:  sudo nft -f $out/firewall.nft
# Порты: $ports, 80 (ACME/редирект).
# SSH: $([ "$ssh_ip" = any ] && echo "с любого адреса, только rate-limit" || echo "только $ssh_ip ($ssh_saddr)"). Лимиты 443 — и для v4, и для v6 (v6 — по /64).

table inet node_protect
delete table inet node_protect
table inet node_protect {
EOF
    if [ "$ROLE" != balancer ]; then
        printf '    set panel_ip {\n        type %s\n        elements = { %s }\n    }\n' "$panel_type" "$panel"
    fi
    echo "    # перманентный бан подсетей (BAN_NETS). На лету: nft add element inet node_protect banned4|banned6 { X/N }"
    _nft_set banned4 ipv4_addr "$ban"
    _nft_set banned6 ipv6_addr "$ban6"
    echo "    # доверенные — на 443 мимо per-IP лимитов (CGNAT, мосты на 443). На лету: protect trust add|del"
    _nft_set trusted4 ipv4_addr "$(_nets_fam "$TRUST_NETS" 4)"
    _nft_set trusted6 ipv6_addr "$(_nets_fam "$TRUST_NETS" 6)"
    echo "    # мосты/балансеры — единственные, кому открыт порт мостов. На лету: protect bridge add|del|port"
    _nft_set bridge4 ipv4_addr "$(_nets_fam "$BRIDGE_NETS" 4)"
    _nft_set bridge6 ipv6_addr "$(_nets_fam "$BRIDGE_NETS" 6)"
    echo "    # состояние per-IP лимитов: size + timeout — записи истекают, set не забивается навсегда"
    _nft_dset icmp4 ipv4_addr "$RL_SIZE6" "$RL_TIMEOUT"
    _nft_dset icmp6 ipv6_addr "$RL_SIZE6" "$RL_TIMEOUT"
    _nft_dset ssh_rate4 ipv4_addr "$RL_SIZE6" 5m
    _nft_dset ssh_rate6 ipv6_addr "$RL_SIZE6" 5m
    _nft_dset conn443_4 ipv4_addr "$RL_SIZE4"
    _nft_dset conn443_6 ipv6_addr "$RL_SIZE6"
    _nft_dset syn443_4 ipv4_addr "$RL_SIZE4" "$RL_TIMEOUT"
    _nft_dset syn443_6 ipv6_addr "$RL_SIZE6" "$RL_TIMEOUT"
    if [ "$HY2" = y ]; then
        _nft_dset udp443_4 ipv4_addr "$RL_SIZE4" "$RL_TIMEOUT"
        _nft_dset udp443_6 ipv6_addr "$RL_SIZE6" "$RL_TIMEOUT"
    fi
    cat <<EOF
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        # бан раньше established — рвёт и уже открытые сессии из этих подсетей
        ip saddr @banned4 counter drop
        ip6 saddr @banned6 counter drop
        ct state established,related accept
        ct state invalid counter drop
        # невозможные комбинации TCP-флагов: под guard (NOTRACK) ct state invalid их не ловит,
        # а ответ ядра RST на такие пакеты — материал для fingerprint'а
        tcp flags & (fin|syn) == (fin|syn) counter drop
        tcp flags & (syn|rst) == (syn|rst) counter drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 counter drop
        tcp flags & (fin|psh|urg) == (fin|psh|urg) counter drop

        # ICMP нужен для PMTU — не резать полностью, только флуд (per-IP, v6 — per-/64)
        ip  protocol icmp  update @icmp4 { ip saddr limit rate over ${ICMP_RATE}/second } counter drop
        ip6 nexthdr icmpv6 update @icmp6 { $K6 limit rate over ${ICMP_RATE}/second } counter drop
        ip  protocol icmp   accept
        ip6 nexthdr icmpv6  accept

$ssh_rules

        # доверенные (trusted4/6) — до лимитов: один IP за многими клиентами упёрся бы в conn443/syn443
        ip saddr @trusted4 tcp dport 443 counter accept comment "nd:trusted"
        ip6 saddr @trusted6 tcp dport 443 counter accept comment "nd:trusted"$trusted_udp

        # 443 — публичный вход. Per-IP лимит одновременных соединений и SYN-rate.
        # (ct count вне set'а считал бы ВСЕ соединения порта разом — душил бы ноду целиком)
        # Под guard (NOTRACK на 443) ct не видит соединений: conn443 (ct count) не действует, а SYN-rate
        # считается по флагу SYN, не по ct state new — SYN-флуд закрывает guard (rr guard on).
        tcp dport 443 meta nfproto ipv4 ct state new \\
            add @conn443_4 { ip saddr ct count over $CONN_LIMIT } counter drop
        tcp dport 443 meta nfproto ipv6 ct state new \\
            add @conn443_6 { $K6 ct count over $CONN_LIMIT } counter drop
        tcp dport 443 meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn \\
            update @syn443_4 { ip saddr limit rate over ${SYN_RATE}/second burst $((SYN_RATE*2)) packets } counter drop
        tcp dport 443 meta nfproto ipv6 tcp flags & (fin|syn|rst|ack) == syn \\
            update @syn443_6 { $K6 limit rate over ${SYN_RATE}/second burst $((SYN_RATE*2)) packets } counter drop
        tcp dport 443 accept$udp_rules

        # 80 — ACME HTTP-01 / редирект на https
        tcp dport 80 accept
$panel_rules$bridge_rules
        # остальное — в лог и drop
        limit rate 5/minute log prefix "node_protect drop: " level info
        counter drop
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        # бан и для трафика в docker-bridge (после DNAT он идёт сюда, а не в input)
        ip saddr @banned4 counter drop
        ip6 saddr @banned6 counter drop
EOF
    if [ "$ROLE" != balancer ]; then
        cat <<EOF
        # Если remnanode крутится в docker BRIDGE-сети (порт опубликован через -p),
        # трафик к нему проходит DNAT и попадает сюда, а НЕ в input — правило
        # NODE_PORT выше его не видит. Тогда раскомментируй (фильтр по исходному dport):
        # ct original proto-dst $node_port ip saddr != @panel_ip ct state new drop
        # Для штатного remnanode с network_mode: host это не нужно — работает input.
EOF
    fi
    cat <<EOF
    }
    chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
    } > "$out/firewall.nft"
}

_gen_ufw() {
    local out=$1 ssh_port=$2 ssh_ip=$3 panel=$4 node_port=$5 n udp="" bridge="" ssh panel_line=""
    [ "$HY2" = y ] && udp="ufw allow 443/udp comment 'HY2/QUIC'"
    if [ "$ssh_ip" = any ]; then
        ssh="ufw allow $ssh_port/tcp comment 'SSH (с любого адреса — брут режет CrowdSec)'"
    else
        ssh="ufw allow from $ssh_ip to any port $ssh_port proto tcp comment 'SSH (только $ssh_ip)'"
    fi
    [ "$ROLE" != balancer ] \
        && panel_line="ufw allow from $panel to any port $node_port proto tcp comment 'Remnawave control-API (панель)'"
    if [ -n "$BRIDGE_PORT" ]; then
        bridge="# порт мостов/балансеров $BRIDGE_PORT — только пул (в ufw правится руками: ufw allow from <IP> to any port $BRIDGE_PORT proto tcp)"
        for n in $BRIDGE_NETS; do
            bridge="$bridge
ufw allow from $n to any port $BRIDGE_PORT proto tcp comment 'мост/балансер'"
        done
    fi
    cat > "$out/firewall-ufw.sh" <<EOF
#!/usr/bin/env bash
# node-diagnostic: firewall через ufw (проще nft, но без per-IP rate-limit — trusted здесь не нужен).
# Применить:  sudo bash $out/firewall-ufw.sh
set -e
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
$ssh
ufw allow 443/tcp comment '$([ "$ROLE" = balancer ] && echo "балансер (SNI → ноды)" || echo "VLESS/Reality")'
$udp
ufw allow 80/tcp comment 'ACME / редирект'
$panel_line
$bridge
# ВАЖНО: НЕ добавляй «ufw limit $ssh_port/tcp» поверх правила по IP — limit в ufw это ALLOW
# отовсюду (с рейт-лимитом): такое правило открыло бы SSH всему интернету и обесценило
# ограничение по IP выше. Анти-брут делает CrowdSec (node-diagnostic.sh install crowdsec).
ufw --force enable
ufw status verbose
EOF
    chmod +x "$out/firewall-ufw.sh" 2>/dev/null || true
}

_gen_sshd() {
    local out=$1 has_key="нет"
    # проверим, есть ли вообще ключи (иначе key-only лок-аут)
    # ecdsa-ключи в authorized_keys называются ecdsa-sha2-nistpN (не «ssh-ecdsa»),
    # FIDO-ключи — sk-…: старый регекс их не видел и зря пугал лок-аутом
    if grep -rqsE '(ssh-(rsa|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-(ssh-ed25519|ecdsa-sha2))' \
        /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null; then
        has_key="да"
    fi
    cat > "$out/sshd-hardening.conf" <<EOF
# node-diagnostic: SSH-хардненинг (drop-in). Обнаружены authorized_keys: $has_key
# ОПАСНО: без рабочего ключа PasswordAuthentication no = лок-аут. Проверь вход по ключу ПЕРЕД применением!
# Скопировать: sudo cp $out/sshd-hardening.conf /etc/ssh/sshd_config.d/99-node-diagnostic.conf
#   sudo sshd -t && sudo systemctl reload ssh   # sshd -t обязателен, чтобы не убить демон опечаткой
PasswordAuthentication no
PermitRootLogin prohibit-password
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
MaxAuthTries 3
LoginGraceTime 20
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
    [ "$has_key" = "нет" ] && msg_warn "authorized_keys не найдены — НЕ применяй sshd-hardening.conf, иначе лок-аут"
}

_gen_apply() {
    local out=$1 ssh_port=$2 ssh_ip=$3 via_nb=$4 nb_addr=$5 nd ssh_note nb_ip nb_net before portmap
    nd="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)/node-diagnostic.sh"
    nb_ip="${nb_addr%/*}"; nb_net=$(ipv4_net "$nb_addr" 2>/dev/null)
    if [ "$ROLE" = balancer ]; then
        before="ПЕРЕД ВСЕМ: убедись, что вместо <YOUR_SSH_IP> подставлен твой SSH-IP (если он в правилах).
  Файлы: firewall.nft / firewall-ufw.sh."
        portmap="Карта портов балансера: 443 (SNI → upstream'ы нод), 80 (редирект на https), SSH.
Порт мостов, NODE_PORT и UDP здесь не нужны. На нодах за балансером: rr protect bridge add <IP балансера>."
    else
        before="ПЕРЕД ВСЕМ: убедись, что в правилах подставлены реальные значения —
  IP панели вместо <PANEL_IP>, NODE_PORT вместо <NODE_PORT>, твой SSH-IP вместо <YOUR_SSH_IP>.
  Файлы: firewall.nft / firewall-ufw.sh."
        portmap="Карта портов Remnawave-ноды: 443 (вход), 80 (ACME), NODE_PORT (панель->нода, только IP панели),
61000/localhost и Caddy :9443/localhost наружу НЕ открываются.
⚠ remnanode в docker BRIDGE (порт через -p): фильтр NODE_PORT в input его не видит
  (трафик идёт через forward после DNAT) — раскомментируй правило в chain forward
  файла firewall.nft. Штатный remnanode с network_mode: host — ничего не нужно."
    fi
    if [ "$ssh_ip" = any ]; then
        ssh_note="⚠ SSH открыт с ЛЮБОГО адреса (protect --ssh-from any): лок-аута по смене IP нет, но порт виден
  всему интернету. Защита — rate-limit $SSH_RATE соединений/мин на IP (v6 — на /64) в firewall.nft,
  CrowdSec (шаг 2) и вход только по ключу (шаг 3) — оба шага здесь обязательны.
  Вернуть ограничение по IP: protect --ssh-from <IP|CIDR>."
    elif [ "$via_nb" = "1" ]; then
        ssh_note="⚠ SSH открыт ТОЛЬКО из NetBird «${ssh_ip}» — с публичного IP вход закрыт.
  Заходи по NetBird-IP ноды: ssh root@${nb_ip:-<NETBIRD_IP>}  (кому из пиров можно — решают ACL NetBird).
  Упадёт NetBird на ноде (демон, management, смена сети) — вход только через VNC/serial-
  консоль хостера. До применения:
    · убедись, что VNC-консоль хостера реально работает;
    · применяй firewall из сессии, открытой ЧЕРЕЗ NetBird (иначе текущая оборвётся);
    · сменилась сеть NetBird — перегенерируй: protect --ssh-from <новая подсеть>."
    else
        ssh_note="⚠ SSH привязан к IP «${ssh_ip}». Если это ДОМАШНИЙ/ДИНАМИЧЕСКИЙ IP — после его
  смены провайдером SSH отрежет наглухо (вход только через VNC/serial-консоль хостера).
  Варианты до применения:
    · вписать вместо одного IP подсеть провайдера (whois $ssh_ip → route/CIDR),
      в firewall.nft: «ip saddr 203.0.113.0/24», в ufw: «from 203.0.113.0/24»;
    · или убрать ограничение по IP и оставить только rate-limit + CrowdSec:
      protect --ssh-from any (перегенерирует nft и ufw);
    · ходишь через NetBird — пусти SSH из его подсети: protect --ssh-from ${nb_net:-100.x.0.0/16};
    · применяешь как есть — убедись, что VNC-консоль хостера реально работает."
    fi
    cat > "$out/APPLY.txt" <<EOF
================  node-diagnostic · применение защиты  ================
Всё сгенерировано, НО НЕ ПРИМЕНЕНО. Порядок безопасного наката на удалённой ноде.

$before

$ssh_note

--- 1. FIREWALL (самое опасное — можно отрезать SSH) ---
Способ А (nftables, с per-IP rate-limit — рекомендуется):
  # СТРАХОВКА от лок-аута: авто-откат через 300с, если не подтвердишь
  sudo systemd-run --on-active=300 --unit=fw-rollback nft delete table inet node_protect
  sudo nft -f $out/firewall.nft
  # проверь, что SSH-сессия жива и открывается НОВАЯ сессия во втором окне.
  # если ок — отменяем откат:
  sudo systemctl stop fw-rollback.timer 2>/dev/null; sudo systemctl reset-failed fw-rollback 2>/dev/null
  # сделать постоянным — ТОЛЬКО свою таблицу (дамп всего ruleset утащил бы таблицы Docker и
  # CrowdSec: после ребута дубли docker-правил и протухшие баны). protect trust|bridge обновляют этот файл сами:
  sudo install -Dm600 $out/firewall.nft $PROTECT_PERSIST
  grep -q 'nftables.d' /etc/nftables.conf || echo 'include "$(dirname "$PROTECT_PERSIST")/*.nft"' | sudo tee -a /etc/nftables.conf
  sudo systemctl enable nftables

Способ Б (ufw, проще):
  sudo bash $out/firewall-ufw.sh
  # держи ВТОРУЮ SSH-сессию открытой на время применения.

--- 2. CrowdSec (анти-брут SSH + community-блоклист) ---
  sudo bash $nd install crowdsec      # или меню [7] → [5]
  # движок + nftables-bouncer; подсеть NetBird, твой SSH-IP и IP панели — в allowlist (не банятся никогда).
  # Таблицы bouncer'а (crowdsec/crowdsec6) отрабатывают раньше node_protect — уживаются.
  sudo cscli decisions list           # кто забанен

--- 3. SSH-хардненинг (только если вход по КЛЮЧУ уже работает!) ---
  # проверь из второго окна: ssh -i ключ user@нода  — заходит без пароля?
  sudo cp $out/sshd-hardening.conf /etc/ssh/sshd_config.d/99-node-diagnostic.conf
  sudo sshd -t && sudo systemctl reload ssh
  # НЕ закрывай текущую сессию, пока не проверил новый вход.

--- ОТКАТ ---
  firewall nft:  sudo nft delete table inet node_protect
  firewall ufw:  sudo ufw disable
  CrowdSec:      sudo apt purge crowdsec crowdsec-firewall-bouncer-nftables   # dnf remove … на RHEL
  sshd:          sudo rm /etc/ssh/sshd_config.d/99-node-diagnostic.conf && sudo systemctl reload ssh

--- TRUSTED / МОСТЫ / БАЛАНСЕРЫ (правятся на лету, без перегенерации руками) ---
  trusted4/6 — на 443 мимо per-IP лимитов ($CONN_LIMIT соединений, $SYN_RATE SYN/с на IP): CGNAT-шлюзы,
  мосты, которые ходят на 443. Один такой IP несёт всех своих клиентов и упёрся бы в лимиты.
    sudo bash $nd protect trust add <IP|CIDR>...      # v4 и v6
    sudo bash $nd protect trust del <IP|CIDR>...
    sudo bash $nd protect trust list                  # conf + живой set + счётчики
  Порт мостов/балансеров (xray + proxy-protocol, напр. 8443) — открыт ТОЛЬКО пулу bridge4/6:
    sudo bash $nd protect bridge port 8443            # открыть порт (off — закрыть, пул сохранится)
    sudo bash $nd protect bridge add <IP_балансера>   # пул: балансеры (rr balancer) и мосты
    sudo bash $nd protect bridge del <IP>
    sudo bash $nd protect bridge list
  Команды правят $out/protect.conf, перегенерируют firewall.nft, применяют изменение к живой таблице
  node_protect (если она загружена) и обновляют $PROTECT_PERSIST (если он есть). SSH не трогают.
  HY2 сейчас: $([ "$HY2" = y ] && echo "да — 443/udp открыт" || echo "нет — 443/udp закрыт"); поменять: protect --hy2 y|n (остальное возьмётся из protect.conf).
  Включён guard --geo ru, а trusted не из России — тот же IP в rr guard allow <IP> (порт мостов guard не фильтрует).
  Порт мостов идёт через conntrack: под пиковую нагрузку через балансер nf_conntrack_max должен быть
  с запасом — его масштабирует rr optimize, заполнение показывает rr diagnose (чек Conntrack).
  Широкие префиксы: /0 не принимается вовсе, короче /8 (v4) и /32 (v6) — только с подтверждением.

⚠ guard (rr guard on) ставит NOTRACK на 443/80: conn443 (ct count) при включённом guard не действует,
  SYN-флуд закрывает guard; SYN-rate (syn443) считается по флагу SYN и работает и под NOTRACK.
  HY2 под guard: лимит udp443 считает только QUIC Long Header (рукопожатие) — поток данных не душится.
  С обфускацией Salamander заголовки случайны: под guard подними UDP_RATE при генерации.
Счётчики лимитов (кого режут): sudo nft list chain inet node_protect input | grep -E 'counter packets [1-9]'

$portmap
======================================================================
EOF
}

# ── живые изменения: protect trust|bridge ───────────────────────────
# Правят protect.conf, перегенерируют артефакты и вносят дельту в живую таблицу node_protect одной
# транзакцией nft -f -. Трогают только accept-правила trusted/bridge и элементы set'ов — SSH вне зоны.
_PNL=$'\n'

_live_ok()    { have nft && need_root && nft list table inet node_protect >/dev/null 2>&1; }
_live_chain() { nft -a list chain inet node_protect input 2>/dev/null; }
# _live_handle REGEX → handle первого правила input, чья строка матчит REGEX (grep -E)
_live_handle() { _live_chain | grep -E "$1" | head -n1 | sed -n 's/.*# handle \([0-9][0-9]*\)$/\1/p'; }
# порт из правил nd:bridge живой таблицы (пусто — правил нет)
_live_bridge_port() { _live_chain | grep '"nd:bridge"' | grep -oE 'tcp dport [0-9]+' | head -n1 | tr -cd '0-9'; }

# _live_rules ЯКОРЬ_REGEX ПРАВИЛО… → строки батча: insert перед якорем (порядок сохраняется), без якоря — add
_live_rules() {
    local h r; h=$(_live_handle "$1"); shift
    for r in "$@"; do
        if [ -n "$h" ]; then printf 'insert rule inet node_protect input handle %s %s\n' "$h" "$r"
        else printf 'add rule inet node_protect input %s\n' "$r"; fi
    done
}

# _live_apply trust|bridge add|del|port "NETS" — дельта в живой таблице (нет таблицы/root/nft — пропуск)
_live_apply() {
    local kind=$1 act=$2 nets=$3 s4 s6 batch="" cur h e n
    if ! _live_ok; then
        if have nft && need_root; then msg_info "живой таблицы node_protect нет — изменение войдёт в firewall.nft при nft -f"
        else msg_info "без root/nft живой firewall не трогаю — изменение войдёт в firewall.nft"; fi
        return 0
    fi
    if [ "$kind" = trust ]; then s4=trusted4; s6=trusted6; else s4=bridge4; s6=bridge6; fi
    # таблица от старой версии protect: set'ов и правил нет — досоздаём
    nft list set inet node_protect "$s4" >/dev/null 2>&1 \
        || batch="${batch}add set inet node_protect $s4 { type ipv4_addr; flags interval; auto-merge; }$_PNL"
    nft list set inet node_protect "$s6" >/dev/null 2>&1 \
        || batch="${batch}add set inet node_protect $s6 { type ipv6_addr; flags interval; auto-merge; }$_PNL"
    if [ "$kind" = trust ] && ! _live_chain | grep -q '"nd:trusted"'; then
        # до лимитов 443 (первое правило с tcp dport 443); udp — только если HY2 в живой таблице открыт
        batch="$batch$(_live_rules 'tcp dport 443' \
            'ip saddr @trusted4 tcp dport 443 counter accept comment "nd:trusted"' \
            'ip6 saddr @trusted6 tcp dport 443 counter accept comment "nd:trusted"')$_PNL"
        _live_chain | grep -q 'udp dport 443' && batch="$batch$(_live_rules 'tcp dport 443' \
            'ip saddr @trusted4 udp dport 443 counter accept comment "nd:trusted"' \
            'ip6 saddr @trusted6 udp dport 443 counter accept comment "nd:trusted"')$_PNL"
    fi
    if [ "$kind" = bridge ]; then
        cur=$(_live_bridge_port)
        if [ "$cur" != "$BRIDGE_PORT" ]; then
            for h in $(_live_chain | grep '"nd:bridge"' | sed -n 's/.*# handle \([0-9][0-9]*\)$/\1/p'); do
                batch="${batch}delete rule inet node_protect input handle $h$_PNL"
            done
            # перед финальным log/drop (без него — перед counter drop, иначе в конец)
            [ -n "$BRIDGE_PORT" ] && batch="$batch$(
                if _live_chain | grep -q 'node_protect drop'; then a='node_protect drop'
                else a='^[[:space:]]*counter packets [0-9]+ bytes [0-9]+ drop'; fi
                _live_rules "$a" \
                    "tcp dport $BRIDGE_PORT ip saddr @bridge4 counter accept comment \"nd:bridge\"" \
                    "tcp dport $BRIDGE_PORT ip6 saddr @bridge6 counter accept comment \"nd:bridge\"")$_PNL"
        fi
    fi
    if [ "$act" = add ]; then
        e=$(_nets_fam "$nets" 4); [ -n "$e" ] && batch="${batch}add element inet node_protect $s4 { $e }$_PNL"
        e=$(_nets_fam "$nets" 6); [ -n "$e" ] && batch="${batch}add element inet node_protect $s6 { $e }$_PNL"
    fi
    if [ -n "${batch//$_PNL/}" ]; then
        if ! printf '%s' "$batch" | nft -f - 2>"$PROTECT_LIVE_ERR"; then
            msg_err "nft не принял изменение (живая таблица не тронута): $(tail -n 1 "$PROTECT_LIVE_ERR")"
            return 1
        fi
    fi
    # удаление — поштучно: отсутствующий элемент (ENOENT) уронил бы весь батч
    if [ "$act" = del ]; then
        for n in $nets; do
            case "$n" in *:*) e=$s6 ;; *) e=$s4 ;; esac
            nft delete element inet node_protect "$e" "{ $n }" 2>/dev/null \
                || { msg_warn "$n в живом $e не найден (или слит auto-merge с соседней подсетью) — проверь: protect $kind list"; }
        done
    fi
    msg_ok "живая таблица node_protect обновлена"
    return 0
}

_live_list() {   # trust|bridge
    local kind=$1 s c
    if [ "$kind" = trust ]; then
        echo -e "    ${DIM}trusted в protect.conf:${NC} ${TRUST_NETS:-—}"; c='"nd:trusted"'
    else
        echo -e "    ${DIM}порт мостов в protect.conf:${NC} ${BRIDGE_PORT:-выключен}"
        echo -e "    ${DIM}пул в protect.conf:${NC} ${BRIDGE_NETS:-—}"; c='"nd:bridge"'
    fi
    _live_ok || { msg_info "живой таблицы node_protect нет (или нет root/nft)"; return 0; }
    for s in ${kind/trust/trusted}4 ${kind/trust/trusted}6; do
        echo -e "    ${DIM}живой $s:${NC} $(nft list set inet node_protect "$s" 2>/dev/null \
            | tr -d '\n' | sed -n 's/.*elements = { *\([^}]*\)}.*/\1/p' | tr -s ' \t' ' ' | sed 's/ *$//')"
    done
    _live_chain | grep "$c" | sed -e 's/ *# handle [0-9]*$//' -e 's/^[[:space:]]*/      /'
    _live_chain | grep -q "$c" || msg_info "правил $c в живой таблице нет"
}

# protect trust|bridge СУБКОМАНДА [АРГ…] (вызывается из protect_main, --out уже разобран)
protect_live() {
    local kind=$1 act=${2:-list} out k v n c nets="" var ssh_port ssh_conf gen_ok=0
    shift; [ $# -gt 0 ] && shift
    out=$(protect_out_dir)
    PROTECT_LIVE_ERR="${TMPDIR:-/tmp}/nd-protect-live.$$"
    # только ключи, реально записанные в conf: иначе пустой BAN_NETS из «нет conf» выключил бы бан
    protect_conf_load "$out" || true
    for k in $PROTECT_CONF_KEYS; do
        case "$CONF_PRESENT" in *" $k "*) v=CONF_$k; printf -v "$k" '%s' "${!v}" ;; esac
    done
    [ "$BRIDGE_PORT" = off ] && BRIDGE_PORT=""
    [ "$kind" = bridge ] && [ "$ROLE" = balancer ] && [ "$act" != list ] \
        && die "protect bridge: это балансер (ROLE=balancer в protect.conf) — порт мостов открывается на нодах"
    ssh_conf=$CONF_SSH_FROM
    if [ "$kind" = trust ]; then var=TRUST_NETS; else var=BRIDGE_NETS; fi
    case "$act" in
        add|del)
            [ $# -gt 0 ] || die "protect $kind $act: укажи IP или подсеть (v4/v6), можно несколько"
            for n in "$@"; do
                c=$(net_norm "$n") || die "protect $kind: «${n}» не IP/подсеть"
                if [ "$act" = add ]; then _net_wide_ok "$c" "protect $kind add" || die "protect $kind: $c не принят"; fi
                nets=$(_nets_add "$nets" "$c")
            done
            # shellcheck disable=SC2086
            if [ "$act" = add ]; then printf -v "$var" '%s' "$(_nets_add "${!var}" $nets)"
            else printf -v "$var" '%s' "$(_nets_del "${!var}" $nets)"; fi ;;
        port)
            [ "$kind" = bridge ] || die "protect trust: port есть только у bridge"
            [ $# -gt 0 ] || die "protect bridge port <ПОРТ>|off"
            if [ "$1" = off ]; then BRIDGE_PORT=""
            else
                [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ] || die "protect bridge port: число 1-65535 или off"
                ssh_port=$(detect_ssh_port)
                case "$1" in 443|80|"$ssh_port"|"$NODE_PORT")
                    die "protect bridge port: $1 занят под 443/80/SSH/NODE_PORT — выбери другой (напр. 8443)" ;;
                esac
                BRIDGE_PORT=$1
            fi ;;
        list) _live_list "$kind"; return 0 ;;
        *) die "protect $kind: add|del <IP|CIDR>…, list$([ "$kind" = bridge ] && echo ", port <ПОРТ>|off")" ;;
    esac

    protect_conf_save "$out" || die "не записал $out/protect.conf"
    case "$act" in
        port) msg_ok "порт мостов: ${BRIDGE_PORT:-выключен} ${DIM}(protect.conf)${NC}" ;;
        *)    msg_ok "$kind $act: $nets ${DIM}(protect.conf)${NC}" ;;
    esac
    [ "$kind" = bridge ] && [ -z "$BRIDGE_PORT" ] && [ "$act" = add ] \
        && msg_warn "порт мостов не задан — пул ждёт его: protect bridge port 8443"

    # артефакты: пересобираем из protect.conf (все параметры уже в нём)
    if [ "$GENERATED" = 1 ]; then
        if ( protect_generate ) > "$out/.regen.log" 2>&1; then
            gen_ok=1; msg_ok "firewall.nft перегенерирован: $out/firewall.nft"
        else
            msg_warn "перегенерация не удалась — $out/.regen.log"
        fi
    else
        msg_warn "в $out нет прошлой генерации — firewall.nft не обновлён; запусти protect (адреса возьмутся из protect.conf)"
    fi

    _live_apply "$kind" "$act" "$nets" || { rm -f "$PROTECT_LIVE_ERR"; return 1; }
    rm -f "$PROTECT_LIVE_ERR"

    # автозагрузка: обновляем, только если её уже завели и в правилах нет плейсхолдеров
    if [ -f "$PROTECT_PERSIST" ]; then
        if [ "$gen_ok" != 1 ]; then
            msg_warn "$PROTECT_PERSIST не обновлён (нет свежего firewall.nft) — после ребута изменение пропадёт"
        elif [ -z "$ssh_conf" ]; then
            # SSH-источник не из conf: перегенерация взяла бы IP этой сессии и затёрла ручную правку
            msg_warn "$PROTECT_PERSIST не обновлён: в protect.conf нет SSH_FROM — перегенерируй protect с --ssh-from, затем install -m600 firewall.nft $PROTECT_PERSIST"
        elif grep -qE '<(PANEL_IP|NODE_PORT|YOUR_SSH_IP)>' "$out/firewall.nft"; then
            msg_warn "$PROTECT_PERSIST не обновлён: в firewall.nft плейсхолдеры — перегенерируй protect с --panel-ip/--node-port/--ssh-from"
        elif install -m600 "$out/firewall.nft" "$PROTECT_PERSIST" 2>/dev/null; then
            msg_ok "автозагрузка обновлена: $PROTECT_PERSIST"
        else
            msg_warn "не записал $PROTECT_PERSIST"
        fi
    fi
    return 0
}

protect_main() {
    local a n c want=0 rest=()
    # trust|bridge — живые команды; --out разрешён в любом месте
    case "${1:-}" in
        trust|bridge)
            for a in "$@"; do
                if [ "$want" = 1 ]; then PROTECT_OUT=$a; want=0; continue; fi
                [ "$a" = --out ] && { want=1; continue; }
                rest+=("$a")
            done
            protect_live "${rest[@]}"
            return $? ;;
    esac
    while [ $# -gt 0 ]; do
        case "$1" in
            --panel-ip)  PANEL_IP="$2"; shift ;;
            --node-port) NODE_PORT="$2"; shift ;;
            --out)       PROTECT_OUT="$2"; shift ;;
            --ssh-from)  SSH_FROM="$2"; shift ;;
            --hy2)       HY2=$(_yn "${2:-}") || die "protect: --hy2 ждёт y или n, получено: ${2:-}"; shift ;;
            --role)      ROLE=${2:-}; case "$ROLE" in node|balancer) ;; *) die "protect: --role ждёт node или balancer, получено: $ROLE" ;; esac; shift ;;
            --trust|--bridge-from)
                c=$(net_norm "${2:-}") || die "protect: $1 ждёт IP или подсеть (v4/v6), получено: ${2:-}"
                _net_wide_ok "$c" "protect $1" || die "protect: $1 $c не принят"
                if [ "$1" = --trust ]; then TRUST_NETS="$TRUST_NETS $c"; else BRIDGE_NETS="$BRIDGE_NETS $c"; fi
                shift ;;
            --bridge-port)
                n=${2:-}
                [ "$n" = off ] || { [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le 65535 ]; } \
                    || die "protect: --bridge-port ждёт порт 1-65535 или off, получено: $n"
                BRIDGE_PORT=$n; shift ;;
            *) die "protect: неизвестный аргумент $1" ;;
        esac
        shift
    done
    # any/all/0.0.0.0/0/::/0 — SSH без ограничения по IP (только rate-limit)
    case "$SSH_FROM" in any|all|ANY|0.0.0.0/0|::/0) SSH_FROM=any ;; esac
    # IPv4[/N] строго; IPv6 — грубо (уходит в ip6 saddr, nft -c отвергнет мусор)
    if [ -n "$SSH_FROM" ] && [ "$SSH_FROM" != any ] && ! ipv4_net "$SSH_FROM" >/dev/null && [[ ! "$SSH_FROM" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ || "$SSH_FROM" != *:* ]]; then
        die "protect: --ssh-from ждёт IP или подсеть (напр. 100.92.0.0/16), получено: $SSH_FROM"
    fi
    protect_generate
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    protect_main "$@"
fi
