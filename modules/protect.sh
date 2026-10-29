#!/usr/bin/env bash
# modules/protect.sh — защита ноды под стек Remnawave. РЕЖИМ: только генерация.
# Пишет готовые артефакты (nftables/ufw firewall, SSH-хардненинг) в каталог
# и печатает пошаговую инструкцию по применению. САМ НИЧЕГО НЕ ПРИМЕНЯЕТ — фаервол на
# удалённой ноде может отрезать SSH, поэтому применяешь руками, сверив IP панели/SSH.
# Анти-брут SSH — CrowdSec, ставится отдельно: node-diagnostic.sh install crowdsec.
#
# Standalone:  sudo bash modules/protect.sh [--panel-ip X.X.X.X] [--node-port N] [--ssh-from IP|CIDR] [--out DIR]
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

PROTECT_OUT="${PROTECT_OUT:-}"
PANEL_IP="${PANEL_IP:-}"
NODE_PORT="${NODE_PORT:-}"
SSH_FROM="${SSH_FROM:-}"      # откуда пускать SSH: IP или CIDR (пусто — авто: NetBird / твой IP)

# per-IP лимиты в nft (из практики node-accelerator)
CONN_LIMIT="${CONN_LIMIT:-2048}"
SYN_RATE="${SYN_RATE:-200}"
UDP_RATE="${UDP_RATE:-200}"
ICMP_RATE="${ICMP_RATE:-10}"
SSH_RATE="${SSH_RATE:-6}"     # соединений/мин на IP

# перманентный бан подсетей (set banned4, drop раньше любых accept). BAN_NETS="" — без бана
BAN_NETS="${BAN_NETS-185.224.228.0/22 195.209.120.0/22 212.192.156.0/23 212.192.158.0/24 194.165.22.0/23}"

protect_generate() {
    local ssh_port ssh_ip ssh_src nb_addr nb="" out
    ssh_port=$(detect_ssh_port)
    ssh_ip=$(ssh_client_ip)
    nb_addr=$(netbird_addr) && nb=$(ipv4_net "$nb_addr")
    # откуда пускать SSH: явный --ssh-from → вся подсеть NetBird, если текущая сессия
    # пришла через неё (админ ходит по NetBird) → IP текущей сессии
    if [ -n "$SSH_FROM" ]; then
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
    [ -z "$NODE_PORT" ] && NODE_PORT=$(detect_node_port || echo "")
    if need_root; then out="${PROTECT_OUT:-/root/node-diagnostic-protect}"; else out="${PROTECT_OUT:-$PWD/node-diagnostic-protect}"; fi
    mkdir -p "$out" || die "не создал каталог $out"

    local ph_panel="$PANEL_IP" ph_ssh="$ssh_src"
    [ -z "$ph_panel" ] && ph_panel="<PANEL_IP>"
    [ -z "$ph_ssh" ]   && ph_ssh="<YOUR_SSH_IP>"

    echo
    ui_head "Генерация защиты ноды" "Remnawave · только генерация файлов"
    echo -e "    ${DIM}SSH-порт:${NC} $ssh_port   ${DIM}SSH разрешён с:${NC} $ph_ssh"
    [ -n "$nb" ] && echo -e "    ${DIM}NetBird:${NC} ${nb_addr%/*} ${DIM}(подсеть $nb)${NC}"
    echo -e "    ${DIM}NODE_PORT (control-API):${NC} ${NODE_PORT:-<не найден, укажи --node-port>}"
    echo -e "    ${DIM}IP панели:${NC} $ph_panel"
    echo -e "    ${DIM}каталог:${NC} $out"
    echo
    [ "$ph_panel" = "<PANEL_IP>" ] && msg_warn "IP панели не задан — в правилах плейсхолдер <PANEL_IP>, подставь перед применением (--panel-ip)"
    [ -z "$NODE_PORT" ] && msg_warn "NODE_PORT не найден — плейсхолдер <NODE_PORT>, подставь (--node-port)"
    # SSH-источник внутри NetBird (пир/подсеть) или накрывает её (100.64.0.0/10)
    local via_nb=0
    if [ -n "$nb" ] && { ip_in_cidr "${ph_ssh%/*}" "$nb" || ip_in_cidr "${nb_addr%/*}" "$ph_ssh"; }; then
        via_nb=1
    fi
    if [ "$ph_ssh" = "<YOUR_SSH_IP>" ]; then
        msg_warn "SSH-IP не определён (не по SSH?) — подставь свой IP вручную или задай --ssh-from"
    elif [ "$via_nb" = "1" ]; then
        msg_warn "SSH будет открыт ТОЛЬКО из NetBird ($ph_ssh) — упадёт NetBird на ноде, вход останется только через VNC-консоль хостера"
    else
        msg_warn "SSH будет открыт ТОЛЬКО с $ph_ssh — если это домашний/динамический IP, после его смены SSH отрежет (детали в APPLY.txt)"
        [ -n "$nb" ] && msg_info "SSH только через NetBird: перегенерируй с --ssh-from $nb (и зайди через NetBird)"
    fi
    # текущая сессия вне разрешённого источника — firewall её оборвёт (IPv6 не сверяем)
    case "$ssh_ip$ph_ssh" in *:*|*"<"*) ;; *)
        [ -n "$ssh_ip" ] && ! ip_in_cidr "$ssh_ip" "$ph_ssh" \
            && msg_warn "текущая сессия ($ssh_ip) не входит в $ph_ssh — firewall её оборвёт: перед применением зайди через NetBird"
    esac
    # бан-подсети: хост-биты обнуляются, не-IPv4 пропускается; свой SSH/панель в бане = лок-аут
    local n bn ban=""
    for n in $BAN_NETS; do
        bn=$(ipv4_net "$n") || { msg_warn "BAN_NETS: «$n» не IPv4-подсеть — пропускаю"; continue; }
        ban="$ban${ban:+, }$bn"
        ip_in_cidr "${ph_ssh%/*}" "$bn" && msg_warn "SSH-источник $ph_ssh в забаненной подсети $bn — firewall отрежет SSH"
        ip_in_cidr "$ph_panel" "$bn" && msg_warn "IP панели $ph_panel в забаненной подсети $bn — нода потеряет панель"
    done

    _gen_nft   "$out" "$ssh_port" "$ph_ssh" "$ph_panel" "${NODE_PORT:-<NODE_PORT>}" "$ban"
    _gen_ufw   "$out" "$ssh_port" "$ph_ssh" "$ph_panel" "${NODE_PORT:-<NODE_PORT>}"
    _gen_sshd  "$out"
    _gen_apply "$out" "$ssh_port" "$ph_ssh" "$via_nb" "$nb_addr"

    echo
    echo -e "  ${G}${BOLD}✓ Сгенерировано в $out${NC}"
    ls -1 "$out" | sed 's/^/      /'
    echo
    echo -e "  ${Y}${BOLD}Ничего не применено.${NC} ${DIM}Открой ${BOLD}$out/APPLY.txt${NC}${DIM} — там пошагово, с защитой от лок-аута.${NC}"
    record_fix "protect artifacts generated -> $out"
}

_gen_nft() {
    local out=$1 ssh_port=$2 ssh_ip=$3 panel=$4 node_port=$5 ban=$6

    # семейство адреса → правильный синтаксис saddr (dual-stack: v6 больше не игнорируется)
    local ssh_saddr="ip saddr" panel_type="ipv4_addr" panel_saddr="ip saddr"
    case "$ssh_ip" in *:*) ssh_saddr="ip6 saddr" ;; esac
    case "$panel"  in *:*) panel_type="ipv6_addr"; panel_saddr="ip6 saddr" ;; esac
    # пустой set валиден, пустой «elements = { }» — нет
    local ban_elems=""
    [ -n "$ban" ] && ban_elems="elements = { $ban }"

    cat > "$out/firewall.nft" <<EOF
#!/usr/sbin/nft -f
# node-diagnostic: firewall для Remnawave-ноды. Своя таблица, ruleset не флашится (уживается с Docker).
# Применить:  sudo nft -f $out/firewall.nft
# Порты: 443 (VLESS/Reality + QUIC/HY2), 80 (ACME/Caddy), NODE_PORT (control-API) — только с IP панели.
# SSH ограничен по семейству твоего адреса ($ssh_saddr), 443 лимитируется и для v4, и для v6.

table inet node_protect
delete table inet node_protect
table inet node_protect {
    set panel_ip {
        type $panel_type
        elements = { $panel }
    }
    # перманентный бан подсетей (BAN_NETS). Добавить на лету: nft add element inet node_protect banned4 { X/N }
    set banned4 {
        type ipv4_addr
        flags interval
        auto-merge
        $ban_elems
    }
    chain input {
        type filter hook input priority 0; policy drop;

        iif "lo" accept
        # бан раньше established — рвёт и уже открытые сессии из этих подсетей
        ip saddr @banned4 counter drop
        ct state established,related accept
        ct state invalid drop

        # ICMP нужен для PMTU — не резать полностью, только флуд (per-IP)
        ip  protocol icmp   meter icmp4 { ip  saddr limit rate over ${ICMP_RATE}/second } drop
        ip6 nexthdr icmpv6  meter icmp6 { ip6 saddr limit rate over ${ICMP_RATE}/second } drop
        ip  protocol icmp   accept
        ip6 nexthdr icmpv6  accept

        # SSH — только с $ssh_ip (IP или подсеть, напр. NetBird) + анти-брут по скорости соединений
        tcp dport $ssh_port $ssh_saddr $ssh_ip ct state new \\
            meter ssh_rate { $ssh_saddr limit rate over ${SSH_RATE}/minute } drop
        tcp dport $ssh_port $ssh_saddr $ssh_ip accept

        # 443 — публичный вход. Per-IP лимит одновременных соединений и SYN-rate.
        # (ct count вне meter считал бы ВСЕ соединения порта разом — душил бы ноду целиком)
        # Отдельные meter'ы для v4 и v6 — key ip saddr не матчит v6-пакеты, они бы обошли лимит.
        tcp dport 443 ip saddr 0.0.0.0/0 ct state new \\
            meter conn443_4 { ip saddr ct count over $CONN_LIMIT } drop
        tcp dport 443 ip6 saddr ::/0 ct state new \\
            meter conn443_6 { ip6 saddr ct count over $CONN_LIMIT } drop
        tcp dport 443 ip saddr 0.0.0.0/0 ct state new \\
            meter syn443_4 { ip saddr limit rate over ${SYN_RATE}/second burst $((SYN_RATE*2)) packets } drop
        tcp dport 443 ip6 saddr ::/0 ct state new \\
            meter syn443_6 { ip6 saddr limit rate over ${SYN_RATE}/second burst $((SYN_RATE*2)) packets } drop
        tcp dport 443 accept
        udp dport 443 ip saddr 0.0.0.0/0 \\
            meter udp443_4 { ip saddr limit rate over ${UDP_RATE}/second } drop
        udp dport 443 ip6 saddr ::/0 \\
            meter udp443_6 { ip6 saddr limit rate over ${UDP_RATE}/second } drop
        udp dport 443 accept

        # 80 — ACME HTTP-01 / редирект (Caddy держит сам)
        tcp dport 80 accept

        # NODE_PORT — канал панель->нода, ТОЛЬКО с IP панели
        tcp dport $node_port $panel_saddr @panel_ip accept

        # остальное — в лог и drop
        limit rate 5/minute log prefix "node_protect drop: " level info
        counter drop
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        # бан и для трафика в docker-bridge (после DNAT он идёт сюда, а не в input)
        ip saddr @banned4 counter drop
        # Если remnanode крутится в docker BRIDGE-сети (порт опубликован через -p),
        # трафик к нему проходит DNAT и попадает сюда, а НЕ в input — правило
        # NODE_PORT выше его не видит. Тогда раскомментируй (фильтр по исходному dport):
        # ct original proto-dst $node_port ip saddr != @panel_ip ct state new drop
        # Для штатного remnanode с network_mode: host это не нужно — работает input.
    }
    chain output  { type filter hook output  priority 0; policy accept; }
}
EOF
}

_gen_ufw() {
    local out=$1 ssh_port=$2 ssh_ip=$3 panel=$4 node_port=$5
    cat > "$out/firewall-ufw.sh" <<EOF
#!/usr/bin/env bash
# node-diagnostic: firewall через ufw (проще nft, но без per-IP rate-limit).
# Применить:  sudo bash $out/firewall-ufw.sh
set -e
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from $ssh_ip to any port $ssh_port proto tcp comment 'SSH (только $ssh_ip)'
ufw allow 443 comment 'VLESS/Reality + QUIC/HY2'
ufw allow 80/tcp comment 'ACME/Caddy'
ufw allow from $panel to any port $node_port proto tcp comment 'Remnawave control-API (панель)'
# ВАЖНО: НЕ добавляй «ufw limit $ssh_port/tcp» — limit в ufw это ALLOW отовсюду
# (с рейт-лимитом): такое правило открыло бы SSH всему интернету и обесценило
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
    local out=$1 ssh_port=$2 ssh_ip=$3 via_nb=$4 nb_addr=$5 nd ssh_note nb_ip nb_net
    nd="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)/node-diagnostic.sh"
    nb_ip="${nb_addr%/*}"; nb_net=$(ipv4_net "$nb_addr" 2>/dev/null)
    if [ "$via_nb" = "1" ]; then
        ssh_note="⚠ SSH открыт ТОЛЬКО из NetBird «$ssh_ip» — с публичного IP вход закрыт.
  Заходи по NetBird-IP ноды: ssh root@${nb_ip:-<NETBIRD_IP>}  (кому из пиров можно — решают ACL NetBird).
  Упадёт NetBird на ноде (демон, management, смена сети) — вход только через VNC/serial-
  консоль хостера. До применения:
    · убедись, что VNC-консоль хостера реально работает;
    · применяй firewall из сессии, открытой ЧЕРЕЗ NetBird (иначе текущая оборвётся);
    · сменилась сеть NetBird — перегенерируй: protect --ssh-from <новая подсеть>."
    else
        ssh_note="⚠ SSH привязан к IP «$ssh_ip». Если это ДОМАШНИЙ/ДИНАМИЧЕСКИЙ IP — после его
  смены провайдером SSH отрежет наглухо (вход только через VNC/serial-консоль хостера).
  Варианты до применения:
    · вписать вместо одного IP подсеть провайдера (whois $ssh_ip → route/CIDR),
      в firewall.nft: «ip saddr 203.0.113.0/24», в ufw: «from 203.0.113.0/24»;
    · или убрать ограничение по IP и оставить только rate-limit + CrowdSec
      (nft: убери «ip saddr …» из SSH-правил; ufw: «ufw limit $ssh_port/tcp»);
    · ходишь через NetBird — пусти SSH из его подсети: protect --ssh-from ${nb_net:-100.x.0.0/16};
    · применяешь как есть — убедись, что VNC-консоль хостера реально работает."
    fi
    cat > "$out/APPLY.txt" <<EOF
================  node-diagnostic · применение защиты  ================
Всё сгенерировано, НО НЕ ПРИМЕНЕНО. Порядок безопасного наката на удалённой ноде.

ПЕРЕД ВСЕМ: убедись, что в правилах подставлены реальные значения —
  IP панели вместо <PANEL_IP>, NODE_PORT вместо <NODE_PORT>, твой SSH-IP вместо <YOUR_SSH_IP>.
  Файлы: firewall.nft / firewall-ufw.sh.

$ssh_note

--- 1. FIREWALL (самое опасное — можно отрезать SSH) ---
Способ А (nftables, с per-IP rate-limit — рекомендуется):
  # СТРАХОВКА от лок-аута: авто-откат через 300с, если не подтвердишь
  sudo systemd-run --on-active=300 --unit=fw-rollback nft delete table inet node_protect
  sudo nft -f $out/firewall.nft
  # проверь, что SSH-сессия жива и открывается НОВАЯ сессия во втором окне.
  # если ок — отменяем откат:
  sudo systemctl stop fw-rollback.timer 2>/dev/null; sudo systemctl reset-failed fw-rollback 2>/dev/null
  # сделать постоянным:
  sudo nft list ruleset > /etc/nftables.conf && sudo systemctl enable nftables

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

Карта портов Remnawave-ноды: 443 (вход), 80 (ACME), NODE_PORT (панель->нода, только IP панели),
61000/localhost и Caddy :9443/localhost наружу НЕ открываются.
⚠ remnanode в docker BRIDGE (порт через -p): фильтр NODE_PORT в input его не видит
  (трафик идёт через forward после DNAT) — раскомментируй правило в chain forward
  файла firewall.nft. Штатный remnanode с network_mode: host — ничего не нужно.
======================================================================
EOF
}

protect_main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --panel-ip)  PANEL_IP="$2"; shift ;;
            --node-port) NODE_PORT="$2"; shift ;;
            --out)       PROTECT_OUT="$2"; shift ;;
            --ssh-from)  SSH_FROM="$2"; shift ;;
            *) die "protect: неизвестный аргумент $1" ;;
        esac
        shift
    done
    # IPv4[/N] строго; IPv6 — грубо (уходит в ip6 saddr, nft -c отвергнет мусор)
    if [ -n "$SSH_FROM" ] && ! ipv4_net "$SSH_FROM" >/dev/null && [[ ! "$SSH_FROM" =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ || "$SSH_FROM" != *:* ]]; then
        die "protect: --ssh-from ждёт IP или подсеть (напр. 100.92.0.0/16), получено: $SSH_FROM"
    fi
    protect_generate
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    protect_main "$@"
fi
