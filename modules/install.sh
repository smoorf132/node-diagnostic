#!/usr/bin/env bash
# modules/install.sh — установка компонентов ноды Remnawave.
# Сабкоманды: node | warp | netbird | monitoring | crowdsec.
# Вызывается через node-diagnostic.sh (пункт меню «Установка Remnanode»).
# Нода и WARP — отдельные модули (node.sh, warp.sh); здесь только диспетчер к ним.
# Внешние установщики запускаются ТОЛЬКО после явного подтверждения.
set -u
_self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$_self/../lib/common.sh" 2>/dev/null || { echo "install: не найден lib/common.sh" >&2; exit 1; }

# ── источники (обнови здесь при смене репо/версий) ────────────────────
NETBIRD_INSTALL_URL="https://pkgs.netbird.io/install.sh"
# CrowdSec — официальный репо packagecloud (в штатных Debian/Ubuntu древний 1.4.x без allowlists)
CROWDSEC_REPO_URL="https://install.crowdsec.net"
CROWDSEC_ALLOWLIST="node-diagnostic"
# cscli (Go ≥1.24) шлёт постквантовый ClientHello (X25519MLKEM768, ~1.8 КБ — два TCP-сегмента),
# и DPI на части маршрутов его режет: запрос к version.crowdsec.net (Cloudflare) висит до
# «TLS handshake timeout», хотя curl на OpenSSL 3.0 проходит. Туда ходит только cscli (выбор
# ветки хаба), демон — нет. Если Go уберёт tlsmlkem, cscli упадёт сразу с «removed GODEBUG».
CROWDSEC_GODEBUG="tlsmlkem=0"
# Мониторинг — версии по гайду https://wiki.egam.es/ru/configuration/grafana-monitoring-setup/
CADVISOR_VER="0.53.0"
NODE_EXPORTER_VER="1.9.1"
VMUTILS_VER="1.123.0"

_need_tty() { [ -t 0 ] || die "нужен интерактивный терминал — установщики спрашивают ввод"; }

_is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    local o; for o in "${BASH_REMATCH[@]:1}"; do [ "$o" -le 255 ] || return 1; done
}

# v4 строго; v6 — грубо (hex + двоеточия): cscli/nft всё равно отвергнут мусор
_is_ip() { _is_ipv4 "$1" || [[ "$1" == *:* && "$1" =~ ^[0-9A-Fa-f:.]+$ ]]; }

_show_cmd() { echo -e "    ${DIM}будет выполнено:${NC}\n    ${C}$1${NC}"; }

_need_curl() { have curl || ensure_pkg curl curl curl curl || die "нужен curl (не удалось поставить)"; }

# ── 1. NetBird + подключение по setup-key ────────────────────────────
inst_netbird() {
    ui_head "Установка NetBird" "агент оверлей-сети + подключение по setup-key"
    local key
    printf "  ${BOLD}Setup-key NetBird${NC}: "; read -r key
    [ -n "$key" ] || { msg_err "ключ пустой — отмена"; return 1; }
    _show_cmd "curl -fsSL $NETBIRD_INSTALL_URL | sh   &&   netbird up --setup-key ***"
    confirm "Установить NetBird и подключиться этим ключом?" || { msg_info "отменено"; return 1; }
    _need_curl
    curl -fsSL "$NETBIRD_INSTALL_URL" | sh || die "установщик NetBird завершился с ошибкой"
    have netbird || die "netbird не появился после установки"
    netbird up --setup-key "$key" || die "netbird up не удался (проверь ключ/сеть)"
    msg_ok "NetBird подключён — проверь: netbird status"
}

# ── 2. Мониторинг ноды (cAdvisor + node_exporter + vmagent) ──────────
# Точно по гайду wiki.egam.es: всё слушает 127.0.0.1, vmagent шлёт remoteWrite
# на центральный VictoriaMetrics по адресу NetBird.
inst_monitoring() {
    ui_head "Мониторинг ноды" "cAdvisor + node_exporter + vmagent → VictoriaMetrics"
    need_root || die "нужен root"
    [ "$(uname -m)" = "x86_64" ] || die "гайд рассчитан на amd64 (uname -m=$(uname -m))"
    have systemctl || die "нужен systemd (юниты cadvisor/nodeexporter/vmagent)"

    local inst ip def_inst
    def_inst="$(hostname)"
    printf "  ${BOLD}Имя инстанса (ноды)${NC} ${DIM}[Enter — %s]${NC}: " "$def_inst"; read -r inst
    inst="${inst:-$def_inst}"
    while true; do
        printf "  ${BOLD}IP сервера мониторинга (NetBird)${NC} ${DIM}напр. 10.0.0.5${NC}: "; read -r ip
        _is_ipv4 "$ip" && break
        msg_warn "это не IPv4-адрес"
    done
    echo
    msg_info "инстанс: $inst · vmagent remoteWrite → http://$ip:8428/api/v1/write"
    confirm "Установить и запустить мониторинг?" || { msg_info "отменено"; return 1; }

    _need_curl
    ensure_pkg tar tar tar tar >/dev/null 2>&1 || true
    have tar || die "нужен tar"

    # 1/4 — компоненты
    ui_head "1/4 загрузка компонентов" "cadvisor $CADVISOR_VER · node_exporter $NODE_EXPORTER_VER · vmutils $VMUTILS_VER"
    mkdir -p /opt/monitoring/cadvisor /opt/monitoring/nodeexporter /opt/monitoring/vmagent/conf.d

    curl -fL --retry 3 -o /opt/monitoring/cadvisor/cadvisor \
        "https://github.com/google/cadvisor/releases/download/v${CADVISOR_VER}/cadvisor-v${CADVISOR_VER}-linux-amd64" \
        && chmod +x /opt/monitoring/cadvisor/cadvisor && msg_ok "cAdvisor" || die "cAdvisor не скачался"

    local ne_tgz="/tmp/nd-node_exporter.tar.gz"
    curl -fL --retry 3 -o "$ne_tgz" \
        "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VER}/node_exporter-${NODE_EXPORTER_VER}.linux-amd64.tar.gz" \
        || die "node_exporter не скачался"
    tar -xf "$ne_tgz" -C /tmp
    mv "/tmp/node_exporter-${NODE_EXPORTER_VER}.linux-amd64/node_exporter" /opt/monitoring/nodeexporter/node_exporter
    chmod +x /opt/monitoring/nodeexporter/node_exporter
    rm -rf "$ne_tgz" "/tmp/node_exporter-${NODE_EXPORTER_VER}.linux-amd64"
    msg_ok "node_exporter"

    local vm_tgz="/tmp/nd-vmutils.tar.gz"
    curl -fL --retry 3 -o "$vm_tgz" \
        "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v${VMUTILS_VER}/vmutils-linux-amd64-v${VMUTILS_VER}.tar.gz" \
        || die "vmutils не скачался"
    tar -xf "$vm_tgz" -C /opt/monitoring/vmagent
    mv /opt/monitoring/vmagent/vmagent-prod /opt/monitoring/vmagent/vmagent
    # прочие бинари из vmutils не нужны — оставляем только vmagent (conf.d не трогаем)
    find /opt/monitoring/vmagent -maxdepth 1 -type f ! -name vmagent -delete
    chmod +x /opt/monitoring/vmagent/vmagent
    rm -f "$vm_tgz"
    msg_ok "vmagent"

    # 2/4 — конфиги vmagent
    ui_head "2/4 конфигурация vmagent" ""
    cat > /opt/monitoring/vmagent/scrape.yml <<'EOF'
scrape_config_files:
  - "/opt/monitoring/vmagent/conf.d/*.yml"

global:
  scrape_interval: 15s
EOF
    cat > /opt/monitoring/vmagent/conf.d/cadvisor.yml <<EOF
- job_name: integrations/cAdvisor
  scrape_interval: 15s
  static_configs:
    - targets: ['localhost:9101']
      labels:
        instance: "$inst"
EOF
    cat > /opt/monitoring/vmagent/conf.d/nodeexporter.yml <<EOF
- job_name: integrations/node_exporter
  scrape_interval: 15s
  static_configs:
    - targets: ['localhost:9100']
      labels:
        instance: "$inst"
EOF
    msg_ok "scrape.yml + conf.d/{cadvisor,nodeexporter}.yml"

    # 3/4 — systemd-юниты
    ui_head "3/4 systemd-юниты" ""
    cat > /etc/systemd/system/cadvisor.service <<'EOF'
[Unit]
Description=cAdvisor
Wants=network-online.target
After=network-online.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/opt/monitoring/cadvisor/cadvisor \
        -listen_ip=127.0.0.1 \
        -logtostderr \
        -port=9101 \
        -docker_only=true
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/nodeexporter.service <<'EOF'
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/opt/monitoring/nodeexporter/node_exporter --web.listen-address=127.0.0.1:9100
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/vmagent.service <<EOF
[Unit]
Description=VictoriaMetrics Agent
Wants=network-online.target
After=network-online.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/opt/monitoring/vmagent/vmagent \\
      -httpListenAddr=127.0.0.1:8429 \\
      -promscrape.config=/opt/monitoring/vmagent/scrape.yml \\
      -promscrape.configCheckInterval=60s \\
      -remoteWrite.url=http://$ip:8428/api/v1/write
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    msg_ok "cadvisor.service + nodeexporter.service + vmagent.service"

    # 4/4 — запуск
    ui_head "4/4 запуск и автозагрузка" ""
    systemctl daemon-reload
    systemctl enable cadvisor nodeexporter vmagent >/dev/null 2>&1 || true
    systemctl restart cadvisor nodeexporter vmagent
    local svc
    for svc in cadvisor nodeexporter vmagent; do
        if systemctl is-active --quiet "$svc"; then
            msg_ok "$svc активен"
        else
            msg_err "$svc НЕ активен — смотри: journalctl -u $svc -n 30"
        fi
    done
    echo
    msg_info "метрики слушают локально (127.0.0.1:9101/9100/8429); центральный VM собирает их по NetBird ($ip)"
}

# ── 3. CrowdSec (анти-брут SSH + community-блоклист) ─────────────────
# Движок + nftables-bouncer. Порядок важен: allowlist (SSH-IP, IP панели) заводится
# ДО установки bouncer'а — если IP попал в community-блоклист, bouncer дропнул бы
# и текущую SSH-сессию прямо посреди установки.

# пакеты CrowdSec есть только deb/rpm (packagecloud)
_cs_pm() {
    if   have apt-get; then echo apt
    elif have dnf;     then echo dnf
    elif have yum;     then echo yum
    else return 1; fi
}

_cs_pkg() {   # _cs_pkg <pm> install|remove <pkg...>
    local pm=$1 op=$2; shift 2
    if [ "$pm" = "apt" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 "$op" -y -q "$@" </dev/null
    else
        "$pm" "$op" -y -q "$@" </dev/null
    fi
}

# allowlist действует и на локальные баны, и на блоклисты, но уже выданные решения
# не снимает (CAPI-блоклист тянется при старте LAPI) — их удаляем явно
_cs_allowlist() {   # _cs_allowlist <ip...>
    [ $# -gt 0 ] || { msg_warn "allowlist пуст — свой IP добавь сам: cscli allowlists add $CROWDSEC_ALLOWLIST <IP> -d admin"; return 0; }
    if ! cscli allowlists list >/dev/null 2>&1; then
        msg_warn "этот cscli не умеет allowlists (CrowdSec < 1.6.8) — IP не защищены от бана"
        return 1
    fi
    cscli allowlists inspect "$CROWDSEC_ALLOWLIST" >/dev/null 2>&1 \
        || cscli allowlists create "$CROWDSEC_ALLOWLIST" -d "node-diagnostic: SSH-админ и панель Remnawave" >/dev/null \
        || { msg_err "не создал allowlist $CROWDSEC_ALLOWLIST"; return 1; }
    local ip
    for ip in "$@"; do
        # повторный add — ошибка cscli («уже есть»): норма при перезапуске пункта
        cscli allowlists add "$CROWDSEC_ALLOWLIST" "$ip" -d "node-diagnostic" >/dev/null 2>&1 || true
        case "$ip" in
            */*) cscli decisions delete --range "$ip" --contained ;;
            *)   cscli decisions delete --ip "$ip" ;;
        esac >/dev/null 2>&1 || true
        msg_ok "allowlist: $ip"
    done
}

# Логи SSH CrowdSec находит сам (cscli setup при установке пакета). Если acquisition
# для sshd всё же нет — движок слеп к брутфорсу, поэтому подстраховка.
_cs_ssh_acquis() {
    local f=/etc/crowdsec/acquis.d/node-diagnostic-sshd.yaml unit=sshd.service
    if grep -rqsE 'ssh|auth\.log|/var/log/secure' /etc/crowdsec/acquis.yaml /etc/crowdsec/acquis.d; then
        msg_ok "логи SSH уже читаются (acquisition от установщика)"
        return 0
    fi
    mkdir -p /etc/crowdsec/acquis.d
    if [ -e /var/log/auth.log ] || [ -e /var/log/secure ]; then
        cat > "$f" <<'EOF'
# node-diagnostic: логи SSH для CrowdSec (файлы rsyslog)
source: file
filenames:
  - /var/log/auth.log
  - /var/log/secure
labels:
  type: syslog
EOF
    else
        # на deb юнит — ssh.service (sshd.service там алиас, журнал по нему не читается)
        systemctl cat ssh.service >/dev/null 2>&1 && unit=ssh.service
        cat > "$f" <<EOF
# node-diagnostic: логи SSH для CrowdSec из journald (rsyslog не установлен)
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=$unit"
labels:
  type: syslog
EOF
    fi
    msg_ok "acquisition SSH: $f"
}

# Пакет раз в сутки зовёт `cscli hub update` из crowdsec-hubupdate.service — ему тот же GODEBUG.
# Нет юнита — хаб обновляется иначе (cron.daily пакета), его не трогаем.
_cs_hubupdate_godebug() {
    local d=/etc/systemd/system/crowdsec-hubupdate.service.d
    systemctl cat crowdsec-hubupdate.service >/dev/null 2>&1 || return 0
    mkdir -p "$d"
    cat > "$d/${ND_DROPIN_PREFIX}.conf" <<EOF
# node-diagnostic: cscli без постквантового TLS (см. CROWDSEC_GODEBUG в modules/install.sh)
[Service]
Environment=GODEBUG=$CROWDSEC_GODEBUG
EOF
    systemctl daemon-reload
    msg_ok "crowdsec-hubupdate: GODEBUG=$CROWDSEC_GODEBUG"
}

inst_crowdsec() {
    ui_head "Установка CrowdSec" "движок + nftables-bouncer · анти-брут SSH, community-блоклист"
    need_root || die "нужен root"
    have systemctl || die "нужен systemd (юниты crowdsec / crowdsec-firewall-bouncer)"
    local pm; pm=$(_cs_pm) || die "CrowdSec ставится только на deb/rpm-системы (apt/dnf/yum)"
    # LAPI слушает 127.0.0.1:8080 — занятый порт = движок не стартует, а bouncer без ключа
    if ! have cscli && have ss && ss -Hltn 'sport = :8080' 2>/dev/null | grep -q .; then
        die "порт 8080 занят — он нужен LAPI CrowdSec. Освободи его; система не тронута"
    fi

    local ssh_ip pip nb allow=()
    ssh_ip=$(ssh_client_ip)
    nb=$(netbird_cidr) || nb=""
    while true; do
        printf "  ${BOLD}IP панели Remnawave${NC} ${DIM}[Enter — пропустить]${NC}: "; read -r pip
        [ -z "$pip" ] || _is_ip "$pip" && break
        msg_warn "это не IP-адрес"
    done
    # подсеть NetBird — все свои пиры (SSH через оверлей); SSH-IP внутри неё уже покрыт
    [ -n "$nb" ] && allow+=("$nb")
    if [ -n "$ssh_ip" ] && ! { [ -n "$nb" ] && ip_in_cidr "$ssh_ip" "$nb"; }; then
        allow+=("$ssh_ip")
    fi
    [ -n "$pip" ] && allow+=("$pip")
    echo
    msg_info "allowlist (не банятся никогда): ${allow[*]:-пусто}"
    [ -z "$ssh_ip" ] && [ -z "$nb" ] && msg_warn "SSH-IP не определён (не по SSH?) — добавь свой IP в allowlist после установки"
    _show_cmd "curl -fsSL $CROWDSEC_REPO_URL | sh   &&   GODEBUG=$CROWDSEC_GODEBUG $pm install crowdsec crowdsec-firewall-bouncer-nftables"
    confirm "Установить CrowdSec?" || { msg_info "отменено"; return 1; }
    _need_curl
    # cscli зовут postinst пакета (`hub update`) и шаг 3 — всем без ML-KEM (см. CROWDSEC_GODEBUG)
    local -x GODEBUG=$CROWDSEC_GODEBUG

    ui_head "1/4 движок" "репозиторий packagecloud + crowdsec"
    # не `curl | sh`: при сбое curl sh получит пустой ввод, вернёт 0 — и apt молча
    # поставил бы древний crowdsec из штатного репо
    local repo_sh
    repo_sh=$(curl -fsSL "$CROWDSEC_REPO_URL") || die "не скачал установщик репозитория CrowdSec"
    printf '%s\n' "$repo_sh" | sh >/dev/null || die "не подключил репозиторий CrowdSec"
    _cs_pkg "$pm" install crowdsec || die "пакет crowdsec не установился"
    have cscli || die "cscli не появился после установки"
    msg_ok "crowdsec установлен"
    _cs_hubupdate_godebug

    ui_head "2/4 allowlist" "до bouncer'а — чтобы не оборвать свою SSH-сессию"
    if ! _cs_allowlist ${allow[@]+"${allow[@]}"}; then
        confirm "Allowlist не заведён — всё равно ставить bouncer (риск бана своего IP)?" \
            || { msg_info "bouncer не ставился; движок crowdsec уже установлен"; return 1; }
    fi

    ui_head "3/4 сценарии SSH" "crowdsecurity/linux + crowdsecurity/sshd"
    if cscli collections install crowdsecurity/linux crowdsecurity/sshd >/dev/null 2>&1; then
        msg_ok "коллекции linux + sshd"
    else
        msg_warn "cscli collections install вернул ошибку — проверь: cscli collections list"
    fi
    _cs_ssh_acquis
    systemctl enable crowdsec >/dev/null 2>&1 || true
    systemctl restart crowdsec || msg_err "crowdsec не перезапустился — смотри: journalctl -u crowdsec -n 30"

    # отдельной транзакцией ПОСЛЕ движка: postinst bouncer'а сам регистрирует ключ
    # через cscli, а в одной транзакции dpkg мог сконфигурировать его раньше crowdsec
    ui_head "4/4 firewall-bouncer" "nftables · таблицы crowdsec/crowdsec6"
    _cs_pkg "$pm" install crowdsec-firewall-bouncer-nftables || die "пакет crowdsec-firewall-bouncer-nftables не установился"
    systemctl enable --now crowdsec-firewall-bouncer >/dev/null 2>&1 || true
    local svc
    for svc in crowdsec crowdsec-firewall-bouncer; do
        if systemctl is-active --quiet "$svc"; then
            msg_ok "$svc активен"
        else
            msg_err "$svc НЕ активен — смотри: journalctl -u $svc -n 30"
        fi
    done
    record_fix "crowdsec + firewall-bouncer-nftables (allowlist: ${allow[*]:-—})"

    if have fail2ban-client; then
        echo
        msg_warn "найден fail2ban — CrowdSec его заменяет, вместе они дублируют баны"
        if confirm "Остановить и удалить fail2ban?"; then
            systemctl disable --now fail2ban >/dev/null 2>&1 || true
            if _cs_pkg "$pm" remove fail2ban; then msg_ok "fail2ban удалён"
            else msg_warn "fail2ban не удалился — убери вручную"; fi
        fi
    fi
    echo
    msg_info "проверка: cscli decisions list · cscli alerts list · cscli metrics"
    msg_info "ещё IP в allowlist: cscli allowlists add $CROWDSEC_ALLOWLIST <IP> -d admin"
}

case "${1:-}" in
    node)       _need_tty; bash "$_self/node.sh" install ;;
    warp)       _need_tty; shift; bash "$_self/warp.sh" "${@:-install}" ;;
    netbird)    _need_tty; inst_netbird ;;
    monitoring) _need_tty; inst_monitoring ;;
    crowdsec)   _need_tty; inst_crowdsec ;;
    selfsteal)
        echo "install: selfsteal теперь часть установки ноды (nginx + шаблон сайта) — sudo bash node-diagnostic.sh install node" >&2
        exit 2 ;;
    ""|help|-h|--help)
        echo "install: sudo bash node-diagnostic.sh install {node|warp|netbird|monitoring|crowdsec}"
        ;;
    *) echo "install: неизвестная сабкоманда '$1' (node|warp|netbird|monitoring|crowdsec)" >&2; exit 2 ;;
esac
