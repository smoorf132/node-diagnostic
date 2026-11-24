#!/usr/bin/env bash
# modules/balancer.sh — L4-балансер перед нодами: nginx stream читает SNI из ClientHello
# (ssl_preread, без расшифровки) и проксирует TCP на upstream этого SNI с proxy-protocol —
# нода видит реальный IP клиента. nginx — последняя stable из официального репозитория nginx.org.
#
#   balancer install [--route SNI=HOST:PORT[,HOST:PORT…]]… [--default SNI] [--no-proxy-protocol]
#   balancer add SNI HOST:PORT[,HOST:PORT…]   — маршрут (есть — upstream'ы заменяются)
#   balancer del SNI | default SNI | list | status | apply | render
#
# Маршруты — в $BALANCER_CONF; /etc/nginx/nginx.conf целиком генерируется из него (бэкап прежнего —
# nginx.conf.nd-bak-<время>, при провале nginx -t он возвращается). На нодах за балансером порт
# мостов открывается только IP балансера: rr protect bridge port 8443 && rr protect bridge add <IP>.

if [ -z "${ND_COMMON_LOADED:-}" ]; then
    _self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "$_self/../lib/common.sh" 2>/dev/null \
        || { echo "не найден lib/common.sh — нужен весь репозиторий (см. install.sh)" >&2; exit 1; }
fi

BALANCER_CONF="${BALANCER_CONF:-/etc/node-diagnostic/balancer.conf}"
NGINX_CONF="${NGINX_CONF:-/etc/nginx/nginx.conf}"
BAL_MARK="# node-diagnostic balancer"           # первая строка nginx.conf, который ведём мы
BAL_WORKER_CONN=65535
# как в исходном шаблоне. У проксируемого соединения два fd (клиент + upstream), так что на воркер
# реально влезает ~35000 соединений, а не worker_connections 65535
BAL_RLIMIT=70000
# ключ подписи пакетов nginx.org (https://nginx.org/en/linux_packages.html) — отпечаток сверяется
NGINX_KEY_URL="https://nginx.org/keys/nginx_signing.key"
NGINX_KEY_FPR="573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"
NGINX_KEYRING="/usr/share/keyrings/nginx-archive-keyring.gpg"

# ── валидация ────────────────────────────────────────────────────────
# SNI: домен или маска *.domain / .domain (map hostnames); в нижний регистр. rc 1 — мусор
bal_sni_norm() {
    local s; s=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
    [[ "$s" =~ ^(\*\.|\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$ ]] || return 1
    echo "$s"
}
# upstream HOST:PORT → канон: IPv4:port, [IPv6]:port, hostname:port. rc 1 — мусор
bal_up_norm() {
    local u=$1 h p v6
    if [[ "$u" =~ ^\[([0-9A-Fa-f:]+)\]:([0-9]{1,5})$ ]]; then
        v6=$(ip6_norm "${BASH_REMATCH[1]}") || return 1
        h="[$v6]"; p=${BASH_REMATCH[2]}
    elif [[ "$u" =~ ^([^:/]+):([0-9]{1,5})$ ]]; then
        h=$(printf '%s' "${BASH_REMATCH[1]}" | tr 'A-Z' 'a-z'); p=${BASH_REMATCH[2]}
        if [[ "$h" =~ ^[0-9.]+$ ]]; then is_ipv4 "$h" || return 1
        else [[ "$h" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1; fi
    else
        return 1
    fi
    [ "$((10#$p))" -ge 1 ] && [ "$((10#$p))" -le 65535 ] || return 1
    echo "$h:$((10#$p))"
}
# список upstream'ов (через запятую и/или пробел) → канон через пробел; rc 1 — пусто или мусор
bal_ups_norm() {
    local u c out=""
    for u in ${1//,/ }; do
        c=$(bal_up_norm "$u") || { msg_err "upstream «${u}» — нужен HOST:PORT (IPv4, [IPv6] или домен)" >&2; return 1; }
        case " $out " in *" $c "*) ;; *) out="$out${out:+ }$c" ;; esac
    done
    [ -n "$out" ] || return 1
    echo "$out"
}

# ── conf: строки «route SNI UP…», «default SNI», «proxy_protocol on|off» ─
BAL_SNI=(); BAL_UPS=(); BAL_DEFAULT=""; BAL_PP=on
bal_load() {
    local kw a rest s u
    BAL_SNI=(); BAL_UPS=(); BAL_DEFAULT=""; BAL_PP=on
    [ -r "$BALANCER_CONF" ] || return 1
    while read -r kw a rest || [ -n "$kw" ]; do
        case "$kw" in
            route)
                s=$(bal_sni_norm "$a") && u=$(bal_ups_norm "$rest" 2>/dev/null) \
                    || { msg_warn "$BALANCER_CONF: битая строка «route $a $rest» — пропускаю"; continue; }
                BAL_SNI+=("$s"); BAL_UPS+=("$u") ;;
            default) BAL_DEFAULT=$(bal_sni_norm "$a") || BAL_DEFAULT="" ;;
            proxy_protocol) case "$a" in off) BAL_PP=off ;; *) BAL_PP=on ;; esac ;;
        esac
    done < "$BALANCER_CONF"
    return 0
}
bal_save() {
    local i
    mkdir -p "$(dirname "$BALANCER_CONF")" || return 1
    {
        echo "# node-diagnostic balancer: SNI → upstream'ы. Правится командами rr balancer add|del|default."
        echo "proxy_protocol $BAL_PP"
        [ -n "$BAL_DEFAULT" ] && echo "default $BAL_DEFAULT"
        for i in "${!BAL_SNI[@]}"; do echo "route ${BAL_SNI[i]} ${BAL_UPS[i]}"; done
    } > "$BALANCER_CONF.tmp" && mv -f "$BALANCER_CONF.tmp" "$BALANCER_CONF"
}
bal_idx() { local i; for i in "${!BAL_SNI[@]}"; do [ "${BAL_SNI[i]}" = "$1" ] && { echo "$i"; return 0; }; done; return 1; }
bal_set_route() {   # SNI "UPS"
    local i
    if i=$(bal_idx "$1"); then BAL_UPS[i]=$2; else BAL_SNI+=("$1"); BAL_UPS+=("$2"); fi
    [ -n "$BAL_DEFAULT" ] || BAL_DEFAULT=$1
}
bal_del_route() {   # SNI → rc 1, если такого нет; удалённый default переезжает на первый оставшийся
    local i s=() u=()
    bal_idx "$1" >/dev/null || return 1
    for i in "${!BAL_SNI[@]}"; do
        [ "${BAL_SNI[i]}" = "$1" ] && continue
        s+=("${BAL_SNI[i]}"); u+=("${BAL_UPS[i]}")
    done
    BAL_SNI=(${s[@]+"${s[@]}"}); BAL_UPS=(${u[@]+"${u[@]}"})
    [ "$BAL_DEFAULT" = "$1" ] && BAL_DEFAULT=${BAL_SNI[0]:-}
    return 0
}
# имя upstream: индекс + SNI без спецсимволов (sni-eu.example.com → up1_sni_eu_example_com)
bal_upname() { echo "up$(( $1 + 1 ))_$(printf '%s' "${BAL_SNI[$1]}" | tr -c 'A-Za-z0-9' '_' | sed 's/^_*//')"; }

bal_has_ipv6() {
    [ "${BAL_IPV6:-}" = 0 ] && return 1
    [ "${BAL_IPV6:-}" = 1 ] && return 0
    [ -s /proc/net/if_inet6 ] && [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = 0 ]
}
bal_user() {
    [ -n "${BAL_USER:-}" ] && { echo "$BAL_USER"; return; }
    if id www-data >/dev/null 2>&1; then echo www-data; else echo nginx; fi
}

# ── рендер nginx.conf (по шаблону пользователя) ──────────────────────
bal_render() {
    local i d="" v6=0 pp=""
    [ "${#BAL_SNI[@]}" -gt 0 ] || { msg_err "нет ни одного маршрута SNI → upstream" >&2; return 1; }
    bal_has_ipv6 && v6=1
    [ "$BAL_PP" = on ] && pp="
        proxy_protocol on;"
    if i=$(bal_idx "$BAL_DEFAULT"); then d=$(bal_upname "$i"); else d=$(bal_upname 0); fi
    cat <<EOF
$BAL_MARK — сгенерировано из $BALANCER_CONF, руками не правится (перезапишется).
# Правка маршрутов: rr balancer add|del|default, затем применяется сам (nginx -t + reload).
user $(bal_user);
worker_processes auto;
worker_rlimit_nofile $BAL_RLIMIT;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;
worker_shutdown_timeout 5m;
events {
    worker_connections $BAL_WORKER_CONN;
    multi_accept on;
}
http {
    server_tokens off;
    access_log off;
    server {
        listen 80 default_server;
$([ "$v6" = 1 ] && echo "        listen [::]:80 default_server;")
        server_name _;
        return 301 https://\$host\$request_uri;
    }
}
stream {
    map \$ssl_preread_server_name \$backend {
        hostnames;
EOF
    for i in "${!BAL_SNI[@]}"; do printf '        %-40s %s;\n' "${BAL_SNI[i]}" "$(bal_upname "$i")"; done
    printf '        %-40s %s;\n    }\n' default "$d"
    for i in "${!BAL_SNI[@]}"; do
        printf '\n    upstream %s {\n' "$(bal_upname "$i")"
        for d in ${BAL_UPS[i]}; do printf '        server %s;\n' "$d"; done
        printf '    }\n'
    done
    cat <<EOF

    server {
        listen 443 reuseport deferred backlog=65535 so_keepalive=30s:10s:3;
$([ "$v6" = 1 ] && echo "        listen [::]:443 reuseport deferred backlog=65535 so_keepalive=30s:10s:3;")

        ssl_preread on;
        preread_timeout 5s;

        proxy_pass \$backend;$pp
        proxy_connect_timeout 5s;
        proxy_timeout 5m;
    }
}
EOF
}

# ── установка nginx stable с nginx.org ──────────────────────────────
_bal_pm() {
    if   have apt-get; then echo apt
    elif have dnf;     then echo dnf
    elif have yum;     then echo yum
    else return 1; fi
}
_bal_has_preread() { nginx -V 2>&1 | grep -q -- '--with-stream_ssl_preread_module'; }
# слушатель порта не от nginx → имя процесса (rc 0 — занят чужим)
_bal_port_foreign() {
    local who
    who=$(ss -Hltnp "sport = :$1" 2>/dev/null | grep -oE 'users:\(\("[^"]+"' | sed 's/users:(("//' | sort -u | tr '\n' ' ')
    [ -n "$who" ] || return 1
    case " $who " in *" nginx "*) [ "$(echo "$who" | wc -w)" -eq 1 ] && return 1 ;; esac
    echo "$who"
}

bal_install_nginx() {
    local pm distro code key tmp
    pm=$(_bal_pm) || die "нужен apt или dnf/yum — на этом дистрибутиве репозиторий nginx.org модулем не ставится"
    if [ "$pm" = apt ]; then
        distro=$(os_id)
        case "$distro" in debian|ubuntu) ;; *) die "nginx.org собирает пакеты для debian и ubuntu, а тут «$distro»" ;; esac
        code=$(os_codename); [ -n "$code" ] || die "не определил кодовое имя релиза (VERSION_CODENAME в /etc/os-release)"
        # nginx из репозитория дистрибутива конфликтует с пакетом nginx.org
        if dpkg-query -W -f='${Status}' nginx-common 2>/dev/null | grep -q 'ok installed'; then
            msg_warn "стоит nginx из репозитория $distro (nginx-common) — с пакетом nginx.org он конфликтует"
            if [ "${BAL_YES:-0}" = 1 ] || { [ -t 0 ] && confirm "Удалить его (apt-get purge nginx nginx-common nginx-core; /etc/nginx сохранится в бэкап)?"; }; then
                [ -d /etc/nginx ] && cp -a /etc/nginx "/etc/nginx.nd-bak-$(date +%Y%m%d-%H%M%S)"
                DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 purge -y -qq \
                    nginx nginx-common nginx-core nginx-full nginx-light nginx-extras >/dev/null 2>&1 </dev/null || true
            else
                die "удали nginx дистрибутива и повтори: apt-get purge nginx nginx-common"
            fi
        fi
        ensure_pkg curl curl curl curl || die "нужен curl"
        ensure_pkg gpg gnupg gnupg2 gnupg || die "нужен gpg (gnupg)"
        pkg_install ca-certificates ca-certificates ca-certificates >/dev/null 2>&1 || true
        tmp=$(mktemp)
        curl -fsSL --max-time 30 "$NGINX_KEY_URL" -o "$tmp" || { rm -f "$tmp"; die "не скачал ключ $NGINX_KEY_URL"; }
        key=$(gpg --dry-run --quiet --no-keyring --import --import-options import-show "$tmp" 2>/dev/null | tr -d ' ')
        case "$key" in *"$NGINX_KEY_FPR"*) ;; *) rm -f "$tmp"; die "отпечаток ключа nginx.org не совпал с $NGINX_KEY_FPR — не ставлю" ;; esac
        gpg --dearmor < "$tmp" > "$NGINX_KEYRING.tmp" && mv -f "$NGINX_KEYRING.tmp" "$NGINX_KEYRING"
        chmod 644 "$NGINX_KEYRING"; rm -f "$tmp"
        echo "deb [signed-by=$NGINX_KEYRING] https://nginx.org/packages/$distro $code nginx" > /etc/apt/sources.list.d/nginx.list
        printf 'Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n' > /etc/apt/preferences.d/99nginx
        msg_info "apt: репозиторий nginx.org (stable, $distro $code)"
        apt-get -o DPkg::Lock::Timeout=60 update -qq >/dev/null 2>&1 </dev/null \
            || die "apt-get update упал — есть ли пакеты nginx.org для $distro $code? (https://nginx.org/packages/$distro/dists/)"
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq \
            -o Dpkg::Options::=--force-confold nginx >/dev/null 2>&1 </dev/null || die "apt-get install nginx не удался"
    else
        cat > /etc/yum.repos.d/nginx.repo <<'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=https://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
        msg_info "$pm: репозиторий nginx.org (nginx-stable)"
        "$pm" install -y -q nginx >/dev/null 2>&1 </dev/null || die "$pm install nginx не удался"
    fi
    have nginx || die "nginx не появился после установки"
    _bal_has_preread || die "nginx собран без stream_ssl_preread — SNI-маршрутизация невозможна"
    msg_ok "$(nginx -v 2>&1 | sed 's/^nginx version: //') (nginx.org, stable)"
}

# ── применение ──────────────────────────────────────────────────────
bal_apply() {
    local tmp bak="" err
    need_root || die "нужен root"
    have nginx || die "nginx не установлен — rr balancer install"
    bal_load || die "нет $BALANCER_CONF — rr balancer install"
    tmp=$(mktemp)
    bal_render > "$tmp" || { rm -f "$tmp"; die "нечего применять"; }
    if [ -f "$NGINX_CONF" ] && ! cmp -s "$tmp" "$NGINX_CONF"; then
        bak="$NGINX_CONF.nd-bak-$(date +%Y%m%d-%H%M%S)"
        cp -a "$NGINX_CONF" "$bak"
    fi
    install -m 644 "$tmp" "$NGINX_CONF"; rm -f "$tmp"
    if ! err=$(nginx -t 2>&1); then
        msg_err "nginx -t не прошёл:"; echo "$err" | sed 's/^/      /'
        [ -n "$bak" ] && cp -a "$bak" "$NGINX_CONF" && msg_info "вернул прежний $NGINX_CONF"
        return 1
    fi
    msg_ok "nginx -t: ok ${bak:+${DIM}(бэкап $bak)${NC}}"
    if have systemctl; then
        systemctl enable nginx >/dev/null 2>&1 || true
        if systemctl is-active --quiet nginx; then systemctl reload nginx || return 1
        else systemctl restart nginx || return 1; fi
        systemctl is-active --quiet nginx && msg_ok "nginx активен" || { msg_err "nginx не поднялся — journalctl -u nginx -n 30"; return 1; }
    else
        nginx -s reload 2>/dev/null || nginx || return 1
    fi
    local sc; sc=$(sysctl -n net.core.somaxconn 2>/dev/null || echo 0)
    [ "$sc" -lt 65535 ] && msg_info "net.core.somaxconn=$sc < backlog 65535 — ядро урежет очередь (поднять: sysctl -w net.core.somaxconn=65535)"
    return 0
}

# после правки conf — применяем, только если nginx.conf уже наш (иначе ждём install/apply)
_bal_maybe_apply() {
    if need_root && have nginx && head -n1 "$NGINX_CONF" 2>/dev/null | grep -q "^$BAL_MARK"; then
        bal_apply
    else
        msg_info "сохранено в $BALANCER_CONF; применить: rr balancer apply (или install)"
    fi
}

bal_list() {
    local i mark
    bal_load || { msg_info "маршрутов нет ($BALANCER_CONF)"; return 0; }
    echo -e "    ${DIM}proxy-protocol:${NC} $BAL_PP   ${DIM}conf:${NC} $BALANCER_CONF"
    [ "${#BAL_SNI[@]}" -gt 0 ] || { msg_info "маршрутов нет"; return 0; }
    for i in "${!BAL_SNI[@]}"; do
        mark=""; [ "${BAL_SNI[i]}" = "$BAL_DEFAULT" ] && mark=" ${DIM}(default)${NC}"
        echo -e "    ${C}${BAL_SNI[i]}${NC}$mark → ${BAL_UPS[i]}"
    done
}

bal_status() {
    local i u h p
    if have nginx; then
        msg_ok "$(nginx -v 2>&1 | sed 's/^nginx version: //')$(_bal_has_preread || echo " — ${R}без ssl_preread${NC}")"
        if have systemctl; then
            systemctl is-active --quiet nginx && msg_ok "nginx активен" || msg_warn "nginx не активен"
        fi
        head -n1 "$NGINX_CONF" 2>/dev/null | grep -q "^$BAL_MARK" || msg_warn "$NGINX_CONF не от balancer — rr balancer apply"
    else
        msg_warn "nginx не установлен — rr balancer install"
    fi
    bal_list
    bal_load || return 0
    # доступность upstream'ов (TCP-connect, 3 с)
    for i in "${!BAL_SNI[@]}"; do
        for u in ${BAL_UPS[i]}; do
            p=${u##*:}; h=${u%:*}; h=${h#[}; h=${h%]}
            if timeout 3 bash -c "exec 3<>/dev/tcp/$h/$p" 2>/dev/null; then msg_ok "upstream $u доступен"
            else msg_warn "upstream $u не отвечает по TCP (firewall ноды: rr protect bridge add <IP балансера>)"; fi
        done
    done
}

_bal_src_ip() { ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1; }

# интерактивный ввод маршрутов (install без --route)
_bal_ask_routes() {
    local sni ups s u def yn
    echo -e "  ${BOLD}Маршруты SNI → upstream${NC} ${DIM}(upstream — нода: IP:порт мостов, напр. 80.79.117.98:8443)${NC}"
    while true; do
        ask "SNI (домен или *.домен; Enter — закончить)" sni "" || break
        if [ -z "$sni" ]; then
            [ "${#BAL_SNI[@]}" -gt 0 ] && break
            echo -e "    ${Y}нужен хотя бы один маршрут${NC}"; continue
        fi
        s=$(bal_sni_norm "$sni") || { echo -e "    ${Y}«${sni}» — не домен${NC}"; continue; }
        while true; do
            ask "upstream'ы для $s (HOST:PORT через запятую)" ups "" || return 1
            u=$(bal_ups_norm "$ups") && break
        done
        bal_set_route "$s" "$u"
        msg_ok "$s → $u"
    done
    [ "${#BAL_SNI[@]}" -gt 0 ] || return 1
    while true; do
        ask "SNI по умолчанию (неизвестные и пустые SNI)" def "${BAL_DEFAULT:-${BAL_SNI[0]}}" || return 1
        def=$(bal_sni_norm "$def") && bal_idx "$def" >/dev/null && { BAL_DEFAULT=$def; break; }
        echo -e "    ${Y}это должен быть один из введённых SNI${NC}"
    done
    while true; do
        ask "proxy-protocol к нодам (на ноде у inbound acceptProxyProtocol) y/n" yn y || return 1
        case "$yn" in y|Y|д) BAL_PP=on; break ;; n|N|н) BAL_PP=off; break ;; esac
    done
}

bal_install() {
    local r s u def="" pp="" routes=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --route) routes+=("${2:-}"); shift ;;
            --default) def=${2:-}; shift ;;
            --no-proxy-protocol) pp=off ;;
            --proxy-protocol) pp=on ;;
            --yes|-y) BAL_YES=1 ;;
            *) die "balancer install: неизвестный аргумент $1" ;;
        esac
        shift
    done
    need_root || die "нужен root"
    echo
    ui_head "Балансер nginx" "SNI → upstream · stream + proxy-protocol"
    bal_load || true
    for r in ${routes[@]+"${routes[@]}"}; do
        case "$r" in *=*) ;; *) die "--route ждёт SNI=HOST:PORT[,HOST:PORT], получено: $r" ;; esac
        s=$(bal_sni_norm "${r%%=*}") || die "--route: «${r%%=*}» — не домен"
        u=$(bal_ups_norm "${r#*=}") || die "--route: плохие upstream'ы в «${r}»"
        bal_set_route "$s" "$u"
    done
    if [ -n "$def" ]; then
        def=$(bal_sni_norm "$def") && bal_idx "$def" >/dev/null || die "--default должен совпасть с одним из SNI"
        BAL_DEFAULT=$def
    fi
    [ -n "$pp" ] && BAL_PP=$pp
    if [ "${#routes[@]}" -eq 0 ]; then
        if [ -t 0 ]; then
            [ "${#BAL_SNI[@]}" -gt 0 ] && { msg_info "уже есть маршруты:"; bal_list; }
            _bal_ask_routes || die "маршруты не заданы"
        elif [ "${#BAL_SNI[@]}" -eq 0 ]; then
            die "нет маршрутов: --route SNI=HOST:PORT (или запусти в терминале)"
        fi
    fi
    # порты 80/443 должен держать только nginx
    for r in 443 80; do
        u=$(_bal_port_foreign "$r") && die "порт $r занят: $u — балансеру нужны 80 и 443"
    done
    bal_save || die "не записал $BALANCER_CONF"
    msg_ok "маршруты: $BALANCER_CONF"
    bal_install_nginx
    bal_apply || die "конфиг не применён"
    record_fix "balancer: nginx stable (nginx.org) + ${#BAL_SNI[@]} SNI-маршрут(ов)"
    echo
    bal_list
    echo
    msg_info "на каждой ноде за балансером — порт мостов только для этого IP:"
    msg_info "  rr protect bridge port 8443 && rr protect bridge add $(_bal_src_ip || true)"
    [ "$BAL_PP" = on ] && msg_info "и у inbound ноды на этом порту — sockopt.acceptProxyProtocol: true (иначе xray не поймёт заголовок)"
}

balancer_main() {
    local cmd=${1:-help} s u
    [ $# -gt 0 ] && shift
    case "$cmd" in
        install) bal_install "$@" ;;
        add)
            [ $# -ge 2 ] || die "balancer add SNI HOST:PORT[,HOST:PORT…]"
            s=$(bal_sni_norm "$1") || die "«${1}» — не домен"; shift
            u=$(bal_ups_norm "$*") || die "плохие upstream'ы: $*"
            bal_load || true
            bal_set_route "$s" "$u"; bal_save || die "не записал $BALANCER_CONF"
            msg_ok "$s → $u"
            _bal_maybe_apply ;;
        del|rm)
            [ $# -ge 1 ] || die "balancer del SNI"
            s=$(bal_sni_norm "$1") || die "«${1}» — не домен"
            bal_load || die "маршрутов нет"
            bal_del_route "$s" || die "маршрута $s нет"
            [ "${#BAL_SNI[@]}" -gt 0 ] || die "это последний маршрут — без маршрутов nginx-конфиг не собрать; сначала добавь новый"
            bal_save || die "не записал $BALANCER_CONF"
            msg_ok "маршрут $s удалён${BAL_DEFAULT:+ (default: $BAL_DEFAULT)}"
            _bal_maybe_apply ;;
        default)
            [ $# -ge 1 ] || die "balancer default SNI"
            s=$(bal_sni_norm "$1") || die "«${1}» — не домен"
            bal_load || die "маршрутов нет"
            bal_idx "$s" >/dev/null || die "маршрута $s нет — сначала balancer add"
            BAL_DEFAULT=$s; bal_save || die "не записал $BALANCER_CONF"
            msg_ok "default: $s"
            _bal_maybe_apply ;;
        list|ls) bal_list ;;
        status|st) bal_status ;;
        apply) bal_apply ;;
        render) bal_load || die "нет $BALANCER_CONF"; bal_render ;;
        help|-h|--help)
            cat <<'HELP'
balancer — L4-балансер на nginx (stream + ssl_preread): SNI → upstream'ы нод с proxy-protocol
  balancer install [--route SNI=HOST:PORT[,HOST:PORT…]]… [--default SNI] [--no-proxy-protocol] [--yes]
                   ставит nginx stable с nginx.org, пишет /etc/nginx/nginx.conf, nginx -t, reload
  balancer add SNI HOST:PORT[,…]   маршрут (есть — upstream'ы заменяются), применяется сразу
  balancer del SNI                 удалить маршрут (default переедет на первый оставшийся)
  balancer default SNI             куда идут неизвестные и пустые SNI
  balancer list | status           маршруты; status — ещё nginx и доступность upstream'ов
  balancer apply | render          пересобрать nginx.conf из conf / показать без применения
HELP
            ;;
        *) echo "balancer: неизвестная команда $cmd (см. balancer help)" >&2; return 2 ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    balancer_main "$@"
fi
