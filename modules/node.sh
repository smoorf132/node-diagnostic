#!/usr/bin/env bash
# modules/node.sh — установка ноды Remnawave под ключ: remnanode + nginx (selfsteal на
# unix-сокете /dev/shm/nginx.sock с proxy_protocol), сертификат любым методом из certs.sh,
# случайный шаблон сайта-маскировки.
# Порт из eGamesAPI/remnawave-reverse-proxy (src/nginx/install_node.sh, install_packages,
# selfsteal_templates.sh) — без Caddy и ufw: NODE_PORT закрывает firewall из protect.
#
# Управление установленной нодой (правки на месте, ручные изменения файлов сохраняются):
# домены сайта в nginx.conf, обновление образов nginx/remnanode по запросу, своё ядро Xray.
# Разбор nginx.conf и docker-compose.yml — modules/node_conf.py.
#
# Standalone:  sudo bash modules/node.sh install|update|domain …|xray …
# Как модуль:  source lib/common.sh; source modules/node.sh; node_render_compose ДИР [xray]

if [ -z "${ND_COMMON_LOADED:-}" ]; then
    _self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "$_self/../lib/common.sh" 2>/dev/null \
        || { echo "не найден lib/common.sh — нужен весь репозиторий (см. install.sh)" >&2; exit 1; }
fi
_node_self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=certs.sh
source "$_node_self/certs.sh" || { echo "не найден modules/certs.sh" >&2; exit 1; }

# ── источники и версии (обнови здесь) ────────────────────────────────
NODE_IMAGE="remnawave/node:latest"
NGINX_IMAGE="nginx:alpine"
# своё ядро Xray: бинарь монтируется в remnanode поверх встроенного
XRAY_DIR="${XRAY_DIR:-/opt/xray-core}"
XRAY_BIN="$XRAY_DIR/xray"
XRAY_TARGET="/usr/local/bin/xray"
NODE_PY="$_node_self/node_conf.py"
NODE_PORT_DEFAULT=2222
NGINX_SOCK="/dev/shm/nginx.sock"
WEB_ROOT="${WEB_ROOT:-/var/www/html}"
# зеркала Docker Hub: с части хостингов (РФ) hub.docker.com не тянется
DOCKER_MIRRORS='["https://mirror.gcr.io/", "https://dockerhub.timeweb.cloud"]'
# шаблоны selfsteal — архивы на фиксированных коммитах, как в апстриме
TEMPLATE_URLS=(
    "https://github.com/eGamesAPI/simple-web-templates/archive/6b7690b37af85c35117b6da65a36b1b3e0503477.zip"
    "https://github.com/distillium/sni-templates/archive/99fafe48b41060f1225592b472994af6c21b057d.zip"
    "https://github.com/prettyleaf/nothing-sni/archive/58a6d1b012ad87d6194c64feb81c0a8801db3f93.zip"
)
NODE_APT_PKGS=(ca-certificates curl jq wget gnupg unzip nano git openssl certbot python3-certbot-dns-cloudflare
               python3-pip unattended-upgrades locales dnsutils coreutils grep gawk cron iproute2 psmisc)

# ── пакеты ───────────────────────────────────────────────────────────
node_check_os() {
    local id ver
    id=$(os_id)
    ver=$( (. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-0}") ); ver=${ver%%.*}
    case "$id" in
        debian) [ "$ver" -ge 11 ] 2>/dev/null && return 0 ;;
        ubuntu) [ "$ver" -ge 22 ] 2>/dev/null && return 0 ;;
    esac
    die "установка ноды поддерживает Debian 11+ и Ubuntu 22.04+ (здесь: $id $ver)"
}

# Свежий сервер первые минуты гоняет unattended-upgrades с локом dpkg; -o у наших
# apt-get не доходит до вложенных apt внутри get.docker.com — глобальный таймаут доходит
apt_lock_wait_conf() {
    mkdir -p /etc/apt/apt.conf.d 2>/dev/null || return 0
    printf '# node-diagnostic: apt ждёт лок dpkg (unattended-upgrades на свежем сервере)\nDPkg::Lock::Timeout "300";\n' \
        > /etc/apt/apt.conf.d/99node-diagnostic-lock-wait 2>/dev/null || true
}

# до 2 минут ждём лок; дальше SIGTERM юнитам автообновлений (таймер перезапустит их сам)
wait_for_dpkg_lock() {
    have fuser || return 0
    local waited=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        [ "$waited" -eq 0 ] && msg_info "dpkg занят (автообновления) — жду до 2 минут…"
        sleep 5; waited=$((waited + 5))
        [ "$waited" -ge 120 ] && break
    done
    fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || return 0
    msg_warn "останавливаю apt-daily / unattended-upgrades, чтобы освободить dpkg"
    systemctl kill --kill-who=all --signal=SIGTERM apt-daily.service apt-daily-upgrade.service unattended-upgrades.service >/dev/null 2>&1
    waited=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && [ "$waited" -lt 120 ]; do sleep 5; waited=$((waited + 5)); done
    # прерванный dpkg мог оставить пакет полунастроенным — доводим
    dpkg --configure -a >/dev/null 2>&1 || true
}

# get.docker.com напрямую доверяем как есть; копию из зеркала — только при совпадении двух
# источников; иначе — подписанные пакеты дистрибутива
node_docker_install() {
    have docker && docker info >/dev/null 2>&1 && return 0
    local s; s=$(mktemp)
    msg_info "ставлю Docker…"
    if { download_file https://get.docker.com "$s" && head -1 "$s" | grep -q '^#!/bin/sh'; } \
       || download_verified https://raw.githubusercontent.com/docker/docker-install/master/install.sh "$s" /bin/sh; then
        wait_for_dpkg_lock
        if ! sh "$s"; then
            msg_warn "повтор через зеркало Aliyun"
            sh "$s" --mirror Aliyun || { rm -f "$s"; msg_err "Docker не установился"; return 1; }
        fi
    else
        msg_warn "скрипт Docker не скачан/не подтверждён — ставлю docker.io из репозитория дистрибутива"
        wait_for_dpkg_lock
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io docker-compose-v2 </dev/null \
            || DEBIAN_FRONTEND=noninteractive apt-get install -y -q docker.io </dev/null \
            || { rm -f "$s"; msg_err "Docker не установился"; return 1; }
    fi
    rm -f "$s"
}

node_docker_mirrors() {
    local f=/etc/docker/daemon.json
    mkdir -p /etc/docker
    if [ ! -s "$f" ]; then
        printf '{\n  "log-driver": "local",\n  "registry-mirrors": %s\n}\n' "$DOCKER_MIRRORS" > "$f"
    elif jq -e 'has("registry-mirrors")' "$f" >/dev/null 2>&1; then
        return 0
    elif jq empty "$f" >/dev/null 2>&1 \
         && jq --argjson m "$DOCKER_MIRRORS" '.["registry-mirrors"] = $m | if has("log-driver") then . else .["log-driver"] = "local" end' \
            "$f" > "$f.tmp" 2>/dev/null; then
        mv -f "$f.tmp" "$f"
    else
        rm -f "$f.tmp"
        msg_warn "$f не разобрался как JSON — зеркала Docker Hub не добавлены"
        return 0
    fi
    msg_ok "зеркала Docker Hub: mirror.gcr.io, dockerhub.timeweb.cloud"
    systemctl restart docker >/dev/null 2>&1
}

node_packages() {
    if have docker && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1 \
       && have certbot && have dig && have jq && have unzip && have crontab; then
        msg_ok "Docker, certbot и утилиты уже установлены"
        return 0
    fi
    ui_head "Пакеты" "Docker · certbot · утилиты"
    apt_lock_wait_conf
    wait_for_dpkg_lock
    apt-get -o DPkg::Lock::Timeout=300 update -q </dev/null || { msg_err "apt-get update не удался"; return 1; }
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q "${NODE_APT_PKGS[@]}" </dev/null \
        || { msg_err "пакеты не установились"; return 1; }
    ensure_cron
    node_docker_install || return 1
    systemctl enable --now docker >/dev/null 2>&1 || { msg_err "docker не запускается"; return 1; }
    node_docker_mirrors
    docker info >/dev/null 2>&1 || { msg_err "docker установлен, но не отвечает"; return 1; }
    docker compose version >/dev/null 2>&1 || { msg_err "нет docker compose (плагин compose v2)"; return 1; }
    # автообновления безопасности
    grep -q 'Unattended-Upgrade::Mail' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null \
        || echo 'Unattended-Upgrade::Mail "root";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' | debconf-set-selections
    if dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 \
       && systemctl restart unattended-upgrades >/dev/null 2>&1; then
        msg_ok "автообновления безопасности включены"
    else
        msg_warn "unattended-upgrades не настроился — не критично"
    fi
    msg_ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null), $(certbot --version 2>&1 | head -1)"
}

# ── предусловия ──────────────────────────────────────────────────────
# Запущенная нода — стоп; остановленные контейнеры с теми же именами мешают compose up
node_check_existing() {
    local running stopped
    running=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -xE 'remnanode|remnawave-nginx' | paste -sd' ' -)
    if [ -n "$running" ]; then
        die "уже запущено: $running. Поверх работающей ноды не ставлю — останови: cd $REMNANODE_DIR && docker compose down"
    fi
    stopped=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -xE 'remnanode|remnawave-nginx' | paste -sd' ' -)
    if [ -n "$stopped" ]; then
        msg_warn "остались остановленные контейнеры: $stopped"
        confirm "Удалить их (docker rm)?" || die "отменено: compose не создаст контейнеры с занятыми именами"
        # shellcheck disable=SC2086  # список имён через пробел
        docker rm $stopped >/dev/null
    fi
}

# 443 займёт xray ноды, 80 — nginx (редирект на https): чужой слушатель
# (Caddy/apache от другого установщика и т.п.) — стоп до записи конфигов
node_port_free() {   # <порт> <кто его займёт>
    local who
    who=$(ss -Htlnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u | paste -sd, -)
    if [ -z "$who" ] && ss -Htln "sport = :$1" 2>/dev/null | grep -q .; then who="неизвестный процесс"; fi
    [ -z "$who" ] && return 0
    die "порт $1 занят ($who) — его должен занять $2. Останови сервис и запусти установку снова"
}

# SECRET_KEY из карточки ноды: вставка в несколько строк, конец — пустая строка.
# Понимает и вставку целиком «NODE_PORT=…/SECRET_KEY=…» (тогда берёт и порт).
# → NODE_SECRET, NODE_PORT_PASTED
node_read_secret() {   # rc: 0 — ок, 1 — неверный ключ, 2 — EOF
    local line
    NODE_SECRET="" NODE_PORT_PASTED=""
    echo -e "  ${BOLD}SECRET_KEY ноды${NC} ${DIM}(карточка ноды в панели; вставь и нажми Enter на пустой строке)${NC}:"
    while true; do
        IFS= read -r line || { [ -n "$NODE_SECRET" ] && break; return 2; }
        line="${line//[[:space:]]/}"
        if [ -z "$line" ]; then [ -n "$NODE_SECRET" ] && break; continue; fi
        case "$line" in
            NODE_PORT=*|APP_PORT=*) NODE_PORT_PASTED="${line#*=}"; NODE_PORT_PASTED="${NODE_PORT_PASTED//[\"\']/}"; continue ;;
            SECRET_KEY=*|SSL_CERT=*) line="${line#*=}" ;;
        esac
        NODE_SECRET+="${line//[\"\']/}"
    done
    [ -n "$NODE_SECRET" ] || return 1
    [[ "$NODE_SECRET" =~ ^[A-Za-z0-9+/=._-]{20,}$ ]] || { msg_err "это не похоже на SECRET_KEY (ждём base64-строку)"; return 1; }
}

# ── рендер конфигов (чистые функции — проверяются smoke-тестом) ──────
node_render_env() {   # <каталог> <порт> <secret>
    ( umask 077; printf 'NODE_PORT=%s\nSECRET_KEY=%s\n' "$2" "$3" > "$1/.env" )
}

# Сертификаты — каталогами: live/ со ссылками certbot (../../archive/…) и archive/ рядом,
# так любой lineage и продление видны nginx без правки compose (после nginx -s reload).
# xray — смонтировать своё ядро $XRAY_BIN в remnanode.
node_render_compose() {   # <каталог> [xray]
    local xray_vol=""
    [ "${2:-}" = xray ] && xray_vol=$'\n'"      - $XRAY_BIN:$XRAY_TARGET:ro"
    cat > "$1/docker-compose.yml" <<EOF
# Managed by node-diagnostic ($ND_VERSION): rr install node
x-common: &common
  ulimits:
    nofile:
      soft: 1048576
      hard: 1048576
  restart: always

x-logging: &logging
  logging:
    driver: json-file
    options:
      max-size: 100m
      max-file: 5

services:
  remnawave-nginx:
    image: $NGINX_IMAGE
    container_name: remnawave-nginx
    hostname: remnawave-nginx
    <<: [*common, *logging]
    network_mode: host
    volumes:
      - ./nginx-main.conf:/etc/nginx/nginx.conf:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - $LE_LIVE:/etc/nginx/ssl:ro
      - $LE_ARCHIVE:/etc/nginx/archive:ro
      - /dev/shm:/dev/shm:rw
      - $WEB_ROOT:/var/www/html:ro
    command: sh -c 'rm -f $NGINX_SOCK && exec nginx -g "daemon off;"'

  remnanode:
    image: $NODE_IMAGE
    container_name: remnanode
    hostname: remnanode
    <<: [*common, *logging]
    network_mode: host
    cap_add:
      - NET_ADMIN
    env_file:
      - .env
    volumes:
      - /dev/shm:/dev/shm:rw
      - /var/log/remnanode:/var/log/remnanode$xray_vol
EOF
}

# Сайт selfsteal (conf.d/default.conf): xray (Reality, xver 1) отдаёт «чужие»
# TLS-соединения на unix-сокет, nginx отвечает сайтом-заглушкой; неизвестные SNI —
# обрыв рукопожатия; :80 — редирект на https, как у обычного сайта.
# access_log в формате proxy_protocol (реальный IP клиента) — формат объявлен в
# nginx-main.conf, без него nginx не стартует. OCSP stapling нет: Let's Encrypt
# с 2025 не пишет OCSP-URL в сертификаты и выключил респондеры — nginx его игнорирует.
node_render_nginx() {   # <каталог> <домен> <каталог сертификата в live/>
    local d=$2 l=$3
    cat > "$1/nginx.conf" <<EOF
# Managed by node-diagnostic ($ND_VERSION): rr install node
server_names_hash_bucket_size 64;

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ""      close;
}
ssl_protocols       TLSv1.3;
ssl_session_timeout 1h;
ssl_session_cache   shared:SSL:10m;
ssl_session_tickets off;

server {
    server_name $d;
    listen unix:$NGINX_SOCK ssl proxy_protocol;
    http2 on;

    ssl_certificate "/etc/nginx/ssl/$l/fullchain.pem";
    ssl_certificate_key "/etc/nginx/ssl/$l/privkey.pem";
    ssl_trusted_certificate "/etc/nginx/ssl/$l/fullchain.pem";

    # Logging (proxy_protocol format includes real client IP)
    access_log /var/log/nginx/access.log proxy_protocol;
    error_log /var/log/nginx/error.log warn;

    root /var/www/html;
    index index.html;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Cache static files
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}

server {
    listen unix:$NGINX_SOCK ssl proxy_protocol default_server;
    server_name _;
    add_header X-Robots-Tag "noindex, nofollow, noarchive, nosnippet, noimageindex" always;
    ssl_reject_handshake on;
    return 444;
}

server {
    listen 80 default_server;
    server_name _;
    return 301 https://\$host\$request_uri;
}
EOF
}

# Главный /etc/nginx/nginx.conf контейнера: воркеры, лимиты, буферы, gzip и
# log_format proxy_protocol, на который ссылается сайт. worker_connections 4096:
# таблица соединений выделяется заранее (~450 байт × N на воркер), а до nginx
# через xray доходят только зонды и редкие заходы на сайт
node_render_nginx_main() {   # <каталог>
    {
        echo "# Managed by node-diagnostic ($ND_VERSION): rr install node"
        cat <<'EOF'
user nginx;
worker_processes auto;
worker_rlimit_nofile 131072;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    log_format proxy_protocol '$proxy_protocol_addr - $remote_user [$time_local] "$request" '
                              '$status $body_bytes_sent "$http_referer" '
                              '"$http_user_agent"';

    access_log /var/log/nginx/access.log main;

    # Performance optimizations
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 1000;
    types_hash_max_size 2048;
    server_tokens off;

    # Buffer optimizations
    client_body_buffer_size 16k;
    client_header_buffer_size 1k;
    client_max_body_size 8m;
    large_client_header_buffers 4 8k;

    # Open file cache for static files
    open_file_cache max=10000 inactive=30s;
    open_file_cache_valid 60s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    # Gzip compression (aggressive)
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_min_length 256;
    gzip_buffers 16 8k;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript
               application/xml application/rss+xml application/atom+xml image/svg+xml
               application/x-javascript application/xhtml+xml application/x-font-ttf
               font/opentype image/x-icon;

    include /etc/nginx/conf.d/*.conf;
}
EOF
    } > "$1/nginx-main.conf"
}

# ── шаблон selfsteal-сайта ───────────────────────────────────────────
# Случайный шаблон из трёх наборов + рандомизация (title/meta/class/комментарии),
# чтобы ноды на одном шаблоне не совпадали отпечатком. Новый сайт кладётся рядом и
# подменяет старый поэлементно: каталог примонтирован в nginx, замена каталога целиком
# пропала бы из контейнера.
selfsteal_template() {   # [web_root]
    local dest=${1:-$WEB_ROOT} tmp url ref dir pick p ok=0 round
    local -a list
    tmp=$(mktemp -d)
    url=${TEMPLATE_URLS[RANDOM % ${#TEMPLATE_URLS[@]}]}
    for round in 1 2; do
        for p in "${GH_PREFIXES[@]}"; do
            download_file "$p$url" "$tmp/t.zip" && [ "$(head -c 2 "$tmp/t.zip")" = "PK" ] && { ok=1; break 2; }
        done
        [ "$round" = 1 ] && sleep 3
    done
    [ "$ok" = 1 ] || { rm -rf "$tmp"; msg_err "шаблон не скачался (GitHub и прокси недоступны)"; return 1; }
    unzip -q -o "$tmp/t.zip" -d "$tmp" || { rm -rf "$tmp"; msg_err "архив шаблона не распаковался"; return 1; }
    ref=${url##*/}; ref=${ref%.zip}

    case "$url" in
        *eGamesAPI*)   dir="$tmp/simple-web-templates-$ref"; rm -rf "$dir/assets" "$dir/.gitattributes" "$dir/README.md" "$dir/_config.yml" ;;
        *nothing-sni*) dir="$tmp/nothing-sni-$ref";          rm -rf "$dir/.github" "$dir/README.md" ;;
        *)             dir="$tmp/sni-templates-$ref";        rm -rf "$dir/assets" "$dir/README.md" "$dir/index.html" ;;
    esac
    [ -d "$dir" ] || { rm -rf "$tmp"; msg_err "неожиданная структура архива шаблона"; return 1; }
    # nothing-sni — отдельные .html, остальные наборы — каталоги с сайтом
    if [[ "$url" == *nothing-sni* ]]; then
        mapfile -t list < <(find "$dir" -maxdepth 1 -type f -name '*.html' -printf '%f\n' | sort)
    else
        mapfile -t list < <(for p in "$dir"/*/; do
            p=${p%/}; [ -n "$(find "$p" -type f -name '*.html' -print -quit)" ] && basename "$p"
        done | sort)
    fi
    [ "${#list[@]}" -gt 0 ] || { rm -rf "$tmp"; msg_err "в архиве нет шаблонов"; return 1; }
    pick=${list[RANDOM % ${#list[@]}]}
    if [[ "$url" == *distillium* && "$pick" == "503 error pages" ]]; then
        p=$(( RANDOM % 2 + 1 )); pick="$pick/v$p"
    fi

    local src="$dir/$pick" meta_id comment cls title footer meta_name user
    local -a meta_names=(viewport-id session-id track-id render-id page-id config-id)
    local -a users=(Payee6296 UserX1234 AlphaBeta GammaRay DeltaForce EchoZulu Foxtrot99 HotelCalifornia IndiaInk JulietBravo)
    local -a prefixes=(style data ui layout theme view)
    meta_id=$(openssl rand -hex 16); comment=$(openssl rand -hex 8)
    cls="${prefixes[RANDOM % ${#prefixes[@]}]}-$(openssl rand -hex 4)"
    title="Page_$(openssl rand -hex 4)"; footer="Designed by RandomSite_$(openssl rand -hex 4)"
    meta_name=${meta_names[RANDOM % ${#meta_names[@]}]}; user=${users[RANDOM % ${#users[@]}]}
    local idsfx; idsfx=$(openssl rand -hex 4)
    find "$src" -type f -name '*.html' -exec sed -i \
        -e "s|<!-- Website template by freewebsitetemplates.com -->||" \
        -e "s|<!-- Theme by: WebThemez.com -->||" \
        -e "s|<a href=\"http://freewebsitetemplates.com\">Free Website Templates</a>|<span>${footer}</span>|" \
        -e "s|<a href=\"http://webthemez.com\" alt=\"webthemez\">WebThemez.com</a>|<span>${footer}</span>|" \
        -e "s|id=\"Content\"|id=\"rnd_${idsfx}\"|" \
        -e "s|id=\"subscribe\"|id=\"sub_${idsfx}\"|" \
        -e "s|<title>.*</title>|<title>${title}</title>|" \
        -e "s|</head>|<meta name=\"${meta_name}\" content=\"${meta_id}\">\n<!-- ${comment} -->\n</head>|" \
        -e "s|\(<body[^>]*[[:space:]]\)class=\"|\1class=\"${cls} |" \
        -e "/<body[^>]*[[:space:]]class=/!s|<body\([^>]*\)>|<body\1 class=\"${cls}\">|" \
        -e "s/CHANGEMEPLS/${user}/g" \
        {} \;
    while IFS= read -r -d '' p; do
        printf '/* %s */\n.%s { display: block; }\n' "$comment" "$cls" >> "$p"
    done < <(find "$src" -type f -name '*.css' -print0)
    grep -Rqs --include='*.html' "$meta_id" "$src" \
        || { rm -rf "$tmp"; msg_err "не удалось рандомизировать HTML шаблона"; return 1; }

    local stage="${dest%/}.nd-stage"
    rm -rf "$stage"; mkdir -p "$stage" "$dest"
    if [ -d "$src" ]; then cp -a "$src"/. "$stage/"; else cp "$src" "$stage/index.html"; fi \
        || { rm -rf "$stage" "$tmp"; msg_err "не скопировал шаблон"; return 1; }
    rm -rf "${dest:?}"/* "$dest"/.[!.]* "$dest"/..?* 2>/dev/null
    find "$stage" -mindepth 1 -maxdepth 1 -exec mv -t "$dest/" -- {} + \
        || { rm -rf "$stage" "$tmp"; msg_err "не переложил шаблон в $dest"; return 1; }
    rm -rf "$stage" "$tmp"
    msg_ok "шаблон сайта: ${pick} → $dest"
}

# Нода отвечает сайтом по https? Xray поднимет 443, когда панель пришлёт ей конфиг —
# поэтому несколько попыток с паузой
node_wait_https() {   # <домен>
    local i
    for i in 1 2 3 4 5; do
        if curl -s --fail --max-time 10 "https://$1" 2>/dev/null | grep -qi html; then
            msg_ok "https://$1 отвечает сайтом-заглушкой — нода подключена"
            return 0
        fi
        msg_info "попытка $i/5: https://$1 пока не отвечает"
        [ "$i" -lt 5 ] && sleep 15
    done
    return 1
}

# бэкап конфигов прошлой установки (DigneZzZ / ручной) перед перезаписью
node_backup_old() {
    local ts f n=0
    ts=$(date +%Y%m%d-%H%M%S)
    for f in docker-compose.yml .env nginx.conf nginx-main.conf; do
        [ -e "$REMNANODE_DIR/$f" ] || continue
        cp -a "$REMNANODE_DIR/$f" "$REMNANODE_DIR/$f.bak-$ts" && n=$((n + 1))
    done
    [ "$n" -gt 0 ] && msg_info "прежние конфиги сохранены: $REMNANODE_DIR/*.bak-$ts"
    return 0
}

# ── установка ────────────────────────────────────────────────────────
node_install() {
    ui_head "Установка ноды Remnawave" "nginx-selfsteal · порт eGamesAPI/remnawave-reverse-proxy"
    need_root || die "нужен root"
    [ -t 0 ] || die "нужен интерактивный терминал — установка спрашивает домен, IP панели и ключ"
    have systemctl || die "нужен systemd"
    node_check_os
    msg_info "будет: Docker + certbot, сертификат, $REMNANODE_DIR/{docker-compose.yml,.env,nginx.conf,nginx-main.conf}, сайт в $WEB_ROOT"
    msg_info "порты: 443 — xray ноды, 80 — nginx (редирект на https)"
    confirm "Продолжить?" || { msg_info "отменено"; return 1; }

    node_packages || die "подготовка пакетов не удалась"
    node_check_existing
    node_port_free 443 "xray ноды"
    node_port_free 80 "nginx ноды (редирект http→https)"

    local domain pip port lineage
    ui_head "Параметры ноды" ""
    while true; do
        ask "Selfsteal-домен ноды (адрес из её карточки в панели)" domain || die "отменено"
        domain="${domain,,}"
        is_domain "$domain" && break
        msg_warn "это не доменное имя"
    done
    # selfsteal — только DNS-only: прокси Cloudflare ломает Reality
    check_domain "$domain" false
    [ $? -eq 2 ] && die "отменено"
    while true; do
        ask "IP панели Remnawave" pip || die "отменено"
        is_ipv4 "$pip" && break
        msg_warn "это не IPv4-адрес"
    done
    local rc
    while true; do
        node_read_secret; rc=$?
        [ "$rc" = 0 ] && break
        [ "$rc" = 2 ] && die "отменено"
        msg_warn "вставь SECRET_KEY ещё раз"
    done
    port=${NODE_PORT_PASTED:-$NODE_PORT_DEFAULT}
    while true; do
        ask "NODE_PORT (порт панель→нода, как в карточке ноды)" port "$port" || die "отменено"
        [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ] && [ "$port" != 443 ] && break
        msg_warn "порт — число 1-65535, не 443"
    done
    local xray_url="" xray=""
    while true; do
        ask "Своё ядро Xray — ссылка на бинарь или zip (Enter — встроенное в remnanode)" xray_url || die "отменено"
        [ -z "$xray_url" ] || [[ "$xray_url" =~ ^https?://[^[:space:]]+$ ]] && break
        msg_warn "нужна http(s)-ссылка, напр. https://github.com/XTLS/Xray-core/releases/download/vX.Y.Z/Xray-linux-64.zip"
    done

    certs_for_domain "$domain" || die "без сертификата нода не запустится — установка остановлена"
    lineage=$CERT_LINEAGE
    le_relativize_links "$lineage"

    ui_head "Конфигурация" "$REMNANODE_DIR"
    mkdir -p "$REMNANODE_DIR" /var/log/remnanode "$WEB_ROOT"
    node_backup_old
    if [ -n "$xray_url" ]; then
        if node_xray_fetch "$xray_url"; then
            xray=xray
        else
            msg_warn "своё ядро не поставлено — нода запустится со встроенным; позже: rr node xray <ссылка>"
        fi
    fi
    node_render_env "$REMNANODE_DIR" "$port" "$NODE_SECRET"
    node_render_compose "$REMNANODE_DIR" "$xray"
    node_render_nginx "$REMNANODE_DIR" "$domain" "$lineage"
    node_render_nginx_main "$REMNANODE_DIR"
    msg_ok "docker-compose.yml · .env (NODE_PORT=$port) · nginx.conf (сайт) · nginx-main.conf${xray:+ · своё ядро Xray}"

    ui_head "Сайт-заглушка" "случайный шаблон selfsteal"
    selfsteal_template "$WEB_ROOT" || msg_warn "шаблон не поставлен — положи свой сайт в $WEB_ROOT (index.html), иначе nginx отдаст пустой каталог"

    ui_head "Запуск" "docker compose up -d"
    local out
    if ! out=$(cd "$REMNANODE_DIR" && docker compose up -d 2>&1); then
        echo "$out" | tail -15 | sed 's/^/    /'
        die "docker compose up не удался — смотри вывод выше"
    fi
    msg_ok "контейнеры remnanode и remnawave-nginx запущены"
    record_fix "node install: $domain (cert $lineage, NODE_PORT $port) → $REMNANODE_DIR"

    ui_head "Проверка" "https://$domain"
    local connected=1
    node_wait_https "$domain" || connected=0

    echo
    box_top "НОДА УСТАНОВЛЕНА"
    box_kv "Домен" "$domain"
    box_kv "Сертификат" "$LE_LIVE/$lineage"
    box_kv "NODE_PORT" "$port (панель $pip)"
    box_kv "Каталог" "$REMNANODE_DIR"
    [ -n "$xray" ] && box_kv "Ядро Xray" "своё: ${XRAY_VERSION:-?}"
    box_kv "Логи" "cd $REMNANODE_DIR && docker compose logs -f"
    box_kv "Управление" "rr node domain add|del · rr node update · rr node xray"
    box_bottom
    if [ "$connected" = 0 ]; then
        msg_warn "сайт по https пока не отвечает — нода ещё не получила конфиг от панели. Проверь:"
        msg_info "  · нода добавлена в панели, адрес — этот сервер, порт $port"
        msg_info "  · профиль Xray: Reality target (dest) = $NGINX_SOCK, xver = 1, serverNames = [\"$domain\"]"
        msg_info "  · панель достаёт до $port/tcp (firewall хостера)"
    else
        msg_info "профиль Xray в панели: Reality target = $NGINX_SOCK, xver = 1, serverNames = [\"$domain\"]"
    fi
    echo
    if have nft && nft list table inet node_protect >/dev/null 2>&1; then
        msg_info "firewall node_protect активен — проверь, что в нём IP панели $pip и порт $port:"
        msg_info "  nft list table inet node_protect | grep -E '$port|panel'"
    else
        msg_warn "NODE_PORT $port открыт всем, пока не закрыт firewall'ом. Сгенерировать правила под IP панели:"
        msg_info "  rr protect --panel-ip $pip --node-port $port"
    fi
}

# ── управление установленной нодой ───────────────────────────────────
# Файлы правятся на месте: nginx.conf смонтирован в контейнер файлом, и запись с новым
# inode (mv) контейнер бы не увидел. Перед каждой правкой — бэкап <файл>.bak-<время>.
_node_py() { python3 "$NODE_PY" "$@"; }
_node_compose() { (cd "$REMNANODE_DIR" && docker compose "$@"); }
_node_running() { docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$1"; }
# после up -d: контейнер работает, а не крутится в перезапусках (restart: always)
_node_alive() { sleep 3; [ "$(docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null)" = running ]; }
_node_image() { _node_py compose-image "$REMNANODE_DIR/docker-compose.yml" "$1" 2>/dev/null; }

_node_image_present() {   # <образ> — есть локально или скачивается
    docker image inspect "$1" >/dev/null 2>&1 && return 0
    msg_info "docker pull $1…"
    docker pull -q "$1" >/dev/null 2>&1 && return 0
    msg_err "образ $1 не скачался"
    return 1
}

# новый файл → цель на месте (тот же inode), бэкап в ND_LAST_BACKUP
_node_write_inplace() {   # <новый файл> <цель>
    ND_LAST_BACKUP="$2.bak-$(date +%Y%m%d-%H%M%S)"
    cp -a "$2" "$ND_LAST_BACKUP" || return 1
    cat "$1" > "$2" && return 0
    cat "$ND_LAST_BACKUP" > "$2"
    return 1
}

node_require() {
    need_root || die "нужен root"
    have docker || die "нет docker — нода не установлена (rr install node)"
    [ -f "$REMNANODE_DIR/docker-compose.yml" ] \
        || die "нет $REMNANODE_DIR/docker-compose.yml — нода не установлена (rr install node)"
    have python3 || ensure_pkg python3 python3 python3 python3 || die "нужен python3 (apt install python3)"
}

node_require_nginx() {
    node_require
    [ -f "$REMNANODE_DIR/nginx.conf" ] || die "нет $REMNANODE_DIR/nginx.conf — нода без nginx-selfsteal"
    _node_py sites "$REMNANODE_DIR/nginx.conf" >/dev/null \
        || die "в $REMNANODE_DIR/nginx.conf не найден сайт selfsteal (server с listen … ssl без default_server)"
}

# Пути ssl_certificate* конфига → файлы на хосте (/etc/nginx/ssl → live/, /etc/nginx/archive →
# archive/). Ссылки live/ → archive/ делаются относительными. rc 1 — сертификата нет
node_certs_check() {   # <nginx.conf>
    local paths p host lin bad=0 end days
    paths=$(_node_py certs "$1") || { msg_err "nginx.conf не разобрался"; return 1; }
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        case "$p" in
            /etc/nginx/ssl/*)
                host="$LE_LIVE/${p#/etc/nginx/ssl/}"
                lin=${p#/etc/nginx/ssl/}; lin=${lin%%/*}
                [ -d "$LE_LIVE/$lin" ] && le_relativize_links "$lin" ;;
            /etc/nginx/archive/*) host="$LE_ARCHIVE/${p#/etc/nginx/archive/}" ;;
            *) msg_info "$p — вне /etc/nginx/ssl, его проверит nginx -t"; continue ;;
        esac
        if [ ! -s "$host" ]; then
            msg_err "нет сертификата: $host (в nginx.conf: $p)"
            bad=1; continue
        fi
        case "$p" in
            */fullchain.pem|*/cert.pem)
                end=$(openssl x509 -in "$host" -noout -enddate 2>/dev/null | cut -d= -f2-)
                days=$(cert_days_left "$end" 2>/dev/null) || days=""
                [ -n "$days" ] && [ "$days" -lt 0 ] && msg_warn "$host просрочен $(( -days )) дн. назад" ;;
        esac
    done <<< "$paths"
    return "$bad"
}

# nginx -t конфига-кандидата в отдельном контейнере с маунтами ноды — живой nginx не трогается
node_nginx_test() {   # <образ> <nginx.conf>
    local img=$1 out main="$REMNANODE_DIR/nginx-main.conf"
    local -a mainv=()
    [ -f "$main" ] && mainv=(-v "$main:/etc/nginx/nginx.conf:ro")
    _node_image_present "$img" || return 1
    if ! out=$(docker run --rm --network none ${mainv[@]+"${mainv[@]}"} \
            -v "$2:/etc/nginx/conf.d/default.conf:ro" \
            -v "$LE_LIVE:/etc/nginx/ssl:ro" -v "$LE_ARCHIVE:/etc/nginx/archive:ro" \
            -v "$WEB_ROOT:/var/www/html:ro" --entrypoint nginx "$img" -t 2>&1); then
        msg_err "nginx -t ($img) не прошёл:"
        printf '%s\n' "$out" | grep -v 'test failed' | tail -n 6 | sed 's/^/      /'
        return 1
    fi
}

# Записать nginx.conf ноды на месте и перечитать. Сертификаты и nginx -t — до записи;
# живой nginx не принял — прежний конфиг возвращается
node_nginx_apply() {   # <кандидат>
    local conf="$REMNANODE_DIR/nginx.conf" img out
    node_certs_check "$1" || return 1
    img=$(_node_image remnawave-nginx) || img=$NGINX_IMAGE
    node_nginx_test "$img" "$1" || return 1
    _node_write_inplace "$1" "$conf" || { msg_err "не записал $conf"; return 1; }
    if ! _node_running "$NGINX_CONTAINER"; then
        msg_warn "$NGINX_CONTAINER не запущен — конфиг записан, применится при старте (cd $REMNANODE_DIR && docker compose up -d)"
        return 0
    fi
    if out=$(docker exec "$NGINX_CONTAINER" nginx -t 2>&1) \
       && docker exec "$NGINX_CONTAINER" nginx -s reload >/dev/null 2>&1; then
        msg_ok "nginx перечитал конфиг (бэкап: $ND_LAST_BACKUP)"
        return 0
    fi
    printf '%s\n' "$out" | tail -n 5 | sed 's/^/      /'
    cat "$ND_LAST_BACKUP" > "$conf"
    docker exec "$NGINX_CONTAINER" nginx -s reload >/dev/null 2>&1
    msg_err "nginx не принял конфиг — возвращён прежний"
    return 1
}

# compose прежних версий (файлы одного сертификата, закреплённый тег nginx) → каталоги
# live/archive и nginx:alpine. Изменился — nginx пересоздаётся; не поднялся — compose
# возвращается. rc 1 — compose не разобрался или nginx не принял новые тома
node_layout() {
    local f="$REMNANODE_DIR/docker-compose.yml" tmp res out img
    tmp=$(mktemp)
    if ! res=$(_node_py compose-migrate "$f" --out "$tmp" --live "$LE_LIVE" --archive "$LE_ARCHIVE" --image "$NGINX_IMAGE"); then
        rm -f "$tmp"
        msg_err "$f не переведён на каталоги сертификатов — поправь тома remnawave-nginx вручную"
        return 1
    fi
    [ "$res" = same ] && { rm -f "$tmp"; return 0; }
    ui_head "docker-compose.yml" "сертификаты — каталогами, nginx — $NGINX_IMAGE"
    # ссылки live/ → archive/ должны стать относительными до пересоздания nginx
    if [ -f "$REMNANODE_DIR/nginx.conf" ]; then
        node_certs_check "$REMNANODE_DIR/nginx.conf" || { rm -f "$tmp"; return 1; }
        img=$(_node_py compose-image "$tmp" remnawave-nginx 2>/dev/null) || img=$NGINX_IMAGE
        node_nginx_test "$img" "$REMNANODE_DIR/nginx.conf" || { rm -f "$tmp"; return 1; }
    fi
    _node_write_inplace "$tmp" "$f" || { rm -f "$tmp"; msg_err "не записал $f"; return 1; }
    rm -f "$tmp"
    msg_ok "$f: тома $LE_LIVE и $LE_ARCHIVE, образ $NGINX_IMAGE (бэкап: $ND_LAST_BACKUP)"
    _node_running "$NGINX_CONTAINER" || return 0
    if out=$(_node_compose up -d remnawave-nginx 2>&1) && _node_alive "$NGINX_CONTAINER"; then
        msg_ok "$NGINX_CONTAINER пересоздан с новыми томами"
        return 0
    fi
    printf '%s\n' "$out" | tail -n 6 | sed 's/^/      /'
    cat "$ND_LAST_BACKUP" > "$f"
    _node_compose up -d remnawave-nginx >/dev/null 2>&1
    msg_err "nginx не поднялся с новыми томами — docker-compose.yml возвращён"
    return 1
}

# без TTY DNS не правим — только предупреждение
_node_dns_note() {   # <домен>
    local sip dip
    sip=$(public_ipv4) || return 0
    dip=$(domain_a_record "$1") || dip=""
    [ "$dip" = "$sip" ] && { msg_ok "$1 → $sip (этот сервер)"; return 0; }
    msg_warn "$1 указывает на ${dip:-ничего}, а IP этого сервера — $sip (DNS не меняю: нет терминала)"
}

node_domain_list() {
    node_require_nginx
    local names cert lin days
    echo
    box_top "ДОМЕНЫ НОДЫ"
    while IFS=$'\t' read -r names cert; do
        lin=${cert#/etc/nginx/ssl/}; lin=${lin%%/*}
        if [ "$cert" = "-" ]; then days="сертификат не задан"
        elif [ ! -s "$LE_LIVE/${cert#/etc/nginx/ssl/}" ]; then days="${R}нет файла сертификата${NC}"
        elif days=$(check_cert_expiry "$lin" 2>/dev/null); then days="$lin · $days дн."
        else days="$lin"; fi
        box_kv "$names" "$days" 30
    done < <(_node_py sites "$REMNANODE_DIR/nginx.conf")
    box_bottom
}

node_domain_add() {   # <домен>
    local domain=${1,,} conf="$REMNANODE_DIR/nginx.conf" tmp lineage rc days
    node_require_nginx
    is_domain "$domain" || die "это не доменное имя: $1"
    if _node_py names "$conf" | grep -qixF "$domain"; then
        msg_ok "$domain уже есть на ноде"
        return 0
    fi
    ui_head "Новый домен ноды" "$domain"
    if [ -t 0 ]; then
        check_domain "$domain" false
        [ $? -eq 2 ] && { msg_info "отменено"; return 1; }
    else
        _node_dns_note "$domain"
    fi
    if lineage=$(resolve_certificate_domain "$domain"); then
        days=$(check_cert_expiry "$lineage") || days="?"
        msg_ok "сертификат: $LE_LIVE/$lineage (осталось $days дн.)"
    else
        msg_warn "сертификата для $domain нет"
        [ -t 0 ] || die "выпусти его: rr certs issue $domain — и повтори"
        confirm "Выпустить сертификат для $domain сейчас?" || { msg_info "отменено"; return 1; }
        certs_for_domain "$domain" || die "сертификат не выпущен — домен не добавлен"
        lineage=$CERT_LINEAGE
    fi
    node_layout || die "домен не добавлен"
    tmp=$(mktemp)
    _node_py add "$conf" "$domain" "$lineage" --out "$tmp"; rc=$?
    case "$rc" in
        0) ;;
        3) rm -f "$tmp"; msg_ok "$domain уже есть на ноде"; return 0 ;;
        *) rm -f "$tmp"; die "nginx.conf не разобрался — домен не добавлен" ;;
    esac
    node_nginx_apply "$tmp" || { rm -f "$tmp"; die "домен не добавлен — nginx.conf прежний"; }
    rm -f "$tmp"
    record_fix "node domain add $domain (cert $lineage)"
    msg_ok "$domain добавлен: сайт-заглушка отвечает и на него"
    msg_info "в панели: добавь $domain в serverNames профиля Reality этой ноды"
}

node_domain_del() {   # <домен>
    local domain=${1,,} conf="$REMNANODE_DIR/nginx.conf" tmp rc
    node_require_nginx
    is_domain "$domain" || die "это не доменное имя: $1"
    tmp=$(mktemp)
    _node_py del "$conf" "$domain" --out "$tmp" 2>/dev/null; rc=$?
    case "$rc" in
        0) ;;
        3) rm -f "$tmp"; die "$domain нет среди сайтов ноды (rr node domain list)" ;;
        5) rm -f "$tmp"; die "$domain — последний домен ноды; удалять нельзя (сначала добавь другой)" ;;
        *) rm -f "$tmp"; die "nginx.conf не разобрался — домен не удалён" ;;
    esac
    if [ -t 0 ]; then
        confirm "Убрать $domain с ноды?" || { rm -f "$tmp"; msg_info "отменено"; return 1; }
    fi
    ui_head "Удаление домена" "$domain"
    node_layout || { rm -f "$tmp"; die "домен не удалён"; }
    node_nginx_apply "$tmp" || { rm -f "$tmp"; die "домен не удалён — nginx.conf прежний"; }
    rm -f "$tmp"
    record_fix "node domain del $domain"
    msg_ok "$domain убран с ноды; сертификат остался в $LE_LIVE"
    msg_info "в панели: убери $domain из serverNames профиля Reality этой ноды"
}

# версия для «было → стало»
_node_ver() {   # <сервис>
    case "$1" in
        remnawave-nginx) docker exec "$1" nginx -v 2>&1 | sed -n 's|.*nginx/||p' ;;
        remnanode)
            local c x
            c=$(docker inspect -f '{{.Image}}' "$1" 2>/dev/null) || return 0
            c=$(docker image inspect -f '{{.Created}}' "$c" 2>/dev/null | cut -c1-10)
            x=$(docker exec "$1" "$XRAY_TARGET" version 2>/dev/null | awk 'NR==1{print $2}')
            printf 'образ от %s%s' "${c:-?}" "${x:+, Xray $x}" ;;
    esac
}

# Образы nginx и remnanode — до последней версии по запросу админа. nginx на новом образе
# сначала проходит nginx -t; не прошёл — остаётся на старом. rc 1 — что-то не обновилось
node_update() {   # [nginx|node]
    local -a svcs
    local s img old new before out rc=0
    case "${1:-all}" in
        all) svcs=(remnawave-nginx remnanode) ;;
        nginx|remnawave-nginx) svcs=(remnawave-nginx) ;;
        node|remnanode) svcs=(remnanode) ;;
        *) echo "node update: nginx | node (без аргумента — оба)" >&2; return 2 ;;
    esac
    node_require
    ui_head "Обновление ноды" "${svcs[*]}"
    node_layout || die "обновление остановлено"
    for s in "${svcs[@]}"; do
        img=$(_node_image "$s") || { msg_err "в docker-compose.yml нет сервиса $s"; rc=1; continue; }
        old=$(docker inspect -f '{{.Image}}' "$s" 2>/dev/null)
        msg_info "$s: проверяю $img…"
        if ! out=$(_node_compose pull -q "$s" 2>&1); then
            printf '%s\n' "$out" | tail -n 4 | sed 's/^/      /'
            msg_err "$s: образ $img не скачался"; rc=1; continue
        fi
        new=$(docker image inspect -f '{{.Id}}' "$img" 2>/dev/null)
        if [ -n "$old" ] && [ "$old" = "$new" ]; then
            msg_ok "$s: уже последняя версия ($(_node_ver "$s"))"
            continue
        fi
        if [ "$s" = remnawave-nginx ]; then
            if ! node_nginx_test "$img" "$REMNANODE_DIR/nginx.conf"; then
                msg_err "nginx не обновлён: nginx.conf не проходит проверку на новом образе"
                rc=1; continue
            fi
        elif [ -t 0 ] && [ -n "$old" ]; then
            msg_warn "remnanode перезапустится — клиенты ноды отключатся на несколько секунд"
            confirm "Обновить remnanode сейчас?" || { msg_info "remnanode не обновлён"; continue; }
        fi
        before=$(_node_ver "$s")
        if ! out=$(_node_compose up -d "$s" 2>&1); then
            printf '%s\n' "$out" | tail -n 6 | sed 's/^/      /'
            msg_err "$s: docker compose up не удался"; rc=1; continue
        fi
        if ! _node_alive "$s"; then
            msg_err "$s не работает после обновления — смотри: docker logs --tail 30 $s"
            rc=1; continue
        fi
        msg_ok "$s обновлён: ${before:-?} → $(_node_ver "$s")"
        record_fix "node update $s ($img)"
    done
    if [[ " ${svcs[*]} " == *" remnanode "* ]] \
       && [[ "$(_node_py compose-xray "$REMNANODE_DIR/docker-compose.yml" status 2>/dev/null)" == on* ]]; then
        out=$(sed -n 's/^VERSION=//p' "$XRAY_DIR/SOURCE" 2>/dev/null)
        msg_warn "ядро Xray своё и не обновлялось (${out:-версия неизвестна})"
        msg_info "  несовместимо с новой remnanode — rr node xray off (встроенное) или rr node xray <новая ссылка>"
    fi
    docker image prune -f >/dev/null 2>&1
    return "$rc"
}

_node_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        armv7l|armv6l) echo arm ;;
        *) uname -m ;;
    esac
}

# Скачать ядро по ссылке (бинарь или zip релиза), проверить архитектуру и запуск в образе
# remnanode, положить в $XRAY_BIN. → XRAY_VERSION
node_xray_fetch() {   # <url>
    local url=$1 d arch want img ver p ok=0
    [[ "$url" =~ ^https?://[^[:space:]]+$ ]] || { msg_err "это не http(s)-ссылка: $url"; return 1; }
    have python3 || ensure_pkg python3 python3 python3 python3 || { msg_err "нужен python3"; return 1; }
    mkdir -p "$XRAY_DIR" && d=$(mktemp -d "$XRAY_DIR/.dl.XXXXXX") || { msg_err "не создал $XRAY_DIR"; return 1; }
    msg_info "скачиваю $url…"
    if [[ "$url" == https://github.com/* ]]; then
        for p in "${GH_PREFIXES[@]}"; do download_file "$p$url" "$d/dl" && { ok=1; break; }; done
    else
        download_file "$url" "$d/dl" && ok=1
    fi
    [ "$ok" = 1 ] || { rm -rf "$d"; msg_err "не скачалось: $url"; return 1; }
    if [ "$(head -c 2 "$d/dl")" = PK ]; then
        _node_py unzip-member "$d/dl" xray "$d/xray" || { rm -rf "$d"; msg_err "в архиве нет файла xray"; return 1; }
    else
        mv "$d/dl" "$d/xray"
    fi
    arch=$(_node_py elf-arch "$d/xray" 2>/dev/null) \
        || { rm -rf "$d"; msg_err "по ссылке не бинарь Linux (не ELF) — проверь ссылку"; return 1; }
    want=$(_node_arch)
    if [ "$arch" != "$want" ]; then
        rm -rf "$d"
        msg_err "ядро собрано под $arch, а сервер — $want: возьми другой файл релиза (Xray-linux-64 — x86_64, Xray-linux-arm64-v8a — aarch64)"
        return 1
    fi
    chmod 755 "$d/xray"
    img=$(_node_image remnanode) || img=$NODE_IMAGE
    _node_image_present "$img" || { rm -rf "$d"; return 1; }
    ver=$(docker run --rm --network none --entrypoint "$XRAY_TARGET" -v "$d/xray:$XRAY_TARGET:ro" "$img" version 2>&1 | head -n1)
    case "$ver" in
        Xray*) ;;
        *) rm -rf "$d"; msg_err "ядро не запускается в образе $img: ${ver:-нет вывода}"; return 1 ;;
    esac
    # прежнее ядро — на откат, если remnanode с новым не поднимется
    rm -f "$XRAY_BIN.prev" "$XRAY_DIR/SOURCE.prev"
    [ -f "$XRAY_BIN" ] && cp -a "$XRAY_BIN" "$XRAY_BIN.prev" && { cp -a "$XRAY_DIR/SOURCE" "$XRAY_DIR/SOURCE.prev" 2>/dev/null || true; }
    mv -f "$d/xray" "$XRAY_BIN" || { rm -rf "$d"; msg_err "не записал $XRAY_BIN"; return 1; }
    rm -rf "$d"
    printf 'URL=%s\nVERSION=%s\nDATE=%s\n' "$url" "$ver" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$XRAY_DIR/SOURCE"
    XRAY_VERSION=$ver
    msg_ok "ядро: $ver → $XRAY_BIN"
}

# том ядра в remnanode: on|off. → NODE_XRAY_CHANGED=1, если compose изменился
_node_xray_mount() {   # on|off
    local f="$REMNANODE_DIR/docker-compose.yml" tmp res
    NODE_XRAY_CHANGED=0
    tmp=$(mktemp)
    if ! res=$(_node_py compose-xray "$f" "$1" --out "$tmp" --mount "$XRAY_BIN:$XRAY_TARGET:ro"); then
        rm -f "$tmp"; msg_err "$f не разобрался — том ядра не изменён"; return 1
    fi
    if [ "$res" = changed ]; then
        _node_write_inplace "$tmp" "$f" || { rm -f "$tmp"; msg_err "не записал $f"; return 1; }
        NODE_XRAY_CHANGED=1
        msg_ok "docker-compose.yml: том ядра $([ "$1" = on ] && echo добавлен || echo убран) (бэкап: $ND_LAST_BACKUP)"
    fi
    rm -f "$tmp"
}

_node_recreate_remnanode() {   # [--force-recreate]
    local out
    msg_warn "remnanode перезапускается — клиенты ноды отключатся на несколько секунд"
    if ! out=$(_node_compose up -d "$@" remnanode 2>&1); then
        printf '%s\n' "$out" | tail -n 6 | sed 's/^/      /'
        msg_err "docker compose up remnanode не удался"
        return 1
    fi
    _node_alive remnanode || { msg_err "remnanode не работает — смотри: docker logs --tail 30 remnanode"; return 1; }
    msg_ok "remnanode: $(docker exec remnanode "$XRAY_TARGET" version 2>/dev/null | head -n1)"
}

node_xray_set() {   # <url>
    [ -n "${1:-}" ] || { echo "node xray: ссылка на бинарь или zip (https://…)" >&2; return 2; }
    node_require
    ui_head "Своё ядро Xray" "$1"
    local was
    was=$(_node_py compose-xray "$REMNANODE_DIR/docker-compose.yml" status 2>/dev/null)
    node_xray_fetch "$1" || die "ядро не установлено — remnanode работает как раньше"
    _node_xray_mount on || die "ядро скачано в $XRAY_BIN, но не подключено"
    if ! _node_recreate_remnanode --force-recreate; then
        # откат: было своё — прежний бинарь, было встроенное — убрать том
        if [[ "$was" == on* ]] && [ -f "$XRAY_BIN.prev" ]; then
            mv -f "$XRAY_BIN.prev" "$XRAY_BIN"
            [ -f "$XRAY_DIR/SOURCE.prev" ] && mv -f "$XRAY_DIR/SOURCE.prev" "$XRAY_DIR/SOURCE"
        else
            _node_xray_mount off
        fi
        _node_recreate_remnanode --force-recreate \
            && die "remnanode с новым ядром не поднялся — возвращено прежнее ядро" \
            || die "remnanode не поднялся и после отката — смотри: docker logs --tail 30 remnanode"
    fi
    rm -f "$XRAY_BIN.prev" "$XRAY_DIR/SOURCE.prev"
    record_fix "node xray $XRAY_VERSION ($1)"
}

node_xray_off() {
    node_require
    ui_head "Ядро Xray" "встроенное в образ remnanode"
    _node_xray_mount off || die "том ядра не убран"
    if [ "$NODE_XRAY_CHANGED" = 0 ]; then
        msg_ok "своё ядро не подключено — remnanode и так на встроенном"
        return 0
    fi
    _node_recreate_remnanode || die "remnanode не перезапустился"
    record_fix "node xray off"
}

node_xray_status() {
    node_require
    local st v
    st=$(_node_py compose-xray "$REMNANODE_DIR/docker-compose.yml" status) || die "docker-compose.yml не разобрался"
    echo
    box_top "ЯДРО XRAY"
    if [[ "$st" == on* ]]; then
        box_kv "Ядро" "своё: ${st#on }"
        v=$(sed -n 's/^URL=//p' "$XRAY_DIR/SOURCE" 2>/dev/null); [ -n "$v" ] && box_kv "Ссылка" "$v"
        v=$(sed -n 's/^DATE=//p' "$XRAY_DIR/SOURCE" 2>/dev/null); [ -n "$v" ] && box_kv "Поставлено" "$v"
    else
        box_kv "Ядро" "встроенное в образ remnanode"
    fi
    if _node_running remnanode; then
        box_kv "Работает" "$(docker exec remnanode "$XRAY_TARGET" version 2>/dev/null | head -n1)"
    else
        box_kv "Работает" "remnanode не запущен"
    fi
    box_bottom
}

node_usage() {
    cat <<'HELP'
node: установка и управление нодой Remnawave (sudo bash node-diagnostic.sh node … / rr node …)
  install                      установка под ключ (то же: rr install node)
  update [nginx|node]          обновить образы до последней версии (без аргумента — оба)
  domain list                  домены сайта-заглушки и их сертификаты
  domain add ДОМЕН             добавить домен в nginx.conf (сертификат проверяется/выпускается)
  domain del ДОМЕН             убрать домен (последний — нельзя)
  xray URL                     своё ядро Xray по ссылке на бинарь или zip релиза
  xray off                     вернуть встроенное ядро
  xray status                  какое ядро работает
HELP
}

node_main() {
    local cmd=${1:-}
    [ $# -gt 0 ] && shift
    case "$cmd" in
        install) node_install ;;
        update|upgrade) node_update "$@" ;;
        domain|domains)
            case "${1:-list}" in
                list|ls) node_domain_list ;;
                add) [ -n "${2:-}" ] || { echo "node domain add ДОМЕН" >&2; return 2; }; node_domain_add "$2" ;;
                del|rm|remove) [ -n "${2:-}" ] || { echo "node domain del ДОМЕН" >&2; return 2; }; node_domain_del "$2" ;;
                *) echo "node domain: list | add ДОМЕН | del ДОМЕН" >&2; return 2 ;;
            esac ;;
        xray|core)
            case "${1:-status}" in
                status) node_xray_status ;;
                off|builtin) node_xray_off ;;
                set) node_xray_set "${2:-}" ;;
                http://*|https://*) node_xray_set "$1" ;;
                *) echo "node xray: URL | off | status" >&2; return 2 ;;
            esac ;;
        ""|help|-h|--help) node_usage ;;
        *) echo "node: неизвестная сабкоманда '$cmd' (install|update|domain|xray)" >&2; return 2 ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    node_main "$@"
fi
