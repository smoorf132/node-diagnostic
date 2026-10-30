#!/usr/bin/env bash
# modules/node.sh — установка ноды Remnawave под ключ: remnanode + nginx (selfsteal на
# unix-сокете /dev/shm/nginx.sock с proxy_protocol), сертификат любым методом из certs.sh,
# случайный шаблон сайта-маскировки.
# Порт из eGamesAPI/remnawave-reverse-proxy (src/nginx/install_node.sh, install_packages,
# selfsteal_templates.sh) — без Caddy и ufw: NODE_PORT закрывает firewall из protect.
#
# Standalone:  sudo bash modules/node.sh install
# Как модуль:  source lib/common.sh; source modules/node.sh; node_render_compose ДИР ЛИНИЯ

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
NGINX_IMAGE="nginx:1.30"
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

node_render_compose() {   # <каталог> <каталог сертификата в live/>
    local l=$2
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
      - $LE_LIVE/$l/fullchain.pem:/etc/nginx/ssl/$l/fullchain.pem:ro
      - $LE_LIVE/$l/privkey.pem:/etc/nginx/ssl/$l/privkey.pem:ro
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
      - /var/log/remnanode:/var/log/remnanode
EOF
}

# Сайт selfsteal (conf.d/default.conf): xray (Reality, xver 1) отдаёт «чужие»
# TLS-соединения на unix-сокет, nginx отвечает сайтом-заглушкой; неизвестные SNI —
# обрыв рукопожатия; :80 — редирект на https, как у обычного сайта.
# access_log в формате proxy_protocol (реальный IP клиента) — формат объявлен в
# nginx-main.conf, без него nginx не стартует.
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

    # OCSP Stapling (faster TLS handshake)
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

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
# log_format proxy_protocol, на который ссылается сайт
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
    worker_connections 65535;
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

    certs_for_domain "$domain" || die "без сертификата нода не запустится — установка остановлена"
    lineage=$CERT_LINEAGE

    ui_head "Конфигурация" "$REMNANODE_DIR"
    mkdir -p "$REMNANODE_DIR" /var/log/remnanode "$WEB_ROOT"
    node_backup_old
    node_render_env "$REMNANODE_DIR" "$port" "$NODE_SECRET"
    node_render_compose "$REMNANODE_DIR" "$lineage"
    node_render_nginx "$REMNANODE_DIR" "$domain" "$lineage"
    node_render_nginx_main "$REMNANODE_DIR"
    msg_ok "docker-compose.yml · .env (NODE_PORT=$port) · nginx.conf (сайт) · nginx-main.conf"

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
    box_kv "Логи" "cd $REMNANODE_DIR && docker compose logs -f"
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

node_main() {
    case "${1:-}" in
        install) node_install ;;
        ""|help|-h|--help) echo "node: sudo bash node-diagnostic.sh install node   (или: bash modules/node.sh install)" ;;
        *) echo "node: неизвестная сабкоманда '$1' (install)" >&2; return 2 ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    node_main "$@"
fi
