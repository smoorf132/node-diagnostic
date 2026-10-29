#!/usr/bin/env bash
# modules/certs.sh — сертификаты Let's Encrypt для ноды: выпуск (Cloudflare / Gcore / Bunny
# DNS-01 wildcard, ACME HTTP-01, свой сертификат), продление, хуки certbot и cron.
# Порт из eGamesAPI/remnawave-reverse-proxy (src/modules/certificates.sh) — без ufw,
# Caddy и Telegram-уведомлений. Порт 80 для HTTP-01 открывает firewall (protect), не мы.
#
# Standalone:  sudo bash modules/certs.sh [menu|renew|issue [ДОМЕН]|manual [ДОМЕН]]
# Как модуль:  source lib/common.sh; source modules/certs.sh; certs_for_domain ДОМЕН

if [ -z "${ND_COMMON_LOADED:-}" ]; then
    _self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    # shellcheck source=../lib/common.sh
    source "$_self/../lib/common.sh" 2>/dev/null \
        || { echo "не найден lib/common.sh — нужен весь репозиторий (см. install.sh)" >&2; exit 1; }
fi
_certs_self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=../lib/dns.sh
source "$_certs_self/../lib/dns.sh" 2>/dev/null \
    || { echo "не найден lib/dns.sh — нужен весь репозиторий (см. install.sh)" >&2; exit 1; }

LE_LIVE="${LE_LIVE:-/etc/letsencrypt/live}"
LE_RENEWAL="${LE_RENEWAL:-/etc/letsencrypt/renewal}"
NGINX_CONTAINER="remnawave-nginx"
CERT_RENEW_DAYS=30            # продлеваем, когда осталось столько дней или меньше
CERT_METHOD="" LETSENCRYPT_EMAIL="" CERT_LINEAGE=""

# ── покрытие и поиск сертификата ─────────────────────────────────────
# Покрывает ли список SAN/CN домен (точно или wildcard'ом ровно на одну метку)
cert_covers_domain() {   # <домен> <список, по строке на имя>
    local domain=$1 entry base label
    while IFS= read -r entry; do
        entry="${entry//[[:space:]]/}"
        [ -z "$entry" ] && continue
        [ "$entry" = "$domain" ] && return 0
        case "$entry" in
            \*.*)
                base="${entry#\*.}"
                case "$domain" in
                    *."$base")
                        # deep.sub.example.com НЕ внутри *.example.com
                        label="${domain%."$base"}"
                        [[ -n "$label" && "$label" != *.* ]] && return 0 ;;
                esac ;;
        esac
    done <<< "$2"
    return 1
}

# имена из сертификата: SAN, а без него — CN
cert_names() {   # <fullchain.pem>
    local sans
    sans=$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | grep -o 'DNS:[^ ,]*' | sed 's/^DNS://')
    [ -z "$sans" ] && sans=$(openssl x509 -in "$1" -noout -subject -nameopt RFC2253 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p')
    printf '%s\n' "$sans"
}

# Каталог в live/, чей сертификат реально покрывает домен: wildcard лежит под базой
# зоны, продления certbot дописывают -0001. Кандидат засчитывается только по SAN —
# одноимённая папка без покрытия не в счёт. Печатает имя каталога.
resolve_certificate_domain() {   # <домен>
    local domain="${1#\*.}" parent cand name
    [[ "$domain" =~ ^[a-zA-Z0-9.-]+$ ]] || return 1
    parent=$domain
    while [[ "$parent" == *.* ]]; do
        while IFS= read -r cand; do
            name="${cand##*/}"
            if [ "$name" != "$parent" ]; then
                [[ "${name#"$parent"-}" =~ ^[0-9]+$ ]] || continue
            fi
            [ -s "$cand/fullchain.pem" ] && [ -s "$cand/privkey.pem" ] || continue
            if cert_covers_domain "$domain" "$(cert_names "$cand/fullchain.pem")"; then
                printf '%s\n' "$name"; return 0
            fi
        done < <(find "$LE_LIVE" -mindepth 1 -maxdepth 1 -type d \
                    \( -name "$parent" -o -name "$parent-[0-9]*" \) 2>/dev/null | sort -V -r)
        parent="${parent#*.}"
    done
    return 1
}

cert_days_left() {   # <notAfter из openssl>
    local end
    end=$(TZ=UTC date -d "$1" +%s 2>/dev/null) || return 1
    echo $(( (end - $(date +%s)) / 86400 ))
}

# дней до истечения: аргумент — имя каталога в live/ или домен
check_cert_expiry() {
    local lineage=$1 end
    [ -s "$LE_LIVE/$lineage/fullchain.pem" ] || lineage=$(resolve_certificate_domain "$1") || return 1
    end=$(openssl x509 -in "$LE_LIVE/$lineage/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2-)
    [ -n "$end" ] || return 1
    cert_days_left "$end"
}

# ── выпуск ───────────────────────────────────────────────────────────
# Проверка ключа Cloudflare на /zones (до 3 попыток с переспросом)
cf_check_api() {
    local attempt resp
    local -a _CF_H
    for attempt in 1 2 3; do
        _cf_auth
        resp=$(curl -s --max-time 20 https://api.cloudflare.com/client/v4/zones "${_CF_H[@]}" -H "Content-Type: application/json")
        if echo "$resp" | grep -q '"success":true'; then msg_ok "ключ Cloudflare принят"; return 0; fi
        msg_err "Cloudflare не принял ключ (попытка $attempt/3)"
        [ "$attempt" -lt 3 ] && { CLOUDFLARE_EMAIL=""; cf_ask_key || return 1; }
    done
    return 1
}

# DNS-плагин certbot: cloudflare — из apt, gcore/bunny — через pip
certbot_dns_plugin() {   # <dns-xxx> <pip-пакет>
    certbot plugins 2>/dev/null | grep -q "$1" && return 0
    msg_info "ставлю плагин certbot $2 (pip)"
    if python3 -m pip install --help 2>&1 | grep -q break-system-packages; then
        python3 -m pip install -q --break-system-packages "$2" >/dev/null 2>&1
    else
        python3 -m pip install -q "$2" >/dev/null 2>&1
    fi
    certbot plugins 2>/dev/null | grep -q "$1" && { msg_ok "плагин $2 установлен"; return 0; }
    msg_err "плагин $2 не установился (python3-pip есть?)"
    return 1
}

# certbot certonly. Метод: 1 Cloudflare, 2 Gcore, 3 Bunny (DNS-01 wildcard), 4 HTTP-01.
get_certificates() {   # <домен> <метод> [email]
    local domain=$1 method=$2 email=${3:-} base
    local -a mail=(--email "$email") common=(--agree-tos --non-interactive --key-type ecdsa --elliptic-curve secp384r1)
    [ -z "$email" ] && mail=(--register-unsafely-without-email)
    base=$(extract_domain "$domain")
    # wildcard покрывает одну метку: node.vpn.example.com нужен *.vpn.example.com
    cert_covers_domain "$domain" "$base"$'\n'"*.$base" || base="${domain#*.}"
    mkdir -p "$CERTBOT_SECRETS"
    dns_saved_credentials_load
    ui_head "Выпуск сертификата" "$domain"

    case "$method" in
        1)
            [ -z "$CLOUDFLARE_API_KEY" ] && { cf_ask_key || return 1; }
            cf_check_api || return 1
            cf_secret_write
            certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CERTBOT_SECRETS/cloudflare.ini" \
                --dns-cloudflare-propagation-seconds 60 --cert-name "$base" -d "$base" -d "*.$base" \
                "${mail[@]}" "${common[@]}" || return 1
            ;;
        2)
            certbot_dns_plugin dns-gcore certbot-dns-gcore || return 1
            [ -z "$GCORE_API_KEY" ] && { ask "API-ключ Gcore" GCORE_API_KEY || return 1; }
            _secret_write "$CERTBOT_SECRETS/gcore.ini" "dns_gcore_apitoken = $GCORE_API_KEY"
            certbot certonly --authenticator dns-gcore --dns-gcore-credentials "$CERTBOT_SECRETS/gcore.ini" \
                --dns-gcore-propagation-seconds 80 --cert-name "$base" -d "$base" -d "*.$base" \
                "${mail[@]}" "${common[@]}" || return 1
            ;;
        3)
            certbot_dns_plugin dns-bunny certbot-dns-bunny || return 1
            [ -z "$BUNNY_API_KEY" ] && { ask "API-ключ аккаунта Bunny.net" BUNNY_API_KEY || return 1; }
            _secret_write "$CERTBOT_SECRETS/bunny.ini" "dns_bunny_api_key = $BUNNY_API_KEY"
            # базу wildcard спрашиваем явно: из двух последних меток не вывести co.uk-зоны
            # и делегированные подзоны (vpn.example.com); при 4+ метках подсказываем родителя
            local bb suggest=$base
            [ "$(awk -F. '{print NF}' <<< "$domain")" -ge 4 ] && suggest="${domain#*.}"
            while true; do
                ask "Базовый домен wildcard-сертификата" bb "$suggest" || return 1
                bb="${bb#\*.}"
                [[ "$bb" =~ ^[a-zA-Z0-9.-]+$ ]] && cert_covers_domain "$domain" "$bb"$'\n'"*.$bb" && break
                msg_warn "$bb не покрывает $domain — укажи зону, напр. example.com или vpn.example.com"
            done
            certbot certonly --authenticator dns-bunny --dns-bunny-credentials "$CERTBOT_SECRETS/bunny.ini" \
                --dns-bunny-propagation-seconds 120 --cert-name "$bb" -d "$bb" -d "*.$bb" \
                "${mail[@]}" "${common[@]}" || return 1
            ;;
        4)
            # standalone занимает :80 сам; nginx ноды слушает только unix-сокет, но на
            # смешанном сервере мог держать 80 — гасим на время проверки, как апстрим
            local nginx_up=0 busy rc
            if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$NGINX_CONTAINER"; then
                nginx_up=1; docker stop "$NGINX_CONTAINER" >/dev/null 2>&1
            fi
            busy=$(ss -Htlnp 'sport = :80' 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | sort -u | paste -sd, -)
            [ -n "$busy" ] && msg_warn "порт 80 занят ($busy) — HTTP-01 не пройдёт, пока он не свободен"
            certbot certonly --standalone --http-01-port 80 -d "$domain" "${mail[@]}" "${common[@]}"
            rc=$?
            [ "$nginx_up" = 1 ] && docker start "$NGINX_CONTAINER" >/dev/null 2>&1
            if [ "$rc" -ne 0 ]; then
                msg_info "HTTP-01: 80/tcp должен быть открыт снаружи (firewall ноды, облачный firewall хостера)"
                return "$rc"
            fi
            ;;
        *) msg_err "неизвестный метод выпуска: $method"; return 1 ;;
    esac
    # каждый certbot выше валит функцию сам; а это ловит выпуск, который «прошёл»,
    # но не покрыл домен — старая (даже просроченная) папка его бы замаскировала
    resolve_certificate_domain "$domain" >/dev/null || { msg_err "сертификат для $domain не появился"; return 1; }
}

# Меню метода → CERT_METHOD (1-5) и LETSENCRYPT_EMAIL. rc=1 — отмена.
cert_method_menu() {
    local def=""
    echo
    echo -e "  ${BOLD}Как выпустить сертификат?${NC}"
    echo -e "    ${C}${BOLD}[1]${NC} Cloudflare DNS API   ${DIM}wildcard, нужен API-токен${NC}"
    echo -e "    ${C}${BOLD}[2]${NC} Gcore DNS API        ${DIM}wildcard, нужен API-ключ${NC}"
    echo -e "    ${C}${BOLD}[3]${NC} Bunny.net DNS API    ${DIM}wildcard, нужен API-ключ${NC}"
    echo -e "    ${C}${BOLD}[4]${NC} ACME HTTP-01         ${DIM}без ключей, один домен, нужен открытый 80/tcp${NC}"
    echo -e "    ${C}${BOLD}[5]${NC} Свой сертификат      ${DIM}загрузить fullchain.pem + privkey.pem${NC}"
    echo -e "    ${C}${BOLD}[0]${NC} Отмена"
    # ключ провайдера уже введён (A-запись) — значит, зона там: его метод по умолчанию
    if   [ -n "$BUNNY_API_KEY" ]; then def=3
    elif [ -n "$GCORE_API_KEY" ]; then def=2
    elif [ -n "$CLOUDFLARE_API_KEY" ]; then def=1
    fi
    while true; do
        ask "Метод [0-5]" CERT_METHOD "$def" || return 1
        case "$CERT_METHOD" in
            0) return 1 ;;
            [1-5]) break ;;
            *) msg_warn "нет такого пункта" ;;
        esac
    done
    LETSENCRYPT_EMAIL=""
    if [ "$CERT_METHOD" != 5 ]; then
        ask "Email для Let's Encrypt (Enter — без email)" LETSENCRYPT_EMAIL || return 1
    fi
}

# ── продление: хуки, структура live/, cron ───────────────────────────
# Переписываем только свои хуки (нет хуков или они про remnawave-nginx): чужие
# (сайдкар xray-checker, хуки пользователя) не трогаем. ufw апстрима здесь нет —
# 80/tcp держит открытым firewall ноды.
configure_certbot_renewal_hooks() {   # <renewal.conf>
    local conf=$1
    [ -f "$conf" ] || return 1
    if grep -E '^(pre_hook|post_hook|renew_hook|deploy_hook) = ' "$conf" | grep -vq "$NGINX_CONTAINER"; then
        return 0
    fi
    sed -i -E '/^(pre_hook|post_hook|renew_hook|deploy_hook) = /d' "$conf"
    if grep -Eq '^[[:space:]]*authenticator[[:space:]]*=[[:space:]]*standalone[[:space:]]*$' "$conf"; then
        # абсолютные пути: у cron и certbot.timer в PATH нет /usr/sbin
        echo "pre_hook = /usr/bin/docker stop $NGINX_CONTAINER" >> "$conf"
        echo "post_hook = /usr/bin/docker start $NGINX_CONTAINER" >> "$conf"
    else
        echo "renew_hook = /usr/bin/docker restart $NGINX_CONTAINER" >> "$conf"
    fi
}

# live/ должен состоять из симлинков на последнюю версию в archive/ — после ручных
# копирований certbot отказывается продлевать
fix_letsencrypt_structure() {   # <каталог в live/>
    local d=$1 live="$LE_LIVE/$1" archive="/etc/letsencrypt/archive/$1" conf="$LE_RENEWAL/$1.conf" ver f
    [ -d "$live" ] && [ -d "$archive" ] && [ -f "$conf" ] || return 1
    [ "$(grep '^archive_dir' "$conf" | cut -d= -f2 | tr -d ' ')" = "$archive" ] || {
        msg_warn "$d: archive_dir в $conf не совпадает с $archive — структуру не трогаю"; return 1; }
    ver=$(find "$archive" -maxdepth 1 -name 'cert[0-9]*.pem' -printf '%f\n' 2>/dev/null \
        | sed -E 's/cert([0-9]+)\.pem/\1/' | sort -n | tail -n1)
    [ -n "$ver" ] || return 1
    for f in cert chain fullchain privkey; do
        [ -f "$archive/$f$ver.pem" ] || { msg_warn "$d: нет $archive/$f$ver.pem"; return 1; }
        [ -f "$live/$f.pem" ] && [ ! -L "$live/$f.pem" ] && rm -f "$live/$f.pem"
        ln -sf "$archive/$f$ver.pem" "$live/$f.pem"
        grep -q "^$f = $live/$f.pem" "$conf" || sed -i "s|^$f =.*|$f = $live/$f.pem|" "$conf"
    done
    configure_certbot_renewal_hooks "$conf"
    chmod 644 "$live/cert.pem" "$live/chain.pem" "$live/fullchain.pem" 2>/dev/null
    chmod 600 "$live/privkey.pem" 2>/dev/null
    return 0
}

ensure_cron() {
    have crontab || ensure_pkg crontab cron cronie cronie >/dev/null 2>&1 || true
    systemctl enable --now cron >/dev/null 2>&1 || systemctl enable --now crond >/dev/null 2>&1 \
        || service cron start >/dev/null 2>&1 || true
    have crontab || { msg_warn "cron не установлен — автопродление только через certbot.timer"; return 1; }
}

# Еженедельный certbot renew (в дополнение к certbot.timer пакета). Только когда есть
# что продлевать: со своими сертификатами задача не нужна.
certs_renew_cron() {
    local line='0 5 * * 0 /usr/bin/certbot renew --quiet --deploy-hook "/usr/bin/docker restart remnawave-nginx" > /dev/null 2>&1'
    ensure_cron || return 0
    if crontab -l 2>/dev/null | grep -q 'certbot renew'; then
        msg_ok "cron продления уже есть"
        return 0
    fi
    { crontab -l 2>/dev/null; echo "$line"; } | crontab -
    msg_ok "cron продления: по воскресеньям в 05:00"
}

# ── свой сертификат ──────────────────────────────────────────────────
verify_manual_certificate() {   # <домен> <каталог>
    local domain=$1 fc="$2/fullchain.pem" pk="$2/privkey.pem" end days names
    [ -s "$fc" ] || { msg_err "нет файла или он пуст: $fc"; return 1; }
    [ -s "$pk" ] || { msg_err "нет файла или он пуст: $pk"; return 1; }
    openssl x509 -in "$fc" -noout >/dev/null 2>&1 || { msg_err "fullchain.pem — не сертификат"; return 1; }
    openssl pkey -in "$pk" -noout >/dev/null 2>&1 || { msg_err "privkey.pem — не приватный ключ"; return 1; }
    if [ "$(openssl x509 -in "$fc" -pubkey -noout 2>/dev/null | md5sum)" != "$(openssl pkey -in "$pk" -pubout 2>/dev/null | md5sum)" ]; then
        msg_err "сертификат и ключ не пара"; return 1
    fi
    names=$(cert_names "$fc")
    cert_covers_domain "$domain" "$names" || { msg_err "сертификат не покрывает $domain (имена: $(echo "$names" | tr '\n' ' '))"; return 1; }
    end=$(openssl x509 -in "$fc" -noout -enddate 2>/dev/null | cut -d= -f2-)
    days=$(cert_days_left "$end") || { msg_err "не прочитал срок действия"; return 1; }
    [ "$days" -lt 0 ] && { msg_err "сертификат просрочен $(( -days )) дн. назад"; return 1; }
    msg_ok "действителен ещё $days дн. (до $end)"
    [ "$days" -le "$CERT_RENEW_DAYS" ] && msg_warn "осталось меньше $CERT_RENEW_DAYS дней — готовь замену"
    return 0
}

# Ждёт загрузки пары в live/<домен>/ и проверяет её. Wildcard базы переезжает в
# каталог базы, чтобы его находил общий поиск для всех поддоменов. → CERT_LINEAGE
manual_certificate_flow() {   # <домен>
    local domain=$1 dir="$LE_LIVE/$1" ip a base
    mkdir -p "$dir"
    ip=$(public_ipv4) || ip="<IP-сервера>"
    msg_info "загрузи файлы сертификата на сервер:"
    msg_info "  $dir/fullchain.pem"
    msg_info "  $dir/privkey.pem"
    msg_info "например, со своего компьютера:  scp fullchain.pem privkey.pem root@$ip:$dir/"
    while true; do
        ask "Enter — проверить файлы, 0 — отмена" a || return 1
        [ "$a" = 0 ] && return 1
        verify_manual_certificate "$domain" "$dir" && break
        msg_warn "проверка не пройдена — поправь файлы и нажми Enter"
    done
    chmod 600 "$dir/privkey.pem"
    CERT_LINEAGE=$domain
    base=$(extract_domain "$domain")
    if [ "$base" != "$domain" ] && cert_names "$dir/fullchain.pem" | grep -qxF "*.$base"; then
        mkdir -p "$LE_LIVE/$base"
        mv -f "$dir/fullchain.pem" "$dir/privkey.pem" "$LE_LIVE/$base/"
        rm -rf "$dir"
        CERT_LINEAGE=$base
        msg_ok "wildcard перенесён в $LE_LIVE/$base — одна папка на все поддомены"
    fi
    msg_ok "сертификат установлен: $LE_LIVE/$CERT_LINEAGE"
    msg_info "свой сертификат certbot не продлевает — перед истечением загрузи новый: rr certs manual"
}

# ── точки входа ──────────────────────────────────────────────────────
# Для установки ноды: сертификат, покрывающий домен, есть или выпускается.
# DNS_RECORD_PROVIDER (A-запись только что создана через API) выбирает метод сам.
# → CERT_LINEAGE (каталог в live/)
certs_for_domain() {   # <домен>
    local domain=$1 days
    ui_head "Сертификат" "$domain"
    if CERT_LINEAGE=$(resolve_certificate_domain "$domain"); then
        days=$(check_cert_expiry "$CERT_LINEAGE") || days="?"
        msg_ok "найден: $LE_LIVE/$CERT_LINEAGE (осталось $days дн.)"
    else
        msg_info "сертификата для $domain нет — выпускаем"
        case "$DNS_RECORD_PROVIDER" in
            cloudflare) CERT_METHOD=1 ;;
            gcore)      CERT_METHOD=2 ;;
            bunny)      CERT_METHOD=3 ;;
            *)          CERT_METHOD="" ;;
        esac
        if [ -n "$CERT_METHOD" ]; then
            msg_info "A-запись создана через API $DNS_RECORD_PROVIDER — wildcard выпускаю тем же методом"
            ask "Email для Let's Encrypt (Enter — без email)" LETSENCRYPT_EMAIL || return 1
        else
            cert_method_menu || return 1
        fi
        if [ "$CERT_METHOD" = 5 ]; then
            manual_certificate_flow "$domain" || return 1
        else
            get_certificates "$domain" "$CERT_METHOD" "$LETSENCRYPT_EMAIL" || { msg_err "выпуск не удался"; return 1; }
            CERT_LINEAGE=$(resolve_certificate_domain "$domain") || return 1
            msg_ok "выпущен: $LE_LIVE/$CERT_LINEAGE"
        fi
    fi
    if [ -f "$LE_RENEWAL/$CERT_LINEAGE.conf" ]; then
        configure_certbot_renewal_hooks "$LE_RENEWAL/$CERT_LINEAGE.conf"
        certs_renew_cron
    fi
    return 0
}

# [1] Продлить те, у кого осталось ≤ CERT_RENEW_DAYS; свои — только показать срок
certs_renew() {
    have certbot || die "certbot не установлен — сначала установи ноду (rr install node)"
    [ -d "$LE_LIVE" ] || { msg_warn "сертификатов нет ($LE_LIVE)"; return 0; }
    ui_head "Продление сертификатов" "порог: $CERT_RENEW_DAYS дн."
    declare -A dirs=()
    local d name key conf days method cf before after rc
    for d in "$LE_LIVE"/*/; do
        [ -d "$d" ] || continue
        name=$(basename "$d")
        dirs["${name%-[0-9]*}"]=$name     # example.com и example.com-0001 → последний
    done
    [ "${#dirs[@]}" -eq 0 ] && { msg_warn "сертификатов нет"; return 0; }
    mkdir -p /var/log/letsencrypt
    dns_saved_credentials_load
    for key in "${!dirs[@]}"; do
        name=${dirs[$key]}
        conf="$LE_RENEWAL/$name.conf"
        if [ ! -f "$conf" ]; then
            if days=$(check_cert_expiry "$name"); then
                msg_info "$name: свой сертификат, осталось $days дн. — заменяется вручную (rr certs manual)"
            else
                msg_warn "$name: свой сертификат, срок не прочитан"
            fi
            continue
        fi
        # credentials-файл DNS-плагина пропал — переспрашиваем ключ, иначе renew упадёт
        method="http-01"
        if grep -q dns_cloudflare "$conf"; then
            method=cloudflare
            cf=$(grep dns_cloudflare_credentials "$conf" | cut -d= -f2 | tr -d ' ')
            if [ -n "$cf" ] && [ ! -s "$cf" ]; then
                msg_warn "$name: нет $cf"
                [ -z "$CLOUDFLARE_API_KEY" ] && { cf_ask_key || continue; }
                cf_check_api || continue
                cf_secret_write "$cf"
            fi
        elif grep -q dns-gcore "$conf" || grep -q dns_gcore "$conf"; then
            method=gcore
            cf=$(grep -E 'dns[-_]gcore[-_]credentials' "$conf" | cut -d= -f2 | tr -d ' ')
            if [ -n "$cf" ] && [ ! -s "$cf" ]; then
                msg_warn "$name: нет $cf"
                [ -z "$GCORE_API_KEY" ] && { ask "API-ключ Gcore" GCORE_API_KEY || continue; }
                _secret_write "$cf" "dns_gcore_apitoken = $GCORE_API_KEY"
            fi
        elif grep -Eq 'dns[-_]bunny' "$conf"; then
            method=bunny
            cf=$(grep -E 'dns[-_]bunny[-_]credentials' "$conf" | cut -d= -f2 | tr -d ' ')
            if [ -n "$cf" ] && [ ! -s "$cf" ]; then
                msg_warn "$name: нет $cf"
                [ -z "$BUNNY_API_KEY" ] && { ask "API-ключ аккаунта Bunny.net" BUNNY_API_KEY || continue; }
                _secret_write "$cf" "dns_bunny_api_key = $BUNNY_API_KEY"
            fi
        fi
        fix_letsencrypt_structure "$name" || true
        days=$(check_cert_expiry "$name") || { msg_err "$name: не прочитал срок действия"; continue; }
        if [ "$days" -gt "$CERT_RENEW_DAYS" ]; then
            msg_ok "$name ($method): осталось $days дн. — продление не нужно"
            continue
        fi
        msg_info "$name ($method): осталось $days дн. — продлеваю…"
        before=$(stat -L -c %Y "$LE_LIVE/$name/fullchain.pem" 2>/dev/null || echo 0)
        certbot renew --cert-name "$name" --no-random-sleep-on-renew >> /var/log/letsencrypt/letsencrypt.log 2>&1
        rc=$?
        after=$(stat -L -c %Y "$LE_LIVE/$name/fullchain.pem" 2>/dev/null || echo 0)
        if [ "$rc" -eq 0 ] && [ "$before" != "$after" ]; then
            msg_ok "$name продлён: осталось $(check_cert_expiry "$name") дн."
            record_fix "certs renew $name"
        else
            msg_err "$name не продлён (rc=$rc) — смотри /var/log/letsencrypt/letsencrypt.log"
        fi
    done
}

# [2] Новый сертификат для любого домена
certs_issue() {   # [домен]
    local domain=${1:-}
    have certbot || die "certbot не установлен — сначала установи ноду (rr install node)"
    while ! is_domain "$domain"; do
        [ -n "$domain" ] && msg_warn "это не доменное имя"
        ask "Домен сертификата" domain || return 1
    done
    cert_method_menu || { msg_info "отменено"; return 1; }
    if [ "$CERT_METHOD" = 5 ]; then
        manual_certificate_flow "$domain" || return 1
    else
        get_certificates "$domain" "$CERT_METHOD" "$LETSENCRYPT_EMAIL" || { msg_err "выпуск не удался"; return 1; }
        CERT_LINEAGE=$(resolve_certificate_domain "$domain") || return 1
        configure_certbot_renewal_hooks "$LE_RENEWAL/$CERT_LINEAGE.conf"
        certs_renew_cron
        msg_ok "выпущен: $LE_LIVE/$CERT_LINEAGE"
    fi
    record_fix "certs issue $domain → $CERT_LINEAGE"
    msg_info "уже запущенная нода новый сертификат сама не подхватит — пути в $REMNANODE_DIR/nginx.conf и docker-compose.yml"
}

# [3] Свой сертификат
certs_manual() {   # [домен]
    local domain=${1:-}
    while ! is_domain "$domain"; do
        [ -n "$domain" ] && msg_warn "это не доменное имя"
        ask "Домен сертификата (напр. example.com)" domain || return 1
    done
    manual_certificate_flow "$domain" || return 1
    record_fix "certs manual $domain → $CERT_LINEAGE"
    msg_info "уже запущенная нода новый сертификат сама не подхватит — пути в $REMNANODE_DIR/nginx.conf и docker-compose.yml"
}

certs_menu() {
    local c
    while true; do
        echo -e "  ${BOLD}Сертификаты${NC}"
        echo -e "    ${C}${BOLD}[1]${NC} Продлить текущие   ${DIM}те, у кого ≤ $CERT_RENEW_DAYS дн.${NC}"
        echo -e "    ${C}${BOLD}[2]${NC} Выпустить новый    ${DIM}Cloudflare / Gcore / Bunny / HTTP-01 / свой${NC}"
        echo -e "    ${C}${BOLD}[3]${NC} Свой сертификат    ${DIM}загрузить fullchain + privkey${NC}"
        echo -e "    ${C}${BOLD}[0]${NC} Назад"
        printf "  ${BOLD}Выбор${NC} ${DIM}[0-3]${NC}: "; read -r c || return 0; echo
        case "$c" in
            1) certs_renew ;;
            2) certs_issue ;;
            3) certs_manual ;;
            0|q|"") return 0 ;;
            *) msg_warn "нет такого пункта" ;;
        esac
        echo
    done
}

certs_main() {
    local cmd=${1:-menu}; shift 2>/dev/null || true
    case "$cmd" in
        help|-h|--help)
            echo "certs: sudo bash node-diagnostic.sh certs [menu|renew|issue [ДОМЕН]|manual [ДОМЕН]]"
            return 0 ;;
        menu|renew|issue|manual) ;;
        *) echo "certs: неизвестная команда '$cmd' (menu|renew|issue|manual)" >&2; return 2 ;;
    esac
    need_root || die "нужен root"
    [ "$cmd" = renew ] || [ -t 0 ] || die "нужен интерактивный терминал — выпуск спрашивает ввод"
    case "$cmd" in
        menu)   certs_menu ;;
        renew)  certs_renew ;;
        issue)  certs_issue "$@" ;;
        manual) certs_manual "$@" ;;
    esac
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    certs_main "$@"
fi
