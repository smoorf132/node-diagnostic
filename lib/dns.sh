#!/usr/bin/env bash
# lib/dns.sh — домены и DNS для установки ноды: базовый домен (с учётом com.ru/co.uk),
# публичный IPv4, проверка A-записи и её создание через API Cloudflare / Gcore / Bunny.
# Порт из eGamesAPI/remnawave-reverse-proxy (check_domain + src/modules/dns_records.sh).
# Только для source, после lib/common.sh.

[ -n "${ND_DNS_LOADED:-}" ] && return 0
ND_DNS_LOADED=1

# Ключи DNS-провайдеров — общие для A-записей и certbot DNS-01. certbot читает их из
# ini-файлов в CERTBOT_SECRETS при каждом продлении, поэтому рабочий ключ пишется туда же.
CLOUDFLARE_API_KEY="${CLOUDFLARE_API_KEY:-}"
CLOUDFLARE_EMAIL="${CLOUDFLARE_EMAIL:-}"
GCORE_API_KEY="${GCORE_API_KEY:-}"
BUNNY_API_KEY="${BUNNY_API_KEY:-}"
DNS_RECORD_PROVIDER="${DNS_RECORD_PROVIDER:-}"   # cloudflare|gcore|bunny — кто только что создал запись
CERTBOT_SECRETS="${CERTBOT_SECRETS:-/root/.secrets/certbot}"

# Двухуровневые публичные суффиксы (com.ru, co.uk…) из Public Suffix List: базовый домен
# для них на метку глубже. Лишняя запись лишь сужает базу (wildcard и поиск зоны это
# переживут), недостающая откатывает к двум меткам — поэтому список с запасом.
declare -A PUBLIC_SUFFIXES=(
    # RU / СНГ
    [com.ru]=1 [net.ru]=1 [org.ru]=1 [pp.ru]=1 [msk.ru]=1 [spb.ru]=1
    [com.ua]=1 [net.ua]=1 [org.ua]=1 [in.ua]=1
    [kiev.ua]=1 [kharkov.ua]=1 [kharkiv.ua]=1 [odessa.ua]=1 [odesa.ua]=1 [lviv.ua]=1 [dnipropetrovsk.ua]=1
    [co.kz]=1 [com.kz]=1 [net.kz]=1 [org.kz]=1 [edu.kz]=1 [gov.kz]=1
    [com.kg]=1 [net.kg]=1 [org.kg]=1 [edu.kg]=1 [gov.kg]=1
    [com.uz]=1 [co.uz]=1 [net.uz]=1 [org.uz]=1
    [com.az]=1 [net.az]=1 [org.az]=1
    [co.rs]=1 [org.rs]=1 [in.rs]=1 [ac.rs]=1 [edu.rs]=1
    # Европа
    [co.uk]=1 [org.uk]=1 [me.uk]=1 [net.uk]=1 [ac.uk]=1 [gov.uk]=1 [ltd.uk]=1 [plc.uk]=1 [sch.uk]=1
    [co.at]=1 [or.at]=1 [ac.at]=1
    [com.es]=1 [net.es]=1 [org.es]=1 [nom.es]=1 [edu.es]=1 [gob.es]=1
    [com.pt]=1 [net.pt]=1 [org.pt]=1 [edu.pt]=1
    [com.pl]=1 [net.pl]=1 [org.pl]=1 [edu.pl]=1 [gov.pl]=1 [info.pl]=1 [biz.pl]=1
    [com.gr]=1 [net.gr]=1 [org.gr]=1 [edu.gr]=1 [gov.gr]=1
    [com.ro]=1 [org.ro]=1 [nom.ro]=1
    [com.cy]=1 [net.cy]=1 [org.cy]=1
    [com.mk]=1 [net.mk]=1 [org.mk]=1
    [co.il]=1 [net.il]=1 [org.il]=1 [ac.il]=1 [gov.il]=1 [muni.il]=1 [idf.il]=1
    # Азия
    [co.jp]=1 [ne.jp]=1 [or.jp]=1 [ac.jp]=1 [ad.jp]=1 [ed.jp]=1 [go.jp]=1 [gr.jp]=1 [lg.jp]=1
    [com.cn]=1 [net.cn]=1 [org.cn]=1 [gov.cn]=1 [edu.cn]=1 [ac.cn]=1
    [com.tw]=1 [org.tw]=1 [net.tw]=1 [edu.tw]=1 [gov.tw]=1 [idv.tw]=1
    [com.hk]=1 [net.hk]=1 [org.hk]=1 [edu.hk]=1 [gov.hk]=1 [idv.hk]=1
    [co.kr]=1 [or.kr]=1 [ne.kr]=1 [re.kr]=1 [pe.kr]=1
    [co.in]=1 [net.in]=1 [org.in]=1 [firm.in]=1 [gen.in]=1 [ind.in]=1 [ac.in]=1 [edu.in]=1 [res.in]=1 [gov.in]=1
    [com.sg]=1 [net.sg]=1 [org.sg]=1 [edu.sg]=1 [gov.sg]=1 [per.sg]=1
    [com.my]=1 [net.my]=1 [org.my]=1 [edu.my]=1 [gov.my]=1 [name.my]=1
    [co.th]=1 [in.th]=1 [or.th]=1 [ac.th]=1 [go.th]=1 [net.th]=1
    [com.tr]=1 [net.tr]=1 [org.tr]=1 [edu.tr]=1 [gov.tr]=1
    [com.pk]=1 [net.pk]=1 [org.pk]=1 [edu.pk]=1 [gov.pk]=1
    [com.vn]=1 [net.vn]=1 [org.vn]=1 [edu.vn]=1 [gov.vn]=1
    [com.ph]=1 [net.ph]=1 [org.ph]=1
    [co.id]=1 [or.id]=1 [web.id]=1 [net.id]=1 [ac.id]=1 [sch.id]=1 [go.id]=1 [my.id]=1 [biz.id]=1
    [com.sa]=1 [net.sa]=1 [org.sa]=1 [edu.sa]=1 [gov.sa]=1
    [com.ae]=1 [net.ae]=1 [org.ae]=1 [ac.ae]=1 [gov.ae]=1
    [com.qa]=1 [net.qa]=1 [org.qa]=1 [edu.qa]=1 [gov.qa]=1
    [com.om]=1 [net.om]=1 [org.om]=1
    [com.lb]=1 [net.lb]=1 [org.lb]=1
    [com.ir]=1 [co.ir]=1 [net.ir]=1 [org.ir]=1
    # Америка
    [com.br]=1 [net.br]=1 [org.br]=1 [gov.br]=1 [edu.br]=1
    [com.mx]=1 [net.mx]=1 [org.mx]=1 [edu.mx]=1 [gob.mx]=1
    [com.ar]=1 [net.ar]=1 [org.ar]=1 [gob.ar]=1 [edu.ar]=1
    [com.co]=1 [net.co]=1 [org.co]=1 [edu.co]=1 [gov.co]=1 [nom.co]=1
    [com.pe]=1 [net.pe]=1 [org.pe]=1 [edu.pe]=1 [gob.pe]=1
    [com.ec]=1 [net.ec]=1 [org.ec]=1 [edu.ec]=1 [gob.ec]=1
    [com.ve]=1 [co.ve]=1 [net.ve]=1 [org.ve]=1
    [com.uy]=1 [net.uy]=1 [org.uy]=1
    [com.py]=1 [net.py]=1 [org.py]=1
    [com.bo]=1 [net.bo]=1 [org.bo]=1
    [com.do]=1 [net.do]=1 [org.do]=1 [edu.do]=1 [gob.do]=1
    [com.gt]=1 [net.gt]=1 [org.gt]=1
    # Африка и Океания
    [co.za]=1 [net.za]=1 [org.za]=1 [web.za]=1 [ac.za]=1 [gov.za]=1
    [com.ng]=1 [net.ng]=1 [org.ng]=1 [edu.ng]=1 [gov.ng]=1
    [co.ke]=1 [or.ke]=1 [ne.ke]=1 [me.ke]=1
    [co.tz]=1 [or.tz]=1 [ne.tz]=1
    [co.ug]=1 [or.ug]=1 [ne.ug]=1
    [com.eg]=1 [net.eg]=1 [org.eg]=1 [edu.eg]=1 [gov.eg]=1
    [com.ma]=1 [net.ma]=1 [org.ma]=1 [ac.ma]=1 [gov.ma]=1
    [com.dz]=1 [net.dz]=1 [org.dz]=1 [edu.dz]=1 [gov.dz]=1
    [com.ly]=1 [net.ly]=1 [org.ly]=1
    [com.jo]=1 [net.jo]=1 [org.jo]=1
    [com.au]=1 [net.au]=1 [org.au]=1 [edu.au]=1 [gov.au]=1 [asn.au]=1 [id.au]=1
    [co.nz]=1 [net.nz]=1 [org.nz]=1 [govt.nz]=1 [ac.nz]=1 [school.nz]=1
)

# регистрируемая база домена: node.example.com → example.com, node.example.com.ru → example.com.ru
extract_domain() {
    local domain="${1,,}" IFS=$' \t\n'
    # shellcheck disable=SC2206  # split по точкам намеренный
    local parts=(${domain//./ })
    local n=${#parts[@]}
    if [ "$n" -ge 3 ] && [ -n "${PUBLIC_SUFFIXES[${parts[n-2]}.${parts[n-1]}]+x}" ]; then
        echo "${parts[n-3]}.${parts[n-2]}.${parts[n-1]}"
    elif [ "$n" -ge 2 ]; then
        echo "${parts[n-2]}.${parts[n-1]}"
    else
        echo "$domain"
    fi
}

# похоже на имя хоста (метки из букв/цифр/дефисов, минимум одна точка)
is_domain() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; }

# Публичный IPv4 сервера. Ответ проверяется по форме: страница ошибки IP-эхо-сервиса
# (HTTP 403/503 с кодом выхода 0) иначе уехала бы в тело DNS-запроса.
public_ipv4() {
    local ip u
    for u in https://api.ipify.org https://ifconfig.me https://ipinfo.io/ip; do
        ip=$(curl -fsS4 --connect-timeout 8 --max-time 15 "$u" 2>/dev/null | tr -d '[:space:]')
        is_ipv4 "$ip" && { printf '%s' "$ip"; return 0; }
    done
    return 1
}

# первый A-адрес домена (dig из dnsutils; без него — getent)
domain_a_record() {
    local ip
    if have dig; then
        ip=$(dig +short A "$1" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
    else
        ip=$(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}')
    fi
    [ -n "$ip" ] && printf '%s' "$ip"
}

# IPv4 внутри опубликованных диапазонов Cloudflare? Список кэшируется на неделю;
# неудачное обновление откатывается к старому кэшу, а не к «не Cloudflare».
ip_is_cloudflare() {
    local ip=$1 cache="$ND_STATE_DIR/cloudflare_ips_v4.cache" ranges cidr
    is_ipv4 "$ip" || return 1
    if [ -s "$cache" ] && [ -z "$(find "$cache" -mtime +7 2>/dev/null)" ]; then
        ranges=$(cat "$cache")
    else
        ranges=$(curl -s --connect-timeout 10 --max-time 15 https://www.cloudflare.com/ips-v4 2>/dev/null)
        if echo "$ranges" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$'; then
            { printf '%s\n' "$ranges" > "$cache"; } 2>/dev/null
        elif [ -s "$cache" ]; then
            ranges=$(cat "$cache")
        fi
    fi
    while IFS= read -r cidr; do
        ipv4_net "$cidr" >/dev/null 2>&1 || continue
        ip_in_cidr "$ip" "$cidr" && return 0
    done <<< "$ranges"
    return 1
}

# Ключи из ini-файлов certbot, оставленных прошлой установкой: без этого каждая
# следующая (новый домен, ещё сертификат) заново спрашивала бы уже сохранённый токен.
dns_saved_credentials_load() {
    local seeded="" f v
    f="$CERTBOT_SECRETS/cloudflare.ini"
    if [ -z "$CLOUDFLARE_API_KEY" ] && [ -r "$f" ]; then
        v=$(sed -n 's/^dns_cloudflare_api_token[[:space:]]*=[[:space:]]*//p' "$f" | head -n1)
        if [ -n "$v" ]; then
            CLOUDFLARE_API_KEY=$v; seeded="Cloudflare"
        else
            v=$(sed -n 's/^dns_cloudflare_api_key[[:space:]]*=[[:space:]]*//p' "$f" | head -n1)
            if [ -n "$v" ]; then
                CLOUDFLARE_API_KEY=$v; seeded="Cloudflare"
                CLOUDFLARE_EMAIL=$(sed -n 's/^dns_cloudflare_email[[:space:]]*=[[:space:]]*//p' "$f" | head -n1)
            fi
        fi
    fi
    f="$CERTBOT_SECRETS/gcore.ini"
    if [ -z "$GCORE_API_KEY" ] && [ -r "$f" ]; then
        v=$(sed -n 's/^dns_gcore_apitoken[[:space:]]*=[[:space:]]*//p' "$f" | head -n1)
        [ -n "$v" ] && { GCORE_API_KEY=$v; seeded="${seeded:+$seeded + }Gcore"; }
    fi
    f="$CERTBOT_SECRETS/bunny.ini"
    if [ -z "$BUNNY_API_KEY" ] && [ -r "$f" ]; then
        v=$(sed -n 's/^dns_bunny_api_key[[:space:]]*=[[:space:]]*//p' "$f" | head -n1)
        [ -n "$v" ] && { BUNNY_API_KEY=$v; seeded="${seeded:+$seeded + }Bunny"; }
    fi
    [ -n "$seeded" ] && msg_info "ключ $seeded взят из $CERTBOT_SECRETS (прошлая установка)"
    return 0
}

# Cloudflare: API-токен (есть заглавные) подписывается сам, глобальный ключ — с email
cf_is_token() { [[ $CLOUDFLARE_API_KEY =~ [A-Z] ]]; }

# certbot-ini: записать, только если содержимое изменилось (и сказать об этом)
_secret_write() {   # _secret_write <файл> <содержимое>
    local f=$1 body=$2
    [ -f "$f" ] && [ "$(cat "$f")" = "$body" ] && return 0
    mkdir -p "$(dirname "$f")"
    ( umask 077; printf '%s\n' "$body" > "$f" )
    chmod 600 "$f" 2>/dev/null
    msg_info "ключ сохранён в $f — по нему certbot продлевает сертификат"
}

# shellcheck disable=SC2120  # [файл] передаёт certs.sh (продление со старым путём ini)
cf_secret_write() {   # [файл] — по умолчанию $CERTBOT_SECRETS/cloudflare.ini
    local body
    if cf_is_token; then
        body="dns_cloudflare_api_token = $CLOUDFLARE_API_KEY"
    else
        body=$(printf 'dns_cloudflare_email = %s\ndns_cloudflare_api_key = %s' "$CLOUDFLARE_EMAIL" "$CLOUDFLARE_API_KEY")
    fi
    _secret_write "${1:-$CERTBOT_SECRETS/cloudflare.ini}" "$body"
}

cf_ask_key() {
    ask "Cloudflare API-токен или глобальный ключ" CLOUDFLARE_API_KEY || return 1
    if ! cf_is_token && [ -z "$CLOUDFLARE_EMAIL" ]; then
        ask "Email аккаунта Cloudflare (для глобального ключа)" CLOUDFLARE_EMAIL || return 1
    fi
}

_cf_auth() {   # заголовки авторизации Cloudflare → массив _CF_H
    if cf_is_token; then
        _CF_H=(-H "Authorization: Bearer ${CLOUDFLARE_API_KEY}")
    else
        _CF_H=(-H "X-Auth-Key: ${CLOUDFLARE_API_KEY}" -H "X-Auth-Email: ${CLOUDFLARE_EMAIL}")
    fi
}

# A-запись указывает сюда (или на прокси Cloudflare, если он допустим)?
dns_record_points_here() {   # <домен> <ip сервера> [allow_cf]
    local ip
    ip=$(domain_a_record "$1") || return 1
    [ "$ip" = "$2" ] && return 0
    [ "${3:-true}" = true ] && ip_is_cloudflare "$ip"
}

# ── Cloudflare ───────────────────────────────────────────────────────
# allow_cf=false (selfsteal-домен ноды): запись только DNS-only, прокси ломает Reality.
ensure_dns_record_cloudflare() {   # <домен> <база> <ip> [allow_cf]
    local domain=$1 base=$2 ip=$3 allow_cf=${4:-false}
    local resp zone_id err attempt rec rec_id rec_ip rec_proxied proxied=false
    local -a _CF_H

    # отозванный/опечатанный токен не валит весь прогон: переспрашиваем до 3 раз
    for attempt in 1 2 3; do
        [ -z "$CLOUDFLARE_API_KEY" ] && { cf_ask_key || return 1; }
        _cf_auth
        resp=$(curl -s --max-time 20 "https://api.cloudflare.com/client/v4/zones?name=$base" \
            "${_CF_H[@]}" -H "Content-Type: application/json")
        if echo "$resp" | jq -e '.success == false' >/dev/null 2>&1; then
            err=$(echo "$resp" | jq -r '.errors[0].message // .errors[0].code // "unknown"')
            msg_err "Cloudflare отклонил ключ ($err) — введи действующий (попытка $attempt/3)"
            CLOUDFLARE_API_KEY=""; CLOUDFLARE_EMAIL=""
            continue
        fi
        zone_id=$(echo "$resp" | jq -r '.result[0].id // empty' 2>/dev/null)
        [ -n "$zone_id" ] && break
        msg_err "зона $base не найдена в Cloudflare — домен делегирован на Cloudflare?"
        return 1
    done
    [ -n "$zone_id" ] || { msg_err "ключ Cloudflare так и не принят"; return 1; }
    cf_secret_write

    rec=$(curl -s --max-time 20 "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=A&name=$domain" \
        "${_CF_H[@]}" -H "Content-Type: application/json")
    rec_id=$(echo "$rec" | jq -r '.result[0].id // empty' 2>/dev/null)
    rec_ip=$(echo "$rec" | jq -r '.result[0].content // empty' 2>/dev/null)
    rec_proxied=$(echo "$rec" | jq -r '.result[0].proxied // false' 2>/dev/null)

    # где прокси допустим, проксируемая запись им и остаётся (DNS-only раскрыл бы origin IP)
    if [ "$allow_cf" = true ] && [ "$rec_proxied" = true ]; then
        proxied=true
        if [ "$rec_ip" = "$ip" ]; then
            DNS_RECORD_PROVIDER=cloudflare; msg_ok "A-запись $domain уже указывает сюда"; return 0
        fi
    fi
    local body="{\"type\":\"A\",\"name\":\"$domain\",\"content\":\"$ip\",\"ttl\":120,\"proxied\":$proxied}"
    if [ -n "$rec_id" ]; then
        resp=$(curl -s --max-time 20 -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$rec_id" \
            "${_CF_H[@]}" -H "Content-Type: application/json" --data "$body")
    else
        resp=$(curl -s --max-time 20 -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            "${_CF_H[@]}" -H "Content-Type: application/json" --data "$body")
    fi
    if echo "$resp" | jq -e '.success == true' >/dev/null 2>&1; then
        DNS_RECORD_PROVIDER=cloudflare
        msg_ok "A-запись $domain → $ip $([ -n "$rec_id" ] && echo обновлена || echo создана) (прокси: $proxied)"
        return 0
    fi
    msg_err "не удалось записать A-запись: $(echo "$resp" | jq -r '.errors[0].message // "неизвестная ошибка"' 2>/dev/null)"
    return 1
}

# ── Gcore (api.gcore.com, затем зеркало EdgeCenter) ──────────────────
ensure_dns_record_gcore() {   # <домен> <база> <ip>
    local domain=$1 base=$2 ip=$3 host code out body verb
    [ -z "$GCORE_API_KEY" ] && { ask "API-ключ Gcore" GCORE_API_KEY || return 1; }
    out=$(mktemp)
    body=$(printf '{"resource_records":[{"content":["%s"],"enabled":true}],"ttl":120}' "$ip")
    for host in https://api.gcore.com https://api.edgecenter.ru; do
        # POST создаёт, на 409 (запись уже есть) — PUT заменяет
        for verb in POST PUT; do
            code=$(curl -s -o "$out" -w '%{http_code}' --max-time 20 -X "$verb" \
                "$host/dns/v2/zones/$base/$domain./A" \
                -H "Authorization: APIKey $GCORE_API_KEY" -H "Content-Type: application/json" --data "$body")
            case "$code" in
                200|201|204)
                    DNS_RECORD_PROVIDER=gcore
                    _secret_write "$CERTBOT_SECRETS/gcore.ini" "dns_gcore_apitoken = $GCORE_API_KEY"
                    msg_ok "A-запись $domain → $ip $([ "$verb" = PUT ] && echo обновлена || echo создана)"
                    rm -f "$out"; return 0 ;;
                409) continue ;;
                *) break ;;
            esac
        done
    done
    msg_err "не удалось записать A-запись (HTTP $code)"
    [ -s "$out" ] && msg_info "$(tail -c 200 "$out")"
    rm -f "$out"
    return 1
}

# ── Bunny.net ────────────────────────────────────────────────────────
# Сначала создаём, потом удаляем устаревшие: неудачное создание оставляет зону как была.
ensure_dns_record_bunny() {   # <домен> <база> <ip>
    local domain=$1 base=$2 ip=$3 zones zone_id zone name has stale id code out
    [ -z "$BUNNY_API_KEY" ] && { ask "API-ключ аккаунта Bunny.net" BUNNY_API_KEY || return 1; }
    zones=$(curl -s --max-time 20 https://api.bunny.net/dnszone -H "AccessKey: $BUNNY_API_KEY" -H "Accept: application/json")
    zone_id=$(echo "$zones" | jq -r --arg z "$base" '.Items[]? | select(.Domain == $z) | .Id' 2>/dev/null | head -n1)
    [ -n "$zone_id" ] || { msg_err "зона $base не найдена в Bunny DNS — домен делегирован на Bunny?"; return 1; }
    _secret_write "$CERTBOT_SECRETS/bunny.ini" "dns_bunny_api_key = $BUNNY_API_KEY"

    if [ "$domain" = "$base" ]; then name="@"; else name="${domain%."$base"}"; fi
    zone=$(curl -s --max-time 20 "https://api.bunny.net/dnszone/$zone_id" -H "AccessKey: $BUNNY_API_KEY" -H "Accept: application/json")
    has=$(echo "$zone" | jq -r --arg n "$name" --arg ip "$ip" \
        '[.Records[]? | select(.Type == 0 and .Name == $n and .Value == $ip)] | length' 2>/dev/null)
    stale=$(echo "$zone" | jq -r --arg n "$name" --arg ip "$ip" \
        '.Records[]? | select(.Type == 0 and .Name == $n and .Value != $ip) | .Id' 2>/dev/null)
    out=$(mktemp)
    if [ "${has:-0}" = "0" ]; then
        code=$(curl -s -o "$out" -w '%{http_code}' --max-time 20 -X PUT "https://api.bunny.net/dnszone/$zone_id/records" \
            -H "AccessKey: $BUNNY_API_KEY" -H "Content-Type: application/json" \
            --data "{\"Type\":0,\"Ttl\":120,\"Name\":\"$name\",\"Value\":\"$ip\"}")
        if [ "$code" != "201" ]; then
            msg_err "не удалось создать A-запись (HTTP $code)"; [ -s "$out" ] && msg_info "$(tail -c 200 "$out")"
            rm -f "$out"; return 1
        fi
    fi
    for id in $stale; do
        code=$(curl -s -o "$out" -w '%{http_code}' --max-time 20 -X DELETE \
            "https://api.bunny.net/dnszone/$zone_id/records/$id" -H "AccessKey: $BUNNY_API_KEY")
        if [ "$code" != "204" ]; then
            msg_err "новая запись есть, но старую (id $id) удалить не вышло (HTTP $code) — отвечают оба IP"
            rm -f "$out"; return 1
        fi
    done
    rm -f "$out"
    DNS_RECORD_PROVIDER=bunny
    msg_ok "A-запись $domain → $ip"
    return 0
}

# ручной путь: показать, что создать, и ждать, пока запись станет видна
manual_dns_record_flow() {   # <домен> <ip> [allow_cf]
    local domain=$1 ip=$2 allow_cf=${3:-true} a
    msg_info "создай у DNS-провайдера A-запись: $domain → $ip (без прокси)"
    while true; do
        ask "Enter — проверить запись, s — продолжить без неё" a || return 1
        [ "${a,,}" = "s" ] && return 1
        if dns_record_points_here "$domain" "$ip" "$allow_cf"; then
            msg_ok "A-запись $domain указывает на этот сервер"; return 0
        fi
        msg_warn "запись пока не видна (DNS расходится до нескольких минут)"
    done
}

# Найти/создать A-запись домена на этот сервер. 0 — запись в порядке.
ensure_dns_record() {   # <домен> [allow_cf]
    local domain=$1 allow_cf=${2:-true} base ip c
    base=$(extract_domain "$domain")
    # без верного IP сервера в DNS писать нельзя: неверное значение ещё и сделало бы
    # правильную запись «чужой» и заменило бы её
    ip=$(public_ipv4) || { msg_err "не удалось определить публичный IPv4 сервера"; return 1; }
    dns_record_points_here "$domain" "$ip" "$allow_cf" && return 0

    dns_saved_credentials_load
    # сохранённый ключ провайдера — пробуем им сразу
    if [ -n "$BUNNY_API_KEY" ]; then ensure_dns_record_bunny "$domain" "$base" "$ip" && return 0
    elif [ -n "$GCORE_API_KEY" ]; then ensure_dns_record_gcore "$domain" "$base" "$ip" && return 0
    elif [ -n "$CLOUDFLARE_API_KEY" ]; then ensure_dns_record_cloudflare "$domain" "$base" "$ip" "$allow_cf" && return 0
    fi

    echo
    echo -e "    ${C}${BOLD}[1]${NC} Создать через Cloudflare API"
    echo -e "    ${C}${BOLD}[2]${NC} Создать через Gcore DNS API"
    echo -e "    ${C}${BOLD}[3]${NC} Создать через Bunny.net API"
    echo -e "    ${C}${BOLD}[4]${NC} Создам сам ${DIM}(подожду, пока запись появится)${NC}"
    while true; do
        ask "Выбор [1-4]" c || return 1
        case "$c" in
            1) ensure_dns_record_cloudflare "$domain" "$base" "$ip" "$allow_cf"; return ;;
            2) ensure_dns_record_gcore "$domain" "$base" "$ip"; return ;;
            3) ensure_dns_record_bunny "$domain" "$base" "$ip"; return ;;
            4) manual_dns_record_flow "$domain" "$ip" "$allow_cf"; return ;;
            *) msg_warn "нет такого пункта" ;;
        esac
    done
}

# Проверка домена перед установкой: 0 — указывает сюда, 1 — нет, но продолжаем
# по согласию, 2 — отмена. allow_cf=false: прокси Cloudflare недопустим (selfsteal).
check_domain() {   # <домен> [allow_cf]
    local domain=$1 allow_cf=${2:-true} dip sip
    sip=$(public_ipv4) || {
        msg_warn "не удалось определить IP сервера — проверь сам, что $domain указывает сюда"
        confirm "Продолжить установку?" || return 2
        return 1
    }
    dip=$(domain_a_record "$domain") || dip=""
    [ "$dip" = "$sip" ] && { msg_ok "$domain → $sip (этот сервер)"; return 0; }
    if [ -n "$dip" ] && ip_is_cloudflare "$dip"; then
        [ "$allow_cf" = true ] && { msg_ok "$domain за прокси Cloudflare ($dip)"; return 0; }
        msg_warn "$domain указывает на прокси Cloudflare ($dip) — для selfsteal нужен режим DNS only"
    elif [ -n "$dip" ]; then
        msg_warn "$domain указывает на $dip, а IP этого сервера — $sip"
    else
        msg_warn "у $domain нет A-записи"
    fi
    ensure_dns_record "$domain" "$allow_cf" && return 0
    confirm "Запись не исправлена. Всё равно продолжить установку?" || return 2
    return 1
}
