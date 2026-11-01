#!/usr/bin/env bash
# tests/smoke.sh — быстрые неразрушающие проверки тулкита (для CI и локально).
# Ничего не применяет к системе: только bash -n, dry-run, генерация во временный каталог,
# статусы и валидность JSON. Ненулевой код выхода = провал.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2
fail=0
ok()  { echo "  ✓ $*"; }
bad() { echo "  ✗ $*"; fail=1; }

echo "== bash -n =="
for f in node-diagnostic.sh install.sh lib/common.sh lib/dns.sh modules/*.sh tests/smoke.sh tests/sshport-it.sh; do
    bash -n "$f" && ok "$f" || bad "syntax $f"
done

echo "== help / version =="
bash node-diagnostic.sh --version 2>/dev/null | grep -q 'node-diagnostic' && ok "version" || bad "version"
bash node-diagnostic.sh help 2>/dev/null | grep -q 'diagnose' && ok "help" || bad "help"

echo "== optimize --all --dry-run =="
bash modules/optimize.sh --all --dry-run >/dev/null 2>&1 && ok "optimize dry-run" || bad "optimize dry-run"

echo "== protect (генерация) =="
out=$(mktemp -d)
bash modules/protect.sh --panel-ip 203.0.113.5 --node-port 2222 --out "$out" >/dev/null 2>&1
if [ -s "$out/firewall.nft" ] && [ -s "$out/firewall-ufw.sh" ] && [ -s "$out/APPLY.txt" ]; then
    ok "protect artifacts"
else
    bad "protect artifacts"
fi
# анти-брут — CrowdSec через install, fail2ban больше не генерируется
if [ ! -e "$out/fail2ban-sshd.local" ] && grep -q 'install crowdsec' "$out/APPLY.txt" 2>/dev/null; then
    ok "protect: без fail2ban, APPLY ведёт на CrowdSec"
else
    bad "protect: fail2ban-артефакт или нет шага CrowdSec в APPLY.txt"
fi
# перманентный бан подсетей: set banned4 с дефолтными BAN_NETS + drop в input и forward
if grep -q 'elements = { 185.224.228.0/22, 195.209.120.0/22, 212.192.156.0/23, 212.192.158.0/24, 194.165.22.0/23 }' "$out/firewall.nft" 2>/dev/null \
   && [ "$(grep -c 'ip saddr @banned4 counter drop' "$out/firewall.nft" 2>/dev/null)" = "2" ]; then
    ok "protect: бан подсетей (banned4)"
else
    bad "protect: нет set banned4 или drop-правил"
fi
# BAN_NETS="" — пустой set без elements (иначе nft не примет), мусор отбрасывается
nob=$(mktemp -d)
BAN_NETS="" bash modules/protect.sh --panel-ip 203.0.113.5 --node-port 2222 --out "$nob" >/dev/null 2>&1
BAN_NETS="bogus 10.1.2.3/8" bash modules/protect.sh --panel-ip 203.0.113.5 --node-port 2222 --out "$nob/j" >/dev/null 2>&1
if ! grep -q 'elements = { *}' "$nob/firewall.nft" 2>/dev/null && grep -q 'set banned4' "$nob/firewall.nft" 2>/dev/null \
   && grep -q 'elements = { 10.0.0.0/8 }' "$nob/j/firewall.nft" 2>/dev/null; then
    ok "protect: BAN_NETS пустой / с мусором"
else
    bad "protect: BAN_NETS пустой / с мусором"
fi
# синтаксис nft (если есть nft) — подставляем плейсхолдеры реальными значениями
if command -v nft >/dev/null 2>&1; then
    sed -e 's/<PANEL_IP>/198.51.100.1/g' -e 's/<YOUR_SSH_IP>/198.51.100.2/g' \
        -e 's/<NODE_PORT>/2222/g' "$out/firewall.nft" > "$out/fw.checked.nft"
    if nft -c -f "$out/fw.checked.nft" >/dev/null 2>&1; then
        ok "nft -c (синтаксис ruleset)"
    elif [ "$(id -u)" -eq 0 ]; then
        # под root nft -c обязан работать — фейл значит битый ruleset
        bad "nft -c (синтаксис ruleset)"
    else
        echo "  ~ nft -c не прошёл (без root netlink недоступен) — не блокирую"
    fi
fi

echo "== protect --ssh-from (SSH из подсети NetBird) =="
# хелперы CIDR: хост-биты обнуляются (NetBird отдаёт 100.92.13.5/16), вхождение в подсеть
cidr_ok=$(bash -c 'source lib/common.sh
    [ "$(ipv4_net 100.92.13.5/16)" = "100.92.0.0/16" ] && ip_in_cidr 100.92.7.7 100.92.0.0/16 \
    && ! ip_in_cidr 100.93.0.1 100.92.0.0/16 && ! ipv4_net 300.1.1.1 >/dev/null && echo yes' 2>/dev/null)
[ "$cidr_ok" = "yes" ] && ok "ipv4_net / ip_in_cidr" || bad "ipv4_net / ip_in_cidr"
nbo=$(mktemp -d)
bash modules/protect.sh --panel-ip 203.0.113.5 --node-port 2222 --ssh-from 100.92.13.5/16 --out "$nbo" >/dev/null 2>&1
if grep -q 'tcp dport [0-9]* ip saddr 100.92.0.0/16 accept' "$nbo/firewall.nft" 2>/dev/null \
   && grep -q 'from 100.92.0.0/16 to any port' "$nbo/firewall-ufw.sh" 2>/dev/null; then
    ok "SSH из подсети в nft и ufw (хост-биты обнулены)"
else
    bad "SSH из подсети: нет правила 100.92.0.0/16 в nft/ufw"
fi
if command -v nft >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
    nft -c -f "$nbo/firewall.nft" >/dev/null 2>&1 && ok "nft -c (SSH по подсети)" || bad "nft -c (SSH по подсети)"
fi
bash modules/protect.sh --ssh-from bogus --out "$nbo" >/dev/null 2>&1 && bad "--ssh-from мусор принят" || ok "--ssh-from отвергает мусор"

echo "== rollback --dry-run =="
bash modules/rollback.sh --dry-run >/dev/null 2>&1 && ok "rollback dry-run" || bad "rollback dry-run"

echo "== bbr3 --status =="
# статус возвращает 0 (BBRv3 активен) или 1 (нет) — оба валидны; 2+/127 = падение
bash modules/bbr3.sh --status >/dev/null 2>&1; rc=$?
[ "$rc" -le 1 ] && ok "bbr3 status (rc=$rc)" || bad "bbr3 status crash (rc=$rc)"

echo "== bbr3 --install --dry-run (без установки) =="
# на контейнере bbr3 должен КОРРЕКТНО отказаться (не x86 kernel-capable) либо показать план
bash modules/bbr3.sh --install --dry-run >/dev/null 2>&1
rc=$?
if [ "$rc" = "0" ] || [ "$rc" = "1" ]; then
    ok "bbr3 install dry-run (rc=$rc)"
else
    bad "bbr3 install dry-run упал (rc=$rc)"
fi

echo "== install (диспетчер, без сайд-эффектов) =="
# help — безопасно (ничего не ставит); неизвестная сабкоманда → rc=2
bash modules/install.sh help >/dev/null 2>&1 && ok "install help" || bad "install help"
bash modules/install.sh bogus >/dev/null 2>&1; [ "$?" = "2" ] && ok "install отвергает мусор (rc=2)" || bad "install bogus rc"
# crowdsec известна диспетчеру (не rc=2) и без TTY отказывает ДО любых изменений
bash modules/install.sh crowdsec </dev/null >/dev/null 2>&1; [ "$?" = "1" ] && ok "install crowdsec без TTY → отказ (rc=1)" || bad "install crowdsec rc"
bash modules/sshport.sh help >/dev/null 2>&1 && ok "ssh-port help" || bad "ssh-port help"
bash modules/sshport.sh 70000 >/dev/null 2>&1; [ "$?" = "2" ] && ok "ssh-port отвергает мусор (rc=2)" || bad "ssh-port bogus rc"
# без TTY — отказ ДО любых изменений sshd (смена порта ждёт подтверждения входа)
bash modules/sshport.sh 2222 </dev/null >/dev/null 2>&1; rc=$?
if [ "$rc" = "1" ] && [ ! -e /etc/ssh/sshd_config.d/99-node-diagnostic-port.conf ]; then
    ok "ssh-port без TTY → отказ, sshd не тронут"
else
    bad "ssh-port без TTY (rc=$rc)"
fi
# selfsteal от DigneZzZ убран — теперь часть install node
bash modules/install.sh selfsteal >/dev/null 2>&1; [ "$?" = "2" ] && ok "install selfsteal → указатель на install node (rc=2)" || bad "install selfsteal rc"

echo "== нода / сертификаты / WARP / IPv6 (диспетчеры) =="
for m in node certs warp ipv6; do
    bash "modules/$m.sh" help >/dev/null 2>&1 && ok "$m help" || bad "$m help"
    bash "modules/$m.sh" bogus >/dev/null 2>&1; [ "$?" = "2" ] && ok "$m отвергает мусор (rc=2)" || bad "$m bogus rc"
done
# без TTY (или без root) — отказ ДО любых изменений
bash modules/node.sh install </dev/null >/dev/null 2>&1; [ "$?" = "1" ] && ok "node install без TTY → отказ (rc=1)" || bad "node install rc"
bash modules/certs.sh issue </dev/null >/dev/null 2>&1; [ "$?" = "1" ] && ok "certs issue без TTY → отказ (rc=1)" || bad "certs issue rc"
bash modules/warp.sh install </dev/null >/dev/null 2>&1; [ "$?" = "1" ] && ok "warp install без TTY → отказ (rc=1)" || bad "warp install rc"
bash modules/warp.sh status >/dev/null 2>&1 && ok "warp status" || bad "warp status"
# статус: 0 (включён) или 1 (выключен) — оба валидны; 2+/127 = падение
bash modules/ipv6.sh status >/dev/null 2>&1; rc=$?
[ "$rc" -le 1 ] && ok "ipv6 status (rc=$rc)" || bad "ipv6 status crash (rc=$rc)"
bash node-diagnostic.sh help 2>/dev/null | grep -q 'certs' && ok "help: certs/warp/ipv6" || bad "help без certs"

# M3: certs HTTP-01 standalone при guard вариант 1 — guard hook pre, certbot, hook post (и при
# провале certbot); без GEO=ru — certbot без хуков. certbot и guard.sh — фейки, лог вызовов в $cg/log
cg=$(mktemp -d)
printf '#!/bin/sh\necho "certbot $*" >>"%s/log"\nexit "${CERTBOT_RC:-0}"\n' "$cg" >"$cg/certbot"
chmod +x "$cg/certbot"
printf 'echo "guard $*" >>"%s/log"\n' "$cg" >"$cg/guard.sh"
mkdir -p "$cg/gd" && printf 'GEO=ru\nPORTS=443,80\n' >"$cg/gd/guard.conf"
cs() {   # cs RC → «rc=N» certs_standalone_certbot с фейками
    PATH="$cg:$PATH" ND_GUARD_SH="$cg/guard.sh" GUARD_DIR="$cg/gd" CERTBOT_RC=$1 bash -c \
        'source lib/common.sh; source modules/certs.sh; certs_standalone_certbot certonly --standalone -d x >/dev/null; echo "rc=$?"' 2>/dev/null
}
r1=$(cs 1); l1=$(tr '\n' '|' <"$cg/log" 2>/dev/null); rm -f "$cg/log"
printf 'GEO=off\n' >"$cg/gd/guard.conf"
r2=$(cs 0); l2=$(tr '\n' '|' <"$cg/log" 2>/dev/null)
if [ "$r1" = rc=1 ] && [ "$l1" = "guard hook pre|certbot certonly --standalone -d x|guard hook post|" ] \
   && [ "$r2" = rc=0 ] && [ "$l2" = "certbot certonly --standalone -d x|" ] \
   && grep -q 'certs_standalone_certbot certonly --standalone' modules/certs.sh; then
    ok "certs: HTTP-01 standalone под guard вариант 1 — hook pre/post и при провале certbot"
else
    bad "certs: хуки guard вокруг standalone ($r1 [$l1]; $r2 [$l2])"
fi

echo "== нода: домены, покрытие сертификатом =="
fn=$(bash -c 'source lib/common.sh; source modules/node.sh
    [ "$(extract_domain node.example.com)" = example.com ] || exit 1
    [ "$(extract_domain a.b.example.com.ru)" = example.com.ru ] || exit 1
    [ "$(extract_domain Node.Example.CO.UK)" = example.co.uk ] || exit 1
    cert_covers_domain node.example.com "*.example.com" || exit 1
    cert_covers_domain example.com "$(printf "example.com\n*.example.com")" || exit 1
    ! cert_covers_domain deep.node.example.com "*.example.com" || exit 1
    ! cert_covers_domain example.org "*.example.com" || exit 1
    is_domain node.example.com && ! is_domain "bad domain" && ! is_domain localhost || exit 1
    is_ipv4 203.0.113.5 && ! is_ipv4 256.1.1.1 || exit 1
    echo yes' 2>/dev/null)
[ "$fn" = "yes" ] && ok "extract_domain / cert_covers_domain / is_domain" || bad "extract_domain / cert_covers_domain / is_domain"

echo "== нода: рендер docker-compose.yml / .env / nginx.conf / nginx-main.conf =="
nd=$(mktemp -d)
bash -c 'source lib/common.sh; source modules/node.sh
    node_render_env "$1" 2222 eyJhbGciOiJIUzI1NiJ9.dGVzdC1zZWNyZXQ
    node_render_compose "$1" example.com
    node_render_nginx "$1" node.example.com example.com
    node_render_nginx_main "$1"' _ "$nd" >/dev/null 2>&1
if grep -qx 'NODE_PORT=2222' "$nd/.env" 2>/dev/null && grep -q '^SECRET_KEY=eyJ' "$nd/.env" \
   && [ "$(stat -c %a "$nd/.env" 2>/dev/null)" = "600" ]; then
    ok ".env (NODE_PORT, SECRET_KEY, 600)"
else
    bad ".env"
fi
if grep -q 'env_file:' "$nd/docker-compose.yml" 2>/dev/null \
   && grep -qF '/etc/letsencrypt/live/example.com/fullchain.pem:/etc/nginx/ssl/example.com/fullchain.pem:ro' "$nd/docker-compose.yml" \
   && grep -qF "rm -f /dev/shm/nginx.sock && exec nginx" "$nd/docker-compose.yml" \
   && grep -qF './nginx-main.conf:/etc/nginx/nginx.conf:ro' "$nd/docker-compose.yml" \
   && grep -qF './nginx.conf:/etc/nginx/conf.d/default.conf:ro' "$nd/docker-compose.yml" \
   && ! grep -qiE 'caddy|ufw' "$nd/docker-compose.yml"; then
    ok "docker-compose.yml (nginx + remnanode, маунты конфигов и сертификата, без Caddy)"
else
    bad "docker-compose.yml"
fi
if grep -q 'server_name node.example.com;' "$nd/nginx.conf" 2>/dev/null \
   && grep -q 'listen unix:/dev/shm/nginx.sock ssl proxy_protocol;' "$nd/nginx.conf" \
   && grep -qF 'ssl_certificate "/etc/nginx/ssl/example.com/fullchain.pem";' "$nd/nginx.conf" \
   && grep -qF 'map $http_upgrade $connection_upgrade' "$nd/nginx.conf" \
   && grep -qF 'try_files $uri $uri/ /index.html;' "$nd/nginx.conf" \
   && grep -qF 'access_log /var/log/nginx/access.log proxy_protocol;' "$nd/nginx.conf" \
   && grep -q 'ssl_reject_handshake on;' "$nd/nginx.conf" \
   && grep -q 'listen 80 default_server;' "$nd/nginx.conf" \
   && grep -qF 'return 301 https://$host$request_uri;' "$nd/nginx.conf" \
   && ! grep -qE 'ssl_stapling|resolver' "$nd/nginx.conf"; then
    ok "nginx.conf (selfsteal на unix-сокете, reject неизвестных SNI, :80 → https, без OCSP)"
else
    bad "nginx.conf"
fi
if grep -qF "log_format proxy_protocol '\$proxy_protocol_addr" "$nd/nginx-main.conf" 2>/dev/null \
   && grep -q 'worker_rlimit_nofile 131072;' "$nd/nginx-main.conf" \
   && grep -q 'worker_connections 4096;' "$nd/nginx-main.conf" \
   && grep -q 'server_tokens off;' "$nd/nginx-main.conf" \
   && grep -qF 'include /etc/nginx/conf.d/*.conf;' "$nd/nginx-main.conf"; then
    ok "nginx-main.conf (log_format proxy_protocol для сайта, include conf.d)"
else
    bad "nginx-main.conf"
fi
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    if docker compose version >/dev/null 2>&1; then
        (cd "$nd" && docker compose config -q) >/dev/null 2>&1 && ok "docker compose config" || bad "docker compose config"
    fi
    # оба конфига целиком через nginx -t в том же образе, что ставит нода
    if command -v openssl >/dev/null 2>&1; then
        img=$(bash -c 'source lib/common.sh; source modules/node.sh; echo "$NGINX_IMAGE"')
        mkdir -p "$nd/ssl/example.com"
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes -days 1 \
            -subj /CN=node.example.com -keyout "$nd/ssl/example.com/privkey.pem" \
            -out "$nd/ssl/example.com/fullchain.pem" >/dev/null 2>&1
        if nt=$(docker run --rm -v "$nd/nginx-main.conf:/etc/nginx/nginx.conf:ro" \
                -v "$nd/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
                -v "$nd/ssl:/etc/nginx/ssl:ro" "$img" nginx -t 2>&1); then
            ok "nginx -t ($img): nginx-main.conf + nginx.conf"
        else
            bad "nginx -t ($img)"; printf '%s\n' "$nt" | tail -n 5 | sed 's/^/      /'
        fi
    fi
fi

echo "== protect: NODE_PORT из docker-compose.yml ноды =="
rn=$(mktemp -d); po=$(mktemp -d)
printf 'services:\n  remnanode:\n    environment:\n      - NODE_PORT=2345\n' > "$rn/docker-compose.yml"
REMNANODE_DIR="$rn" bash modules/protect.sh --panel-ip 203.0.113.5 --out "$po" >/dev/null 2>&1
grep -q 'tcp dport 2345 ' "$po/firewall.nft" 2>/dev/null && ok "detect_node_port: compose environment" || bad "detect_node_port: compose environment"

bash modules/shape.sh help >/dev/null 2>&1 && ok "shape help" || bad "shape help"
bash modules/shape.sh bogus >/dev/null 2>&1; [ "$?" = "2" ] && ok "shape отвергает мусор (rc=2)" || bad "shape bogus rc"
python3 -c 'import ast; ast.parse(open("modules/shape_ctrl.py").read())' 2>/dev/null && ok "shape_ctrl.py синтаксис" || bad "shape_ctrl.py syntax"
if ! grep -q 'qdisc del dev "$iface" clsact' modules/shape.sh \
   && [ "$(grep -c 'pref "$ND_TC_PREF_SHAPER"' modules/shape.sh)" -ge 2 ] \
   && [ "$(grep -c 'tc_filter_put .*"$ND_TC_PREF_SHAPER"' modules/shape.sh)" -ge 2 ]; then
    ok "shape: свои фильтры по pref, clsact не сносится"
else bad "shape: сносит clsact целиком"; fi

echo "== diagnose --no-net --json → валидный JSON =="
if command -v python3 >/dev/null 2>&1; then
    js=$(bash modules/diagnose.sh --no-net --json 2>/dev/null | tail -n1)
    if [ -n "$js" ] && printf '%s' "$js" | python3 -m json.tool >/dev/null 2>&1; then
        ok "diagnose --json валиден"
    else
        bad "diagnose --json невалиден/пуст"
    fi
else
    echo "  ~ python3 нет — пропускаю проверку JSON"
fi

echo "== guard: гео-список и чистые тесты guard_ctrl (без root) =="
if command -v python3 >/dev/null 2>&1; then
    if python3 -m unittest tests/test_guard_geo.py >/dev/null 2>&1; then
        ok "guard_geo unittest"
    else
        bad "guard_geo unittest"
    fi
    if python3 -m unittest tests.guard_xdp_test.GuardCtrlPureTest >/dev/null 2>&1; then
        ok "guard_ctrl чистые тесты"
    else
        bad "guard_ctrl чистые тесты"
    fi
else
    echo "  ~ python3 нет — пропускаю guard-тесты"
fi

echo "== guard: чистые функции и диспетчер (source modules/guard.sh) =="
# последним блоком: source подключает и lib/common.sh в этот shell
# shellcheck source=../modules/guard.sh
source modules/guard.sh 2>/dev/null || bad "source modules/guard.sh"
_guard_port_ok 443 10000 && ! _guard_port_ok 20000 10000 && ok "_guard_port_ok" || bad "_guard_port_ok"
[ "$(_guard_rcv_wscale 6291456)" = 7 ] && [ "$(_guard_rcv_wscale 134217728)" = 12 ] \
  && [ "$(_guard_rcv_wscale 65535)" = 0 ] && [ "$(_guard_rcv_wscale 1099511627776)" = 14 ] && ok "rcv_wscale" || bad "rcv_wscale"
# rc 1, а не «не 0»: иначе отсутствующая функция (rc 127) прошла бы
_guard_need_xdp off auto 0 2>/dev/null; [ "$?" = 1 ] && ok "вариант 2 без kfunc — XDP не нужен" || bad "need_xdp off/auto/0"
_guard_need_xdp ru off 0 && _guard_need_xdp off auto 1 && ok "need_xdp" || bad "need_xdp"
[ "$(_guard_effective_cookies auto 0 2>/dev/null)" = off ] && [ "$(_guard_effective_cookies always 1)" = always ] \
  && ok "effective_cookies (без kfunc — off)" || bad "effective_cookies"
GUARD_FORCE_KFUNC=1 _guard_has_kfunc && { GUARD_FORCE_KFUNC=0 _guard_has_kfunc 2>/dev/null; [ "$?" = 1 ]; } \
  && ok "has_kfunc: GUARD_FORCE_KFUNC" || bad "has_kfunc: GUARD_FORCE_KFUNC"
# R11: на veth XDP_TX (cookie SYN-ACK) native не доходит до peer'а → с cookies generic; без cookies и не veth — drv
[ "$(_guard_xdp_mode_plan veth 1 2>/dev/null)" = generic ] && [ "$(_guard_xdp_mode_plan veth 0)" = drv ] \
  && [ "$(_guard_xdp_mode_plan virtio_net 1)" = drv ] && [ "$(_guard_xdp_mode_plan "" 1)" = drv ] \
  && ok "xdp_mode_plan: veth+cookies → generic; veth без cookies, virtio_net → drv" || bad "xdp_mode_plan"
gr=$(_guard_nft_render eth0 443,80 2>/dev/null)
if command -v nft >/dev/null 2>&1; then
    if [ -n "$gr" ] && printf '%s\n' "$gr" | nft -c -f - >/dev/null 2>&1; then
        ok "nft render валиден"
    elif [ "$(id -u)" -eq 0 ]; then
        bad "nft render"
    else
        echo "  ~ nft -c (guard) не прошёл (без root netlink недоступен) — не блокирую"
    fi
fi
printf '%s\n' "$gr" | grep -q 'udp sport { 443, 80 } notrack' && ok "notrack udp out" || bad "notrack udp out"
# F5: ICMP-ошибки о потоках guard — мимо conntrack (иначе ct state invalid → drop раньше accept ICMP)
printf '%s\n' "$gr" | grep -qF 'iifname "eth0" icmp type { destination-unreachable, time-exceeded, parameter-problem } @th,224,16 { 443, 80 } notrack' \
  && printf '%s\n' "$gr" | grep -qF 'iifname "eth0" icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } @th,384,16 { 443, 80 } notrack' \
  && ok "notrack ICMP/ICMPv6-ошибок по внутреннему sport (PMTU)" || bad "нет notrack ICMP-ошибок"
# F4: порт SSH в --ports — отказ; печатается сам порт
[ "$(_guard_ports_conflict_ssh 443,22 22 2>/dev/null)" = 22 ] && ! _guard_ports_conflict_ssh 443,80 22 \
  && [ "$(_guard_ports_conflict_ssh 443,80 0443)" = 443 ] && ! _guard_ports_conflict_ssh 443,80 "" \
  && ok "ports_conflict_ssh" || bad "ports_conflict_ssh"
# M4: XDP/tc guard разбирают Ethernet — tun/wg (link/none) и ppp — отказ
_guard_iface_ether '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff' 2>/dev/null \
  && ! _guard_iface_ether '5: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/none ' \
  && ! _guard_iface_ether '7: ppp0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1492 qdisc fq state UNKNOWN qlen 3\    link/ppp ' \
  && ok "iface_ether: link/ether — да; link/none, link/ppp — нет" || bad "iface_ether"
# F8: cookie_sent ≥ 100 при cookie_ok = 0 — драйвер теряет XDP_TX; подсказка сохраняет вариант
_guard_xdp_tx_lost 100 0 2>/dev/null && ! _guard_xdp_tx_lost 99 0 && ! _guard_xdp_tx_lost 5000 1 && ! _guard_xdp_tx_lost "" 0 \
  && ok "xdp_tx_lost: 100/0 — да; 99/0, 5000/1 — нет" || bad "xdp_tx_lost"
[ "$(_guard_cookies_off_cmd ru 443,80 eth0 eth0 2>/dev/null)" = "rr guard on --geo ru --cookies off" ] \
  && [ "$(_guard_cookies_off_cmd off 443 ens3 eth0)" = "rr guard on --ports 443 --iface ens3 --cookies off" ] \
  && ok "cookies_off_cmd: вариант, порты и интерфейс сохраняются" || bad "cookies_off_cmd"
# D2: ядро без kfunc — на Ubuntu 24.04 сначала HWE (6.11+), XanMod — альтернатива; иначе — XanMod
osr=$(mktemp -d)
printf 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n' >"$osr/u2404"
printf 'NAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\n' >"$osr/u2604"
printf 'ID=debian\nVERSION_ID="12"\n' >"$osr/deb12"
h24=$(_guard_kernel_hint "$osr/u2404" 2>/dev/null)
case "$h24" in *"apt install --install-recommends linux-generic-hwe-24.04"*"reboot"*"rr bbr3 --install"*) k24=1 ;; *) k24=0 ;; esac
[ "$k24" = 1 ] && [ "$(_guard_kernel_hint "$osr/u2604")" = "rr bbr3 --install (XanMod)" ] \
  && [ "$(_guard_kernel_hint "$osr/deb12")" = "rr bbr3 --install (XanMod)" ] \
  && [ "$(_guard_kernel_hint "$osr/нет")" = "rr bbr3 --install (XanMod)" ] \
  && ok "kernel_hint: Ubuntu 24.04 → HWE, затем XanMod; 26.04, Debian, без os-release → XanMod" || bad "kernel_hint ($h24)"
rm -rf "$osr"
printf '%s\n' "$gr" | grep -q 'iifname "eth0" tcp dport { 443, 80 } notrack' && printf '%s\n' "$gr" | grep -q 'priority raw' \
  && ok "notrack tcp in, priority raw" || bad "notrack tcp in"
# фейковый docker в PATH: опубликованный :443 → конфликт (печать имени); host-сеть и :8443->443 — нет
fk=$(mktemp -d)
printf '#!/bin/sh\necho "nginx 0.0.0.0:443->443/tcp, [::]:443->443/tcp"\n' >"$fk/docker"
chmod +x "$fk/docker"
dc=$(PATH="$fk:$PATH" _guard_docker_conflict 443,80 2>/dev/null) && [ "$dc" = nginx ] \
  && ok "docker: опубликованный :443 → конфликт ($dc)" || bad "docker: конфликт не найден ($dc)"
printf '#!/bin/sh\nprintf "remnanode \\nweb 0.0.0.0:8443->443/tcp\\n"\n' >"$fk/docker"
PATH="$fk:$PATH" _guard_docker_conflict 443,80 >/dev/null 2>&1; [ "$?" = 1 ] \
  && ok "docker: host-сеть и :8443->443 — не конфликт" || bad "docker: ложный конфликт"
bash modules/guard.sh bogus >/dev/null 2>&1; [ "$?" = 2 ] && ok "guard rc=2 на мусор" || bad "guard bogus rc"
bash modules/guard.sh help >/dev/null 2>&1 && ok "guard help (rc 0)" || bad "guard help"
bash modules/guard.sh status >/dev/null 2>&1 && ok "guard status (выключен) rc 0" || bad "guard status"

bash node-diagnostic.sh help | grep -q 'guard' && ok "help: guard" || bad "help: guard"
bash node-diagnostic.sh guard help >/dev/null 2>&1 && ok "dispatcher guard" || bad "dispatcher guard"
[ "$(grep -c 'tcp flags & (fin|syn|rst|ack) == syn' "$out/firewall.nft")" = 2 ] \
  && ! grep -B1 'meter syn443_' "$out/firewall.nft" | grep -q 'ct state new' \
  && ok "protect: SYN-rate работает и под NOTRACK" || bad "protect: syn443 на ct state new"

echo
if [ "$fail" = "0" ]; then echo "SMOKE OK"; exit 0; else echo "SMOKE FAIL"; exit 1; fi
