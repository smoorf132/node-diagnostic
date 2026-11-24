#!/usr/bin/env bash
# tests/integration.sh — интеграционный тест РЕАЛЬНОГО применения (для CI в privileged-контейнере).
# В отличие от smoke (dry-run), реально применяет optimize к системе, сверяет значения,
# откатывает и проверяет, что откат дочиста. ТРЕБУЕТ: root + ND_INTEGRATION=1 (защита от
# случайного запуска на рабочей ноде — тест меняет sysctl/iptables и откатывает их).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

[ "${ND_INTEGRATION:-0}" = "1" ] || { echo "пропуск: выставь ND_INTEGRATION=1 (тест реально меняет систему)"; exit 0; }
[ "$(id -u)" -eq 0 ]             || { echo "нужен root"; exit 2; }

fail=0
ok()  { echo "  ✓ $*"; }
bad() { echo "  ✗ $*"; fail=1; }

# shellcheck source=../lib/common.sh
source lib/common.sh

echo "== optimize --all (реальное применение) =="
if bash modules/optimize.sh --all > /tmp/it-opt.log 2>&1; then ok "optimize отработал"; else bad "optimize упал"; fi
grep -aE "line [0-9]+:|No such file" /tmp/it-opt.log && bad "сырые bash-ошибки в выводе" || ok "вывод без сырых ошибок"

echo "== значения реально в ядре =="
v() { # v <key> <want> <label>
    if verify_sysctl "$1" "$2"; then ok "$3"; else
        # в контейнере часть ключей может отсутствовать — различаем «нет ключа» и «не то значение»
        if sysctl -n "$1" >/dev/null 2>&1; then bad "$3 (ключ есть, значение не то: $(sysctl -n "$1" 2>/dev/null))"
        else echo "  ~ $3: ключа нет в этом ядре — не блокирую"; fi
    fi
}
v net.ipv4.tcp_min_snd_mss 512            "tcp_min_snd_mss=512"
v net.ipv4.tcp_mtu_probing 1              "tcp_mtu_probing=1"
v net.core.somaxconn 8192                 "somaxconn=8192"
v fs.nr_open 2097152                      "fs.nr_open=2M"
v vm.swappiness 10                        "swappiness=10"

echo "== артефакты =="
[ -f /etc/sysctl.d/99-node-diagnostic-tuning.conf ] && ok "tuning drop-in" || bad "нет tuning drop-in"
[ -f /etc/security/limits.d/99-node-diagnostic.conf ] && ok "limits.d" || bad "нет limits.d"
if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    grep -q '\$\$q' /etc/systemd/system/node-diagnostic-rps.service 2>/dev/null \
        && ok "RPS-юнит с \$\$q (systemd не съест переменную)" || bad "RPS-юнит битый/отсутствует"
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
        && ok "MSS clamp в OUTPUT" || bad "MSS clamp не встал"
fi

echo "== идемпотентность (второй прогон не дублирует) =="
bash modules/optimize.sh --all > /tmp/it-opt2.log 2>&1
# grep -c сам печатает 0 при отсутствии совпадений — «|| echo 0» добавил бы второй 0
n_rules=$(iptables -t mangle -S 2>/dev/null | grep -c TCPMSS); n_rules=${n_rules:-0}
[ "$n_rules" -le 2 ] && ok "MSS-правила не задвоились ($n_rules)" || bad "MSS-правила задвоились ($n_rules)"

echo "== rollback дочиста =="
bash modules/rollback.sh --yes > /tmp/it-rb.log 2>&1 && ok "rollback отработал" || bad "rollback упал"
leftovers=$(ls /etc/sysctl.d/99-node-diagnostic-* /etc/systemd/system/node-diagnostic-* \
    /etc/security/limits.d/99-node-diagnostic.conf 2>/dev/null | wc -l)
[ "$leftovers" -eq 0 ] && ok "артефактов не осталось" || bad "остались артефакты: $leftovers"
if command -v iptables >/dev/null 2>&1; then
    n_after=$(iptables -t mangle -S 2>/dev/null | grep -c TCPMSS); n_after=${n_after:-0}
    [ "$n_after" -eq 0 ] && ok "MSS-правила сняты" || bad "MSS-правила остались ($n_after)"
fi

echo "== clsact: чужие фильтры не сносятся =="
ip link add ndt0 type dummy && ip link set ndt0 up
clsact_ensure ndt0
tc filter add dev ndt0 ingress pref 10 matchall action pass
clsact_release ndt0
tc qdisc show dev ndt0 | grep -q clsact && ok "clsact_release_keeps_foreign_filters" || bad "clsact снесён при живом фильтре"
tc filter del dev ndt0 ingress pref 10
clsact_release ndt0
tc qdisc show dev ndt0 | grep -q clsact && bad "пустой clsact не убран" || ok "clsact_release убирает пустой qdisc"
ip link del ndt0

echo "== clsact_ensure: повтор и гонка юнитов на boot =="
ip link add ndt2 type dummy && ip link set ndt2 up
clsact_ensure ndt2; r1=$?
clsact_ensure ndt2; r2=$?
[ "$r1 $r2" = "0 0" ] && ok "clsact_ensure ×2 → rc 0 и 0" || bad "clsact_ensure ×2 → rc $r1 и $r2"
# гонка: соседний юнит добавил clsact между нашим show и add — add получает EEXIST.
# Первый `tc qdisc show` подменён пустым ответом («ещё нет»), остальное — настоящий tc.
# Флаг — файл: show идёт в конвейере (подоболочке), переменная оттуда не вернётся
_race_flag=$(mktemp)
rc=$(
    tc() {
        if [ "$1 $2" = "qdisc show" ] && [ -e "$_race_flag" ]; then rm -f "$_race_flag"; return 0; fi
        command tc "$@"
    }
    clsact_ensure ndt2; echo $? )
rm -f "$_race_flag"
[ "$rc" = 0 ] && ok "clsact_ensure: EEXIST при живом clsact — успех" || bad "clsact_ensure в гонке → rc $rc"
tc qdisc del dev ndt2 clsact 2>/dev/null
ip link del ndt2

echo "== tc_filter_put: повторный attach не плодит дубли =="
ip link add ndt1 type dummy && ip link set ndt1 up
clsact_ensure ndt1
tc_filter_put ndt1 ingress "$ND_TC_PREF_SHAPER" matchall action pass
tc_filter_put ndt1 ingress "$ND_TC_PREF_SHAPER" matchall action pass
n=$(tc filter show dev ndt1 ingress pref "$ND_TC_PREF_SHAPER" | grep -c 'matchall.*handle')
[ "$n" = "1" ] && ok "tc_filter_put идемпотентен (1 фильтр)" || bad "tc_filter_put: фильтров $n вместо 1"
tc filter del dev ndt1 ingress pref "$ND_TC_PREF_SHAPER"; clsact_release ndt1
ip link del ndt1

echo "== protect: генерация + nft -c =="
out=$(mktemp -d)
PROTECT_OUT="$out" bash modules/protect.sh --panel-ip 203.0.113.5 --node-port 2222 >/dev/null 2>&1
sed 's/<YOUR_SSH_IP>/198.51.100.2/g' "$out/firewall.nft" > "$out/fw.nft"
if command -v nft >/dev/null 2>&1; then
    nft -c -f "$out/fw.nft" && ok "nft -c валиден" || bad "nft -c не прошёл"
fi

echo "== protect trust/bridge: живая таблица (netns) =="
# свой netns: firewall с policy drop не задевает контейнер, nft-состояние изолировано
# lnum PATTERN — номер первой строки живой цепочки input с PATTERN (пусто — нет)
lnum() { ip netns exec ndprot nft -a list chain inet node_protect input | grep -n -- "$1" | head -1 | cut -d: -f1; }
pset() { ip netns exec ndprot nft list set inet node_protect "$1" 2>/dev/null; }
pp() { ip netns exec ndprot env PROTECT_PERSIST="$lo/persist.nft" PROTECT_OUT="$lo" bash modules/protect.sh "$@" >/tmp/it-pl.log 2>&1; }
if command -v nft >/dev/null 2>&1 && ip netns add ndprot 2>/dev/null; then
    lo=$(mktemp -d)
    PROTECT_OUT="$lo" bash modules/protect.sh --panel-ip 203.0.113.5 --node-port 2222 --ssh-from 198.51.100.2 --hy2 y >/dev/null 2>&1
    cp "$lo/firewall.nft" "$lo/persist.nft"
    ip netns exec ndprot nft -f "$lo/firewall.nft" && ok "firewall загружен в netns" || bad "firewall не загрузился в netns"

    pp trust add 192.0.2.0/24 2001:db8::/32
    pset trusted4 | grep -q '192.0.2.0/24' && pset trusted6 | grep -q '2001:db8::/32' \
        && grep -q 'TRUST_NETS="192.0.2.0/24 2001:db8::/32"' "$lo/protect.conf" \
        && grep -A4 'set trusted4' "$lo/persist.nft" | grep -q '192.0.2.0/24' \
        && ok "trust add: живые trusted4/6 + conf + автозагрузка" || { bad "trust add"; cat /tmp/it-pl.log; }

    pp bridge port 8443; pp bridge add 203.0.113.7 2001:db8:1::/64
    lb=$(lnum 'tcp dport 8443 ip saddr @bridge4'); ld=$(lnum 'node_protect drop')
    [ -n "$lb" ] && [ -n "$ld" ] && [ "$lb" -lt "$ld" ] && [ -n "$(lnum 'tcp dport 8443 ip6 saddr @bridge6')" ] \
        && pset bridge4 | grep -q '203.0.113.7' && pset bridge6 | grep -q '2001:db8:1::/64' \
        && ok "bridge port 8443 + add: правила до финального drop, пул в set'ах" || { bad "bridge port/add"; cat /tmp/it-pl.log; }

    pp bridge port 9443
    [ -z "$(lnum 'dport 8443')" ] && [ -n "$(lnum 'tcp dport 9443 ip saddr @bridge4')" ] \
        && ok "bridge port 9443: правило перенесено" || bad "bridge port: смена порта"
    pp bridge port off
    [ -z "$(lnum '"nd:bridge"')" ] && pset bridge4 | grep -q '203.0.113.7' \
        && ok "bridge port off: правил нет, пул сохранён" || bad "bridge port off"

    pp trust del 192.0.2.0/24
    ! pset trusted4 | grep -q '192.0.2.0/24' && pset trusted6 | grep -q '2001:db8::/32' \
        && ok "trust del: элемент снят из живого set" || bad "trust del"
    pp trust del 198.51.100.200
    pset trusted6 | grep -q '2001:db8::/32' && ok "trust del отсутствующего: остальное не тронуто" || bad "trust del отсутствующего"

    # таблица от старой версии protect: без set'ов trusted/bridge и правил nd:*
    ip netns exec ndprot nft delete table inet node_protect
    rm -f "$lo/protect.conf"
    awk '/^    set (trusted|bridge)[46] \{/{skip=1} skip{ if ($0 ~ /^    \}/) skip=0; next } /"nd:/{next} {print}' \
        "$lo/firewall.nft" > "$lo/old.nft"
    # комментарии с «trusted4» остаются — проверяем именно отсутствие set'ов и правил nd:*
    ip netns exec ndprot nft -f "$lo/old.nft" && ! grep -qE 'set (trusted|bridge)[46] \{|"nd:' "$lo/old.nft" \
        && ok "старая таблица загружена" || bad "старая таблица не загрузилась"
    pp trust add 198.51.100.50
    lt=$(lnum 'ip saddr @trusted4 tcp dport 443'); lc=$(lnum 'conn443_4')
    pset trusted4 | grep -q '198.51.100.50' && [ -n "$lt" ] && [ -n "$lc" ] && [ "$lt" -lt "$lc" ] \
        && [ -n "$(lnum 'ip6 saddr @trusted6 udp dport 443')" ] \
        && ok "старая таблица: trust add досоздал set'ы и правила до лимитов 443 (+udp при HY2)" \
        || { bad "старая таблица: trust add"; cat /tmp/it-pl.log; ip netns exec ndprot nft -a list chain inet node_protect input; }
    pp bridge port 8443
    lb=$(lnum 'tcp dport 8443 ip saddr @bridge4'); ld=$(lnum 'node_protect drop')
    [ -n "$lb" ] && [ "$lb" -lt "$ld" ] && pset bridge6 >/dev/null \
        && ok "старая таблица: bridge port досоздал set'ы и правила до drop" || bad "старая таблица: bridge port"

    ip netns del ndprot
    rm -rf "$lo"
else
    echo "  ~ нет nft или netns — пропуск живых trust/bridge"
fi

echo
if [ "$fail" = "0" ]; then echo "INTEGRATION OK"; exit 0; else echo "INTEGRATION FAIL"; exit 1; fi
