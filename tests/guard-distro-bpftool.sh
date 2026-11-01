#!/usr/bin/env bash
# tests/guard-distro-bpftool.sh — bpftool и тулчейн дистрибутива (R14), без статического bpftool
# из tests/guard-deps.sh: ensure_bpftool (lib/common.sh) находит или ставит рабочий bpftool, а
# _guard_compile + _guard_load (modules/guard.sh, через source) собирают и грузят им оба объекта.
# CI: джоба guard-distro-bpftool, privileged-контейнер debian:12 / ubuntu:22.04 с clang, libbpf-dev,
# linux-libc-dev, gcc-multilib, iproute2, python3, curl. Запуск от root:
#   ND_BPFTOOL_EXPECT="pkg" bash tests/guard-distro-bpftool.sh   # допустимые шаги через пробел
# → последняя строка GUARD-DISTRO-BPFTOOL OK (rc 0), иначе … FAIL (rc 1).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

fail=0
ok()  { echo "  ✓ $*"; }
bad() { echo "  ✗ $*"; fail=1; }

[ "$(id -u)" = 0 ] || { echo "guard-distro-bpftool: нужен root" >&2; exit 1; }
grep -qs ' /sys/fs/bpf bpf ' /proc/mounts || mount -t bpf bpf /sys/fs/bpf \
    || { echo "guard-distro-bpftool: bpffs не смонтировать" >&2; exit 1; }

tmp=$(mktemp -d)
export GUARD_DIR="$tmp/guard" GUARD_PIN=/sys/fs/bpf/nd-guard-distro
trap 'rm -rf "$tmp" "$GUARD_PIN" "$GUARD_PIN-new"' EXIT
mkdir -p "$GUARD_DIR"

# shellcheck source=../modules/guard.sh
source modules/guard.sh || { echo "source modules/guard.sh" >&2; exit 1; }

echo "== ensure_bpftool ($(. /etc/os-release && echo "$PRETTY_NAME"), ядро $(uname -r)) =="
unset BPFTOOL
if ensure_bpftool; then
    ok "bpftool: $BPFTOOL (шаг $ND_BPFTOOL_VIA) — $("$BPFTOOL" version | sed -n 's/^using //p')"
else
    bad "ensure_bpftool: рабочего bpftool нет (шаг $ND_BPFTOOL_VIA)"
fi
case " ${ND_BPFTOOL_EXPECT:-$ND_BPFTOOL_VIA} " in
*" $ND_BPFTOOL_VIA "*) ok "шаг $ND_BPFTOOL_VIA ожидаем (${ND_BPFTOOL_EXPECT:-любой})" ;;
*) bad "шаг $ND_BPFTOOL_VIA, ожидался один из: $ND_BPFTOOL_EXPECT" ;;
esac
bpftool_usable "$BPFTOOL" && ok "libbpf ≥ 1.0" || bad "bpftool_usable $BPFTOOL"
# повтор — без установок: находит то же (статический — в ND_BPFTOOL_LOCAL, не в PATH)
b=$BPFTOOL
unset BPFTOOL
if bpftool_find && bpftool_usable "$BPFTOOL"; then ok "bpftool_find без установок: $BPFTOOL"; else bad "bpftool_find не нашёл $b"; fi

echo "== guard.sh: _guard_compile + _guard_load (clang $(clang --version | sed -n '1s/.*version \([0-9.]*\).*/\1/p')) =="
if _guard_compile; then
    ok "собраны nd-guard-xdp.bpf.o и nd-guard-tc.bpf.o"
else
    bad "сборка: $(tail -n 3 "$GUARD_DIR"/clang-*.log 2>/dev/null | tr '\n' ' ')"
fi
_guard_load 1
rc=$?
[ "$rc" = 0 ] && ok "_guard_load 1 → rc 0" || bad "_guard_load 1 → rc $rc: $(tail -n 3 "$GUARD_DIR/load.log" | tr '\n' ' ')"
for p in "$GUARD_XDP_PROG" "$GUARD_TC_PROG"; do
    [ -e "$GUARD_STAGE/progs/$p" ] && ok "pin $GUARD_STAGE/progs/$p" || bad "нет pin'а $GUARD_STAGE/progs/$p ($(ls "$GUARD_STAGE/progs" 2>/dev/null | tr '\n' ' '))"
done
for m in guard_cfg_map guard_state_map guard_ports_map guard_stats_map geo4_map geo6_map allow4_map allow6_map; do
    [ -e "$GUARD_STAGE/maps/$m" ] || bad "нет карты $m"
done
# tc держит те же 4 карты, что XDP (переиспользование по pin'ам)
if python3 - "$BPFTOOL" "$GUARD_STAGE/progs/$GUARD_TC_PROG" "$GUARD_STAGE/maps" <<'PY'
import json, subprocess, sys
bt, prog, maps = sys.argv[1:4]
j = lambda *a: json.loads(subprocess.run([bt, "-j", *a], capture_output=True, text=True, check=True).stdout)
ids = set(j("prog", "show", "pinned", prog).get("map_ids", []))
sys.exit(0 if all(j("map", "show", "pinned", maps + "/" + m)["id"] in ids
                  for m in ("guard_cfg_map", "guard_state_map", "guard_ports_map", "guard_stats_map")) else 1)
PY
then ok "карты guard_cfg/state/ports/stats_map — общие у XDP и tc"; else bad "tc грузит свои карты, а не pin'ы XDP"; fi
python3 modules/guard_ctrl.py --pin-dir "$GUARD_STAGE/maps" set-port 443 tcp,udp,geo >/dev/null \
    && [ "$(python3 modules/guard_ctrl.py --pin-dir "$GUARD_STAGE/maps" get-port 443)" = tcp,udp,geo ] \
    && ok "guard_ctrl.py через этот bpftool (env BPFTOOL)" || bad "guard_ctrl.py set-port/get-port"

echo
if [ "$fail" = 0 ]; then echo "GUARD-DISTRO-BPFTOOL OK"; exit 0; else echo "GUARD-DISTRO-BPFTOOL FAIL"; exit 1; fi
