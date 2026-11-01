#!/usr/bin/env bash
# Зависимости BPF-тестов guard (tests/guard_xdp_test.py, tests/guard-netns.sh).
# Идемпотентно: ставится только то, чего нет (в образе nd-guard-dev — ничего).
#   clang libbpf-dev linux-libc-dev gcc-multilib iproute2 nftables conntrack python3 ethtool
#   + статический bpftool (libbpf/bpftool release) в /usr/local/bin, если рабочего (libbpf ≥ 1.0) нет —
#     версия, URL и sha256 — общие с ensure_bpftool (lib/common.sh: ND_BPFTOOL_*)
#   + bpffs на /sys/fs/bpf
# Запуск от root; на CI: sudo --preserve-env=GH_TOKEN bash tests/guard-deps.sh
set -eu
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lib/common.sh
source "$ROOT/lib/common.sh"

say() { printf 'guard-deps: %s\n' "$*"; }
die() { printf 'guard-deps: ОШИБКА: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "нужен root"

# пакет → проверка «уже есть»
have_pkg() {
	case "$1" in
	clang) command -v clang >/dev/null 2>&1 ;;
	libbpf-dev) [ -e /usr/include/bpf/bpf_helpers.h ] ;;
	linux-libc-dev) [ -e /usr/include/linux/bpf.h ] ;;
	gcc-multilib) dpkg-query -W -f='${Status}' gcc-multilib 2>/dev/null | grep -q 'ok installed' ;;
	iproute2) command -v ip >/dev/null 2>&1 && command -v tc >/dev/null 2>&1 ;;
	nftables) command -v nft >/dev/null 2>&1 ;;
	conntrack) command -v conntrack >/dev/null 2>&1 ;;
	python3) command -v python3 >/dev/null 2>&1 ;;
	ethtool) command -v ethtool >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
}

missing=()
for p in clang libbpf-dev linux-libc-dev gcc-multilib iproute2 nftables conntrack python3 ethtool; do
	have_pkg "$p" || missing+=("$p")
done
if [ "${#missing[@]}" -gt 0 ]; then
	command -v apt-get >/dev/null 2>&1 || die "нет apt-get, а не хватает: ${missing[*]}"
	say "ставлю: ${missing[*]}"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
fi

# bpftool: обёртка Ubuntu /usr/sbin/bpftool без linux-tools-$(uname -r) не работает, на libbpf 0.x —
# не годится; тесты зовут bpftool из PATH — статический ставится в /usr/local/bin
if ! bpftool_usable bpftool; then
	say "ставлю статический bpftool $ND_BPFTOOL_TAG"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	tgz=""
	# gh (CI, GH_TOKEN) — архив из релиза; без gh архив качает bpftool_static_install. sha256 сверяется всегда
	if command -v gh >/dev/null 2>&1 && [ -n "${GH_TOKEN:-}" ] && [ "$(uname -m)" = x86_64 ]; then
		gh release download "$ND_BPFTOOL_TAG" -R libbpf/bpftool -p "bpftool-$ND_BPFTOOL_TAG-amd64.tar.gz" -D "$tmp" \
			&& tgz="$tmp/bpftool-$ND_BPFTOOL_TAG-amd64.tar.gz"
	fi
	bpftool_static_install /usr/local/bin/bpftool ${tgz:+"$tgz"} \
		|| die "статический bpftool $ND_BPFTOOL_TAG не поставлен (не скачался или sha256 не сошёлся)"
	hash -r
	bpftool_usable bpftool || die "bpftool не запускается"
fi

if ! grep -qs ' /sys/fs/bpf bpf ' /proc/mounts; then
	say "монтирую bpffs"
	mount -t bpf bpf /sys/fs/bpf
fi

say "OK ($(bpftool version | head -1), $(clang --version | head -1))"
