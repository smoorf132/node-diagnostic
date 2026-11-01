#!/usr/bin/env bash
# Зависимости BPF-тестов guard (tests/guard_xdp_test.py, tests/guard-netns.sh).
# Идемпотентно: ставится только то, чего нет (в образе nd-guard-dev — ничего).
#   clang libbpf-dev linux-libc-dev gcc-multilib iproute2 nftables conntrack python3 ethtool
#   + статический bpftool (libbpf/bpftool release) в /usr/local/bin, если рабочего нет
#   + bpffs на /sys/fs/bpf
# Запуск от root; на CI: sudo --preserve-env=GH_TOKEN bash tests/guard-deps.sh
set -eu

BPFTOOL_TAG="${BPFTOOL_TAG:-v7.8.1}"

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

# bpftool: обёртка Ubuntu /usr/sbin/bpftool без linux-tools-$(uname -r) не работает
if bpftool version >/dev/null 2>&1; then
	:
else
	say "ставлю статический bpftool $BPFTOOL_TAG"
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	tgz="bpftool-$BPFTOOL_TAG-amd64.tar.gz"
	if command -v gh >/dev/null 2>&1 && [ -n "${GH_TOKEN:-}" ]; then
		gh release download "$BPFTOOL_TAG" -R libbpf/bpftool -p '*amd64.tar.gz*' -D "$tmp"
	else
		url="https://github.com/libbpf/bpftool/releases/download/$BPFTOOL_TAG"
		curl -fsSL -o "$tmp/$tgz" "$url/$tgz"
		curl -fsSL -o "$tmp/$tgz.sha256sum" "$url/$tgz.sha256sum"
	fi
	(cd "$tmp" && sha256sum -c --quiet "$tgz.sha256sum") || die "контрольная сумма $tgz не сошлась"
	tar -xzf "$tmp/$tgz" -C "$tmp"
	install -m 0755 "$tmp/bpftool" /usr/local/bin/bpftool
	hash -r
	bpftool version >/dev/null 2>&1 || die "bpftool не запускается"
fi

if ! grep -qs ' /sys/fs/bpf bpf ' /proc/mounts; then
	say "монтирую bpffs"
	mount -t bpf bpf /sys/fs/bpf
fi

say "OK ($(bpftool version | head -1), $(clang --version | head -1))"
