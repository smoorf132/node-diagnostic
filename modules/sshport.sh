#!/usr/bin/env bash
# modules/sshport.sh — быстрая смена SSH-порта без лок-аута.
# Два шага: sshd слушает СТАРЫЙ + НОВЫЙ → новый открывается в firewall (node_protect/ufw/
# firewalld, с тем же источником: твой IP / подсеть NetBird) → проверяешь вход во втором
# окне → старый снимается. Текущая сессия не рвётся ни на одном шаге; не подтвердил — откат.
#
#   sudo bash node-diagnostic.sh ssh-port [НОВЫЙ_ПОРТ]
set -u
_self="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
# shellcheck source=../lib/common.sh
source "$_self/../lib/common.sh" 2>/dev/null || { echo "ssh-port: не найден lib/common.sh" >&2; exit 1; }

SSHD_MAIN=/etc/ssh/sshd_config
SSHD_DIR=/etc/ssh/sshd_config.d
PORT_DROPIN="$SSHD_DIR/${ND_DROPIN_PREFIX}-port.conf"
SSHD_BIN=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
SP_BK=""      # каталог бэкапа этого запуска

_sp_usage() {
    cat <<HELP
ssh-port — смена SSH-порта без лок-аута (sshd + firewall + SELinux).
  sudo bash node-diagnostic.sh ssh-port [НОВЫЙ_ПОРТ]   # без аргумента — спросит
Шаги: sshd слушает старый+новый → новый открывается в firewall → проверка входа
во втором окне → старый снимается. Не подтвердил вход — откат на старый.
HELP
}

_sp_valid() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
_sp_listening() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }

# эффективные порты sshd (sshd -T нужен /run/sshd — на socket-activated Ubuntu его может не быть)
_sp_ports() {
    mkdir -p /run/sshd 2>/dev/null
    "$SSHD_BIN" -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | tr '\n' ' ' | sed 's/ $//'
}

_sp_has_include() { grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_MAIN" 2>/dev/null; }

_sp_backup() {
    SP_BK="$BACKUP_DIR/sshd-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$SP_BK" || die "не создал бэкап $SP_BK"
    cp -a "$SSHD_MAIN" "$SP_BK/sshd_config" || die "не скопировал $SSHD_MAIN"
    [ -d "$SSHD_DIR" ] && cp -a "$SSHD_DIR" "$SP_BK/sshd_config.d"
    msg_info "бэкап: $SP_BK"
}

# вернуть конфиги sshd как были до запуска (наш drop-in, если его не было, — удалить)
_sp_restore() {
    [ -n "$SP_BK" ] || return 1
    cat "$SP_BK/sshd_config" > "$SSHD_MAIN"
    if [ -d "$SP_BK/sshd_config.d" ]; then cp -a "$SP_BK/sshd_config.d/." "$SSHD_DIR/"; fi
    [ -e "$SP_BK/sshd_config.d/${PORT_DROPIN##*/}" ] || rm -f "$PORT_DROPIN"
}

# порты sshd = ровно этот набор. Port аддитивен: любая чужая Port-строка ДОБАВИЛА бы порт
# к нашим, поэтому чужие комментируются, а наши живут в одном месте
_sp_write() {   # _sp_write <порт...>
    local f p
    for f in "$SSHD_MAIN" "$SSHD_DIR"/*.conf; do
        [ -f "$f" ] && [ "$f" != "$PORT_DROPIN" ] || continue
        grep -qiE '^[[:space:]]*Port[[:space:]]' "$f" || continue
        sed -i -E 's/^([[:space:]]*[Pp][Oo][Rr][Tt][[:space:]].*)$/#\1  # node-diagnostic: порт задаёт ssh-port/' "$f"
    done
    if _sp_has_include; then
        mkdir -p "$SSHD_DIR"
        { echo "# node-diagnostic ssh-port. Сменить: node-diagnostic.sh ssh-port <порт>"
          for p in "$@"; do echo "Port $p"; done; } > "$PORT_DROPIN"
    else
        # без Include (RHEL 8 и т.п.) — управляемый блок в НАЧАЛЕ конфига, до любых Match
        sed -i '/^# >>> node-diagnostic ssh-port/,/^# <<< node-diagnostic ssh-port/d' "$SSHD_MAIN"
        { echo "# >>> node-diagnostic ssh-port"
          for p in "$@"; do echo "Port $p"; done
          echo "# <<< node-diagnostic ssh-port"
          cat "$SSHD_MAIN"; } > "$SSHD_MAIN.nd-tmp" \
            && cat "$SSHD_MAIN.nd-tmp" > "$SSHD_MAIN"   # cat >, а не mv: сохраняем права/владельца
        rm -f "$SSHD_MAIN.nd-tmp"
    fi
}

_sp_reload() {
    if have systemctl && systemctl is-active --quiet ssh.socket 2>/dev/null; then
        # Ubuntu 22.10+: порт держит ssh.socket, генератор переносит Port из sshd_config
        # в сокет на daemon-reload. Живые сессии — отдельные процессы, не рвутся
        systemctl daemon-reload && systemctl restart ssh.socket
    elif have systemctl; then
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
            || systemctl restart ssh 2>/dev/null || systemctl restart sshd
    elif have rc-service; then
        rc-service sshd reload 2>/dev/null || rc-service sshd restart
    else
        return 1
    fi
}

_sp_wait() {    # _sp_wait <порт...> — все слушаются (до 10 с)
    local p ok
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        ok=1
        for p in "$@"; do _sp_listening "$p" || ok=0; done
        [ "$ok" = "1" ] && return 0
        sleep 1
    done
    return 1
}

# применить набор портов: проверка конфига → reload → ждём листенеры
_sp_apply() {   # _sp_apply <порт...>
    local err
    _sp_write "$@"
    # restart ssh.socket останавливает ssh.service, и systemd сносит его RuntimeDirectory
    # /run/sshd — без него sshd -t падает «Missing privilege separation directory»
    mkdir -p /run/sshd 2>/dev/null
    err=$("$SSHD_BIN" -t 2>&1) || { msg_err "sshd -t отверг конфиг: $err"; return 1; }
    _sp_reload || { msg_err "не перезагрузил sshd"; return 1; }
    _sp_wait "$@" || { msg_err "sshd не слушает: $*"; return 1; }
}

_sp_rollback() {
    _sp_restore && _sp_reload && _sp_wait "$@" \
        && msg_warn "откат: sshd снова на $*" \
        || msg_err "откат не подтвердился — проверь: ss -ltnp | grep sshd; бэкап: $SP_BK"
}

# SELinux не даст sshd слушать неразмеченный порт
_sp_selinux() {
    have getenforce && [ "$(getenforce 2>/dev/null)" = "Enforcing" ] || return 0
    have semanage || ensure_pkg semanage policycoreutils-python-utils policycoreutils-python-utils policycoreutils \
        || die "SELinux Enforcing, а semanage нет — sshd не сможет слушать $1; система не тронута"
    semanage port -a -t ssh_port_t -p tcp "$1" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$1" \
        || die "semanage не разметил порт $1 под ssh_port_t; система не тронута"
    msg_ok "SELinux: $1 размечен как ssh_port_t"
}

# открыть НОВЫЙ порт там же и для тех же источников, что и старый (твой IP / подсеть NetBird)
_sp_fw_open() {   # _sp_fw_open <new> <old...>
    local new=$1 old r act src n=0 any=0; shift
    if have nft && nft list table inet node_protect >/dev/null 2>&1; then
        any=1
        for old in "$@"; do
            # meter-правило (rate-limit) не копируем: полный набор вернёт перегенерация protect
            while IFS= read -r r; do
                r=$(sed -E "s/tcp dport $old( |$)/tcp dport $new\1/" <<< "$r")
                # shellcheck disable=SC2086  # правило nft — набор слов
                nft insert rule inet node_protect input $r && n=$((n+1))
            done < <(nft list chain inet node_protect input 2>/dev/null \
                | sed -n -E "s/^[[:space:]]*(.*tcp dport $old( .*)? accept)$/\1/p" | grep -v meter)
        done
    fi
    if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
        any=1
        local found=0
        for old in "$@"; do
            while read -r act src; do
                found=1
                if [ "$src" = "Anywhere" ]; then ufw "${act,,}" "$new/tcp" >/dev/null
                else ufw "${act,,}" from "$src" to any port "$new" proto tcp >/dev/null; fi && n=$((n+1))
            done < <(ufw status 2>/dev/null \
                | awk -v p="$old" '($1==p"/tcp" || $1==p) && ($2=="ALLOW" || $2=="LIMIT") {print $2, $3}')
        done
        # SSH пускал профиль OpenSSH (он жёстко на 22) — открываем так же всем
        [ "$found" = "0" ] && ufw allow "$new/tcp" >/dev/null && n=$((n+1))
    fi
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        any=1
        firewall-cmd --quiet --permanent --add-port="$new/tcp" && firewall-cmd --quiet --reload && n=$((n+1))
    fi
    if [ "$any" = "0" ]; then
        msg_info "firewall (node_protect/ufw/firewalld) не найден — правила не нужны"
    elif [ "$n" -gt 0 ]; then
        msg_ok "firewall: $new открыт ($n $(plural_ru "$n" правило правила правил))"
    else
        msg_warn "firewall активен, но правило для $new не добавилось — открой порт сам, иначе проверка не пройдёт"
    fi
    msg_info "firewall/security group у хостера (если есть) — открой $new там вручную"
}

sp_main() {
    case "${1:-}" in -h|--help|help) _sp_usage; return 0 ;; esac
    [ $# -le 1 ] || { _sp_usage >&2; exit 2; }
    local new="${1:-}"
    if [ -n "$new" ] && ! _sp_valid "$new"; then echo "ssh-port: порт — число 1-65535, получено: $new" >&2; exit 2; fi
    [ -t 0 ] || die "нужен интерактивный терминал — смена порта ждёт подтверждения входа"
    need_root || die "нужен root"
    [ -x "$SSHD_BIN" ] || die "sshd не найден"
    have ss || ensure_pkg ss iproute2 iproute iproute2 || die "нужен ss (iproute2)"

    local cur p
    cur=$(_sp_ports)
    [ -n "$cur" ] || die "sshd -T не отдал порт — конфиг битый? Проверь: sshd -t"
    # ListenAddress с явным портом перекрывает Port — такую схему правь руками
    if grep -hqiE '^[[:space:]]*ListenAddress[[:space:]]+([0-9.]+|\[[0-9A-Fa-f:]+\]):[0-9]+' \
        "$SSHD_MAIN" "$SSHD_DIR"/*.conf 2>/dev/null; then
        die "в sshd_config есть ListenAddress с портом — он перекрывает Port, смени порт там вручную"
    fi

    ui_head "Смена SSH-порта" "сейчас: $cur"
    while [ -z "$new" ]; do
        printf "  ${BOLD}Новый SSH-порт${NC} ${DIM}[1-65535]${NC}: "; read -r new
        _sp_valid "$new" || { msg_warn "порт — число 1-65535"; new=""; }
    done
    new=$((10#$new))   # «0443» → 443: иначе ведущий ноль обходит проверки ниже
    for p in $cur; do [ "$p" = "$new" ] && { msg_info "SSH уже слушает $new — менять нечего"; return 0; }; done
    case "$new" in 80|443) die "$new занят под ноду (443 — VLESS/Reality, 80 — ACME)" ;; esac
    _sp_listening "$new" && die "порт $new уже занят: $(ss -Hltnp "sport = :$new" 2>/dev/null | head -1)"

    msg_info "1) sshd слушает и $cur, и $new   2) $new открывается в firewall"
    msg_info "3) проверяешь вход по $new во втором окне   4) $cur снимается"
    msg_info "текущая сессия не рвётся; вход не подтвердил — откат на $cur"
    confirm "Сменить SSH-порт $cur → $new?" || { msg_info "отменено"; return 1; }

    _sp_selinux "$new"
    _sp_backup

    ui_head "1/3 sshd" "слушает $cur + $new"
    # shellcheck disable=SC2086  # cur — список портов через пробел
    if ! _sp_apply $cur "$new"; then
        # shellcheck disable=SC2086
        _sp_rollback $cur
        die "смена прервана — sshd на прежнем порту"
    fi
    msg_ok "sshd слушает: $cur $new"

    ui_head "2/3 firewall" "$new — для тех же источников, что и $cur"
    # shellcheck disable=SC2086
    _sp_fw_open "$new" $cur

    ui_head "3/3 проверка входа" "ЭТУ сессию не закрывай"
    # адрес, по которому ты зашёл сейчас (3-е поле SSH_CONNECTION) — публичный или NetBird
    local host; host=$(awk '{print $3}' <<< "${SSH_CONNECTION:-}")
    echo -e "    во ВТОРОМ окне: ${C}ssh -p $new $(id -un)@${host:-<адрес ноды>}${NC}"
    if ! confirm "Вход по порту $new работает?"; then
        # shellcheck disable=SC2086
        _sp_rollback $cur
        msg_info "правило firewall для $new осталось — порт закрыт sshd, вреда нет"
        return 1
    fi

    if ! _sp_apply "$new"; then
        # shellcheck disable=SC2086
        _sp_rollback $cur
        die "не снял старый порт — откат на $cur"
    fi
    record_fix "ssh port $cur -> $new"
    echo
    msg_ok "SSH-порт: ${BOLD}$new${NC}"
    msg_info "firewall.nft из protect ещё со старым портом — перегенерируй: node-diagnostic.sh protect"
    msg_info "старые правила firewall для $cur не трогал — sshd там больше не слушает"
}

if [ "${BASH_SOURCE[0]:-$0}" = "${0}" ]; then
    sp_main "$@"
fi
