#!/usr/bin/env bash
# tests/sshport-it.sh — интеграция ssh-port с НАСТОЯЩИМ sshd под systemd (CI: контейнер с PID 1 = systemd).
# Гоняет шаги модуля без TTY: 22 → 22+2222 → вход по 2222 → только 2222 → откат на 22.
# ТРЕБУЕТ: root + ND_INTEGRATION=1 (тест меняет порт sshd).
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

[ "${ND_INTEGRATION:-0}" = "1" ] || { echo "пропуск: выставь ND_INTEGRATION=1 (тест меняет порт sshd)"; exit 0; }
[ "$(id -u)" -eq 0 ]             || { echo "нужен root"; exit 2; }

fail=0
ok()  { echo "  ✓ $*"; }
bad() { echo "  ✗ $*"; fail=1; }

# shellcheck source=../modules/sshport.sh
source modules/sshport.sh
BACKUP_DIR=$(mktemp -d)
lst() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }
# sshd реально отвечает баннером (при socket-activation коннект и поднимает ssh.service)
banner() { timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1 && head -c 7 <&3" 2>/dev/null | grep -q '^SSH-2.0'; }

mode="service"; systemctl is-active --quiet ssh.socket 2>/dev/null && mode="ssh.socket"
echo "== режим sshd: $mode =="

[ "$(_sp_ports)" = "22" ] && ok "старт: sshd на 22" || bad "старт: порты '$(_sp_ports)'"
_sp_backup >/dev/null

echo "== шаг 1: 22 + 2222 =="
if _sp_apply 22 2222 && lst 22 && lst 2222; then ok "слушает 22 и 2222"; else bad "шаг 1"; fi
banner 2222 && ok "вход по 2222: баннер SSH" || bad "2222 не отвечает баннером"
[ "$(_sp_ports)" = "22 2222" ] && ok "sshd -T: 22 2222" || bad "sshd -T: '$(_sp_ports)'"

echo "== шаг 2: только 2222 =="
if _sp_apply 2222 && lst 2222 && ! lst 22; then ok "слушает только 2222"; else bad "шаг 2 (22 всё ещё слушает?)"; fi
banner 2222 && ok "2222 отвечает после снятия 22" || bad "2222 не отвечает после шага 2"

echo "== откат на 22 =="
_sp_rollback 22 >/dev/null
if lst 22 && ! lst 2222; then ok "снова только 22"; else bad "откат: 22/2222 не те"; fi
banner 22 && ok "22 отвечает баннером" || bad "22 не отвечает после отката"
[ ! -e "$PORT_DROPIN" ] && ok "drop-in снят (его не было до запуска)" || bad "drop-in остался"

echo
if [ "$fail" = "0" ]; then echo "SSHPORT-IT OK"; exit 0; else echo "SSHPORT-IT FAIL"; exit 1; fi
