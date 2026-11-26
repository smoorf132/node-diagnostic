#!/usr/bin/env bash
# install.sh — бутстрап node-diagnostic: скачать репозиторий целиком и запустить меню.
# Установка одной командой:
#   curl -sSL https://raw.githubusercontent.com/smoorf132/node-diagnostic/main/install.sh | sudo bash
# Переопределяемо через env: ND_REPO, ND_REF (ветка/тег), ND_DEST (каталог).
set -eu

REPO="${ND_REPO:-https://github.com/smoorf132/node-diagnostic}"
REF="${ND_REF:-main}"
if [ "$(id -u)" -eq 0 ]; then DEST="${ND_DEST:-/opt/node-diagnostic}"
else DEST="${ND_DEST:-$HOME/.local/share/node-diagnostic}"; fi

have() { command -v "$1" >/dev/null 2>&1; }
say()  { printf '  %s\n' "$*"; }

say "node-diagnostic → $DEST  (ref: $REF)"

if have git; then
    if [ -d "$DEST/.git" ]; then
        # origin старой копии мог смотреть в другой репозиторий (ставили из апстрима,
        # теперь из форка / ND_REPO) — без set-url fetch молча тянул бы оттуда
        old_repo=$(git -C "$DEST" remote get-url origin 2>/dev/null || true)
        if [ "${old_repo%.git}" != "${REPO%.git}" ]; then
            git -C "$DEST" remote set-url origin "$REPO" 2>/dev/null \
                || git -C "$DEST" remote add origin "$REPO"
            say "источник: ${old_repo:-нет} → $REPO"
        fi
        # FETCH_HEAD вместо origin/$REF — работает и для ветки, и для тега
        # (origin/<тег> не существует, старый вариант на теге молча умирал)
        if git -C "$DEST" fetch --depth 1 origin "$REF" >/dev/null 2>&1 \
           && git -C "$DEST" reset --hard FETCH_HEAD >/dev/null 2>&1; then
            say "обновлено через git"
        else
            say "ОШИБКА: не смог обновить $DEST (нет сети? ref '$REF' существует?)"
            exit 1
        fi
    else
        rm -rf "$DEST"
        git clone --quiet --depth 1 --branch "$REF" "$REPO" "$DEST" \
            || { say "ОШИБКА: клонирование не удалось ($REPO, ref '$REF')"; exit 1; }
        say "склонировано через git"
    fi
else
    # без git — tarball; пробуем ветку, затем тег
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    fetch() {
        if   have curl; then curl -fsSL "$1" -o "$tmp/src.tgz"
        elif have wget; then wget -qO "$tmp/src.tgz" "$1"
        else say "нужен git, curl или wget"; exit 1; fi
    }
    fetch "$REPO/archive/refs/heads/$REF.tar.gz" \
        || fetch "$REPO/archive/refs/tags/$REF.tar.gz" \
        || { say "ОШИБКА: не скачал tarball для ref '$REF'"; exit 1; }
    tar -xzf "$tmp/src.tgz" -C "$tmp"
    mkdir -p "$DEST"
    cp -r "$tmp"/node-diagnostic-*/. "$DEST/"
    say "распаковано из tarball"
fi

chmod +x "$DEST/node-diagnostic.sh" "$DEST"/modules/*.sh "$DEST"/lib/*.sh 2>/dev/null || true

# ── команда rr ───────────────────────────────────────────────────────
# Обёртка, а не симлинк: node-diagnostic.sh ищет lib/ рядом с собой, а рядом с
# симлинком в /usr/local/bin тулкита нет. Не под root — перезапускает себя через sudo.
# При каждом запуске подтягивает актуальную версию ($REF) в $DEST тем же способом, что
# и установка (git или tarball). Нет доступа к GitHub — предупреждает и запускает локальную
# копию: тулкит должен работать и на ноде с поломанной сетью. ND_NO_PULL=1 — не подтягивать.
# Логика внутри обёртки: она лежит вне $DEST и не перезаписывает сама себя на ходу.
if [ "$(id -u)" -eq 0 ]; then BIN_DIR="${ND_BIN_DIR:-/usr/local/bin}"
else BIN_DIR="${ND_BIN_DIR:-$HOME/.local/bin}"; fi
RR="$BIN_DIR/rr"
if [ -e "$RR" ] && ! grep -q 'node-diagnostic' "$RR" 2>/dev/null; then
    say "ВНИМАНИЕ: $RR уже есть и это не node-diagnostic — не перезаписываю"
else
    mkdir -p "$BIN_DIR"
    {
        printf '#!/usr/bin/env bash\n# rr — запуск node-diagnostic (ставит install.sh; источник: %s, ref %s)\n' "$REPO" "$REF"
        printf 'ND_RR_DEST=%q\nND_RR_REPO=%q\nND_RR_REF=%q\n' "$DEST" "$REPO" "$REF"
        cat <<'EOF'
# При каждом запуске подтягивает актуальную версию; нет доступа к GitHub — запускает
# локальную копию. ND_NO_PULL=1 — без подтягивания.
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
    [ -n "${ND_NO_PULL:-}" ] && exec sudo ND_NO_PULL=1 bash "$0" "$@"
    exec sudo bash "$0" "$@"
fi

nd_rr_pull() {
    [ -n "${ND_NO_PULL:-}" ] && return 0
    local t="" old before after tmp d src=""
    command -v timeout >/dev/null 2>&1 && t="timeout 20"
    if [ -d "$ND_RR_DEST/.git" ] && command -v git >/dev/null 2>&1; then
        old=$(git -C "$ND_RR_DEST" remote get-url origin 2>/dev/null)
        if [ "${old%.git}" != "${ND_RR_REPO%.git}" ]; then
            git -C "$ND_RR_DEST" remote set-url origin "$ND_RR_REPO" 2>/dev/null \
                || git -C "$ND_RR_DEST" remote add origin "$ND_RR_REPO" 2>/dev/null
        fi
        before=$(git -C "$ND_RR_DEST" rev-parse --short HEAD 2>/dev/null)
        GIT_TERMINAL_PROMPT=0 $t git -C "$ND_RR_DEST" -c http.lowSpeedLimit=1000 -c http.lowSpeedTime=10 \
            fetch -q --depth 1 origin "$ND_RR_REF" >/dev/null 2>&1 || return 1
        git -C "$ND_RR_DEST" reset -q --hard FETCH_HEAD >/dev/null 2>&1 || return 1
        after=$(git -C "$ND_RR_DEST" rev-parse --short HEAD 2>/dev/null)
        [ "$before" = "$after" ] || printf '  node-diagnostic: обновлён %s → %s\n' "${before:-?}" "$after" >&2
        return 0
    fi
    # без git — tarball ветки, затем тега
    tmp=$(mktemp -d) || return 1
    _get() {
        if command -v curl >/dev/null 2>&1; then $t curl -fsSL --connect-timeout 10 -o "$tmp/src.tgz" "$1"
        else $t wget -q --timeout=15 -O "$tmp/src.tgz" "$1"; fi
    }
    if { _get "$ND_RR_REPO/archive/refs/heads/$ND_RR_REF.tar.gz" || _get "$ND_RR_REPO/archive/refs/tags/$ND_RR_REF.tar.gz"; } \
       && tar -xzf "$tmp/src.tgz" -C "$tmp" 2>/dev/null; then
        for d in "$tmp"/*/; do [ -f "$d/node-diagnostic.sh" ] && src=$d; done
        [ -n "$src" ] && cp -r "$src". "$ND_RR_DEST/" && { rm -rf "$tmp"; return 0; }
    fi
    rm -rf "$tmp"
    return 1
}

if ! nd_rr_pull; then
    v=$(sed -n 's/^ND_VERSION="\(.*\)"$/\1/p' "$ND_RR_DEST/lib/common.sh" 2>/dev/null)
    printf '  ⚠ node-diagnostic: актуальная версия не подтянулась (нет доступа к GitHub?) — запускаю локальную v%s\n' "${v:-?}" >&2
fi
exec bash "$ND_RR_DEST/node-diagnostic.sh" "$@"
EOF
    } > "$RR"
    chmod 755 "$RR"
    say "команда rr → $RR"
    case ":$PATH:" in *":$BIN_DIR:"*) ;; *) say "ВНИМАНИЕ: $BIN_DIR нет в PATH — добавь его или запускай $RR" ;; esac
fi
# remnawave-reverse-proxy вешает alias rr='remnawave_reverse' в /etc/bash.bashrc — alias
# перекрывает команду в интерактивном bash, rr открывал бы чужой скрипт
for rc in /etc/bash.bashrc "$HOME/.bashrc"; do
    [ -w "$rc" ] && grep -qE "^[[:space:]]*alias rr=" "$rc" || continue
    sed -i -E "s/^([[:space:]]*alias rr=.*)$/# node-diagnostic: rr теперь node-diagnostic; было: \1/" "$rc"
    say "alias rr в $rc отключён (remnawave-reverse-proxy остаётся командой remnawave_reverse)"
    say "  в этой сессии он ещё жив: выполни 'unalias rr' или перелогинься"
done

echo
say "Готово. Запуск:"
say "  rr          (или: sudo bash $DEST/node-diagnostic.sh)"

# В терминале — сразу открыть меню. При `curl | bash` stdin занят пайпом,
# поэтому подключаем клавиатуру через /dev/tty (иначе меню не открылось бы никогда).
if [ -t 1 ] && [ -r /dev/tty ]; then
    exec bash "$DEST/node-diagnostic.sh" "$@" </dev/tty
fi
