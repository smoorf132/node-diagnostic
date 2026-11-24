# protect: HY2 / trusted / порт мостов + балансер nginx — план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `protect` спрашивает про HY2, держит пополняемые на лету наборы `trusted4/6` (мимо per-IP лимитов 443) и опциональный порт мостов/балансеров (8443, только пул `bridge4/6`); новый модуль `balancer` ставит nginx stable с nginx.org и SNI-маршрутизацией в stream с proxy-protocol.

**Architecture:** Параметры генерации `protect` сохраняются в `<out>/protect.conf`. Живые команды `protect trust|bridge …` правят conf, перегенерируют артефакты и применяют дельту к живой таблице `inet node_protect` (элементы set'ов, при необходимости — set'ы и правила со `comment "nd:…"`, вставленные по handle). `modules/balancer.sh` хранит маршруты в `/etc/node-diagnostic/balancer.conf` и рендерит `/etc/nginx/nginx.conf` по шаблону пользователя.

**Tech Stack:** bash 4+, nftables, nginx (пакеты nginx.org, stable), shellcheck, GitHub Actions.

**Spec:** запрос пользователя в сессии 2026-11-24 (п.1–4) + конфиг nginx (финальная версия, upstream'ы на :8443).

## Global Constraints

- `protect` (генерация) по-прежнему ничего не применяет. Живые изменения — только командами `protect trust|bridge`, и только добавление/удаление accept-правил и элементов: SSH они не трогают.
- Обратная совместимость: без новых флагов `protect` генерирует то же поведение, что и раньше (HY2 = y, 443/udp открыт), плюс пустые set'ы `trusted4/6`, `bridge4/6`.
- Приоритет параметров: флаг CLI > переменная окружения > `protect.conf` > автодетект/дефолт. Списки (`--trust`, `--bridge-from`) объединяются с conf, удаление — `… del`.
- Порт мостов ≠ 443, 80, SSH-порт, NODE_PORT; диапазон 1–65535.
- `banned4` сильнее trusted и bridge (стоит раньше).
- nginx: только официальный репозиторий nginx.org, ветка stable, ключ подписи проверяется по отпечатку `573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62`. Сборка должна иметь `--with-stream_ssl_preread_module`.
- Конфиг балансера повторяет присланный шаблон; отличия: `user` — www-data, если есть, иначе nginx; `listen [::]` — только при наличии IPv6 на хосте.
- Тексты для пользователя — на русском, стиль существующих модулей (`msg_ok/msg_warn/…`).

## Review Focus

1. Живая таблица, сгенерированная старой версией (нет set'ов trusted/bridge) — `trust add`/`bridge port` должны досоздать set'ы и вставить правила **до** лимитов 443 / до финального drop, а не после него. → тест в integration (netns).
2. IPv6-адреса в `--trust`/`--bridge-from` попадают в `*6`-set'ы, мусор отвергается с ненулевым кодом. → smoke.
3. Повторный `protect` без флагов не теряет trusted/bridge/HY2 из conf. → smoke.
4. `bridge port off` убирает правило порта из живой таблицы и из firewall.nft, пул сохраняется. → integration.
5. Балансер: SNI-маска `*.example.com`, IPv6-upstream `[2001:db8::1]:8443`, удаление маршрута, который выбран default. → smoke (рендер) + CI `nginx -t` в образе nginx.

---

### Task 1: protect — conf, HY2, trusted/bridge в генерации

**Files:**
- Modify: `modules/protect.sh` (переменные, `protect_generate`, `_gen_nft`, `_gen_ufw`, `_gen_apply`, `protect_main`)
- Test: `tests/smoke.sh` (секция protect)

**Interfaces:**
- Produces:
  - `_net_norm NET` → stdout нормализованный IPv4-CIDR или IPv6[/N] (lowercase); rc 1 — мусор.
  - `_nets_fam "LIST" 4|6` → элементы семейства через `, `.
  - `_nets_add "LIST" NET…` / `_nets_del "LIST" NET…` → новый список (без дублей).
  - `protect_conf_load DIR` / `protect_conf_save DIR` — ключи `PANEL_IP NODE_PORT SSH_FROM HY2 TRUST_NETS BRIDGE_PORT BRIDGE_NETS BAN_NETS`, формат `KEY="value"`, парсится построчно (не `source`).
  - Флаги: `--hy2 y|n`, `--trust NET` (повт.), `--bridge-port N|off`, `--bridge-from NET` (повт.).
  - В firewall.nft: set'ы `trusted4/6`, `bridge4/6` (`flags interval; auto-merge`); правила `… @trusted{4,6} tcp dport 443 counter accept comment "nd:trusted"` (+udp при HY2) перед `conn443_4`; `tcp dport P ip{,6} saddr @bridge{4,6} counter accept comment "nd:bridge"` перед финальным log/drop.

- [ ] **Step 1: smoke-тесты** — `--hy2 n` → нет `udp dport 443` в nft, в ufw `allow 443/tcp`; `--trust 192.0.2.7/24 --trust 2001:DB8::/32` → `elements = { 192.0.2.0/24 }` в trusted4 и `2001:db8::/32` в trusted6; `--bridge-port 8443 --bridge-from 198.51.100.9` → правило `tcp dport 8443 ip saddr @bridge4`; `--bridge-port 443` и `--trust bogus` → rc≠0; повторный запуск с тем же `--out` без флагов сохраняет trusted/bridge/HY2=n; правило `nd:trusted` стоит раньше `meter conn443_4`; `nft -c` полного варианта.
- [ ] **Step 2:** прогнать — новые проверки падают.
- [ ] **Step 3:** реализовать; меню `[3]` спрашивает HY2 (y/n, обязательно), trusted, порт мостов и пул.
- [ ] **Step 4:** прогнать smoke — зелёный (локально без nft — синтаксис через CI).
- [ ] **Step 5:** commit `feat(protect): HY2 y/n, trusted4/6 и порт мостов bridge4/6 в генерации`.

### Task 2: protect — живые команды trust/bridge

**Files:**
- Modify: `modules/protect.sh` (`protect_live_*`, диспетчер `protect_main`), `node-diagnostic.sh` (help, подменю `[3]`)
- Test: `tests/integration.sh` (netns `ndprot`)

**Interfaces:**
- Consumes: Task 1 (`protect_conf_*`, `_net_norm`, `_nets_*`, имена set'ов/comment'ов).
- Produces: `protect trust add|del NET… | list`, `protect bridge add|del NET… | list | port N|off`, общий `--out DIR`. Поток: conf → перегенерация артефактов (если в conf есть полный набор параметров) → дельта в живой таблице (если она есть и есть root+nft) → копия в `PROTECT_PERSIST` (`/etc/nftables.d/node_protect.nft`), если файл существует.
- Вставка: `nft insert rule inet node_protect input handle H …` (перед H). Якорь trusted — первое правило с `tcp dport 443`; якорь bridge — правило с `node_protect drop`.

- [ ] **Step 1: integration-тесты в netns** — загрузить сгенерированный firewall; `trust add 192.0.2.0/24 2001:db8::/32` → элементы в живых set'ах и в conf; `bridge port 8443` + `bridge add 203.0.113.7` → правило в живой цепочке до `node_protect drop`; `bridge port off` → правила нет, элемент в bridge4 остался; `trust del` → элемента нет; «старая» таблица без trusted/bridge (вырезаны awk) → `trust add` досоздаёт set и правило раньше `conn443_4`.
- [ ] **Step 2:** реализовать.
- [ ] **Step 3:** shellcheck/bash -n, commit `feat(protect): trust/bridge — пополнение firewall на лету`.

### Task 3: balancer — nginx stable + SNI-маршруты

**Files:**
- Create: `modules/balancer.sh`
- Modify: `node-diagnostic.sh` (dispatch `balancer|lb`, help, меню `[13]`), `modules/install.sh` (`install balancer` → модуль)
- Test: `tests/smoke.sh` (рендер/conf), CI `nginx -t` в `nginx:stable-alpine`

**Interfaces:**
- Produces:
  - `balancer install [--route SNI=HOST:PORT[,HOST:PORT…]]… [--default SNI] [--no-proxy-protocol]` (без маршрутов в TTY — спрашивает).
  - `balancer add SNI HOST:PORT[,…]`, `del SNI`, `default SNI`, `list`, `apply`, `status`.
  - `bal_render CONF OUT [user] [ipv6 0|1]` — чистая функция рендера (для smoke).
  - conf `BALANCER_CONF` (по умолч. `/etc/node-diagnostic/balancer.conf`): строки `route SNI UP1 [UP2…]`, `default SNI`, `proxy_protocol on|off`.
  - Имя upstream: `up_` + SNI с заменой `[^A-Za-z0-9]` → `_`.
  - apply: бэкап `/etc/nginx/nginx.conf.nd-bak-<ts>`, `nginx -t` (провал → откат бэкапа, rc≠0), `systemctl enable nginx` + reload/start.

- [ ] **Step 1: smoke** — рендер двух маршрутов: `map $ssl_preread_server_name $backend`, `hostnames;`, строки SNI→upstream, `default up_…`, `ssl_preread on;`, `proxy_pass $backend;`, `proxy_protocol on;`, `server 80.79.117.98:8443;`; `worker_rlimit_nofile` ≥ 131070; без IPv6 нет `listen [::]`; `*.example.com` и `[2001:db8::1]:8443` принимаются; `bad_sni!`/`1.2.3.4:99999` отвергаются; `del` default-маршрута переводит default на первый оставшийся.
- [ ] **Step 2:** реализовать модуль + установку nginx.org (apt: keyring + отпечаток + pin 900; dnf/yum: nginx-stable repo); проверка `nginx -V` на ssl_preread; занятые 80/443 чужим процессом → отказ.
- [ ] **Step 3:** `nginx -t` рендера в `nginx:stable-alpine` — в smoke (джоба smoke-ubuntu, где есть docker), отдельная CI-джоба не нужна.
- [ ] **Step 4:** commit `feat(balancer): nginx stable с nginx.org, SNI → upstream с proxy-protocol`.

### Task 4: документация

- [ ] README (`protect`, новый раздел `balancer`), CHANGELOG `[Unreleased]`, help — commit `docs: …`.
