# Changelog

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/).

## [Unreleased]

Установка ноды из eGamesAPI/remnawave-reverse-proxy (без Caddy и ufw), сертификаты,
WARP, IPv6 и команда `rr`. fail2ban заменён на CrowdSec; SSH можно пускать из всей подсети NetBird.

### Added
- **`install node`** (меню `[7]` → `[1]`, модуль `modules/node.sh`) — нода Remnawave под ключ, порт варианта с nginx из [eGamesAPI/remnawave-reverse-proxy](https://github.com/eGamesAPI/remnawave-reverse-proxy) без Caddy и ufw. Ставятся Docker, certbot, зеркала Docker Hub и unattended-upgrades. Проверяется A-запись selfsteal-домена (без прокси Cloudflare); если её нет, она создаётся через API Cloudflare / Gcore / Bunny или вручную. Спрашиваются IP панели, `SECRET_KEY` (понимает вставку целиком с `NODE_PORT=`) и `NODE_PORT`. Затем выпускается сертификат, в `/opt/remnanode` пишутся `docker-compose.yml`, `.env` (600) и `nginx.conf`: nginx на unix-сокете `/dev/shm/nginx.sock` с `proxy_protocol`, неизвестные SNI обрываются. Ставится случайный рандомизированный шаблон сайта, после `docker compose up -d` проверяется `https://домен`. Прежние конфиги сохраняются в `*.bak-<время>`. В конце подсказывается `rr protect` под IP панели вместо ufw.
- **`certs`** (меню `[10]`, модуль `modules/certs.sh`) — сертификаты: продление тех, у кого ≤30 дней, выпуск и загрузка своего. Пять методов: Cloudflare / Gcore / Bunny DNS-01 (wildcard), ACME HTTP-01, свой `fullchain.pem` + `privkey.pem` (проверяются пара, покрытие домена и срок; wildcard переносится в папку базы). Есть хуки продления (перезапуск `remnawave-nginx`; для HTTP-01 — остановка и запуск nginx, без ufw), cron, починка симлинков `live/`. Если пропал ini-файл ключа DNS-плагина, ключ спрашивается заново. Без Telegram-уведомлений.
- **`warp`** (меню `[7]` → `[2]`, модуль `modules/warp.sh`) — установка и удаление distillium/warp-native. Скрипт запускается только тогда, когда два независимых источника отдали одинаковые байты. После установки печатается JSON outbound'а `warp-out` для профиля Xray.
- **`ipv6`** (меню `[11]`, модуль `modules/ipv6.sh`) — статус и включение/выключение IPv6 через `/etc/sysctl.d/99-remnawave-ipv6.conf` (тот же файл, что у апстрима). Применение проверяется: `ipv6.disable=1` в GRUB sysctl молча игнорирует. Если адреса нет, предлагается обновить сеть. Перед выключением при SSH по IPv6 спрашивается подтверждение.
- **Команда `rr`**: `install.sh` ставит обёртку `/usr/local/bin/rr` (без root — `~/.local/bin`), которая не под root перезапускается через `sudo`. Alias `rr` от remnawave-reverse-proxy в `/etc/bash.bashrc` комментируется, иначе он перекрыл бы команду.
- `lib/dns.sh`: `extract_domain` с двухуровневыми суффиксами (`com.ru`, `co.uk`…), `public_ipv4`, диапазоны Cloudflare, A-записи через API. В `lib/common.sh`: `ask`, `is_ipv4`, `download_file`, `download_verified`, `REMNANODE_DIR`.
- `protect` находит `NODE_PORT` в `docker-compose.yml` ноды (`- NODE_PORT=2222` / `NODE_PORT: 2222`), то есть и в установках remnawave-reverse-proxy.
- nginx ноды: сайт `nginx.conf` (TLS 1.3, без OCSP stapling — у Let's Encrypt он выключен, access-лог `proxy_protocol`, security-заголовки, кэш статики, `:80` → https) и главный `nginx-main.conf` → `/etc/nginx/nginx.conf` контейнера (`worker_connections 4096`, `worker_rlimit_nofile`, буферы, `open_file_cache`, gzip, `log_format proxy_protocol`). Установщик проверяет, что свободны и 443, и 80.
- smoke: диспетчеры node/certs/warp/ipv6, отказ без TTY, `extract_domain`/`cert_covers_domain`, рендер compose/.env/nginx.conf/nginx-main.conf, `docker compose config`, `nginx -t` обоих конфигов в образе ноды, детект `NODE_PORT` из compose.
- **`ssh-port`** (меню `[9]`, модуль `modules/sshport.sh`) — быстрая смена SSH-порта без лок-аута. Сначала sshd слушает старый и новый порт, новый открывается в firewall (`node_protect` / ufw / firewalld) для тех же источников, что и старый, при SELinux Enforcing порт размечается через `semanage`. После подтверждения входа во втором окне старый порт снимается; не подтвердил — конфиги sshd возвращаются из бэкапа. Учтены аддитивность `Port` (чужие строки комментируются), конфиги без `Include` и socket-activation Ubuntu 22.10+ (`daemon-reload` + `restart ssh.socket`). В CI новая джоба `sshport`: настоящий sshd под systemd на Ubuntu 24.04 и Debian 12, проверяются оба шага, вход и откат.
- **protect: SSH из подсети NetBird** — если текущая SSH-сессия пришла через NetBird, правила nft/ufw открывают SSH всей подсети NetBird (`wt0` или `netbird status`), а не одному IP пира. Новый флаг `--ssh-from IP|CIDR` и вопрос в меню `[3]` задают источник явно; хост-биты обнуляются (`100.92.13.5/16` → `100.92.0.0/16`, ufw иначе отвергает правило). Отдельные предупреждения на экране и в `APPLY.txt`: «SSH только через NetBird», «текущая сессия вне разрешённой подсети — firewall её оборвёт». Если NetBird есть, а сессия пришла с публичного IP, модуль подсказывает готовый `--ssh-from`.
- **protect: перманентный бан подсетей** — в `firewall.nft` появился set `banned4` (`flags interval`, `auto-merge`) из `BAN_NETS`, по умолчанию `185.224.228.0/22 195.209.120.0/22 212.192.156.0/23 212.192.158.0/24 194.165.22.0/23`. Drop стоит раньше `established` в input и в forward (docker-bridge после DNAT), со счётчиком. Хост-биты обнуляются, не-IPv4 пропускается с предупреждением. Если SSH-источник или IP панели попадает в забаненную подсеть, модуль предупреждает о лок-ауте. `BAN_NETS=""` отключает бан.
- `lib/common.sh`: `ipv4_net`, `ip_in_cidr`, `netbird_addr`, `netbird_cidr`.
- `install crowdsec`: подсеть NetBird заносится в allowlist; уже выданные решения по ней снимаются (`decisions delete --range … --contained`).
- **`install crowdsec`** (меню `[7]` → `[5]`): движок CrowdSec из packagecloud + `crowdsec-firewall-bouncer-nftables`, коллекции `crowdsecurity/linux` + `crowdsecurity/sshd`. SSH-IP и IP панели заносятся в allowlist `node-diagnostic` до установки bouncer'а, уже выданные по ним решения снимаются, чтобы IP из community-блоклиста не оборвал SSH-сессию посреди установки. Если acquisition для SSH нет, пишется fallback (файлы rsyslog или journald `ssh.service`/`sshd.service`). Перед установкой проверяется, что свободен порт LAPI 8080. Найденный fail2ban установщик предлагает остановить и удалить. Только deb/rpm + systemd.
- `diagnose` в рекомендациях предлагает `install.sh crowdsec`, если CrowdSec не установлен.

### Changed
- Репозиторий по умолчанию — `smoorf132/node-diagnostic` (`install.sh`, подсказки, README).

### Removed
- **`install node` / `install selfsteal` от DigneZzZ/remnawave-scripts**: оба писали в `/opt/remnanode` и конфликтовали бы с новой установкой. Selfsteal теперь часть `install node`, а `install selfsteal` подсказывает новую команду (rc=2).
- **protect: fail2ban** — `fail2ban-sshd.local` больше не генерируется. В `APPLY.txt` шаг 2 теперь ставит CrowdSec, откат — `apt purge crowdsec crowdsec-firewall-bouncer-nftables`.

### Fixed
- **install.sh**: при обновлении существующей копии `git fetch` шёл из её старого `origin`, а не из `REPO`. Установка из апстрима `Case211` молча оставалась на нём, даже если установщик запускали из форка или с `ND_REPO`. Теперь `origin` переставляется на `REPO` с сообщением «источник: старый → новый».
- **detect_virt**: на bare-metal `systemd-detect-virt` печатает `none` и выходит с кодом 1, поэтому `|| echo unknown` дописывал вторую строку: в баннере меню выходило `none` + `unknown`, в `diagnose` — переносы в поле Virt. `diagnose` теперь использует общий `detect_virt`.

## [4.4.0] — в `main` с 2026-07-20

Per-IP eBPF-шейпер полосы, диагностика «reality over sysctl» и точечный
сетевой тюнинг. Идеи из ресёрча DonMatteoVPN/Reshala-Remnawave-Bedolaga (MIT)
и jestivald/node-accelerator.

### Added
- **Шейпер трафика (`[8]` в меню, команда `shape`, eBPF + EDT)** — per-IP лимиты
  полосы: каждый клиентский IP получает независимый DL/UL под правилом порта,
  whitelist обходит шейпинг, опц. dynamic-режим со штраф-рейтом абузеру.
  `nd-shaper.bpf.c` (clsact: DL=EDT egress, UL=token-bucket ingress) +
  `shape_ctrl.py` (bpftool) + `shape.sh` (компиляция/attach/persist/rollback).
  Требует ядро ≥5.4 + clang/bpftool/libbpf-dev. CI собирает BPF (`bpf-compile`).
- **diagnose: reality-чеки (24→27)** — CPU steal % (оверселл VPS), UDP
  RcvbufErrors (дропы QUIC/Hysteria2/TUIC), PSI (`/proc/pressure`), accept-queue
  backlog, а также BBR live-socket, MSS-коллапс по живым сокетам, single-queue
  NIC — «считаем живое, а не только sysctl».
- **optimize: irqbalance + journald-cap** (в `--all`), **zram-swap** (opt-in
  `--zram` / меню `[z]`), sysctl `netdev_budget`/`tcp_ecn=2`/`src_valid_mark=1`,
  `ethtool -K lro off`.

### Fixed
- `src_valid_mark=1` рядом с `rp_filter` — иначе строгий reverse-path мог молча
  ронять исходящий WireGuard/WARP на ноде.

## [4.3.0] — в `main` с 2026-07-20

Провижининг ноды из меню и надёжный `optimize` на минимальных образах.

### Added
- **Меню: пункт «Установка Remnanode»** (`[7]`, команда `install`, модуль `modules/install.sh`) с четырьмя сабкомандами. Внешние установщики запускаются только после явного подтверждения (показ команды + `confirm`).
  - `node` — установщик ноды Remnawave (`remnanode.sh @ install`, DigneZzZ/remnawave-scripts).
  - `selfsteal` — установщик Selfsteal (`selfsteal.sh @ install`).
  - `netbird` — агент NetBird (`pkgs.netbird.io/install.sh`) + `netbird up --setup-key` (ключ спрашивается интерактивно).
  - `monitoring` — cAdvisor 0.53.0 + node_exporter 1.9.1 + vmagent (vmutils 1.123.0) точно по гайду wiki.egam.es: `/opt/monitoring`, конфиги `scrape.yml`/`conf.d`, три systemd-юнита; спрашивает имя инстанса и IP сервера мониторинга (NetBird) для `remoteWrite`; всё слушает `127.0.0.1`; гейты root/amd64/systemd.
- **`lib/common.sh`: общий `confirm()`** (y/N-подтверждение).

### Fixed
- **`optimize` сам ставит свои зависимости** (`iproute2`/`ethtool`/`iptables`). Раньше их тянул только `diagnose` — на минимальной ноде без `iproute2` `default_iface` слепла и RPS/RFS/XPS + NIC-тюнинг молча пропускались («интерфейс не определён»). Добавлен `ensure_pkg` в `lib/common.sh` (root + пакетный менеджер, `apt update` максимум раз за процесс).

## [4.2.0] — в `main` с 2026-07-13

Единый визуальный язык на весь тулкит, полноценный dual-stack IPv6, проверенные до конца установочные пути и новый чек безопасности. XanMod-путь впервые прогнан живьём (ключ → репо → пакет ядра → prereboot-чеки) на Ubuntu 24.04 и Debian 12.

### Added
- **UI: единый визуальный язык «карточки в рамках»** — дашборд диагностики (сводка по категориям + карточка «ВЕРДИКТ» со score-баром), `status` и вывод модулей собраны из общих UI-примитивов в `lib/common.sh` (`box_*`, `ui_head`/`ui_divider`/`ui_rule`, семантические токены). Ширина рамки считается по видимым колонкам (`vlen`: срез ANSI + учёт кириллицы/вариационных селекторов), адаптируется под ширину терминала; `⚠` форсит text-presentation (1 колонка везде).
- **diagnose: 24-й чек «Открытые порты»** — скан публичных листенеров (`ss`): docker-API 2375/2376 и голые БД (postgres/mysql/redis/mongo/es/etcd) на `0.0.0.0`/`[::]` → критично; нестандартные порты → предупреждение; свой SSH/443/80 — штатны.
- **protect: полный dual-stack IPv6** — SSH/NODE_PORT/panel_ip генерятся по семейству адреса (`ip6 saddr`/`ipv6_addr`), per-IP лимиты 443 продублированы на v6 (раньше v6-клиенты обходили rate-limit). `nft -c` проходит во всех комбинациях v4/v6. Прежний код при v6-адресе просто ставил плейсхолдер.
- **status** — новая команда и пункт меню [6]: что тулкит наложил на систему (drop-in'ы, юниты, MSS clamp), ядро, cc/qdisc, хвост журнала применённого.
- **tests/integration.sh + CI-джоба** — реальное применение `optimize --all` → сверка значений в ядре → идемпотентность → `rollback` дочиста → `protect`/`nft -c` в privileged-контейнере (Ubuntu 24.04 + Debian 12). То, что smoke (dry-run) не покрывал. CI-матрица расширена до Ubuntu 22.04/24.04 + Alpine.

### Fixed
- **bbr3**: XanMod дропает репозитории старых релизов (`jammy`/`focal` → 404) — раньше скрипт успевал поставить ключ и источник, ломал `apt update` юзеру и падал с невнятным warn. Теперь пре-чек suite ДО любых изменений: на Ubuntu 22.04 — внятный отказ («система не тронута»), с живыми альтернативами.
- **bbr3**: при психе `apt update` после добавления репо источник и ключ убираются автоматически (apt юзера восстанавливается).
- **bbr3**: подбор пакета перепрыгивал v3 — CPU уровня v4 получал v2-ядро, хотя v3 в репо есть (v4 XanMod не публикует). Деградация теперь ступенчатая v4→v3→v2→v1; на реальном CPU v4 выбирается `linux-xanmod-lts-x64v3`.
- **diagnose/ensure_deps**: dpkg-лок-таймаут 60с (unattended-upgrades на Ubuntu держит лок — установка молча отваливалась); честный отчёт «не удалось поставить: …» в дашборд; список устанавливаемого — в лог; `iproute2/iproute` добавлен в карту (минимальные RHEL-образы без `ip` — NIC/туннели были слепые). dnf-путь впервые проверен живьём (Rocky 9: все 10 утилит ставятся), apk — тоже.
- **diagnose/CPU**: колонка softirq в mpstat искалась по фиксированному номеру `$9` — это `%steal`, не `%soft`: детект «softirq — настрой RPS» годами читал не ту метрику. Колонки теперь ищутся по имени из заголовка (sysstat с/без `%gnice`, busybox).
- **optimize/MSS clamp**: `iptables-persistent` на apt-дистро ставится автоматически (тихо, noninteractive) — раньше правила не переживали reboot, а скрипт лишь советовал доустановить руками.

## [4.1.1] — в `main` с 2026-07-13

Второй аудит — косяки, найденные живыми прогонами на Alpine (busybox) и non-root Debian.

### Fixed
- **diagnose/variance**: расчёт разброса шёл через `bc` с тернарником `?:`, которого у bc нет (ни GNU, ни busybox) — строка всегда падала, `ratio` был пустой («(x)» в сводке), а пороги троттлинга x2/x3 не срабатывали. Детект троттлинга по разбросу был мёртв. Переведено на целочисленный bash.
- **diagnose/4-flow**: под non-root/минимальной системой без `bc` результат был пустым — дашборд показывал «Speed: 4-flow  Mbit/s» без числа и печатал «integer expression expected». Считается нативным bash.
- **optimize/RPS**: битмаска CPU обнулялась при 64+ ядрах (переполнение `1<<n`) и давала невалидный формат при 33–63 — RPS/RFS/XPS не применялся. Хелпер `cpu_mask` генерит корректный многословный формат (`ffffffff,ffffffff`).
- **protect/ufw**: правило `ufw limit <ssh>/tcp` («анти-брут») — это ALLOW отовсюду с рейт-лимитом: оно открывало SSH всему интернету и обесценивало ограничение по IP. Удалено (анти-брут — fail2ban), в скрипте предупреждение.
- **protect**: подсказка для remnanode в docker-bridge (NODE_PORT-фильтр в input не видит DNAT-трафик — готовое правило для forward закомментировано в firewall.nft + пометка в APPLY.txt); IPv6-адрес SSH/панели больше не уезжает в IPv4-шаблон (плейсхолдер + предупреждение); детект authorized_keys видит `ecdsa-sha2-*` и `sk-*` ключи; комментарий для fail2ban без systemd (Alpine).
- **diagnose**: полностью выпилен `bc` (identify/CPU/bufferbloat/retrans/variance/4-flow) — на системах без bc пороги молча не работали; убран из автоустановки. Совместимость с busybox: MTU без `grep -P` (на Alpine был «слеп»), «ping без `-M do`» отличается от «ICMP порезан», fallback MemFree для ядер без MemAvailable, `export LANG`.
- **diagnose/bufferbloat**: объём под нагрузкой меряется по файлу (`stat`), а не `-w %{size_download}` — kill по дедлайну терял вывод, и на каналах медленнее ~115 Mbit/s тест всегда фейлился «0 bytes».
- **diagnose/services**: один повторный запрос при коде 000 — разовый сетевой чих больше не даёт ложное «Недоступны: …».
- **optimize**: на системах без systemd (Alpine/OpenRC) — честное предупреждение вместо сырой ошибки записи юнита; runtime-применение sysctl через `sysctl -p` (busybox без `--system`).
- **install**: обновление по тегу работало только при первой установке (`origin/<тег>` не существует — теперь `FETCH_HEAD`); ошибки git/скачивания больше не молчат; tarball-путь пробует и `refs/tags`.
- **меню**: октеты IPv4 проверяются (`300.1.1.1` отклоняется), NODE_PORT — число 1–65535 с переспросом.

## [4.1.0] — в `main` с 2026-07-12

Меню доведено до полностью интерактивного: флаги больше не нужны ни для одного пункта.

### Added
- **Меню → Диагностика**: выбор режима — полная (~5 мин) / быстрая `[q]` (~1 мин).
- **Меню → Защита**: визард спрашивает IP панели (с проверкой, что это IPv4) и NODE_PORT; Enter — плейсхолдер/автодетект как раньше.
- **Меню → BBRv3**: план (dry-run) и установка запускаются прямо из пункта (`[d]`/`[i]`), установка — со своим подтверждением y/N; в не-TTY по-прежнему печатаются команды.

### Fixed
- **diagnose**: тихая установка зависимостей (`ensure_deps`) наследовала TTY — debconf съедал клавиатурный ввод, и меню после диагностики зависало на «Enter — вернуться» (найдено TTY-тестом меню). Теперь пакетные менеджеры получают `</dev/null` + `DEBIAN_FRONTEND=noninteractive`.

## [4.0.1] — в `main` с 2026-07-12

Пакет фиксов по аудиту v4.0 после мержа в main.

### Fixed
- **protect**: явное предупреждение о лок-ауте при динамическом SSH-IP — на экране при генерации и в `APPLY.txt` (варианты: CIDR подсети провайдера / только rate-limit+fail2ban / проверка VNC-консоли).
- **версия**: `ND_VERSION`/`SCRIPT_VERSION` дублировались — теперь единый источник `lib/common.sh` (диспетчер передаёт через env, standalone diagnose вытягивает сам).
- **optimize**: RPS-юнит писал мусор в корень ФС (`/rps_cpus` и др.) и не восстанавливал RPS/RFS/XPS после ребута — systemd раскрывал `$q` в ExecStart (нужно `$$`).
- **protect**: connlimit на 443 был глобальным на порт (душил ноду при >2048 суммарных соединений), а не per-IP — теперь `meter { ip saddr ct count }`.
- **protect**: `detect_node_port` мог взять published-порт чужого контейнера и брал internal-часть маппинга вместо хостовой.
- **bbr3**: sysctl-конфликт с optimize — `…-tuning.conf` сортируется позже `…-bbr.conf` и перекрывал cc обратно (сценарий «поставил XanMod, а cc снова cubic»).
- **bbr3**: гейт контейнеров не видел Docker/Podman (`/.dockerenv`, `/run/.containerenv`, cgroup) — установка ядра предлагалась внутри контейнера.
- **bbr3**: dry-run и сообщение об отсутствии пакета игнорировали `--level`.
- **diagnose**: ложный «PMTU=28» (crit) когда ICMP не ходит вовсе — теперь skip с подсказкой.
- **diagnose**: спидтесты затирали вывод curl при exit 28 — ложные fail на каналах медленнее ~70 (1-flow) / ~160 (variance) Mbit/s; теперь считается реально скачанное.
- **diagnose**: отсутствие `nc` считалось блокировкой UDP/443.
- **diagnose**: `--no-net` всё равно ходил в интернет (идентификация: ipify/гео-базы/latency-пробы).
- **diagnose**: 403 анти-бот-фронтов (Claude, Reddit) считался блокировкой IP на любом IP.
- **diagnose**: спиннер лился кадрами в пайп/лог (не гейтился на TTY); `apt-get update` дёргался на каждом прогоне даже без недостающих пакетов.
- **common**: `verify_sysctl` не нормализовал табы — multi-value ключи вечно «не применились».
- **common/optimize**: ошибки редиректов (`> file 2>/dev/null`) летели на экран, persist модулей в `modules-load.d` молча терялся без каталога — после ребута слетали bbr/conntrack-ключи.
- **все точки входа**: запуск через pipe (`curl … | bash`) падал с «BASH_SOURCE[0]: unbound variable»; модули без common.sh продолжали работать вхолостую — теперь внятный отказ с подсказкой.
- **install**: обещанное меню после `curl | sudo bash` никогда не открывалось (stdin занят пайпом) — теперь через `/dev/tty`.
- **CI**: `nft -c` фактически не выполнялся (нет CAP_NET_ADMIN) — smoke под sudo/NET_ADMIN, фейл под root блокирующий.

## [4.0] — в `main` с 2026-07-11 (PR #1)

Переработка монолита в модульный тулкит + защита под Remnawave + BBRv3.

### Added
- Модульная структура: `node-diagnostic.sh` (меню + диспетчер команд) · `lib/common.sh` · `modules/{diagnose,optimize,protect,bbr3,rollback}.sh`.
- Интерактивное меню и подкоманды (`diagnose`/`optimize`/`protect`/`bbr3`/`rollback`) + флаги для CI/non-TTY.
- `optimize`: `tcp_min_snd_mss=512`, FD-лимиты (`fs.file-max` + systemd `DefaultLimitNOFILE` для xray + pam), SYN-flood/anti-spoof, TIME_WAIT/keepalive, UDP-буферы, буферы и conntrack масштабом по RAM, RPS/RFS/XPS, NIC offloads. Загрузка модулей (`tcp_bbr`/`nf_conntrack`/`sch_cake`) + verify-after-apply + выбор cc/qdisc по доступности. Флаг `--from-findings`.
- `protect`: генерация firewall (nftables/ufw — 443/80 всем, NODE_PORT только с IP панели, per-IP rate-limit), fail2ban, SSH-хардненинг + `APPLY.txt` с защитой от лок-аута. Режим только генерация.
- `bbr3`: установка ядра XanMod (BBRv3) — гейт контейнеров, проверка отпечатка GPG-ключа, psABI-детект, override `--level`, предупреждение о маскированном CPU, без автоперезагрузки.
- `rollback`: откат namespaced-артефактов.
- `diagnose --json` — машиночитаемый вывод для агрегации по флоту.
- `install.sh` — бутстрап `curl | bash`.
- CI (GitHub Actions): shellcheck + smoke на Ubuntu и Debian · `tests/smoke.sh`.

### Changed
- Движок 23 чеков вынесен в `modules/diagnose.sh`; sysctl теперь в namespaced drop-in (`/etc/sysctl.d/99-node-diagnostic-*.conf`), откат детерминированный.

### Fixed
- `tcp_mtu_probing=1` без `tcp_min_snd_mss` → коллапс send-MSS до 48б на лоссовом плече (перенято из node-accelerator).
- sysctl `bbr`/conntrack применялись вслепую — теперь грузятся модули и проверяется фактическое значение.

## [3.4] и ранее

Монолитный `node-diagnostic.sh`: 23 чека (система/сеть/скорость/сервисы/репутация IP/Xray) + inline-автофиксы (sysctl/MSS clamp/RPS/ring).