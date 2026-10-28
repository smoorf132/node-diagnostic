# node-diagnostic

Модульный тулкит для VPN/Linux-ноды (заточен под стек **Remnawave**): диагностика, оптимизация сети, защита, per-IP шейпер полосы, установка ноды/ядра с BBRv3. Диагностика — компактный дашборд с прогресс-баром, сводкой и вердиктом; фиксы вынесены в отдельные модули с явным откатом.

```
  NODE DIAGNOSTIC  v4.4.0 · toolkit
  ─────────────────────────────────────────────────────

[ 1/27] ✓ Идентификация             host.example.com · Helsinki/FI · ~2ms→Tallinn
[ 2/27] ✓ CPU и нагрузка            2c · load 0.05 · idle 94% · steal 0%
[ 4/27] ⚠ PSI (давление)            cpu 0.1 · mem 0.0 · io 12.3
[ 6/27] ✓ TCP congestion            bbr + cake
[ 7/27] ⚠ TCP tuning                mtu_probing=0
[10/27] ⚠ UDP-ошибки                RcvbufErrors 2043
[14/27] ✗ Speed: 1-flow             21 Mbit/s
...
```

## Модули

| Команда | Что делает | Применяет? |
|---|---|---|
| `diagnose` | 27 чеков: система, сеть, скорость, сервисы, репутация IP, Xray/Remnanode | — (только читает) |
| `optimize` | sysctl-тюнинг, BBR+cake, FD-лимиты, RPS/RFS/XPS, NIC, MSS clamp, irqbalance, journald, zram | да (namespaced drop-in) |
| `protect`  | firewall под Remnawave, SSH-хардненинг, DDoS-хардненинг | **нет — только генерирует файлы** |
| `shape`    | per-IP шейпер полосы (eBPF/EDT): лимит DL/UL на клиента, whitelist, dynamic-штраф | да (tc clsact + BPF, свой `off`) |
| `bbr3`     | ядро XanMod для TCP **BBRv3** (mainline даёт только v1) | да, но **без автоперезагрузки** |
| `install`  | установка ноды Remnawave / Selfsteal / NetBird / мониторинга / CrowdSec | да (по подтверждению) |
| `ssh-port` | быстрая смена SSH-порта: sshd + firewall + SELinux, проверка входа, откат | да (по подтверждению входа) |
| `rollback` | снять всё, что наложил `optimize` | да |

## Структура

```
node-diagnostic.sh          точка входа: меню + диспетчер команд
install.sh                  bootstrap-установщик (curl|bash)
lib/common.sh               палитра, детекторы (virt/psABI/ssh), backup, namespaced drop-in, dry-run, ensure_pkg
modules/
  diagnose.sh               27 чеков, дашборд, вердикт, рекомендации
  optimize.sh               сетевой/системный тюнинг
  protect.sh                защита ноды (генерация артефактов)
  bbr3.sh                   установка XanMod (BBRv3)
  rollback.sh               откат оптимизаций
  install.sh                установка ноды/Selfsteal/NetBird/мониторинга/CrowdSec
  sshport.sh                смена SSH-порта без лок-аута
  shape.sh                  per-IP eBPF-шейпер (оркестратор)
  nd-shaper.bpf.c           BPF-программа шейпера (clsact + EDT)
  shape_ctrl.py             программирование BPF-карт через bpftool
```

## Установка

**Одной командой:**

```bash
curl -sSL https://raw.githubusercontent.com/smoorf132/node-diagnostic/main/install.sh | sudo bash
```

Скачивает репозиторий в `/opt/node-diagnostic`; в терминале сразу открывает меню. Переопределяемо через env: `ND_REF` (ветка/тег), `ND_DEST` (каталог).

**Или вручную** (тулкит модульный — нужен весь репозиторий):

```bash
git clone https://github.com/smoorf132/node-diagnostic
cd node-diagnostic
sudo bash node-diagnostic.sh        # интерактивное меню
```

Зависимости диагностики (`mtr`, `dig`, `ethtool`, `conntrack`, `jq` и т.д.) ставятся сами через apt/dnf/yum/apk.

## Использование

```bash
sudo bash node-diagnostic.sh                       # меню (диагностика, если ввод не TTY)
sudo bash node-diagnostic.sh diagnose -q           # быстрая диагностика ~1 мин
sudo bash node-diagnostic.sh diagnose --json       # машиночитаемый JSON (для агрегации по флоту)
sudo bash node-diagnostic.sh optimize --all        # весь тюнинг
sudo bash node-diagnostic.sh optimize --from-findings   # только фиксы по находкам диагностики
sudo bash node-diagnostic.sh optimize --dry-run    # показать, что применил бы
sudo bash node-diagnostic.sh protect --panel-ip 1.2.3.4 --node-port 2222
sudo bash node-diagnostic.sh bbr3 --install        # XanMod (нужен reboot); --level 2 если CPU маскирован
sudo bash node-diagnostic.sh install monitoring    # нода/Selfsteal/NetBird/мониторинг/CrowdSec
sudo bash node-diagnostic.sh shape on              # включить eBPF-шейпер
sudo bash node-diagnostic.sh shape rule 1 443 50 20   # порт 443: 50 Mbit DL / 20 UL на каждый IP
sudo bash node-diagnostic.sh ssh-port 2222         # сменить SSH-порт (с проверкой входа и откатом)
sudo bash node-diagnostic.sh rollback              # откат оптимизаций
sudo bash node-diagnostic.sh status                # что наложено на систему, ядро, cc/qdisc
```

Типовой поток: `diagnose` → он сохраняет находки → `optimize --from-findings` применяет только релевантное. Для флота: `diagnose --json` на каждой ноде, сводишь в одну картину.

Каждый модуль запускается и самостоятельно: `sudo bash modules/optimize.sh --sysctl`.

## Что проверяет `diagnose` (27 чеков)

**Система** — CPU/память/load/softirq, **CPU steal** (оверселл VPS/шумный сосед), **PSI** (`/proc/pressure` — затык ядра под нагрузкой), NIC drops/single-queue, ring buffers, ethtool offloads.
**Сеть** — TCP congestion + qdisc (+ проверка живых bbr-сокетов), буферы, conntrack, **UDP RcvbufErrors** (дропы до приложения — QUIC/Hysteria2/TUIC), **MSS-коллапс по живым сокетам**, **accept-queue backlog**, DNS, PMTU (бинпоиск с защитой от false-negative на лоссе), туннели (WireGuard/NetBird/Tailscale/OpenVPN/IPsec), loss/latency до Google и DNS, MTR с худшим хопом, UDP/QUIC/HTTP-3, IPv6.
**Производительность** — 1-flow (Cachefly), 4-flow, мульти-CDN (детект ASN-троттлинга), **bufferbloat** (ping под нагрузкой), variance.
**Сервисы** — reachability + TTFB для 19 популярных (YouTube/Netflix/Twitch/TikTok/Telegram/Discord/ChatGPT/Claude/Gemini/Spotify/…); различает 200 / блок (403/429) / unreachable.
**Репутация IP** — Cloudflare colo, гео-кросс-чек по 3 базам, реальная локация по latency до IX, Google CAPTCHA-проба, reverse DNS, «датацентр vs резидентский».
**Xray/Remnanode** — версия, ресурсы контейнера, ошибки в логах, рестарты.
**Открытые порты** — публичные листенеры (`ss`): docker-API (2375/2376), голые БД (postgres/mysql/redis/mongo/…) и нестандартные порты на `0.0.0.0`/`[::]` — частая дыра, через которую ломают ноду.

## `optimize` — что накладывает

Всё пишется в namespaced drop-in (`/etc/sysctl.d/99-node-diagnostic-*.conf`, `node-diagnostic-*.service`), поэтому откат детерминированный (`rollback`), а не восстановление дампа.

- **sysctl** — BBR + cake; **`tcp_min_snd_mss=512`** (пол MSS под `tcp_mtu_probing=1` — без него на лоссовом плече MSS схлопывается до 48б); буферы и conntrack **масштабируются по RAM** (16M→128M); SYN-flood + anti-spoof (`rp_filter=2` loose + **`src_valid_mark=1`** — чтобы не ломать WireGuard/WARP-outbound); `netdev_budget` (softirq под high-PPS); `tcp_ecn=2`; TIME_WAIT/keepalive; UDP-буферы (Hysteria2/TUIC/QUIC); `ip_local_port_range`.
- **FD-лимиты** — `fs.file-max`/`nr_open` + `limits.d` + **systemd `DefaultLimitNOFILE`** (xray-сервис читает именно его) + pam.
- **RPS/RFS/XPS** + **irqbalance** — размазать softirq/flow-steering/прерывания NIC по всем CPU (systemd-юнит для постоянства).
- **NIC** — ring buffers max + `gro/gso/tso on`, **`lro off`** (LRO ломает форвардинг), `txqueuelen 10000`.
- **MSS clamp** — iptables TCPMSS `--clamp-mss-to-pmtu` (FORWARD/OUTPUT), persist.
- **journald cap** — лимит журнала 300M + сжатие (флуд логов не забивает диск).
- **zram-swap** (opt-in `--zram`) — компрессированный swap в RAM (lz4), анти-OOM на мелких нодах.

`optimize --all` включает всё выше, кроме zram (он `--zram`). `optimize` сам доставляет свои зависимости (`iproute2`/`ethtool`/`iptables`).

## `protect` — защита под Remnawave (только генерация)

Firewall на удалённой ноде может отрезать SSH, поэтому модуль **ничего не применяет** — пишет готовые артефакты в каталог и даёт пошаговый `APPLY.txt` с защитой от лок-аута (авто-откат правил через `systemd-run` таймер).

Генерируется:
- `firewall.nft` / `firewall-ufw.sh` — карта портов ноды: **443** (VLESS/Reality + QUIC/HY2) и **80** (ACME/Caddy) всем; **NODE_PORT** (control-API панель→нода) — только с IP панели; **SSH** — с твоего IP или из подсети NetBird (см. ниже); ICMP не режется полностью (нужен для PMTU), только per-IP флуд; per-IP connlimit/SYN-rate; всё прочее — drop. `61000`/localhost и Caddy `:9443`/localhost наружу не открываются.
- `sshd-hardening.conf` — key-only, `PermitRootLogin prohibit-password` и т.д. (модуль проверяет наличие `authorized_keys` и предупреждает о риске лок-аута).
- `sysctl` DDoS-хардненинг идёт через `optimize` (syncookies/anti-spoof).
- Анти-брут SSH здесь не генерируется: CrowdSec ставится через `install crowdsec`, шаг описан в `APPLY.txt`.

```bash
sudo bash node-diagnostic.sh protect --panel-ip <IP_панели> --node-port <NODE_PORT>
# → /root/node-diagnostic-protect/  (открыть APPLY.txt)
sudo bash node-diagnostic.sh protect --panel-ip <IP_панели> --ssh-from 100.92.0.0/16   # SSH только из NetBird
```

Откуда пускать SSH:
- `--ssh-from IP|CIDR` — явно. Хост-биты обнуляются, поэтому можно передать адрес ноды в том виде, в каком его отдаёт NetBird: `100.92.13.5/16` → `100.92.0.0/16`.
- Без флага, если текущая SSH-сессия пришла **через NetBird** (её IP входит в подсеть интерфейса `wt0` или `netbird status`), SSH открывается всей подсети NetBird. С публичного IP SSH тогда закрыт, а `APPLY.txt` предупреждает о рисках: при падении NetBird вход останется только через VNC-консоль хостера.
- Иначе SSH открывается только с IP текущей сессии. Если на ноде есть NetBird, модуль подскажет нужный `--ssh-from`.

Из меню то же самое без флагов: пункт **[3]** спросит IP панели, NODE_PORT и откуда пускать SSH (Enter — автодетект/плейсхолдер).

## `bbr3` — TCP BBRv3 через XanMod

Mainline-ядро отдаёт только BBRv1; BBRv3 приходит с кастомным ядром **XanMod**. Модуль:
- гейтит контейнеры (OpenVZ/LXC используют ядро хоста — своё не поставить) и не-x86_64;
- проверяет **отпечаток GPG-ключа** XanMod перед установкой;
- выбирает сборку по **psABI** (x64v1..v4) под реальный CPU (иначе ядро не загрузится);
- **не перезагружает сам**, делает проверки перед reboot (новое ядро в /boot, старое остаётся как откат, GRUB_TIMEOUT);
- детект «это именно v3»: `uname -r` содержит `xanmod` и ядро ≥6.4.

```bash
sudo bash node-diagnostic.sh bbr3 --status              # что сейчас
sudo bash node-diagnostic.sh bbr3 --install --dry-run   # план без установки
sudo bash node-diagnostic.sh bbr3 --install             # затем reboot вручную
```

## `shape` — per-IP шейпер полосы (eBPF/EDT)

Каждый клиентский IP получает независимый лимит DL/UL под правилом порта; whitelist обходит шейпинг; опц. dynamic-режим со штраф-рейтом абузеру. BPF-программа (`nd-shaper.bpf.c`) вешается на `tc clsact`: download = EDT (`skb->tstamp`) на egress, upload = token-bucket drop на ingress. Карты программируются через `bpftool` (`shape_ctrl.py`).

```bash
sudo bash node-diagnostic.sh shape on                       # собрать BPF + прицепить (+ systemd на boot)
sudo bash node-diagnostic.sh shape rule 1 443,8443 50 20    # порты → 50 Mbit DL / 20 UL на каждый IP
sudo bash node-diagnostic.sh shape rule 2 all 100 50 --dynamic   # все порты, штраф абузеру
sudo bash node-diagnostic.sh shape wl 10.0.0.5              # IP без лимита
sudo bash node-diagnostic.sh shape status                  # активные правила
sudo bash node-diagnostic.sh shape off                     # снять
```

Требует ядро Linux **≥5.4** (EDT/clsact) и `clang`/`bpftool`/`libbpf-dev` (ставятся сами). Порт из [DonMatteoVPN/Reshala-Remnawave-Bedolaga](https://github.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga) (MIT). Снимается своим `shape off` (в `rollback` не входит).

## `install` — установка компонентов ноды

Пункт меню **[7]** и команда `install`. Внешние установщики запускаются только после подтверждения (показ команды + `y/N`).

```bash
sudo bash node-diagnostic.sh install node         # нода Remnawave (DigneZzZ/remnawave-scripts)
sudo bash node-diagnostic.sh install selfsteal    # Selfsteal
sudo bash node-diagnostic.sh install netbird      # NetBird + setup-key (спросит ключ)
sudo bash node-diagnostic.sh install monitoring   # cAdvisor + node_exporter + vmagent → VictoriaMetrics
sudo bash node-diagnostic.sh install crowdsec     # CrowdSec + nftables-bouncer (анти-брут SSH)
```

Мониторинг ставится точно по гайду [wiki.egam.es](https://wiki.egam.es/ru/configuration/grafana-monitoring-setup/): спрашивает имя инстанса и IP сервера мониторинга (NetBird) для `remoteWrite`, всё слушает `127.0.0.1`.

CrowdSec ставится из официального репозитория packagecloud (в штатных репо Debian/Ubuntu лежит устаревший 1.4.x): движок, `crowdsec-firewall-bouncer-nftables` и коллекции `crowdsecurity/linux` + `crowdsecurity/sshd`. Установщик спрашивает IP панели. Этот IP, твой SSH-IP и подсеть NetBird (если он поднят на ноде) попадают в allowlist `node-diagnostic` **до** установки bouncer'а: иначе, если твой IP окажется в community-блоклисте, SSH-сессия оборвётся посреди установки. Если движок сам не подхватил логи SSH (нет rsyslog), пишется acquisition из journald. Если на ноде есть fail2ban, установщик предлагает его удалить. Работает только на deb/rpm-системах с systemd; порт `127.0.0.1:8080` (LAPI) должен быть свободен.

## `ssh-port` — смена SSH-порта без лок-аута

Пункт меню **[9]** и команда `ssh-port [ПОРТ]` (без аргумента — спросит).

```bash
sudo bash node-diagnostic.sh ssh-port 2222
```

Смена идёт в два шага, и ни на одном из них текущая сессия не рвётся:
1. sshd начинает слушать **и старый, и новый** порт. Новый порт открывается в найденном firewall для тех же источников, что и старый: таблица `node_protect` из `protect` (твой IP или подсеть NetBird), ufw или firewalld. При SELinux в режиме Enforcing порт размечается через `semanage`.
2. Ты проверяешь вход по новому порту во втором окне (команда подсказывается с тем адресом, по которому ты зашёл сейчас) и подтверждаешь. Только после этого старый порт снимается. Если не подтвердил или что-то пошло не так, конфиги sshd возвращаются из бэкапа (`/var/backups/node-diagnostic/sshd-*`).

Порт пишется в `/etc/ssh/sshd_config.d/99-node-diagnostic-port.conf`. Чужие строки `Port` комментируются, потому что директива аддитивна и они добавили бы свои порты. Без `Include` в `sshd_config` (RHEL 8 и т.п.) используется управляемый блок в начале основного конфига. На Ubuntu 22.10+ с socket-activation порт переносится в `ssh.socket` через `daemon-reload`.

После смены перегенерируй `protect`: в `firewall.nft` правило с rate-limit ещё на старом порту. Firewall или security group у хостера модуль не видит, там порт открывается вручную. В `rollback` смена порта не входит: вернуть порт вслепую значит получить лок-аут за firewall. Возврат делается той же командой: `ssh-port 22`.

## Откат

```bash
sudo bash node-diagnostic.sh rollback            # снять sysctl drop-in, systemd-юниты, limits, MSS clamp
sudo bash node-diagnostic.sh rollback --dry-run  # показать, что снял бы
```
Не входит: ядро XanMod (`apt purge 'linux-xanmod*' && update-grub && reboot`), firewall/sshd (generate-only — откат в их `APPLY.txt`), CrowdSec (`apt purge crowdsec crowdsec-firewall-bouncer-nftables`) и eBPF-шейпер (`shape off`).

## Артефакты

- `/tmp/node-diagnostic-<ts>.log` — полный лог диагностики
- `/tmp/node-diagnostic-summary-<ts>.txt` — плоская сводка без ANSI
- `/var/backups/node-diagnostic/*` — снапшоты sysctl/iptables/nft перед фиксом
- `/etc/node-diagnostic.applied` — журнал применённого

## Требования

- bash 4+, root для `optimize`/`protect`/`bbr3`/`rollback` (диагностика работает и без root, часть проверок пропускается).
- Поддержка дистрибутивов по модулям:
  - `diagnose`, `optimize`, `rollback` — Ubuntu/Debian/RHEL/Fedora/Alpine (sysctl универсален; deps ставятся через apt/dnf/yum/apk).
  - `protect` — firewall на nftables/ufw универсален.
  - `install crowdsec` — deb/rpm-дистрибутивы с systemd (Debian/Ubuntu/RHEL/Fedora); на Alpine не поддерживается.
  - `bbr3` — **только Debian/Ubuntu** (XanMod = deb-репозиторий) и **только bare-metal/KVM x86_64** (не контейнер).
  - `shape` — ядро Linux **≥5.4** (EDT/clsact) + `clang`/`bpftool`/`libbpf-dev`; не в контейнере.

CI гоняет: shellcheck (`--severity=warning`), компиляцию BPF-шейпера (`clang -target bpf`), smoke на Ubuntu-runner/22.04/24.04/Debian 12/Alpine 3.19 и integration (реальное `optimize`→verify→rollback→`protect`/`nft -c`) в privileged-контейнерах Ubuntu 24.04 + Debian 12.

## Лицензия

MIT.
