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
| `guard`    | защита от DDoS: XDP-cookies + NOTRACK, вариант «только Россия» / «весь мир», allowlist, dead-man | да (XDP + tc + nft, свой `off`) |
| `bbr3`     | ядро XanMod для TCP **BBRv3** (mainline даёт только v1) | да, но **без автоперезагрузки** |
| `install`  | установка ноды Remnawave (nginx-selfsteal + сертификат) / WARP / NetBird / мониторинга / CrowdSec | да (по подтверждению) |
| `certs`    | сертификаты: продление, выпуск (Cloudflare / Gcore / Bunny / HTTP-01), свой сертификат | да |
| `warp`     | WARP Native: интерфейс `warp` для outbound Xray | да (по подтверждению) |
| `ipv6`     | включить/выключить IPv6 (sysctl `disable_ipv6`) | да |
| `ssh-port` | быстрая смена SSH-порта: sshd + firewall + SELinux, проверка входа, откат | да (по подтверждению входа) |
| `rollback` | снять всё, что наложил `optimize` | да |

## Структура

```
node-diagnostic.sh          точка входа: меню + диспетчер команд
install.sh                  bootstrap-установщик (curl|bash)
lib/common.sh               палитра, детекторы (virt/psABI/ssh), backup, namespaced drop-in, dry-run, ensure_pkg
lib/dns.sh                  базовый домен, публичный IP, A-записи через API Cloudflare/Gcore/Bunny
modules/
  diagnose.sh               27 чеков, дашборд, вердикт, рекомендации
  optimize.sh               сетевой/системный тюнинг
  protect.sh                защита ноды (генерация артефактов)
  bbr3.sh                   установка XanMod (BBRv3)
  rollback.sh               откат оптимизаций
  install.sh                диспетчер установки: нода/WARP/NetBird/мониторинг/CrowdSec
  node.sh                   установка ноды: remnanode + nginx-selfsteal + шаблон сайта
  certs.sh                  сертификаты: выпуск 5 методами, продление, хуки, cron
  warp.sh                   WARP Native (distillium/warp-native)
  ipv6.sh                   включение/выключение IPv6
  sshport.sh                смена SSH-порта без лок-аута
  shape.sh                  per-IP eBPF-шейпер (оркестратор)
  nd-shaper.bpf.c           BPF-программа шейпера (clsact + EDT)
  shape_ctrl.py             программирование BPF-карт через bpftool
  guard.sh                  защита от DDoS (оркестратор): on/off/status/allow/reattach
  nd-guard-xdp.bpf.c        XDP: гео, SYN-ACK с cookie (порог SYN/с для режима auto)
  nd-guard-tc.bpf.c         tc: проверка cookie в ACK, bpf_sk_assign_tcp_reqsk
  nd-guard.h, nd-guard-cookie.h   общие структуры и cookie
  guard_ctrl.py             программирование BPF-карт guard через bpftool
  guard_geo.py              гео-список RU: RIPEstat + db-ip, sanity-проверка
```

## Установка

**Одной командой:**

```bash
curl -sSL https://raw.githubusercontent.com/smoorf132/node-diagnostic/main/install.sh | sudo bash
```

Скачивает репозиторий в `/opt/node-diagnostic`, ставит команду **`rr`** (`/usr/local/bin/rr`) и в терминале сразу открывает меню. Дальше тулкит запускается просто `rr` (`rr certs renew`, `rr ipv6 status` и т.д.); не под root `rr` сам перезапускается через `sudo`. Если на сервере остался alias `rr` от remnawave-reverse-proxy (`/etc/bash.bashrc`), установщик его комментирует, а сам скрипт остаётся доступен как `remnawave_reverse`. Переопределяемо через env: `ND_REF` (ветка/тег), `ND_DEST` (каталог), `ND_BIN_DIR` (куда положить `rr`).

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
sudo bash node-diagnostic.sh install node          # нода Remnawave: nginx-selfsteal + сертификат
sudo bash node-diagnostic.sh certs renew           # продлить сертификаты, у которых ≤30 дней
sudo bash node-diagnostic.sh ipv6 off              # выключить IPv6
sudo bash node-diagnostic.sh install monitoring    # WARP/NetBird/мониторинг/CrowdSec — так же
sudo bash node-diagnostic.sh shape on              # включить eBPF-шейпер
sudo bash node-diagnostic.sh shape rule 1 443 50 20   # порт 443: 50 Mbit DL / 20 UL на каждый IP
sudo bash node-diagnostic.sh guard on --geo ru     # защита от DDoS, вариант 1 (затем guard confirm)
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
- `firewall.nft` / `firewall-ufw.sh` — карта портов ноды: **443** (VLESS/Reality + QUIC/HY2) и **80** (ACME/Caddy) всем; **NODE_PORT** (control-API панель→нода) — только с IP панели; **SSH** — с твоего IP или из подсети NetBird (см. ниже); ICMP не режется полностью (нужен для PMTU), только per-IP флуд; per-IP connlimit/SYN-rate; всё прочее — drop. `61000`/localhost и Caddy `:9443`/localhost наружу не открываются. В `firewall.nft` есть перманентный бан подсетей: set `banned4` из `BAN_NETS` (по умолчанию `185.224.228.0/22 195.209.120.0/22 212.192.156.0/23 212.192.158.0/24 194.165.22.0/23`). Drop стоит раньше `established` в input и в forward, поэтому рвутся и уже открытые сессии, и трафик в docker-bridge. Свой список задаётся через `BAN_NETS="a/N b/N"`, `BAN_NETS=""` отключает бан. На применённом firewall подсеть добавляется так: `nft add element inet node_protect banned4 { X/N }`.
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

## `guard` — защита от DDoS (XDP + tc + NOTRACK)

Два готовых режима для ноды на 443/80:

```bash
sudo rr guard on --geo ru      # вариант 1: только Россия — остальной мир режется в XDP
sudo rr guard on               # вариант 2: весь мир — без гео
sudo rr guard confirm          # подтвердить (иначе откат через 5 минут)
sudo rr guard status           # состояние, счётчики, гео-список, dead-man
sudo rr guard allow 203.0.113.0/24   # IP/CIDR мимо гео; unallow — убрать
sudo rr guard off              # выключить и убрать всё
```

Оба варианта ставят NOTRACK на 443/80 TCP+UDP (conntrack не заполняется флудом). SYN-cookies в XDP по умолчанию `auto`: включаются при > 10000 SYN/с и держатся 60 с после атаки; `--cookies always|off` меняет поведение. Остальные команды: `reattach` (вернуть после ребута/ручного detach), `update-geo` (обновить список), `help`. Меню: `[12]`.

- **Dead-man.** После `on` guard сам откатывается через 5 минут, пока не выполнен `rr guard confirm`. Перезагрузка до подтверждения тоже откатывает guard: таймер dead-man её не переживает, поэтому на boot `reattach` видит метку «не подтверждён» и выполняет `guard off` вместо восстановления. SSH не затрагивается никогда: порт SSH в `--ports` — отказ.
- **Ядро.** XDP-cookies требуют ядро **≥ 6.9** с `bpf_sk_assign_tcp_reqsk` в BTF. На Ubuntu 24.04 штатное ядро 6.8 его не имеет, но достаточно HWE-ядра (6.11+): `apt install --install-recommends linux-generic-hwe-24.04` и reboot. Более новые релизы Ubuntu ставят подходящее ядро по умолчанию. Альтернатива — XanMod (`rr bbr3 --install`). `guard on` и `guard status` подсказывают нужный вариант для своей системы. На более старом ядре guard откатывается на NOTRACK + гео + штатные syncookies ядра и сообщает об этом. Для XDP нужен BTF ядра (`/sys/kernel/btf/vmlinux`): без него применяется только NOTRACK, а вариант 1 отказывается. Сам guard требует ядро **≥ 5.10**.
- **bpftool.** Нужен bpftool на libbpf ≥ 1.0; guard и `shape` находят его сами: PATH, пакет `bpftool` (Debian), `linux-tools` Ubuntu (с ядром XanMod — мимо нерабочей обёртки `/usr/sbin/bpftool`), иначе статический bpftool v7.8.1 из релиза libbpf/bpftool (sha256 закреплён) в `/usr/local/lib/node-diagnostic/bpftool`. Не загрузился tc-объект — cookies выключаются, XDP остаётся для гео.
- **Интерфейс.** Только Ethernet: XDP и tc разбирают Ethernet-заголовок, поэтому на tun/wg/ppp (`link/none`) guard отказывается.
- **Кого режет вариант 1.** Пользователей за границей. RKN-пробы он не останавливает: они приходят с российских адресов.
- **Allowlist.** CDN-фронтинг (xhttp через Cloudflare), каскады и админы за границей без `rr guard allow IP|CIDR` будут отрезаны вариантом 1.
- **ACME.** Продление certbot по HTTP-01 покрыто хуками: на время продления гео на :80 снимается. Первый выпуск через `rr certs` методом HTTP-01 зовёт те же хуки сам. Другие ACME-клиенты (например Caddy с auto-ACME на selfsteal-нодах: HTTP-01 на 80 или TLS-ALPN-01 на 443) вариантом 1 **не покрыты** — их запросы будут отрезаны гео.
- **LXC/veth.** На veth-интерфейсах (контейнеры LXC/Proxmox) cookie-путь работает через generic XDP: нативный XDP_TX на veth не доходит до стороны хоста. Цена: generic XDP висит всё время, пока cookies включены (и в `auto` вне атаки тоже), и линеаризует GRO-пакеты всего входящего трафика интерфейса — пропускная способность падает. Если это заметно, `--cookies off` вернёт native XDP (останется гео) или снимет XDP совсем (вариант 2).
- **XDP_TX.** Если драйвер принимает XDP, но молча теряет XDP_TX, в `auto` под атакой (в `always` — всегда) новые соединения не устанавливаются. `guard status` предупредит, когда cookie-ответов ушло ≥ 100, а ни одно соединение по ним не завершилось, и покажет команду, которая выключит cookies, сохранив вариант (`rr guard on --geo ru --cookies off`).
- **PMTU и ICMP.** ICMP-ошибки (frag-needed, packet-too-big) о потоках на портах guard тоже идут мимо conntrack. Иначе записи потока для них нет, они попадают в `ct state invalid`, а `ct state invalid drop` в `protect` и в `before*.rules` ufw стоит раньше разрешения ICMP: клиенты за путями с меньшим MTU (IPv6-туннели) зависали бы.
- **Docker.** Docker bridge с опубликованными 80/443 несовместим, guard отказывается. С `network_mode: host` всё работает.
- **Гео-источники.** RIPEstat + db-ip country lite; обновляется еженедельным таймером, список проходит sanity-проверку, без списка гео не включается (иначе дропнулось бы всё). Реальный RU — около 12 тыс. v4- и 9 тыс. v6-префиксов; geo-карта XDP вмещает 131072 на семейство, список больше половины ёмкости не принимается.
- **protect.** `conn443` (`ct count`) при включённом guard не действует; SYN-rate считается по флагу SYN и продолжает работать.

Гео-данные: IP to Country Lite by [DB-IP](https://db-ip.com), лицензия CC BY 4.0.

## `install` — установка компонентов ноды

Пункт меню **[7]** и команда `install`. Внешние установщики запускаются только после подтверждения (показ команды + `y/N`).

```bash
sudo bash node-diagnostic.sh install node         # нода Remnawave: remnanode + nginx-selfsteal + сертификат
sudo bash node-diagnostic.sh install warp         # WARP Native (то же: warp install)
sudo bash node-diagnostic.sh install netbird      # NetBird + setup-key (спросит ключ)
sudo bash node-diagnostic.sh install monitoring   # cAdvisor + node_exporter + vmagent → VictoriaMetrics
sudo bash node-diagnostic.sh install crowdsec     # CrowdSec + nftables-bouncer (анти-брут SSH)
```

### Нода Remnawave (`install node`)

Порт установки ноды из [eGamesAPI/remnawave-reverse-proxy](https://github.com/eGamesAPI/remnawave-reverse-proxy) (вариант с nginx) **без Caddy и ufw**. Только Debian 11+ / Ubuntu 22.04+.

1. Пакеты: Docker (get.docker.com → проверенная копия с зеркала → `docker.io` из дистрибутива), certbot, `dig`, `jq`, cron, зеркала Docker Hub (`mirror.gcr.io`, `dockerhub.timeweb.cloud`), unattended-upgrades. BBR не трогает: это делает `optimize`.
2. Проверки: на сервере не запущены `remnanode`/`remnawave-nginx`, свободны порты 443 (xray ноды) и 80 (nginx, редирект на https).
3. Selfsteal-домен: A-запись должна указывать на сервер **без прокси Cloudflare**. Если записи нет или она чужая, её можно создать через API Cloudflare / Gcore / Bunny или вручную (установщик ждёт, пока запись появится).
4. IP панели, `SECRET_KEY` из карточки ноды (можно вставить целиком вместе с `NODE_PORT=`), `NODE_PORT` (по умолчанию 2222).
5. Сертификат: уже есть подходящий — берётся он; нет — выпускается (см. `certs`). Если A-запись только что создана через API провайдера, wildcard выпускается тем же провайдером без вопроса.
6. `/opt/remnanode`: `docker-compose.yml` (nginx + remnanode, `network_mode: host`), `.env` (`NODE_PORT`, `SECRET_KEY`, права 600), `nginx.conf` (сайт, монтируется в `conf.d/default.conf`), `nginx-main.conf` (главный `/etc/nginx/nginx.conf` контейнера: воркеры, буферы, gzip, `log_format proxy_protocol`). Прежние конфиги сохраняются как `*.bak-<время>`.
7. Случайный шаблон сайта-маскировки в `/var/www/html` из одного из трёх наборов: simple-web-templates, sni-templates, nothing-sni. Title, meta и классы рандомизируются.
8. `docker compose up -d` и проверка, что `https://домен` отвечает сайтом.

nginx принимает selfsteal только на unix-сокете `/dev/shm/nginx.sock` с `proxy_protocol` (TLS 1.3, access-лог с реальным IP клиента, неизвестные SNI — обрыв рукопожатия), а на `:80` отвечает редиректом на https. При продлении HTTP-01 certbot на время останавливает `remnawave-nginx` (pre/post-хуки), чтобы освободить 80. В профиле Xray в панели: Reality `target` = `/dev/shm/nginx.sock`, `xver: 1`, `serverNames: ["домен"]`. ufw нет, поэтому `NODE_PORT` открыт всем, пока его не закроет firewall. Установщик в конце подсказывает команду `rr protect --panel-ip … --node-port …`; `protect` и сам находит порт в `/opt/remnanode/.env`.

### WARP Native (`warp`)

Запускает установщик/деинсталлятор [distillium/warp-native](https://github.com/distillium/warp-native). Скрипт выполняется только тогда, когда два независимых источника (GitHub и прокси) отдали одинаковые байты. Поднимается WireGuard-интерфейс `warp`. Outbound `warp-out` (`sockopt.interface: "warp"`) добавляется в профиль Xray в панели, и установщик печатает готовый JSON. Правка профиля через API панели из апстрима сюда не перенесена: на ноде панели нет.

Мониторинг ставится точно по гайду [wiki.egam.es](https://wiki.egam.es/ru/configuration/grafana-monitoring-setup/): спрашивает имя инстанса и IP сервера мониторинга (NetBird) для `remoteWrite`, всё слушает `127.0.0.1`.

CrowdSec ставится из официального репозитория packagecloud (в штатных репо Debian/Ubuntu лежит устаревший 1.4.x): движок, `crowdsec-firewall-bouncer-nftables` и коллекции `crowdsecurity/linux` + `crowdsecurity/sshd`. Установщик спрашивает IP панели. Этот IP, твой SSH-IP и подсеть NetBird (если он поднят на ноде) попадают в allowlist `node-diagnostic` **до** установки bouncer'а: иначе, если твой IP окажется в community-блоклисте, SSH-сессия оборвётся посреди установки. Если движок сам не подхватил логи SSH (нет rsyslog), пишется acquisition из journald. Если на ноде есть fail2ban, установщик предлагает его удалить. Работает только на deb/rpm-системах с systemd; порт `127.0.0.1:8080` (LAPI) должен быть свободен.

## `certs` — сертификаты

Пункт меню **[10]** и команда `certs`. Порт управления сертификатами из remnawave-reverse-proxy без Telegram-уведомлений и без ufw.

```bash
sudo bash node-diagnostic.sh certs                 # меню
sudo bash node-diagnostic.sh certs renew           # продлить те, у кого ≤30 дней
sudo bash node-diagnostic.sh certs issue node.example.com
sudo bash node-diagnostic.sh certs manual example.com   # загрузить свой fullchain.pem + privkey.pem
```

| Метод | Что выпускает | Что нужно |
|---|---|---|
| Cloudflare DNS API | wildcard `база + *.база` | API-токен (или глобальный ключ + email) |
| Gcore DNS API | wildcard | API-ключ (плагин `certbot-dns-gcore` ставится через pip) |
| Bunny.net DNS API | wildcard, базу зоны спрашивает | API-ключ (плагин `certbot-dns-bunny`) |
| ACME HTTP-01 | один домен | открытый снаружи 80/tcp (firewall `protect` его открывает) |
| Свой сертификат | что загрузишь | `fullchain.pem` + `privkey.pem`; проверяются пара, домен и срок |

Ключи DNS-провайдеров хранятся в `/root/.secrets/certbot/*.ini` (600): по ним certbot продлевает сертификат, и следующая установка их не спрашивает. Ключи ECDSA secp384r1. Продление идёт через `certbot.timer` пакета и cron (`0 5 * * 0 certbot renew`). Хук перезапускает `remnawave-nginx`, потому что сертификат примонтирован в контейнер файлом. Для HTTP-01 хуки останавливают nginx на время проверки и запускают обратно. Свой сертификат certbot не продлевает: `renew` только показывает его срок.

## `ipv6` — IPv6 на ноде

Пункт меню **[11]** и команда `ipv6 [status|on|off]`. Значение пишется в `/etc/sysctl.d/99-remnawave-ipv6.conf`: это тот же файл, что у remnawave-reverse-proxy, поэтому две настройки не конфликтуют. Старые ключи вычищаются из `/etc/sysctl.conf`. После включения проверяется, что sysctl применился (`ipv6.disable=1` в GRUB он молча игнорирует). Если глобального адреса нет, установщик предлагает обновить сеть (netplan / ifupdown / networkd) и подсказывает, где прописать адрес. Если SSH-сессия идёт по IPv6, перед выключением спрашивается подтверждение. В `rollback` не входит.

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
Не входит: ядро XanMod (`apt purge 'linux-xanmod*' && update-grub && reboot`), firewall/sshd (generate-only — откат в их `APPLY.txt`), CrowdSec (`apt purge crowdsec crowdsec-firewall-bouncer-nftables`), eBPF-шейпер (`shape off`) и guard (`guard off`).

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
  - `install node`, `certs` — Debian 11+ / Ubuntu 22.04+ с systemd (Docker, certbot из apt).
  - `bbr3` — **только Debian/Ubuntu** (XanMod = deb-репозиторий) и **только bare-metal/KVM x86_64** (не контейнер).
  - `shape` — ядро Linux **≥5.4** (EDT/clsact) + `clang`/`bpftool`/`libbpf-dev`; не в контейнере.
  - `guard` — ядро Linux **≥5.10** + BTF, Ethernet-интерфейс, `clang`/`bpftool` (libbpf ≥ 1.0)/`libbpf-dev` (ставятся сами, bpftool — из пакета, linux-tools или статический); XDP-cookies — ядро **≥6.9** (Ubuntu 24.04 — HWE-ядро, 26.04+ — штатное); Docker bridge с опубликованными 80/443 несовместим.

CI гоняет: shellcheck (`--severity=warning`), компиляцию BPF-шейпера и guard (`clang -target bpf`), smoke на Ubuntu-runner/22.04/24.04/Debian 12/Alpine 3.19, integration (реальное `optimize`→verify→rollback→`protect`/`nft -c`) в privileged-контейнерах Ubuntu 24.04 + Debian 12, guard на ядре runner'а (`bpftool prog run`, netns-стенд с cookie-рукопожатием) и загрузку guard bpftool и тулчейном Debian 12 / Ubuntu 22.04 (`ensure_bpftool`).

## Лицензия

MIT.
