#!/usr/bin/env python3
"""guard_geo.py — сборка гео-списка страны (RU) из локальных файлов.

Источники (скачивает guard.sh, не этот скрипт):
  --ripe FILE  RIPEstat country-resource-list JSON (CIDR и диапазоны a-b)
  --dbip FILE  db-ip country lite CSV (start,end,cc), .csv или .csv.gz

Результат: DIR/geo4.txt, DIR/geo6.txt (по CIDR на строку), DIR/geo.meta (json).
rc 0 — записано; rc 3 — проверка здравости не прошла (мало адресов/префиксов или префиксов больше,
чем влезет в geo-карту XDP; файлы не тронуты); rc 4 — ни один источник не распарсился (файлы не тронуты).
Только stdlib, совместимо с Python 3.9.
"""
import argparse
import csv
import datetime
import gzip
import ipaddress
import json
import os
import sys

# = GUARD_GEO_MAX_ENTRIES в modules/nd-guard-xdp.bpf.c (max_entries geo4_map/geo6_map); меняются вместе,
# tests/test_guard_geo.py сверяет. Верхняя граница списка по умолчанию — половина: geo-sync сначала
# добавляет новые префиксы, потом удаляет старые, и в карте временно лежат оба списка (иначе ENOSPC).
GEO_MAP_CAPACITY = 131072
GEO_MAX_PREFIXES = GEO_MAP_CAPACITY // 2


def _addr_range(a, b):
    first = ipaddress.ip_address(a.strip())
    last = ipaddress.ip_address(b.strip())
    if first.version != last.version or int(first) > int(last):
        raise ValueError("bad range")
    return list(ipaddress.summarize_address_range(first, last))


def _split(nets, v4, v6):
    for n in nets:
        (v4 if n.version == 4 else v6).append(n)


def parse_ripestat(text):
    """RIPEstat JSON -> (v4, v6); понимает CIDR и 'a-b'. Битые записи пропускаются."""
    data = json.loads(text)
    res = data["data"]["resources"]
    v4, v6 = [], []
    for key in ("ipv4", "ipv6"):
        for item in res.get(key) or []:
            try:
                item = str(item).strip()
                if "-" in item:
                    a, b = item.split("-", 1)
                    nets = _addr_range(a, b)
                else:
                    nets = [ipaddress.ip_network(item, strict=False)]
            except ValueError:
                continue
            _split(nets, v4, v6)
    return v4, v6


def parse_dbip(lines, cc):
    """db-ip CSV (start,end,cc) -> (v4, v6) только для страны cc. Мусор пропускается."""
    want = cc.strip().upper()
    v4, v6 = [], []
    for row in csv.reader(lines):
        if len(row) < 3 or row[2].strip().upper() != want:
            continue
        try:
            nets = _addr_range(row[0], row[1])
        except ValueError:
            continue
        _split(nets, v4, v6)
    return v4, v6


def merge(*lists):
    """Объединение списков сетей: collapsed и отсортировано (v4 и v6 не смешивать)."""
    allnets = [n for lst in lists for n in lst]
    return sorted(ipaddress.collapse_addresses(allnets),
                  key=lambda n: (n.version, int(n.network_address), n.prefixlen))


def _addrs(nets):
    return sum(n.num_addresses for n in nets)


def sanity(v4, v6, mins, maxs=(GEO_MAX_PREFIXES, GEO_MAX_PREFIXES)):
    """mins = (мин. v4-адресов, мин. v4-префиксов, мин. v6-префиксов),
    maxs = (макс. v4-префиксов, макс. v6-префиксов) -> (ok, причина)."""
    min_addrs, min_p4, min_p6 = mins
    max_p4, max_p6 = maxs
    a = _addrs(v4)
    if a < min_addrs:
        return False, "мало v4-адресов: %d < %d" % (a, min_addrs)
    if len(v4) < min_p4:
        return False, "мало v4-префиксов: %d < %d" % (len(v4), min_p4)
    if len(v6) < min_p6:
        return False, "мало v6-префиксов: %d < %d" % (len(v6), min_p6)
    if len(v4) > max_p4:
        return False, "много v4-префиксов: %d > %d (geo-карта — %d)" % (len(v4), max_p4, GEO_MAP_CAPACITY)
    if len(v6) > max_p6:
        return False, "много v6-префиксов: %d > %d (geo-карта — %d)" % (len(v6), max_p6, GEO_MAP_CAPACITY)
    return True, ""


def _load_ripe(path):
    with open(path, "r", encoding="utf-8") as f:
        return parse_ripestat(f.read())


def _load_dbip(path, cc):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
        return parse_dbip(f, cc)


def _atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _err(msg):
    sys.stderr.write("guard_geo: %s\n" % msg)


def cmd_build(args):
    ok_names, v4s, v6s = [], [], []
    for name, path, loader in (("ripestat", args.ripe, _load_ripe),
                               ("dbip", args.dbip, lambda p: _load_dbip(p, args.cc))):
        if not path:
            continue
        try:
            a, b = loader(path)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, EOFError) as e:
            _err("источник %s не прочитан: %s" % (name, e))
            continue
        if not a and not b:
            _err("источник %s не дал ни одной сети" % name)
            continue
        ok_names.append(name)
        v4s.append(a)
        v6s.append(b)
    if not ok_names:
        _err("ни один источник не распарсился")
        return 4
    v4, v6 = merge(*v4s), merge(*v6s)
    ok, reason = sanity(v4, v6, (args.min_v4_addrs, args.min_v4_prefixes, args.min_v6_prefixes),
                        (args.max_v4_prefixes, args.max_v6_prefixes))
    if not ok:
        _err("проверка здравости не прошла: %s" % reason)
        return 3
    meta = {"date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"), "sources_ok": ok_names,
            "v4_prefixes": len(v4), "v4_addrs": _addrs(v4), "v6_prefixes": len(v6)}
    os.makedirs(args.out_dir, exist_ok=True)
    for fname, nets in (("geo4.txt", v4), ("geo6.txt", v6)):
        _atomic_write(os.path.join(args.out_dir, fname), "".join("%s\n" % n for n in nets))
    _atomic_write(os.path.join(args.out_dir, "geo.meta"), json.dumps(meta) + "\n")
    print("geo %s: v4 %d префиксов (%d адресов), v6 %d префиксов, источники: %s" % (
        args.cc, len(v4), meta["v4_addrs"], len(v6), ",".join(ok_names)))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="guard_geo.py")
    sub = p.add_subparsers(dest="cmd")
    b = sub.add_parser("build", help="собрать geo4.txt/geo6.txt/geo.meta")
    b.add_argument("--cc", default="RU")
    b.add_argument("--out-dir", required=True)
    b.add_argument("--ripe")
    b.add_argument("--dbip")
    b.add_argument("--min-v4-addrs", type=int, default=25000000)
    b.add_argument("--min-v4-prefixes", type=int, default=3000)
    b.add_argument("--min-v6-prefixes", type=int, default=300)
    b.add_argument("--max-v4-prefixes", type=int, default=GEO_MAX_PREFIXES)
    b.add_argument("--max-v6-prefixes", type=int, default=GEO_MAX_PREFIXES)
    args = p.parse_args(argv)
    if args.cmd != "build":
        p.print_usage(sys.stderr)
        return 2
    return cmd_build(args)


if __name__ == "__main__":
    sys.exit(main())
