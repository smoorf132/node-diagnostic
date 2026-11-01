#!/usr/bin/env python3
"""guard_ctrl.py — управление BPF-картами guard через bpftool.

ABI карт — modules/nd-guard.h:
  guard_cfg_map[0]      = struct guard_cfg (CFG_FMT, 40 байт; ключ SipHash — 16 байт как есть)
  guard_state_map[0]    = struct guard_state (3×u64, часы CLOCK_MONOTONIC)
  guard_ports_map[port] = u8 GUARD_P_* (ключ — порт, host order)
  geo4_map/geo6_map, allow4_map/allow6_map — LPM {u32 prefixlen (host), addr (network)} → u8 1
  guard_stats_map       = PERCPU_ARRAY[ST__MAX] u64 — stats суммирует по CPU

Все команды принимают --pin-dir DIR (каталог maps/). Путь к bpftool — env BPFTOOL.
Вызывает modules/guard.sh; чистые функции (pack_cfg, lpm_key, port_flags, diff_prefixes)
тестируются без root в tests/guard_xdp_test.py. Только stdlib, Python ≥ 3.9.
"""
import argparse
import ipaddress
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

CFG_FMT = "=IIIIIHH2Q"   # native = «<IIIIIHH2Q» на x86/arm64
STATE_FMT = "=QQQ"
COOKIE_MODES = {"off": 0, "auto": 1, "always": 2}
PORT_FLAGS = (("tcp", 0x1), ("udp", 0x2), ("geo", 0x4))
STAT_NAMES = ("pass", "geo_drop", "allow", "syn", "cookie_sent", "cookie_ok", "cookie_bad",
              "assign_err", "syn_mptcp", "syn_nolisten")
GEO_MAPS = ((4, "geo4_map", "loaded4.txt"), (6, "geo6_map", "loaded6.txt"))


# ── чистые функции ──

def pack_cfg(geo_on, cookie_mode, syn_threshold, hold_sec, rcv_wscale, mss4, mss6, key):
    """struct guard_cfg → 40 байт. cookie_mode — off|auto|always или 0..2; key — 16 байт."""
    if isinstance(cookie_mode, str):
        cookie_mode = COOKIE_MODES[cookie_mode]
    if len(key) != 16:
        raise ValueError("ключ SipHash — ровно 16 байт, а не %d" % len(key))
    k0, k1 = struct.unpack("=QQ", key)
    return struct.pack(CFG_FMT, int(geo_on), cookie_mode, syn_threshold, hold_sec, rcv_wscale,
                       mss4, mss6, k0, k1)


def lpm_key(cidr):
    """Ключ LPM: prefixlen (u32 host order) + адрес сети (network order). IP без /N — /32|/128."""
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    return struct.pack("=I", net.prefixlen) + net.network_address.packed


def port_flags(s):
    """'tcp,udp,geo' | 'none' → GUARD_P_*"""
    s = s.strip()
    if s in ("", "none"):
        return 0
    names = dict(PORT_FLAGS)
    v = 0
    for tok in s.split(","):
        tok = tok.strip()
        if tok not in names:
            raise ValueError("неизвестный флаг порта %r (tcp,udp,geo | none)" % tok)
        v |= names[tok]
    return v


def flags_str(v):
    """GUARD_P_* → 'tcp,udp,geo' | 'none' (обратное port_flags)"""
    names = [n for n, b in PORT_FLAGS if v & b]
    return ",".join(names) if names else "none"


def _net_order(cidr):
    n = ipaddress.ip_network(cidr, strict=False)
    return n.version, int(n.network_address), n.prefixlen


def diff_prefixes(old, new):
    """(добавить, удалить) — списки CIDR, отсортированные по адресу."""
    return sorted(new - old, key=_net_order), sorted(old - new, key=_net_order)


# ── bpftool ──

def die(msg, rc=1):
    sys.stderr.write("guard_ctrl: %s\n" % msg)
    sys.exit(rc)


def _hex(b):
    return ["%02x" % x for x in b]


def _unhex(lst):
    return bytes(int(x, 16) for x in lst)


def _pin(pin_dir, name):
    return os.path.join(pin_dir, name)


def _errmsg(r):
    """текст ошибки bpftool: в режиме -j она в stdout как {"error": …}"""
    out = r.stdout.strip()
    if out.startswith("{"):
        try:
            return json.loads(out).get("error", out)
        except ValueError:
            pass
    return (r.stderr.strip() or out)


def _bpftool(args, check=True):
    cmd = [os.environ.get("BPFTOOL", "bpftool"), *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        die("bpftool не запустился: %s" % e)
    if check and r.returncode != 0:
        die("%s → %s" % (" ".join(args[:4]), _errmsg(r)))
    return r


def _update(pin_dir, m, key, val):
    _bpftool(["map", "update", "pinned", _pin(pin_dir, m), "key", "hex", *_hex(key),
              "value", "hex", *_hex(val)])


def _lookup(pin_dir, m, key):
    """значение (bytes) или None, если ключа нет"""
    r = _bpftool(["-j", "map", "lookup", "pinned", _pin(pin_dir, m), "key", "hex", *_hex(key)],
                 check=False)
    if r.returncode != 0:
        if r.stdout.strip() == "null":   # -j: ключа нет
            return None
        die("lookup %s → %s" % (m, _errmsg(r)))
    return _unhex(json.loads(r.stdout)["value"])


def _dump(pin_dir, m):
    return json.loads(_bpftool(["-j", "map", "dump", "pinned", _pin(pin_dir, m)]).stdout or "[]")


def _lpm_map(cidr, kind):
    return "%s%d_map" % (kind, ipaddress.ip_network(cidr.strip(), strict=False).version)


def _u32(key=0):
    return struct.pack("=I", key)


# ── команды ──

def cmd_set_cfg(a):
    try:
        with open(a.key_file, "rb") as f:
            key = f.read()
    except OSError as e:
        die("ключ %s: %s" % (a.key_file, e.strerror))
    try:
        val = pack_cfg(a.geo, a.cookies, a.syn_threshold, a.hold, a.rcv_wscale, a.mss4, a.mss6, key)
    except ValueError as e:
        die("%s: %s" % (a.key_file, e))
    _update(a.pin_dir, "guard_cfg_map", _u32(), val)


def cmd_set_port(a):
    _update(a.pin_dir, "guard_ports_map", _u32(a.port), bytes([a.flags]))


def cmd_get_port(a):
    v = _lookup(a.pin_dir, "guard_ports_map", _u32(a.port))
    print(flags_str(v[0] if v else 0))


def cmd_allow_add(a):
    _update(a.pin_dir, _lpm_map(a.cidr, "allow"), lpm_key(a.cidr), b"\x01")


def cmd_allow_del(a):
    m = _lpm_map(a.cidr, "allow")
    r = _bpftool(["map", "delete", "pinned", _pin(a.pin_dir, m), "key", "hex",
                  *_hex(lpm_key(a.cidr))], check=False)
    if r.returncode != 0 and "delete failed: No such file or directory" not in _errmsg(r):
        die("delete %s → %s" % (m, _errmsg(r)))


def _read_prefixes(path, version, missing_ok=False):
    out = set()
    try:
        f = open(path)
    except FileNotFoundError:
        if missing_ok:
            return out
        die("нет файла %s" % path)
    with f:
        for ln, line in enumerate(f, 1):
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            try:
                n = ipaddress.ip_network(s, strict=False)
            except ValueError:
                die("%s:%d: не CIDR: %r" % (path, ln, s))
            if n.version != version:
                die("%s:%d: ожидался IPv%d: %s" % (path, ln, version, s))
            out.add(n.with_prefixlen)
    return out


def _map_prefixes(pin_dir, m):
    """что реально лежит в LPM-карте"""
    out = set()
    for e in _dump(pin_dir, m):
        kb = _unhex(e["key"])
        plen = struct.unpack("=I", kb[:4])[0]
        net = ipaddress.ip_network((kb[4:], plen), strict=False)
        out.add(net.with_prefixlen)
    return out


def _apply_batch(pin_dir, plan):
    """plan: [(map, new, old)] → один bpftool batch: сначала все add, потом все delete."""
    lines = []
    dels = []
    for m, new, old in plan:
        add, rm = diff_prefixes(old, new)
        path = _pin(pin_dir, m)
        lines += ["map update pinned %s key hex %s value hex 01" % (path, " ".join(_hex(lpm_key(c))))
                  for c in add]
        dels += ["map delete pinned %s key hex %s" % (path, " ".join(_hex(lpm_key(c)))) for c in rm]
    lines += dels
    if not lines:
        return True, ""
    fd, tmp = tempfile.mkstemp(prefix="guard-geo-", suffix=".batch")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        r = _bpftool(["batch", "file", tmp], check=False)
    finally:
        os.unlink(tmp)
    return r.returncode == 0, _errmsg(r)


def _write_atomic(path, lines):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("".join(x + "\n" for x in lines))
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def cmd_geo_sync(a):
    if " " in a.pin_dir:
        die("--pin-dir с пробелами не поддерживается bpftool batch")
    os.makedirs(a.loaded_dir, exist_ok=True)
    plan, files = [], []
    for (ver, m, loaded), src in zip(GEO_MAPS, (a.v4, a.v6)):
        new = _read_prefixes(src, ver)
        old = _read_prefixes(os.path.join(a.loaded_dir, loaded), ver, missing_ok=True)
        # карту пересоздали (reboot, reattach), а список «загруженного» остался —
        # без сверки diff ничего бы не добавил, и гео дропнуло бы всех
        if old and _lookup(a.pin_dir, m, lpm_key(min(old, key=_net_order))) is None:
            old = _map_prefixes(a.pin_dir, m)
        plan.append([m, new, old])
        files.append((os.path.join(a.loaded_dir, loaded), new))
    ok, err = _apply_batch(a.pin_dir, plan)
    if not ok:
        # loaded*.txt разошёлся с картой (прерванный прошлый batch) — сверка по факту
        for p in plan:
            p[2] = _map_prefixes(a.pin_dir, p[0])
        ok, err = _apply_batch(a.pin_dir, plan)
        if not ok:
            die("bpftool batch: %s" % err)
    out = []
    for (path, new), (m, _, old) in zip(files, plan):
        _write_atomic(path, sorted(new, key=_net_order))
        add, rm = diff_prefixes(old, new)
        out.append("%s +%d -%d =%d" % (m, len(add), len(rm), len(new)))
    print(" ".join(out))


def cmd_stats(a):
    tot = [0] * len(STAT_NAMES)
    for e in _dump(a.pin_dir, "guard_stats_map"):
        idx = struct.unpack("=I", _unhex(e["key"]))[0]
        if idx < len(tot):
            tot[idx] = sum(struct.unpack("=Q", _unhex(c["value"]))[0] for c in e["values"])
    print(" ".join("%s=%d" % (n, v) for n, v in zip(STAT_NAMES, tot)))


def cmd_state(a):
    v = _lookup(a.pin_dir, "guard_state_map", _u32())
    if v is None:
        die("guard_state_map[0] не читается")
    _, _, until = struct.unpack(STATE_FMT, v)
    print("attack_until_ns=%d now_ns=%d" % (until, time.clock_gettime_ns(time.CLOCK_MONOTONIC)))


# ── argparse ──

def _int_range(lo, hi):
    def conv(s):
        try:
            v = int(s, 0)
        except ValueError:
            raise argparse.ArgumentTypeError("не число: %r" % s)
        if not lo <= v <= hi:
            raise argparse.ArgumentTypeError("%d вне [%d, %d]" % (v, lo, hi))
        return v
    return conv


def _flags_arg(s):
    try:
        return port_flags(s)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


def _cidr_arg(s):
    try:
        ipaddress.ip_network(s.strip(), strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError("не IP/CIDR: %r" % s)
    return s.strip()


def build_parser():
    ap = argparse.ArgumentParser(prog="guard_ctrl.py", description="карты guard (nd-guard.h)")
    ap.add_argument("--pin-dir", dest="pin_dir", help="каталог закреплённых карт (…/maps)")
    pin = argparse.ArgumentParser(add_help=False)
    pin.add_argument("--pin-dir", dest="pin_dir", default=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    u32 = _int_range(0, 0xFFFFFFFF)

    s = sub.add_parser("set-cfg", parents=[pin])
    s.add_argument("--geo", type=int, choices=(0, 1), default=0)
    s.add_argument("--cookies", choices=tuple(COOKIE_MODES), default="auto")
    s.add_argument("--syn-threshold", dest="syn_threshold", type=u32, default=10000)
    s.add_argument("--hold", type=u32, default=60)
    s.add_argument("--rcv-wscale", dest="rcv_wscale", type=_int_range(0, 14), default=7)
    s.add_argument("--mss4", type=_int_range(0, 0xFFFF), default=1460)
    s.add_argument("--mss6", type=_int_range(0, 0xFFFF), default=1440)
    s.add_argument("--key-file", dest="key_file", required=True)
    s.set_defaults(func=cmd_set_cfg)

    s = sub.add_parser("set-port", parents=[pin])
    s.add_argument("port", type=_int_range(1, 65535))
    s.add_argument("flags", type=_flags_arg)
    s.set_defaults(func=cmd_set_port)

    s = sub.add_parser("get-port", parents=[pin])
    s.add_argument("port", type=_int_range(1, 65535))
    s.set_defaults(func=cmd_get_port)

    for name, fn in (("allow-add", cmd_allow_add), ("allow-del", cmd_allow_del)):
        s = sub.add_parser(name, parents=[pin])
        s.add_argument("cidr", type=_cidr_arg)
        s.set_defaults(func=fn)

    s = sub.add_parser("geo-sync", parents=[pin])
    s.add_argument("--v4", required=True)
    s.add_argument("--v6", required=True)
    s.add_argument("--loaded-dir", dest="loaded_dir", required=True)
    s.set_defaults(func=cmd_geo_sync)

    sub.add_parser("stats", parents=[pin]).set_defaults(func=cmd_stats)
    sub.add_parser("state", parents=[pin]).set_defaults(func=cmd_state)
    return ap


def main(argv=None):
    ap = build_parser()
    a = ap.parse_args(argv)
    if not a.pin_dir:
        ap.error("нужен --pin-dir")
    a.func(a)


if __name__ == "__main__":
    main()
