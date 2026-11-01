#!/usr/bin/env python3
"""Тесты XDP-части guard.

GuardCtrlPureTest — чистые функции modules/guard_ctrl.py: без root, bpftool и clang.
GuardXdpTest      — modules/nd-guard-xdp.bpf.c через `bpftool prog run` (нужны root,
                    bpftool, clang; зависимости ставит tests/guard-deps.sh).

Запуск: sudo python3 tests/guard_xdp_test.py -v
"""
import importlib
import ipaddress
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES = os.path.join(REPO, "modules")
CTRL = os.path.join(MODULES, "guard_ctrl.py")
BPF_SRC = os.path.join(MODULES, "nd-guard-xdp.bpf.c")
BPFTOOL = os.environ.get("BPFTOOL", "bpftool")
PIN = "/sys/fs/bpf/nd-guard-test"
MAPS = PIN + "/maps"
PROG = PIN + "/progs/nd_guard_xdp"

XDP_DROP, XDP_PASS, XDP_TX = 1, 2, 3
M64 = (1 << 64) - 1


def load_ctrl():
    if MODULES not in sys.path:
        sys.path.insert(0, MODULES)
    return importlib.import_module("guard_ctrl")


# ── эталон SipHash-2-4 (48 байт) и cookie — как в modules/nd-guard-cookie.h ──

def _rotl(x, b):
    return ((x << b) | (x >> (64 - b))) & M64


def ref_siphash48(k0, k1, words):
    v = [k0 ^ 0x736F6D6570736575, k1 ^ 0x646F72616E646F6D,
         k0 ^ 0x6C7967656E657261, k1 ^ 0x7465646279746573]

    def rnd():
        v[0] = (v[0] + v[1]) & M64; v[1] = _rotl(v[1], 13); v[1] ^= v[0]; v[0] = _rotl(v[0], 32)
        v[2] = (v[2] + v[3]) & M64; v[3] = _rotl(v[3], 16); v[3] ^= v[2]
        v[0] = (v[0] + v[3]) & M64; v[3] = _rotl(v[3], 21); v[3] ^= v[0]
        v[2] = (v[2] + v[1]) & M64; v[1] = _rotl(v[1], 17); v[1] ^= v[2]; v[2] = _rotl(v[2], 32)

    for w in words:
        v[3] ^= w
        rnd(); rnd()
        v[0] ^= w
    b = 48 << 56
    v[3] ^= b
    rnd(); rnd()
    v[0] ^= b
    v[2] ^= 0xFF
    rnd(); rnd(); rnd(); rnd()
    return v[0] ^ v[1] ^ v[2] ^ v[3]


def ref_cookie_hash24(key, saddr16, daddr16, sport_raw, dport_raw, isn, slot, optbyte):
    """R3: адреса/порты — сырые байты пакета, прочитанные как native u32/u16."""
    k0, k1 = struct.unpack("=QQ", key)
    s = struct.unpack("=4I", saddr16)
    d = struct.unpack("=4I", daddr16)
    sp = struct.unpack("=H", sport_raw)[0]
    dp = struct.unpack("=H", dport_raw)[0]
    m = [s[0] << 32 | s[1], s[2] << 32 | s[3], d[0] << 32 | d[1], d[2] << 32 | d[3],
         sp << 48 | dp << 32 | isn, (slot & 0xFFFFFFFF) << 8 | optbyte]
    return ref_siphash48(k0, k1, m) >> 40


# ── сборка пакетов ──

SRV_MAC = bytes.fromhex("020000000001")
CLI_MAC = bytes.fromhex("020000000002")
SRV4, SRV6 = "192.0.2.1", "2001:db8::1"
RU4, NONRU4 = "10.1.2.3", "198.51.100.7"
RU6, NONRU6 = "fd00::abcd", "2001:db8:dead::7"


def inet_csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def addr(ip):
    return ipaddress.ip_address(ip).packed


def pseudo(src, dst, proto, length):
    s, d = addr(src), addr(dst)
    if len(s) == 4:
        return s + d + struct.pack("!BBH", 0, proto, length)
    return s + d + struct.pack("!IxxxB", length, proto)


def tcp_seg(src, dst, sport, dport, seq, flags, opts=b"", ack=0):
    opts += b"\0" * (-len(opts) % 4)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (20 + len(opts)) // 4 << 4,
                      flags, 64240, 0, 0) + opts
    c = inet_csum(pseudo(src, dst, 6, len(hdr)) + hdr)
    return hdr[:16] + struct.pack("!H", c) + hdr[18:]


def udp_dgram(src, dst, sport, dport, payload=b"q"):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    c = inet_csum(pseudo(src, dst, 17, len(hdr)) + hdr)
    return hdr[:6] + struct.pack("!H", c) + hdr[8:]


def frame(src, dst, proto, l4, ihl=5):
    if ipaddress.ip_address(src).version == 4:
        ipopt = b"\x01" * (4 * (ihl - 5))
        h = struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, 4 * ihl + len(l4), 0x1234, 0x4000,
                        57, proto, 0, addr(src), addr(dst)) + ipopt
        h = h[:10] + struct.pack("!H", inet_csum(h)) + h[12:]
        return SRV_MAC + CLI_MAC + b"\x08\x00" + h + l4
    h = struct.pack("!IHBB16s16s", 0x60000000, len(l4), proto, 57, addr(src), addr(dst))
    return SRV_MAC + CLI_MAC + b"\x86\xdd" + h + l4


SYN, ACK = 0x02, 0x10
ISN = 0xDEADBEEF
TSVAL = 0x01020304
# Linux: MSS 1460, SACKOK, TS, NOP, WS 7
OPTS_LINUX = (bytes.fromhex("020405b4") + bytes.fromhex("0402080a") + struct.pack("!II", TSVAL, 0)
              + bytes.fromhex("01030307"))
# Windows: MSS 1460, NOP, WS 8, NOP, NOP, SACKOK — без TS
OPTS_WINDOWS = bytes.fromhex("020405b4" "01030308" "01010402")


def syn(src, dport=443, opts=OPTS_LINUX, sport=40000, ihl=5):
    dst = SRV4 if ipaddress.ip_address(src).version == 4 else SRV6
    return frame(src, dst, 6, tcp_seg(src, dst, sport, dport, ISN, SYN, opts), ihl=ihl)


def parse_tcp_opts(raw):
    """[(kind, bytes)] — NOP как (1, b"")"""
    out, i = [], 0
    while i < len(raw):
        k = raw[i]
        if k == 0:
            break
        if k == 1:
            out.append((1, b""))
            i += 1
            continue
        ln = raw[i + 1]
        out.append((k, raw[i + 2:i + ln]))
        i += ln
    return out


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


class GuardCtrlPureTest(unittest.TestCase):
    """Без root: упаковка ABI-структур и диффы — modules/guard_ctrl.py."""

    @classmethod
    def setUpClass(cls):
        cls.gc = load_ctrl()

    def test_pack_cfg_len_40(self):
        key = bytes(range(16))
        b = self.gc.pack_cfg(geo_on=1, cookie_mode="auto", syn_threshold=10000, hold_sec=60,
                             rcv_wscale=7, mss4=1460, mss6=1440, key=key)
        self.assertEqual(len(b), 40)
        self.assertEqual(struct.unpack("=IIIIIHH", b[:24]), (1, 1, 10000, 60, 7, 1460, 1440))
        self.assertEqual(b[24:], key)  # ключ — 16 байт как есть (2×u64 native)

    def test_lpm_key(self):
        self.assertEqual(self.gc.lpm_key("5.3.0.0/16"),
                         (16).to_bytes(4, sys.byteorder) + bytes([5, 3, 0, 0]))
        self.assertEqual(self.gc.lpm_key("2a00:1fa0::/32"),
                         (32).to_bytes(4, sys.byteorder) + bytes.fromhex("2a001fa0") + bytes(12))
        self.assertEqual(self.gc.lpm_key("198.51.100.7"),
                         (32).to_bytes(4, sys.byteorder) + bytes([198, 51, 100, 7]))

    def test_port_flags(self):
        self.assertEqual(self.gc.port_flags("tcp,geo"), 5)
        self.assertEqual(self.gc.port_flags("tcp,udp,geo"), 7)
        self.assertEqual(self.gc.port_flags("none"), 0)
        with self.assertRaises(ValueError):
            self.gc.port_flags("tcp,icmp")
        self.assertEqual(self.gc.flags_str(5), "tcp,geo")
        self.assertEqual(self.gc.flags_str(0), "none")

    def test_diff_prefixes(self):
        add, dele = self.gc.diff_prefixes({"10.0.0.0/8", "5.3.0.0/16"},
                                          {"5.3.0.0/16", "31.40.0.0/22", "2.60.0.0/14"})
        self.assertEqual(add, ["2.60.0.0/14", "31.40.0.0/22"])
        self.assertEqual(dele, ["10.0.0.0/8"])
        self.assertEqual(self.gc.diff_prefixes(set(), set()), ([], []))

    def test_ref_siphash_vector(self):
        # эталон из этого файла против vectors_sip64[48] — тот же вектор, что в host-тесте
        k0, k1 = struct.unpack("<QQ", bytes(range(16)))
        m = struct.unpack("<6Q", bytes(range(48)))
        self.assertEqual(ref_siphash48(k0, k1, m),
                         struct.unpack("<Q", bytes.fromhex("51a9cb9ecba312e6"))[0])


def _bpf_env_ok():
    return os.geteuid() == 0 and shutil.which(BPFTOOL) and shutil.which("clang")


@unittest.skipUnless(_bpf_env_ok(), "нужны root, bpftool и clang (tests/guard-deps.sh)")
class GuardXdpTest(unittest.TestCase):
    MSS4, MSS6, RCV_WS = 1452, 1432, 9

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="nd-guard-xdp-")
        try:
            cls._load()
        except Exception:
            cls._cleanup()
            raise

    @classmethod
    def _load(cls):
        obj = os.path.join(cls.tmp, "nd-guard-xdp.bpf.o")
        inc = ["-I/usr/include/x86_64-linux-gnu"] if os.path.isdir("/usr/include/x86_64-linux-gnu") else []
        r = run(["clang", "-O2", "-g", "-Wall", "-target", "bpf", *inc, "-c", BPF_SRC, "-o", obj])
        if r.returncode != 0:
            raise RuntimeError("clang:\n" + r.stderr)
        shutil.rmtree(PIN, ignore_errors=True)
        os.makedirs(PIN)  # loadall не создаёт родителя pin-каталога
        r = run([BPFTOOL, "prog", "loadall", obj, PIN + "/progs", "type", "xdp", "pinmaps", MAPS])
        if r.returncode != 0:
            raise RuntimeError("bpftool prog loadall:\n" + r.stdout + r.stderr)
        cls.key = os.urandom(16)
        cls.keyfile = os.path.join(cls.tmp, "key")
        with open(cls.keyfile, "wb") as f:
            f.write(cls.key)
        cls.geo4 = os.path.join(cls.tmp, "geo4.txt")
        cls.geo6 = os.path.join(cls.tmp, "geo6.txt")
        cls.loaded = os.path.join(cls.tmp, "loaded")
        os.mkdir(cls.loaded)

    @classmethod
    def _cleanup(cls):
        shutil.rmtree(PIN, ignore_errors=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._cleanup()

    @staticmethod
    def _write(path, lines):
        with open(path, "w") as f:
            f.write("".join(x + "\n" for x in lines))

    @classmethod
    def ctrl(cls, *args):
        r = run([sys.executable, CTRL, "--pin-dir", MAPS, *args])
        if r.returncode != 0:
            raise AssertionError("guard_ctrl %s → rc %d\n%s%s" % (args, r.returncode, r.stdout, r.stderr))
        return r.stdout.strip()

    def set_cfg(self, geo=1, cookies="off", threshold=10000):
        self.ctrl("set-cfg", "--geo", str(geo), "--cookies", cookies, "--syn-threshold", str(threshold),
                  "--hold", "60", "--rcv-wscale", str(self.RCV_WS), "--mss4", str(self.MSS4),
                  "--mss6", str(self.MSS6), "--key-file", self.keyfile)

    def geo_sync(self, v4=("10.0.0.0/8",), v6=("fd00::/16",)):
        self._write(self.geo4, v4)
        self._write(self.geo6, v6)
        return self.ctrl("geo-sync", "--v4", self.geo4, "--v6", self.geo6, "--loaded-dir", self.loaded)

    def setUp(self):
        # каждый тест — с базового состояния: гео RU = 10/8 + fd00::/16, 443/80 tcp,udp,geo
        self.set_cfg()
        self.geo_sync()
        self.ctrl("allow-del", "198.51.100.0/24")
        self.ctrl("set-port", "443", "tcp,udp,geo")
        self.ctrl("set-port", "80", "tcp,udp,geo")
        r = run([BPFTOOL, "map", "update", "pinned", MAPS + "/guard_state_map",
                 "key", "hex", "00", "00", "00", "00", "value", "hex", *["00"] * 24])
        self.assertEqual(r.returncode, 0, r.stderr)

    def send(self, pkt):
        fin = os.path.join(self.tmp, "in.bin")
        fout = os.path.join(self.tmp, "out.bin")
        with open(fin, "wb") as f:
            f.write(pkt)
        if os.path.exists(fout):
            os.unlink(fout)
        r = run([BPFTOOL, "prog", "run", "pinned", PROG, "data_in", fin,
                 "data_out", fout, "data_size_out", "1500"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        m = re.search(r"Return value: (\d+)", r.stdout + r.stderr)
        self.assertIsNotNone(m, r.stdout + r.stderr)
        with open(fout, "rb") as f:
            return int(m.group(1)), f.read()

    def stats(self):
        out = self.ctrl("stats")
        self.assertRegex(out, r"^pass=\d+ geo_drop=\d+ allow=\d+ syn=\d+ cookie_sent=\d+ "
                              r"cookie_ok=\d+ cookie_bad=\d+ assign_err=\d+$")
        return {k: int(v) for k, v in (x.split("=") for x in out.split())}

    def delta(self, before):
        after = self.stats()
        return {k: after[k] - before[k] for k in after}

    # ── гео / порты / allowlist ──

    def test_non_ru_syn_dropped_when_geo_on(self):
        s0 = self.stats()
        self.assertEqual(self.send(syn(NONRU4))[0], XDP_DROP)
        d = self.delta(s0)
        self.assertEqual(d["geo_drop"], 1)
        self.assertEqual(d["pass"], 0)

    def test_non_ru_v6_syn_dropped_when_geo_on(self):
        self.assertEqual(self.send(syn(NONRU6))[0], XDP_DROP)
        self.assertEqual(self.send(syn(RU6))[0], XDP_PASS)

    def test_ru_syn_passes_cookie_off(self):
        s0 = self.stats()
        self.assertEqual(self.send(syn(RU4))[0], XDP_PASS)
        d = self.delta(s0)
        self.assertEqual((d["syn"], d["pass"], d["cookie_sent"], d["geo_drop"]), (1, 1, 0, 0))

    def test_geo_off_passes_non_ru(self):
        self.set_cfg(geo=0)
        self.assertEqual(self.send(syn(NONRU4))[0], XDP_PASS)

    def test_unguarded_port_passes(self):
        s0 = self.stats()
        self.assertEqual(self.send(syn(NONRU4, dport=22))[0], XDP_PASS)
        self.assertEqual(set(self.delta(s0).values()), {0})  # статистика не пишется

    def test_allowlisted_non_ru_passes(self):
        self.ctrl("allow-add", "198.51.100.0/24")
        try:
            s0 = self.stats()
            self.assertEqual(self.send(syn(NONRU4))[0], XDP_PASS)
            d = self.delta(s0)
            self.assertEqual((d["allow"], d["geo_drop"]), (1, 0))
            self.set_cfg(cookies="always")  # allowlist обходит и cookies
            self.assertEqual(self.send(syn(NONRU4))[0], XDP_PASS)
        finally:
            self.ctrl("allow-del", "198.51.100.0/24")
        self.assertEqual(self.send(syn(NONRU4))[0], XDP_DROP)

    def test_port80_without_geo_flag_passes(self):
        self.ctrl("set-port", "80", "tcp,udp")
        self.assertEqual(self.ctrl("get-port", "80"), "tcp,udp")
        self.assertEqual(self.send(syn(NONRU4, dport=80))[0], XDP_PASS)
        self.ctrl("set-port", "80", "tcp,udp,geo")
        self.assertEqual(self.ctrl("get-port", "80"), "tcp,udp,geo")
        self.assertEqual(self.send(syn(NONRU4, dport=80))[0], XDP_DROP)

    def test_udp443_non_ru_dropped(self):
        self.assertEqual(self.send(frame(NONRU4, SRV4, 17, udp_dgram(NONRU4, SRV4, 5000, 443)))[0],
                         XDP_DROP)
        self.assertEqual(self.send(frame(RU4, SRV4, 17, udp_dgram(RU4, SRV4, 5000, 443)))[0],
                         XDP_PASS)

    def test_tcp_only_port_passes_udp(self):
        self.ctrl("set-port", "443", "tcp,geo")
        s0 = self.stats()
        self.assertEqual(self.send(frame(NONRU4, SRV4, 17, udp_dgram(NONRU4, SRV4, 5000, 443)))[0],
                         XDP_PASS)
        self.assertEqual(set(self.delta(s0).values()), {0})

    def test_ip_options_pass(self):
        self.assertEqual(self.send(syn(NONRU4, ihl=6))[0], XDP_PASS)

    def test_ack_passes_in_always_mode(self):
        self.set_cfg(cookies="always")
        pkt = frame(RU4, SRV4, 6, tcp_seg(RU4, SRV4, 40000, 443, ISN + 1, ACK, ack=12345))
        self.assertEqual(self.send(pkt)[0], XDP_PASS)

    # ── SYN-ACK с cookie ──

    def check_synack(self, src, opts, v6):
        self.set_cfg(cookies="always")
        dst = SRV6 if v6 else SRV4
        pkt = syn(src, opts=opts)
        s0 = self.stats()
        t0 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        ret, out = self.send(pkt)
        t1 = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        self.assertEqual(ret, XDP_TX)
        d = self.delta(s0)
        self.assertEqual((d["syn"], d["cookie_sent"], d["pass"]), (1, 1, 0))

        self.assertEqual(out[0:6], CLI_MAC)
        self.assertEqual(out[6:12], SRV_MAC)
        self.assertEqual(out[12:14], pkt[12:14])
        if v6:
            ip, l4 = out[14:54], out[54:]
            ver_tc_fl, plen, nh, hop = struct.unpack("!IHBB", ip[:8])
            self.assertEqual((ver_tc_fl >> 28, nh, hop), (6, 6, 64))
            self.assertEqual(plen, len(l4))
            self.assertEqual((ip[8:24], ip[24:40]), (addr(dst), addr(src)))
        else:
            ip, l4 = out[14:34], out[34:]
            self.assertEqual(ip[0], 0x45)
            tot, ipid, frag, ttl, proto = struct.unpack("!2xHHHBB", ip[:10])
            self.assertEqual((tot, ipid, frag, ttl, proto), (20 + len(l4), 0, 0x4000, 64, 6))
            self.assertEqual(inet_csum(ip), 0, "IP checksum")
            self.assertEqual((ip[12:16], ip[16:20]), (addr(dst), addr(src)))
        self.assertEqual(inet_csum(pseudo(dst, src, 6, len(l4)) + l4), 0, "TCP checksum")

        sport, dport, seq, ackn, off, flags, win, _, urg = struct.unpack("!HHIIBBHHH", l4[:20])
        self.assertEqual((sport, dport), (443, 40000))
        self.assertEqual(flags, 0x12)
        self.assertEqual(ackn, (ISN + 1) & 0xFFFFFFFF)
        self.assertEqual((win, urg), (65535, 0))
        self.assertEqual(off >> 4, len(l4) // 4)
        self.assertEqual(len(l4) % 4, 0)

        # cookie сверяется с эталоном: те же входы (R3), что возьмёт tc-проверка
        cin = pkt[54:] if v6 else pkt[34:]
        sa, da = (pkt[22:38], pkt[38:54]) if v6 else (pkt[26:30] + bytes(12), pkt[30:34] + bytes(12))
        slots = {t0 >> 36, t1 >> 36}
        want = {ref_cookie_hash24(self.key, sa, da, cin[0:2], cin[2:4], ISN, sl, seq & 0xFF)
                for sl in slots}
        self.assertIn(seq >> 8, want, "cookie не совпал с эталоном SipHash")
        return seq, parse_tcp_opts(l4[20:]), t0, t1

    def test_cookie_always_syn_ack_v4(self):
        seq, opts, t0, t1 = self.check_synack(RU4, OPTS_LINUX, v6=False)
        self.assertEqual(seq & 0xF, 7)            # WS клиента
        self.assertEqual((seq >> 4) & 1, 1)       # SACK
        self.assertEqual((seq >> 5) & 7, 7)       # mss_idx(1460) = 7
        self.assertEqual([k for k, _ in opts], [2, 4, 8, 1, 3])  # MSS, SACKOK, TS, NOP, WS
        d = dict(opts)
        self.assertEqual(struct.unpack("!H", d[2])[0], self.MSS4)
        self.assertEqual(d[3], bytes([self.RCV_WS]))
        tsval, tsecr = struct.unpack("!II", d[8])
        self.assertEqual(tsecr, TSVAL)
        self.assertLessEqual(t0 // 1000000 & 0xFFFFFFFF, tsval)
        self.assertLessEqual(tsval, t1 // 1000000 & 0xFFFFFFFF)

    def test_cookie_always_syn_ack_v6(self):
        seq, opts, _, _ = self.check_synack(RU6, OPTS_LINUX, v6=True)
        self.assertEqual((seq & 0xF, (seq >> 4) & 1, (seq >> 5) & 7), (7, 1, 7))
        self.assertEqual([k for k, _ in opts], [2, 4, 8, 1, 3])
        d = dict(opts)
        self.assertEqual(struct.unpack("!H", d[2])[0], self.MSS6)
        self.assertEqual(d[3], bytes([self.RCV_WS]))
        self.assertEqual(struct.unpack("!II", d[8])[1], TSVAL)

    def test_syn_no_ts(self):
        seq, opts, _, _ = self.check_synack(RU4, OPTS_WINDOWS, v6=False)
        self.assertEqual(seq & 0xF, 8)
        self.assertEqual((seq >> 4) & 1, 1)
        self.assertEqual(opts, [(2, struct.pack("!H", self.MSS4)), (1, b""), (1, b""), (4, b""),
                                (1, b""), (3, bytes([self.RCV_WS]))])

    def test_syn_ts_without_sack(self):
        o = bytes.fromhex("020405b4" "0101080a") + struct.pack("!II", TSVAL, 0)
        seq, opts, _, _ = self.check_synack(RU4, o, v6=False)
        self.assertEqual((seq & 0xF, (seq >> 4) & 1), (15, 0))  # WS не прислан → 15
        self.assertEqual([k for k, _ in opts], [2, 1, 1, 8])

    def test_syn_bare_defaults_and_ws_clamp(self):
        # без опций: MSS по умолчанию 536 → mss_idx 0, WS нет → 15, SACK нет; длина растёт (+4)
        seq, opts, _, _ = self.check_synack(RU4, b"", v6=False)
        self.assertEqual(seq & 0xFF, 0x0F)
        self.assertEqual(opts, [(2, struct.pack("!H", self.MSS4))])
        # WS 15 у клиента → 14; v6 без MSS → 1220 → mss_idx 0
        seq, opts, _, _ = self.check_synack(RU6, bytes.fromhex("0103030f"), v6=True)
        self.assertEqual(seq & 0xFF, 0x0E)

    def test_syn_unknown_option_and_shrink(self):
        # MSS 1400, TFO-запрос (kind 34) пропускается, NOP-набивка; SYN-ACK короче SYN (16 → 8)
        o = bytes.fromhex("02040578" "2202" "0101" "01030302" "01010101")
        seq, opts, _, _ = self.check_synack(RU4, o, v6=False)
        self.assertEqual(seq & 0xFF, 4 << 5 | 2)  # mss_idx(1400) = 4, без SACK, WS 2
        self.assertEqual(opts, [(2, struct.pack("!H", self.MSS4)), (1, b""), (3, bytes([self.RCV_WS]))])

    def test_auto_mode_engages_over_threshold(self):
        self.set_cfg(cookies="auto", threshold=5)
        pkt = syn(RU4)
        for i in range(5):
            self.assertEqual(self.send(pkt)[0], XDP_PASS, "SYN %d" % (i + 1))
        self.assertEqual(self.send(pkt)[0], XDP_TX, "SYN 6")
        m = re.fullmatch(r"attack_until_ns=(\d+) now_ns=(\d+)", self.ctrl("state"))
        self.assertIsNotNone(m)
        self.assertGreater(int(m.group(1)), int(m.group(2)))

    # ── guard_ctrl: синхронизация гео ──

    def test_geo_sync_add_then_delete(self):
        out = self.geo_sync(v4=("10.0.0.0/8", "198.51.100.0/24"))
        self.assertEqual(out, "geo4_map +1 -0 =2 geo6_map +0 -0 =1")
        self.assertEqual(self.send(syn(NONRU4))[0], XDP_PASS)
        with open(os.path.join(self.loaded, "loaded4.txt")) as f:
            self.assertEqual(f.read().split(), ["10.0.0.0/8", "198.51.100.0/24"])
        out = self.geo_sync(v4=("198.51.100.0/24",))
        self.assertEqual(out, "geo4_map +0 -1 =1 geo6_map +0 -0 =1")
        self.assertEqual(self.send(syn(NONRU4))[0], XDP_PASS)
        self.assertEqual(self.send(syn(RU4))[0], XDP_DROP)

    def test_geo_sync_resyncs_when_map_lost_entries(self):
        # карта пересоздана (reboot/reattach), а loaded4.txt остался — список заливается заново
        lpm = load_ctrl().lpm_key("10.0.0.0/8")
        r = run([BPFTOOL, "map", "delete", "pinned", MAPS + "/geo4_map",
                 "key", "hex", *("%02x" % x for x in lpm)])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.send(syn(RU4))[0], XDP_DROP)
        self.assertEqual(self.geo_sync(), "geo4_map +1 -0 =1 geo6_map +0 -0 =1")
        self.assertEqual(self.send(syn(RU4))[0], XDP_PASS)

    def test_geo_sync_recovers_from_stale_loaded_list(self):
        # loaded4.txt врёт (прерванный прошлый batch): delete несуществующего ломает batch →
        # сверка с картой по факту, и синхронизация всё равно доходит до конца
        with open(os.path.join(self.loaded, "loaded4.txt"), "w") as f:
            f.write("10.0.0.0/8\n203.0.113.0/24\n")
        self.assertEqual(self.geo_sync(), "geo4_map +0 -0 =1 geo6_map +0 -0 =1")
        self.assertEqual(self.send(syn(RU4))[0], XDP_PASS)


if __name__ == "__main__":
    unittest.main()
