#!/usr/bin/env python3
"""Тесты modules/guard_geo.py (без root, только stdlib)."""
import contextlib
import gzip
import io
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "modules"))
import guard_geo  # noqa: E402

FIX = os.path.join(REPO, "tests", "fixtures", "guard")
RIPE = os.path.join(FIX, "ripestat-ru.json")
DBIP = os.path.join(FIX, "dbip-sample.csv")
LOW = ["--min-v4-addrs", "1000", "--min-v4-prefixes", "1", "--min-v6-prefixes", "1"]


def net(s):
    return ipaddress.ip_network(s)


def read(p):
    with open(p, "rb") as f:
        return f.read()


def run_main(args):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return guard_geo.main(args)


class GuardGeoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="nd-geo-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_parse_ripestat_prefix_and_range(self):
        text = json.dumps({"data": {"resources": {
            "ipv4": ["5.3.0.0/16", "31.40.0.0-31.40.3.255"], "ipv6": ["2a00:1fa0::/32"]}}})
        v4, v6 = guard_geo.parse_ripestat(text)
        self.assertEqual(v4, [net("5.3.0.0/16"), net("31.40.0.0/22")])
        self.assertEqual(v6, [net("2a00:1fa0::/32")])

    def test_parse_dbip_filters_cc_and_summarizes(self):
        lines = ["1.0.0.0,1.0.0.255,AU", "5.3.0.0,5.3.255.255,RU",
                 "2a00:1fa0::,2a00:1fa0:ffff:ffff:ffff:ffff:ffff:ffff,RU", "мусор", ""]
        v4, v6 = guard_geo.parse_dbip(lines, "RU")
        self.assertEqual(v4, [net("5.3.0.0/16")])
        self.assertEqual(v6, [net("2a00:1fa0::/32")])

    def test_merge_union_collapses(self):
        self.assertEqual(guard_geo.merge([net("5.3.0.0/17")], [net("5.3.128.0/17")]),
                         [net("5.3.0.0/16")])

    def test_sanity_rejects_small(self):
        ok, reason = guard_geo.sanity([net(x) for x in ("5.3.0.0/23", "5.3.2.0/24", "5.3.3.0/25", "5.3.3.128/26", "5.3.3.192/27", "5.3.3.224/29")], [], (25000000, 3000, 300))
        self.assertEqual((ok, reason), (False, "мало v4-адресов: 1000 < 25000000"))

    def test_sanity_rejects_too_many_prefixes(self):
        v4 = [net(x) for x in ("5.3.0.0/16", "5.4.0.0/16", "5.5.0.0/16")]
        v6 = [net("2a00:1fa0::/32"), net("2a00:1fa1::/32")]
        self.assertEqual(guard_geo.sanity(v4, v6, (1, 1, 1), (2, 10)),
                         (False, "много v4-префиксов: 3 > 2 (geo-карта — %d)" % guard_geo.GEO_MAP_CAPACITY))
        self.assertEqual(guard_geo.sanity(v4, v6, (1, 1, 1), (10, 1)),
                         (False, "много v6-префиксов: 2 > 1 (geo-карта — %d)" % guard_geo.GEO_MAP_CAPACITY))
        self.assertEqual(guard_geo.sanity(v4, v6, (1, 1, 1), (3, 2)), (True, ""))

    def test_build_too_many_prefixes_rc3_keeps_old(self):
        old = os.path.join(self.tmp, "geo4.txt")
        with open(old, "wb") as f:
            f.write(b"1.2.3.0/24\n")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = guard_geo.main(["build", "--cc", "RU", "--out-dir", self.tmp, "--ripe", RIPE,
                                 "--max-v4-prefixes", "1"] + LOW)
        self.assertEqual(rc, 3)
        self.assertIn("много v4-префиксов: 2 > 1", err.getvalue())
        self.assertEqual(read(old), b"1.2.3.0/24\n")

    def test_capacity_in_sync_with_bpf_maps(self):
        # max_entries geo4_map/geo6_map = GUARD_GEO_MAX_ENTRIES (C) = GEO_MAP_CAPACITY (python)
        with open(os.path.join(REPO, "modules", "nd-guard-xdp.bpf.c"), encoding="utf-8") as f:
            src = f.read()
        m = re.search(r"^#define GUARD_GEO_MAX_ENTRIES (\d+)\s*$", src, re.M)
        self.assertIsNotNone(m, "нет #define GUARD_GEO_MAX_ENTRIES в nd-guard-xdp.bpf.c")
        self.assertEqual(int(m.group(1)), guard_geo.GEO_MAP_CAPACITY)
        for name in ("geo4_map", "geo6_map"):
            body = re.search(r"struct \{([^}]*)\} %s SEC" % name, src)
            self.assertIsNotNone(body, name)
            self.assertIn("__uint(max_entries, GUARD_GEO_MAX_ENTRIES);", body.group(1), name)
        # верхняя граница по умолчанию: старый и новый список вместе (geo-sync: add, потом delete) влезают
        self.assertLessEqual(2 * guard_geo.GEO_MAX_PREFIXES, guard_geo.GEO_MAP_CAPACITY)
        # флаги по умолчанию берут GEO_MAX_PREFIXES (фикстура: v4 — 2 префикса)
        saved = guard_geo.GEO_MAX_PREFIXES
        self.addCleanup(setattr, guard_geo, "GEO_MAX_PREFIXES", saved)
        guard_geo.GEO_MAX_PREFIXES = 1
        self.assertEqual(run_main(["build", "--cc", "RU", "--out-dir", self.tmp, "--ripe", RIPE] + LOW), 3)
        guard_geo.GEO_MAX_PREFIXES = saved
        self.assertEqual(run_main(["build", "--cc", "RU", "--out-dir", self.tmp, "--ripe", RIPE] + LOW), 0)
        # реальный RU (RIPEstat ∪ db-ip, 2026-11; один db-ip — 12902/10152): ёмкость ≥ 4× замера
        for measured in (11679, 8580, 12902, 10152):
            self.assertLessEqual(4 * measured, guard_geo.GEO_MAP_CAPACITY)
            self.assertLess(measured, guard_geo.GEO_MAX_PREFIXES)

    def test_build_keeps_old_files_on_sanity_fail(self):
        old = {"geo4.txt": b"1.2.3.0/24\n", "geo6.txt": b"2001:db8::/32\n", "geo.meta": b"{}"}
        for n, d in old.items():
            with open(os.path.join(self.tmp, n), "wb") as f:
                f.write(d)
        rc = run_main(["build", "--cc", "RU", "--out-dir", self.tmp, "--ripe", RIPE])
        self.assertEqual(rc, 3)
        for n, d in old.items():
            self.assertEqual(read(os.path.join(self.tmp, n)), d)

    def test_build_one_source_ok(self):
        rc = run_main(["build", "--cc", "RU", "--out-dir", self.tmp, "--ripe", RIPE] + LOW)
        self.assertEqual(rc, 0)
        meta = json.loads(read(os.path.join(self.tmp, "geo.meta")).decode())
        self.assertEqual(meta["sources_ok"], ["ripestat"])
        self.assertEqual(meta["v4_prefixes"], 2)
        self.assertEqual(meta["v4_addrs"], 65536 + 1024)
        self.assertEqual(meta["v6_prefixes"], 1)
        self.assertEqual(read(os.path.join(self.tmp, "geo4.txt")), b"5.3.0.0/16\n31.40.0.0/22\n")
        self.assertEqual(read(os.path.join(self.tmp, "geo6.txt")), b"2a00:1fa0::/32\n")

    def test_build_both_sources_union(self):
        rc = run_main(["build", "--cc", "RU", "--out-dir", self.tmp, "--ripe", RIPE,
                       "--dbip", DBIP] + LOW)
        self.assertEqual(rc, 0)
        meta = json.loads(read(os.path.join(self.tmp, "geo.meta")).decode())
        self.assertEqual(meta["sources_ok"], ["ripestat", "dbip"])
        lines = read(os.path.join(self.tmp, "geo4.txt")).decode().split()
        self.assertEqual(lines, ["5.3.0.0/16", "5.4.0.0/24", "31.40.0.0/22"])

    def test_build_dbip_gz(self):
        gz = os.path.join(self.tmp, "dbip.csv.gz")
        with open(gz, "wb") as f:
            f.write(gzip.compress(read(DBIP)))
        out = os.path.join(self.tmp, "out")
        rc = run_main(["build", "--cc", "RU", "--out-dir", out, "--dbip", gz] + LOW)
        self.assertEqual(rc, 0)
        meta = json.loads(read(os.path.join(out, "geo.meta")).decode())
        self.assertEqual(meta["sources_ok"], ["dbip"])

    def test_build_no_source_parsed_rc4_keeps_old(self):
        bad = os.path.join(self.tmp, "bad.json")
        with open(bad, "w") as f:
            f.write("{not json")
        old = os.path.join(self.tmp, "geo4.txt")
        with open(old, "wb") as f:
            f.write(b"1.2.3.0/24\n")
        for args in (["--ripe", bad], ["--ripe", os.path.join(self.tmp, "nope")], []):
            rc = run_main(["build", "--cc", "RU", "--out-dir", self.tmp] + args + LOW)
            self.assertEqual(rc, 4)
        self.assertEqual(read(old), b"1.2.3.0/24\n")
        self.assertFalse([n for n in os.listdir(self.tmp) if n.endswith(".tmp")])


if __name__ == "__main__":
    unittest.main()
