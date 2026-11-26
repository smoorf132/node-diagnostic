#!/usr/bin/env python3
"""Тесты modules/node_conf.py (без root и docker, только stdlib)."""
import io
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "modules"))
import node_conf as nc  # noqa: E402

FIX = os.path.join(REPO, "tests", "fixtures", "node")


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return f.read()


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = nc.main(list(argv))
    return rc, out.getvalue(), err.getvalue()


class NginxParseTest(unittest.TestCase):
    def setUp(self):
        self.conf = fixture("nginx.conf")

    def test_sites_only_selfsteal(self):
        st = nc.sites(self.conf)
        self.assertEqual(len(st), 1)
        self.assertEqual(nc.server_names(st[0]), ["node.example.com"])

    def test_cert_paths(self):
        self.assertEqual(nc.cert_paths(self.conf), [
            "/etc/nginx/ssl/example.com/fullchain.pem",
            "/etc/nginx/ssl/example.com/privkey.pem",
        ])

    def test_braces_in_strings_and_regex(self):
        conf = 'server {\n    listen 443 ssl;\n    server_name a.example.com;\n' \
               '    location ~ "^/x{2,3}$" { return 200 "}{"; }\n    set $v "${host}";\n}\n'
        self.assertEqual(nc.server_names(nc.sites(conf)[0]), ["a.example.com"])

    def test_broken_conf(self):
        with self.assertRaises(nc.ConfError):
            nc.parse("server {\n listen 443 ssl;\n")
        with self.assertRaises(nc.ConfError):
            nc.parse("server { listen 443 ssl }\n")

    def test_full_nginx_conf_with_http_block(self):
        conf = "events {}\nhttp {\n server { listen 443 ssl; server_name h.example.com; }\n}\n" \
               "stream {\n server { listen 443; }\n}\n"
        self.assertEqual([nc.server_names(s) for s in nc.sites(conf)], [["h.example.com"]])


class AddSiteTest(unittest.TestCase):
    def setUp(self):
        self.conf = fixture("nginx.conf")

    def test_add_copies_first_site(self):
        res = nc.add_site(self.conf, "Two.Example.org", "two.example.org")
        st = nc.sites(res)
        self.assertEqual([nc.server_names(s) for s in st], [["node.example.com"], ["two.example.org"]])
        new = res[st[1].start:st[1].end]
        self.assertIn('ssl_certificate "/etc/nginx/ssl/two.example.org/fullchain.pem";', new)
        self.assertIn('ssl_certificate_key "/etc/nginx/ssl/two.example.org/privkey.pem";', new)
        self.assertIn('ssl_trusted_certificate "/etc/nginx/ssl/two.example.org/fullchain.pem";', new)
        # ручная правка первого сайта переехала в копию
        self.assertIn("location = /robots.txt", new)
        self.assertIn("listen unix:/dev/shm/nginx.sock ssl proxy_protocol;", new)
        # первый сайт, reject и :80 не тронуты
        self.assertTrue(res.startswith(self.conf[:self.conf.index("\n}\n") + 3]))
        self.assertIn("ssl_reject_handshake on;", res)
        self.assertIn("listen 80 default_server;", res)
        self.assertEqual(res.count("server_name _;"), 2)
        # новый блок стоит после первого сайта и до reject
        self.assertLess(res.index("two.example.org"), res.index("default_server"))
        self.assertNotIn("\n\n\n", res)

    def test_add_existing_rc3(self):
        with self.assertRaises(nc.DomainError) as cm:
            nc.add_site(self.conf, "NODE.example.com", "example.com")
        self.assertEqual(cm.exception.code, nc.EXIT_EXISTS)

    def test_add_rejects_garbage(self):
        with self.assertRaises(nc.ConfError):
            nc.add_site(self.conf, "bad;domain.com", "example.com")
        with self.assertRaises(nc.ConfError):
            nc.add_site(self.conf, "ok.example.com", "../etc")

    def test_add_without_site(self):
        conf = "server {\n    listen 80 default_server;\n    return 444;\n}\n"
        with self.assertRaises(nc.ConfError) as cm:
            nc.add_site(conf, "a.example.com", "example.com")
        self.assertEqual(cm.exception.code, 1)

    def test_add_inserts_missing_cert_directives(self):
        conf = "server {\n    listen 443 ssl;\n    root /srv;\n}\n"
        res = nc.add_site(conf, "b.example.com", "b.example.com")
        new = nc.sites(res)[1]
        self.assertEqual(nc.server_names(new), ["b.example.com"])
        keys = {c.key: c.values() for c in new.children}
        self.assertEqual(keys["ssl_certificate"], ["/etc/nginx/ssl/b.example.com/fullchain.pem"])
        self.assertEqual(keys["ssl_certificate_key"], ["/etc/nginx/ssl/b.example.com/privkey.pem"])

    def test_add_then_del_roundtrip(self):
        res = nc.add_site(self.conf, "two.example.org", "two.example.org")
        self.assertEqual(nc.del_site(res, "two.example.org"), self.conf)


class DelSiteTest(unittest.TestCase):
    def setUp(self):
        self.conf = fixture("nginx.conf")

    def test_del_last_rc5(self):
        with self.assertRaises(nc.DomainError) as cm:
            nc.del_site(self.conf, "node.example.com")
        self.assertEqual(cm.exception.code, nc.EXIT_LAST)

    def test_del_missing_rc3(self):
        with self.assertRaises(nc.DomainError) as cm:
            nc.del_site(self.conf, "nope.example.com")
        self.assertEqual(cm.exception.code, nc.EXIT_EXISTS)

    def test_del_name_from_multi_server_name(self):
        conf = self.conf.replace("server_name node.example.com;", "server_name node.example.com alt.example.com;")
        res = nc.del_site(conf, "ALT.example.com")
        self.assertEqual(res, self.conf)
        res2 = nc.del_site(conf, "node.example.com")
        self.assertIn("server_name alt.example.com;", res2)
        self.assertEqual(len(nc.sites(res2)), 1)

    def test_del_block_keeps_others(self):
        two = nc.add_site(self.conf, "two.example.org", "two.example.org")
        three = nc.add_site(two, "three.example.net", "example.net")
        res = nc.del_site(three, "two.example.org")
        self.assertEqual([nc.server_names(s) for s in nc.sites(res)],
                         [["node.example.com"], ["three.example.net"]])
        self.assertIn("ssl_reject_handshake on;", res)
        self.assertNotIn("\n\n\n", res)

    def test_cli_codes(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "nginx.conf")
            with open(p, "w") as f:
                f.write(self.conf)
            self.assertEqual(run("del", p, "node.example.com")[0], 5)
            self.assertEqual(run("add", p, "node.example.com", "example.com")[0], 3)
            out = os.path.join(d, "new.conf")
            self.assertEqual(run("add", p, "x.example.com", "example.com", "--out", out)[0], 0)
            rc, so, _ = run("sites", out)
            self.assertEqual(rc, 0)
            self.assertEqual(so.splitlines(), [
                "node.example.com\t/etc/nginx/ssl/example.com/fullchain.pem",
                "x.example.com\t/etc/nginx/ssl/example.com/fullchain.pem",
            ])
            rc, so, _ = run("names", out)
            self.assertEqual(so.split(), ["node.example.com", "x.example.com", "_", "_"])


class ComposeTest(unittest.TestCase):
    def setUp(self):
        self.old = fixture("compose-old.yml")

    def test_migrate_old(self):
        res = nc.compose_migrate(self.old)
        self.assertIn("    image: nginx:alpine\n", res)
        self.assertNotIn("1.30.6", res)
        self.assertNotIn("/etc/letsencrypt/live/example.com", res)
        self.assertIn("      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro\n"
                      "      - /etc/letsencrypt/live:/etc/nginx/ssl:ro\n"
                      "      - /etc/letsencrypt/archive:/etc/nginx/archive:ro\n"
                      "      - /dev/shm:/dev/shm:rw\n", res)
        # ручная правка и remnanode не тронуты
        self.assertIn("/opt/geo/geosite.dat:/usr/local/share/xray/geosite.dat:ro", res)
        self.assertIn("    image: remnawave/node:latest\n", res)
        # повторная миграция ничего не меняет
        self.assertEqual(nc.compose_migrate(res), res)

    def test_migrate_conflicting_mount(self):
        bad = self.old.replace("      - /dev/shm:/dev/shm:rw\n", "      - ./ssl:/etc/nginx/ssl:ro\n      - /dev/shm:/dev/shm:rw\n", 1)
        with self.assertRaises(nc.ConfError):
            nc.compose_migrate(bad)

    def test_migrate_keeps_foreign_image(self):
        res = nc.compose_migrate(self.old.replace("image: nginx:1.30.6-alpine", "image: openresty/openresty:alpine"))
        self.assertIn("image: openresty/openresty:alpine", res)

    def test_compose_image(self):
        self.assertEqual(nc.compose_image(self.old, "remnawave-nginx"), "nginx:1.30.6-alpine")
        self.assertEqual(nc.compose_image(self.old, "remnanode"), "remnawave/node:latest")
        with self.assertRaises(nc.ConfError):
            nc.compose_image(self.old, "nope")

    def test_xray_on_off(self):
        self.assertEqual(nc.compose_xray(self.old, "status"), "off")
        on = nc.compose_xray(self.old, "on")
        self.assertIn("      - /opt/xray-core/xray:/usr/local/bin/xray:ro\n", on)
        self.assertEqual(nc.compose_xray(on, "status"), "on /opt/xray-core/xray")
        self.assertEqual(nc.compose_xray(on, "on"), on)
        # mount строго внутри remnanode (после его последнего тома)
        self.assertGreater(on.index("/opt/xray-core/xray"), on.index("  remnanode:"))
        off = nc.compose_xray(on, "off")
        self.assertEqual(off, self.old if self.old.endswith("\n") else self.old + "\n")

    def test_xray_replaces_other_source(self):
        other = self.old.replace("      - /var/log/remnanode:/var/log/remnanode\n",
                                 "      - /var/log/remnanode:/var/log/remnanode\n      - /root/xray:/usr/local/bin/xray\n")
        on = nc.compose_xray(other, "on")
        self.assertNotIn("/root/xray", on)
        self.assertEqual(on.count("/usr/local/bin/xray"), 1)

    def test_xray_without_volumes(self):
        y = "services:\n  remnanode:\n    image: remnawave/node:latest\n    network_mode: host\n"
        on = nc.compose_xray(y, "on")
        self.assertEqual(on, y + "    volumes:\n      - /opt/xray-core/xray:/usr/local/bin/xray:ro\n")
        self.assertEqual(nc.compose_xray(on, "off"), y)

    def test_long_form_volume(self):
        y = ("services:\n  remnawave-nginx:\n    image: nginx\n    volumes:\n"
             "      - type: bind\n        source: /etc/letsencrypt/live/a.com/fullchain.pem\n"
             "        target: /etc/nginx/ssl/a.com/fullchain.pem\n      - /dev/shm:/dev/shm\n")
        res = nc.compose_migrate(y)
        self.assertNotIn("type: bind", res)
        self.assertIn("    image: nginx:alpine\n", res)
        self.assertIn("      - /etc/letsencrypt/live:/etc/nginx/ssl:ro\n", res)

    def test_cli_changed_same(self):
        with tempfile.TemporaryDirectory() as d:
            p, o = os.path.join(d, "c.yml"), os.path.join(d, "o.yml")
            with open(p, "w") as f:
                f.write(self.old)
            self.assertEqual(run("compose-migrate", p, "--out", o)[1].strip(), "changed")
            self.assertEqual(run("compose-migrate", o, "--out", p)[1].strip(), "same")
            self.assertEqual(run("compose-xray", p, "status")[1].strip(), "off")


class BinaryTest(unittest.TestCase):
    def _elf(self, d, machine, endian="<"):
        p = os.path.join(d, "bin%d" % machine)
        with open(p, "wb") as f:
            f.write(b"\x7fELF" + bytes([2, 1 if endian == "<" else 2]) + b"\0" * 12 + struct.pack(endian + "H", machine))
        return p

    def test_elf_arch(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(nc.elf_arch(self._elf(d, 62)), "x86_64")
            self.assertEqual(nc.elf_arch(self._elf(d, 183)), "aarch64")
            self.assertEqual(nc.elf_arch(self._elf(d, 99)), "ELF:99")
            txt = os.path.join(d, "t")
            with open(txt, "w") as f:
                f.write("<html>not found</html>")
            self.assertIsNone(nc.elf_arch(txt))
            self.assertEqual(run("elf-arch", txt)[0], 1)

    def test_unzip_member(self):
        with tempfile.TemporaryDirectory() as d:
            z = os.path.join(d, "x.zip")
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("README.md", "readme")
                zf.writestr("geoip.dat", "geo")
                zf.writestr("xray", "BINARY")
            dest = os.path.join(d, "xray")
            nc.unzip_member(z, "xray", dest)
            with open(dest) as f:
                self.assertEqual(f.read(), "BINARY")
            with self.assertRaises(nc.ConfError):
                nc.unzip_member(z, "nope", dest)
            bad = os.path.join(d, "bad.zip")
            with open(bad, "w") as f:
                f.write("PK not a zip")
            with self.assertRaises(nc.ConfError):
                nc.unzip_member(bad, "xray", dest)


if __name__ == "__main__":
    unittest.main()
