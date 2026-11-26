#!/usr/bin/env python3
"""node_conf.py — правка конфигов ноды на месте: сайты selfsteal в nginx.conf и тома
в docker-compose.yml. Ручные правки файлов сохраняются: меняются только нужные директивы,
блоки server и строки томов, остальной текст (комментарии, отступы) не трогается.

Вызывает modules/node.sh; тесты — tests/test_node_conf.py. Только stdlib, Python ≥ 3.9.

  sites FILE                          сайты selfsteal: «имена через пробел<TAB>ssl_certificate»
  names FILE                          все server_name всех server (по строке)
  certs FILE                          пути ssl_certificate* из всех server (по строке)
  add FILE DOMAIN LINEAGE [--out F]   сайт DOMAIN — копия первого сайта с сертификатом LINEAGE
  del FILE DOMAIN [--out F]           убрать DOMAIN: имя из server_name или блок целиком
  compose-migrate FILE --out F        тома сертификатов → каталоги live/archive, nginx → nginx:alpine
  compose-xray FILE on|off --out F [--mount M]
  compose-xray FILE status            «on <источник>» | «off»
  compose-image FILE SERVICE          образ сервиса
  elf-arch FILE                       x86_64 | aarch64 | arm | i386 | ELF:<e_machine>
  unzip-member ZIP NAME DEST          извлечь из zip файл с basename NAME

Сайт selfsteal — server с listen … ssl и без default_server (блок reject неизвестных SNI
и редирект :80 не сайты). compose-* печатают «changed» или «same».
Коды выхода: 0 — готово; 1 — ошибка или конфиг не распознан; 3 — домен уже есть (add)
или не найден (del); 5 — последний домен ноды (del).
"""
import argparse
import posixpath
import re
import struct
import sys
import zipfile

SSL_ROOT = "/etc/nginx/ssl"
LE_LIVE = "/etc/letsencrypt/live"
LE_ARCHIVE = "/etc/letsencrypt/archive"
NGINX_IMAGE = "nginx:alpine"
XRAY_MOUNT = "/opt/xray-core/xray:/usr/local/bin/xray:ro"
XRAY_TARGET = "/usr/local/bin/xray"
CERT_DIRECTIVES = ("ssl_certificate", "ssl_certificate_key", "ssl_trusted_certificate")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$")
LINEAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
EXIT_EXISTS = 3
EXIT_LAST = 5


class ConfError(Exception):
    """Конфиг не разобрался или правка невозможна (rc 1)."""

    code = 1


class DomainError(ConfError):
    def __init__(self, msg, code):
        super().__init__(msg)
        self.code = code


# ── nginx: токенизатор и дерево со смещениями ──────────────────────────

class Tok:
    __slots__ = ("kind", "value", "start", "end")

    def __init__(self, kind, value, start, end):
        self.kind, self.value, self.start, self.end = kind, value, start, end


class Node:
    """Директива: name/args — токены; end — сразу за «;» или «}»; children — None у простой."""

    __slots__ = ("name", "args", "end", "children")

    def __init__(self, name, args, end, children=None):
        self.name, self.args, self.end, self.children = name, args, end, children

    @property
    def start(self):
        return self.name.start

    @property
    def key(self):
        return self.name.value

    def values(self):
        return [a.value for a in self.args]


def tokenize(text):
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "#":
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c in ";{}":
            yield Tok(c, c, i, i + 1)
            i += 1
        elif c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            if j >= n:
                raise ConfError("незакрытая кавычка (смещение %d)" % i)
            yield Tok("w", "".join(buf), i, j + 1)
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in ";{}":
                if text[j] == "$" and j + 1 < n and text[j + 1] == "{":   # ${var}
                    k = text.find("}", j)
                    j = n if k < 0 else k + 1
                    continue
                if text[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                j += 1
            yield Tok("w", text[i:j], i, j)
            i = j


def parse(text):
    toks = list(tokenize(text))
    pos = 0

    def block(depth):
        nonlocal pos
        nodes = []
        while pos < len(toks):
            t = toks[pos]
            if t.kind == "}":
                if depth == 0:
                    raise ConfError("лишняя «}» (смещение %d)" % t.start)
                return nodes, t
            if t.kind != "w":
                raise ConfError("«%s» без директивы (смещение %d)" % (t.kind, t.start))
            pos += 1
            args = []
            while pos < len(toks) and toks[pos].kind == "w":
                args.append(toks[pos])
                pos += 1
            if pos >= len(toks):
                raise ConfError("директива «%s» без «;»" % t.value)
            t2 = toks[pos]
            if t2.kind == ";":
                nodes.append(Node(t, args, t2.end))
                pos += 1
            elif t2.kind == "{":
                pos += 1
                children, close = block(depth + 1)
                if close is None:
                    raise ConfError("незакрытый блок «%s»" % t.value)
                pos += 1
                nodes.append(Node(t, args, close.end, children))
            else:
                raise ConfError("директива «%s» без «;»" % t.value)
        return nodes, None

    nodes, _ = block(0)
    return nodes


def servers(nodes):
    """server верхнего уровня (файл из conf.d) и внутри http (целый nginx.conf); stream — нет."""
    out = []
    for nd in nodes:
        if nd.children is None:
            continue
        if nd.key == "server":
            out.append(nd)
        elif nd.key == "http":
            out.extend(servers(nd.children))
    return out


def is_site(srv):
    listens = [c for c in srv.children if c.key == "listen"]
    if not listens:
        return False
    ssl = False
    for ln in listens:
        vals = ln.values()
        if "default_server" in vals or "default" in vals:
            return False
        ssl = ssl or "ssl" in vals
    return ssl


def server_names(srv):
    return [a.value for c in srv.children if c.key == "server_name" for a in c.args]


def sites(text):
    return [s for s in servers(parse(text)) if is_site(s)]


# ── nginx: правки по смещениям ─────────────────────────────────────────

def _line_start(text, pos):
    ls = text.rfind("\n", 0, pos) + 1
    return ls if text[ls:pos].strip() == "" else pos


def _line_span(text, start, end):
    """[start, end) расширяется до целых строк, если на них нет ничего, кроме пробелов."""
    ls = text.rfind("\n", 0, start) + 1
    le = text.find("\n", end)
    le = len(text) if le < 0 else le
    if text[ls:start].strip() == "" and text[end:le].strip() == "":
        return ls, min(le + 1, len(text))
    return start, end


def _indent_of(text, node, default="    "):
    ls = text.rfind("\n", 0, node.start) + 1
    ws = text[ls:node.start]
    return ws if ws.strip() == "" else default


def _apply(text, repl):
    for s, e, new in sorted(repl, key=lambda r: (r[0], r[1]), reverse=True):
        text = text[:s] + new + text[e:]
    return text


def _quoted_like(raw, value):
    q = raw[0] if raw and raw[0] in "\"'" else ""
    return q + value + q


def _check_domain(domain):
    if not DOMAIN_RE.match(domain):
        raise ConfError("это не доменное имя: %r" % domain)
    return domain.lower()


def add_site(text, domain, lineage, ssl_root=SSL_ROOT):
    domain = _check_domain(domain)
    if not LINEAGE_RE.match(lineage):
        raise ConfError("плохое имя каталога сертификата: %r" % lineage)
    nodes = parse(text)
    srvs = servers(nodes)
    st = [s for s in srvs if is_site(s)]
    if not st:
        raise ConfError("в nginx.conf нет сайта selfsteal (server с listen … ssl без default_server)")
    for s in srvs:
        if domain in (n.lower() for n in server_names(s)):
            raise DomainError("%s уже есть в nginx.conf" % domain, EXIT_EXISTS)

    tpl, last = st[0], st[-1]
    off = _line_start(text, tpl.start)
    block = text[off:tpl.end]
    repl, inserts = [], []
    ind = _indent_of(text, tpl.children[0]) if tpl.children else "    "

    sn = [c for c in tpl.children if c.key == "server_name"]
    if sn and sn[0].args:
        repl.append((sn[0].args[0].start - off, sn[0].args[-1].end - off, domain))
    elif sn:   # «server_name;» без имён
        repl.append((sn[0].name.end - off, sn[0].name.end - off, " " + domain))
    else:
        inserts.append("server_name %s;" % domain)
    for extra in sn[1:]:
        s, e = _line_span(text, extra.start, extra.end)
        repl.append((s - off, e - off, ""))

    have = set()
    for c in tpl.children:
        if c.key in CERT_DIRECTIVES and c.args:
            a = c.args[0]
            raw = text[a.start:a.end]
            path = "%s/%s/%s" % (ssl_root, lineage, posixpath.basename(a.value))
            repl.append((a.start - off, a.end - off, _quoted_like(raw, path)))
            have.add(c.key)
    for key, fname in (("ssl_certificate", "fullchain.pem"), ("ssl_certificate_key", "privkey.pem")):
        if key not in have:
            inserts.append('%s "%s/%s/%s";' % (key, ssl_root, lineage, fname))

    if inserts:
        # сразу за «{» блока server
        lb = text.find("{", tpl.name.end) + 1
        repl.append((lb - off, lb - off, "".join("\n" + ind + s for s in inserts)))
    new_block = _apply(block, repl)
    return text[:last.end] + "\n\n" + new_block + text[last.end:]


def del_site(text, domain):
    domain = _check_domain(domain)
    st = sites(text)
    hit = [s for s in st if domain in (n.lower() for n in server_names(s))]
    if not hit:
        raise DomainError("%s нет среди сайтов nginx.conf" % domain, EXIT_EXISTS)
    total = sum(len(server_names(s)) for s in st)
    if total <= 1:
        raise DomainError("%s — последний домен ноды, удалять нельзя" % domain, EXIT_LAST)
    srv = hit[0]
    if len(server_names(srv)) > 1:
        repl = []
        for d in (c for c in srv.children if c.key == "server_name"):
            keep = [a for a in d.args if a.value.lower() != domain]
            if len(keep) == len(d.args):
                continue
            if keep:
                repl.append((d.args[0].start, d.args[-1].end, " ".join(text[a.start:a.end] for a in keep)))
            else:
                s, e = _line_span(text, d.start, d.end)
                repl.append((s, e, ""))
        return _apply(text, repl)
    s, e = _line_span(text, _line_start(text, srv.start), srv.end)
    # пустая строка-разделитель перед блоком уходит вместе с ним
    if s >= 2 and text[s - 2:s] == "\n\n":
        s -= 1
    return text[:s] + text[e:]


def cert_paths(text):
    out = []

    def walk(nodes):
        for nd in nodes:
            if nd.key in CERT_DIRECTIVES and nd.args and nd.args[0].value not in out:
                out.append(nd.args[0].value)
            if nd.children is not None and nd.key in ("http", "server"):
                walk(nd.children)

    walk(parse(text))
    return out


# ── docker-compose.yml: построчно, без PyYAML ──────────────────────────

def _ind(line):
    return len(line) - len(line.lstrip(" "))


def _blank(line):
    s = line.strip()
    return not s or s.startswith("#")


def _unq(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _service_range(lines, service):
    si = next((i for i, ln in enumerate(lines) if re.match(r"^services:\s*(#.*)?$", ln.rstrip("\n"))), None)
    if si is None:
        raise ConfError("в docker-compose.yml нет services:")
    end = next((i for i in range(si + 1, len(lines)) if not _blank(lines[i]) and _ind(lines[i]) == 0), len(lines))
    sind = next((_ind(lines[i]) for i in range(si + 1, end) if not _blank(lines[i])), None)
    pat = re.compile(r"^\s*[\"']?" + re.escape(service) + r"[\"']?:\s*(#.*)?$")
    for i in range(si + 1, end):
        if _blank(lines[i]) or _ind(lines[i]) != sind or not pat.match(lines[i].rstrip("\n")):
            continue
        j = i + 1
        while j < end and (_blank(lines[j]) or _ind(lines[j]) > sind):
            j += 1
        while j > i + 1 and _blank(lines[j - 1]):
            j -= 1
        return i, j
    return None


def _key_indent(lines, rng):
    return next((_ind(lines[i]) for i in range(rng[0] + 1, rng[1]) if not _blank(lines[i])), None)


def _volumes(lines, rng):
    """→ (строка volumes:, [(начало, конец, источник, цель)], отступ элементов) или None."""
    kind = _key_indent(lines, rng)
    for v in range(rng[0] + 1, rng[1]):
        ln = lines[v].rstrip("\n")
        if _blank(ln) or _ind(ln) != kind:
            continue
        m = re.match(r"^\s*volumes:\s*(.*)$", ln)
        if not m:
            continue
        rest = m.group(1).strip()
        if rest and not rest.startswith("#"):
            raise ConfError("volumes в строку (%s) не поддерживается — нужен список «- …»" % rest)
        items, iind, j = [], None, v + 1
        while j < rng[1]:
            ln2 = lines[j]
            if _blank(ln2):
                j += 1
                continue
            s = ln2.strip()
            if iind is None and s.startswith("-") and _ind(ln2) >= kind:
                iind = _ind(ln2)
            if iind is None or _ind(ln2) < iind or (_ind(ln2) == iind and not s.startswith("-")):
                break
            if _ind(ln2) == iind:
                items.append([j, j + 1])
            else:
                items[-1][1] = j + 1
            j += 1
        out = []
        for s, e in items:
            first = lines[s].strip()[1:].strip()
            src = dst = ""
            if re.match(r"^[A-Za-z_]+:(\s|$)", first):
                # длинная форма: «- type: bind» + source/target (именованный том «data:/x» — короткая)
                for k in range(s, e):
                    mm = re.match(r"^\s*-?\s*(source|target):\s*(.+?)\s*$", lines[k].rstrip("\n"))
                    if mm:
                        if mm.group(1) == "source":
                            src = _unq(mm.group(2))
                        else:
                            dst = _unq(mm.group(2))
            else:
                parts = _unq(first.split(" #")[0]).split(":")
                src = parts[0]
                dst = parts[1] if len(parts) > 1 else parts[0]
            out.append((s, e, src, dst))
        return v, out, (iind if iind is not None else kind + 2)
    return None


def _need_service(lines, service):
    rng = _service_range(lines, service)
    if rng is None:
        raise ConfError("в docker-compose.yml нет сервиса %s" % service)
    return rng


def compose_image(text, service):
    lines = text.splitlines(keepends=True)
    rng = _need_service(lines, service)
    kind = _key_indent(lines, rng)
    for i in range(rng[0] + 1, rng[1]):
        m = re.match(r"^\s*image:\s*(.+?)\s*(#.*)?$", lines[i].rstrip("\n"))
        if m and _ind(lines[i]) == kind:
            return _unq(m.group(1))
    raise ConfError("у сервиса %s нет image" % service)


def compose_migrate(text, live=LE_LIVE, archive=LE_ARCHIVE, image=NGINX_IMAGE):
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    rng = _need_service(lines, "remnawave-nginx")
    kind = _key_indent(lines, rng)
    out = list(lines)

    for i in range(rng[0] + 1, rng[1]):
        ln = lines[i].rstrip("\n")
        m = re.match(r"^(\s*image:\s*)([\"']?)((?:docker\.io/)?(?:library/)?nginx(?::[^\s\"'#]*)?)\2(\s*(#.*)?)$", ln)
        if m and _ind(ln) == kind and m.group(3) != image:
            out[i] = "%s%s%s\n" % (m.group(1), image, m.group(4))

    vol = _volumes(lines, rng)
    if vol is None:
        raise ConfError("у remnawave-nginx нет volumes")
    _, items, iind = vol
    drop, at = set(), None
    has = {"/etc/nginx/ssl": False, "/etc/nginx/archive": False}
    want = {"/etc/nginx/ssl": live, "/etc/nginx/archive": archive}
    for s, e, src, dst in items:
        d = dst.rstrip("/")
        if d in want:
            if src.rstrip("/") != want[d]:
                raise ConfError("на %s уже смонтирован %s — убери том вручную" % (d, src))
            has[d] = True
        elif d.startswith("/etc/nginx/ssl/") or d.startswith("/etc/nginx/archive/"):
            if not src.startswith(live + "/"):
                raise ConfError("том %s:%s мешает каталогу сертификатов — убери его вручную" % (src, dst))
            drop.update(range(s, e))
            at = s if at is None else at
    add = ["%s- %s:%s:ro\n" % (" " * iind, want[d], d) for d in ("/etc/nginx/ssl", "/etc/nginx/archive") if not has[d]]
    if at is None:
        at = items[-1][1] if items else vol[0] + 1
    res = []
    for i, ln in enumerate(out):
        if i == at:
            res.extend(add)
        if i not in drop:
            res.append(ln)
    if at >= len(out):
        res.extend(add)
    return "".join(res)


def compose_xray(text, mode, mount=XRAY_MOUNT):
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    rng = _need_service(lines, "remnanode")
    vol = _volumes(lines, rng)
    target = mount.split(":")[1]
    hits = [it for it in (vol[1] if vol else []) if it[3].rstrip("/") == target]
    if mode == "status":
        return ("on %s" % hits[0][2]) if hits else "off"
    if mode == "off":
        if not hits:
            return text
        drop = {i for s, e, _, _ in hits for i in range(s, e)}
        if len(hits) == len(vol[1]):    # пустой volumes: compose не примет — убираем ключ
            drop.add(vol[0])
        return "".join(ln for i, ln in enumerate(lines) if i not in drop)
    # on
    if vol is None:
        kind = _key_indent(lines, rng)
        ins = "%svolumes:\n%s- %s\n" % (" " * kind, " " * (kind + 2), mount)
        return "".join(lines[:rng[1]]) + ins + "".join(lines[rng[1]:])
    line = "%s- %s\n" % (" " * vol[2], mount)
    if hits:
        s, e = hits[0][0], hits[0][1]
        if e - s == 1 and lines[s] == line:
            return "".join(lines)
        return "".join(lines[:s]) + line + "".join(lines[e:])
    at = vol[1][-1][1] if vol[1] else vol[0] + 1
    return "".join(lines[:at]) + line + "".join(lines[at:])


# ── бинарь ядра ────────────────────────────────────────────────────────

ELF_MACHINES = {62: "x86_64", 183: "aarch64", 40: "arm", 3: "i386", 243: "riscv64"}


def elf_arch(path):
    with open(path, "rb") as f:
        h = f.read(20)
    if len(h) < 20 or h[:4] != b"\x7fELF":
        return None
    m = struct.unpack(("<" if h[5] == 1 else ">") + "H", h[18:20])[0]
    return ELF_MACHINES.get(m, "ELF:%d" % m)


def unzip_member(zpath, name, dest):
    try:
        with zipfile.ZipFile(zpath) as z:
            cand = [i for i in z.infolist() if not i.is_dir() and posixpath.basename(i.filename) == name]
            if not cand:
                raise ConfError("в архиве нет файла %s" % name)
            cand.sort(key=lambda i: i.filename.count("/"))
            with z.open(cand[0]) as src, open(dest, "wb") as dst:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    dst.write(chunk)
    except zipfile.BadZipFile as e:
        raise ConfError("битый zip: %s" % e)


# ── CLI ────────────────────────────────────────────────────────────────

def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _emit(text, out):
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="node_conf.py")
    sp = ap.add_subparsers(dest="cmd", required=True)
    for c in ("sites", "names", "certs"):
        sp.add_parser(c).add_argument("file")
    p = sp.add_parser("add")
    p.add_argument("file")
    p.add_argument("domain")
    p.add_argument("lineage")
    p.add_argument("--out")
    p.add_argument("--ssl-root", default=SSL_ROOT)
    p = sp.add_parser("del")
    p.add_argument("file")
    p.add_argument("domain")
    p.add_argument("--out")
    p = sp.add_parser("compose-migrate")
    p.add_argument("file")
    p.add_argument("--out", required=True)
    p.add_argument("--live", default=LE_LIVE)
    p.add_argument("--archive", default=LE_ARCHIVE)
    p.add_argument("--image", default=NGINX_IMAGE)
    p = sp.add_parser("compose-xray")
    p.add_argument("file")
    p.add_argument("mode", choices=("on", "off", "status"))
    p.add_argument("--out")
    p.add_argument("--mount", default=XRAY_MOUNT)
    p = sp.add_parser("compose-image")
    p.add_argument("file")
    p.add_argument("service")
    sp.add_parser("elf-arch").add_argument("file")
    p = sp.add_parser("unzip-member")
    p.add_argument("zip")
    p.add_argument("name")
    p.add_argument("dest")
    a = ap.parse_args(argv)

    try:
        if a.cmd == "sites":
            st = sites(_read(a.file))
            for s in st:
                cert = next((c.args[0].value for c in s.children if c.key == "ssl_certificate" and c.args), "-")
                print("%s\t%s" % (" ".join(server_names(s)) or "-", cert))
            return 0 if st else 1
        if a.cmd == "names":
            for s in servers(parse(_read(a.file))):
                for n in server_names(s):
                    print(n)
            return 0
        if a.cmd == "certs":
            for p_ in cert_paths(_read(a.file)):
                print(p_)
            return 0
        if a.cmd == "add":
            _emit(add_site(_read(a.file), a.domain, a.lineage, a.ssl_root), a.out)
            return 0
        if a.cmd == "del":
            _emit(del_site(_read(a.file), a.domain), a.out)
            return 0
        if a.cmd in ("compose-migrate", "compose-xray"):
            src = _read(a.file)
            if a.cmd == "compose-migrate":
                res = compose_migrate(src, a.live.rstrip("/"), a.archive.rstrip("/"), a.image)
            elif a.mode == "status":
                print(compose_xray(src, "status", a.mount))
                return 0
            else:
                if not a.out:
                    ap.error("compose-xray on|off: нужен --out")
                res = compose_xray(src, a.mode, a.mount)
            _emit(res, a.out)
            print("changed" if res != src else "same")
            return 0
        if a.cmd == "compose-image":
            print(compose_image(_read(a.file), a.service))
            return 0
        if a.cmd == "elf-arch":
            arch = elf_arch(a.file)
            if arch is None:
                print("node_conf: %s — не ELF-бинарь" % a.file, file=sys.stderr)
                return 1
            print(arch)
            return 0
        if a.cmd == "unzip-member":
            unzip_member(a.zip, a.name, a.dest)
            return 0
    except ConfError as e:
        print("node_conf: %s" % e, file=sys.stderr)
        return e.code
    except OSError as e:
        print("node_conf: %s" % e, file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
