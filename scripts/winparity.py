#!/usr/bin/env python3
"""OSyx Win Parity Check.

Measures how much of the Windows API OSyx's Win32 layer (compatibility/win32)
implements, against a fixed reference dataset of real Windows DLL export
tables, and how much of that is backed by executed tests.

Sources of evidence (nothing is invented; every number says where it is from):

* reference  - export tables of real Windows DLLs, read from the PE files of a
               Windows installation by `winparity.py reference` and committed in
               compatibility/win32/parity/reference (x64 from System32, x86 from
               SysWOW64). The Windows build is recorded in MANIFEST.json.
* osyx       - the built-in DLL export tables, found by reading the Rust sources
               of compatibility/win32/src (loader.rs `builtins()` and the
               `exports()` functions). Optionally cross-checked against the
               compiled tables (`WIN_EXPORT` lines of `winrun --capabilities`).
* class      - a static classification of each exported function body:
               implemented, partial, stub_success (fake success), stub_empty,
               unsupported (explicit error), placeholder, or unknown.
               This is a heuristic over source text, not a proof of behaviour.
* wow64      - 32-bit coverage: exports that have a bridge signature in
               compatibility/win32/src/wow64/sigs.rs, against SysWOW64 exports.
* behaviour  - only from executed tests: a serial log of scripts/win-test.ps1
               (programs that ran and passed, and `ok` check lines naming an API).
               Without a log behaviour is reported as "not measured".
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import hashlib
import html
import json
import os
import re
import struct
import subprocess
import sys
from collections import Counter, OrderedDict

SCHEMA = 1
REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
WIN32 = os.path.join("compatibility", "win32")
DEFAULT_REFERENCE = os.path.join(WIN32, "parity", "reference")
DEFAULT_PROFILES = os.path.join(WIN32, "parity", "profiles.json")
DEFAULT_OUT = os.path.join("build", "winparity")
DEFAULT_TEST_LOG = os.path.join("build", "test", "win.serial.log")

# Implementation classes, weakest first. `rank` orders them for regressions.
CLASSES = ["missing", "placeholder", "stub_empty", "stub_success", "unsupported", "partial", "implemented", "unknown"]
RANK = {"missing": 0, "placeholder": 1, "stub_empty": 1, "stub_success": 1, "unsupported": 1, "partial": 2, "implemented": 3}
REAL = ("implemented", "partial")
STUBS = ("stub_success", "stub_empty", "placeholder")


# --------------------------------------------------------------------------
# PE reading
# --------------------------------------------------------------------------

class PE:
    """Minimal PE32/PE32+ reader: exports, imports, delay imports, version."""

    def __init__(self, data: bytes):
        if data[:2] != b"MZ":
            raise ValueError("not an MZ file")
        self.d = data
        self.pe = self.u32(0x3C)
        if data[self.pe:self.pe + 4] != b"PE\0\0":
            raise ValueError("no PE signature")
        self.machine = self.u16(self.pe + 4)
        nsec = self.u16(self.pe + 6)
        optsize = self.u16(self.pe + 20)
        self.opt = self.pe + 24
        self.plus = self.u16(self.opt) == 0x20B
        self.image_base = struct.unpack_from("<Q", data, self.opt + 24)[0] if self.plus else self.u32(self.opt + 28)
        self.dd = self.opt + (112 if self.plus else 96)
        self.ndd = self.u32(self.dd - 4)
        st = self.opt + optsize
        self.sections = []
        for i in range(nsec):
            o = st + 40 * i
            vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((va, max(vsize, rawsize), raw, rawsize))

    @property
    def arch(self) -> str:
        return {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(self.machine, hex(self.machine))

    def u16(self, o): return struct.unpack_from("<H", self.d, o)[0]
    def u32(self, o): return struct.unpack_from("<I", self.d, o)[0]

    def dir(self, i):
        if i >= self.ndd:
            return 0, 0
        return struct.unpack_from("<II", self.d, self.dd + 8 * i)

    def off(self, rva):
        for va, size, raw, rawsize in self.sections:
            if va <= rva < va + size:
                return raw + rva - va
        return None

    def cstr(self, rva):
        o = self.off(rva)
        if o is None:
            return ""
        return self.d[o:self.d.index(b"\0", o)].decode("latin1")

    def exports(self):
        """(named, ordinal_only, forwarders): sorted names, ordinals, name->target."""
        rva, size = self.dir(0)
        if not rva:
            return [], [], {}
        o = self.off(rva)
        base, nfun, nnames, fun, names, ords = struct.unpack_from("<IIIIII", self.d, o + 16)[0:6]
        # fields: Base, NumberOfFunctions, NumberOfNames, AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals
        fo, no, oo = self.off(fun), self.off(names), self.off(ords)
        named, fwd, used = [], {}, set()
        for i in range(nnames):
            name = self.cstr(struct.unpack_from("<I", self.d, no + 4 * i)[0])
            idx = struct.unpack_from("<H", self.d, oo + 2 * i)[0]
            used.add(idx)
            frva = struct.unpack_from("<I", self.d, fo + 4 * idx)[0]
            named.append(name)
            if rva <= frva < rva + size:
                fwd[name] = self.cstr(frva)
        only = []
        for idx in range(nfun):
            if idx not in used and struct.unpack_from("<I", self.d, fo + 4 * idx)[0]:
                only.append(base + idx)
        return sorted(named), only, fwd

    def _thunks(self, rva):
        """Import names from a thunk array: names or '#ordinal'."""
        out, step = [], 8 if self.plus else 4
        o = self.off(rva)
        if o is None:
            return out
        high = 1 << (63 if self.plus else 31)
        while True:
            v = int.from_bytes(self.d[o:o + step], "little")
            if v == 0:
                return out
            if v & high:
                out.append("#%d" % (v & 0xFFFF))
            else:
                hn = self.off(v & 0x7FFFFFFF)
                out.append(self.cstr((v & 0x7FFFFFFF) + 2) if hn is not None else "?")
            o += step

    def imports(self, delay=False):
        """{dll_lowercase: [names]} of the (delay-)import table."""
        rva, _ = self.dir(13 if delay else 1)
        res = OrderedDict()
        if not rva:
            return res
        o = self.off(rva)
        if o is None:
            return res
        while True:
            if delay:
                attrs, name, _mod, _iat, int_ = struct.unpack_from("<IIIII", self.d, o)[0:5]
                if not name:
                    return res
                fix = 0 if attrs & 1 else self.image_base
                dll = self.cstr(name - fix).lower()
                names = self._thunks(int_ - fix) if int_ else []
                o += 32
            else:
                ilt, _ts, _fw, name, iat = struct.unpack_from("<IIIII", self.d, o)
                if not name:
                    return res
                dll = self.cstr(name).lower()
                names = self._thunks(ilt or iat)
                o += 20
            res.setdefault(dll, []).extend(names)

    def file_version(self):
        """VS_FIXEDFILEINFO of the RT_VERSION resource as a dotted string."""
        rva, _ = self.dir(2)
        if not rva:
            return None
        base = self.off(rva)
        if base is None:
            return None

        def entries(rel):
            n = self.u16(base + rel + 12) + self.u16(base + rel + 14)
            return [struct.unpack_from("<II", self.d, base + rel + 16 + 8 * i) for i in range(n)]

        try:
            e = next((v for i, v in entries(0) if i == 16), None)
            if e is None:
                return None
            e = entries(e & 0x7FFFFFFF)[0][1]
            e = entries(e & 0x7FFFFFFF)[0][1]
            drva, dsize = struct.unpack_from("<II", self.d, base + e)
            o = self.off(drva)
            blob = self.d[o:o + dsize]
            k = blob.find(b"\xbd\x04\xef\xfe")
            if k < 0:
                return None
            ms, ls = struct.unpack_from("<II", blob, k + 8)
            return "%d.%d.%d.%d" % (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
        except (IndexError, ValueError, struct.error):
            return None


# --------------------------------------------------------------------------
# Rust source scanning
# --------------------------------------------------------------------------

def mask_rust(src: str):
    """Returns (nocomment, masked): same length as `src`. `nocomment` blanks
    comments; `masked` blanks comments and the inside of string/char
    literals, so brace and token matching ignores them."""
    n = len(src)
    a = list(src)
    b = list(src)
    i = 0

    def blank(lst, lo, hi):
        for k in range(lo, hi):
            if lst[k] not in "\r\n":
                lst[k] = " "

    while i < n:
        c = src[i]
        if c == "/" and src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            blank(a, i, j); blank(b, i, j)
            i = j
        elif c == "/" and src.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith("/*", j):
                    depth += 1; j += 2
                elif src.startswith("*/", j):
                    depth -= 1; j += 2
                else:
                    j += 1
            blank(a, i, j); blank(b, i, j)
            i = j
        elif c == "r" and re.match(r'r#*"', src[i:i + 8]) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")):
            m = re.match(r'r(#*)"', src[i:])
            close = '"' + m.group(1)
            j = src.find(close, i + len(m.group(0)))
            j = n if j < 0 else j + len(close)
            blank(b, i + len(m.group(0)), max(i + len(m.group(0)), j - len(close)))
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            blank(b, i + 1, min(j, n))
            i = j + 1
        elif c == "'":
            m = re.match(r"'(\\.[^']*|[^\\'])'", src[i:i + 12])
            if m:
                blank(b, i + 1, i + len(m.group(0)) - 1)
                i += len(m.group(0))
            else:
                i += 1  # a lifetime
        else:
            i += 1
    return "".join(a), "".join(b)


def match_close(masked: str, i: int, open_c: str, close_c: str) -> int:
    """Index just after the bracket matching masked[i] (== open_c)."""
    depth = 0
    for j in range(i, len(masked)):
        ch = masked[j]
        if ch == open_c:
            depth += 1
        elif ch == close_c:
            depth -= 1
            if depth == 0:
                return j + 1
    return -1


def split_top(text: str, sep=","):
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{<" and ch != "<":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


FN_RE = re.compile(r'(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?extern\s+"win64"\s+fn\s+(\w+)\s*\(')

SUCCESS_CONST = {"TRUE", "1", "1i32", "1u32", "1u64", "1usize", "S_OK", "STATUS_SUCCESS", "ERROR_SUCCESS", "true", "Ok(())"}
EMPTY_CONST = {"FALSE", "0", "0i32", "0u32", "0u64", "0usize", "0u16", "0u8", "false", "()", "", "None", "core::ptr::null()", "core::ptr::null_mut()"}
UNSUPPORTED_ERR = ("ERROR_CALL_NOT_IMPLEMENTED", "ERROR_NOT_SUPPORTED", "STATUS_NOT_IMPLEMENTED", "STATUS_NOT_SUPPORTED", "ERROR_PROC_NOT_FOUND")
SETTER_RE = re.compile(r"^(?:let\s+_\w*\s*=.*|_\s*=.*|SetLastError\s*\(.*\)|set_error\s*\(.*\)|diag\s*\(.*\))$", re.S)
PARTIAL_MARKERS = ("ERROR_NOT_SUPPORTED", "ERROR_CALL_NOT_IMPLEMENTED", "STATUS_NOT_IMPLEMENTED", "STATUS_NOT_SUPPORTED",
                   "not supported", "unsupported", "not implemented", "TODO", "FIXME", "stub", "not yet")


class RustFn:
    __slots__ = ("name", "file", "params", "body", "raw", "cls", "reason", "wow64")

    def __init__(self, name, file, params, body, raw):
        self.name, self.file, self.params, self.body, self.raw = name, file, params, body, raw
        self.cls, self.reason = None, ""
        self.wow64 = "wow64::is_active" in body


def expand_macros(src: str):
    """Source of the functions `macro_rules!` repetitions generate in `src`.

    Handles the shape this tree uses: one rule `($($a:ident = $b:ident;)*) =>
    {$( extern "win64" fn $a(..) {..} )*}` invoked as `name! { x = y; ... }`.
    Each invocation entry is matched against the rule's pattern and the
    template is instantiated with its values, so the generated functions are
    classified like hand-written ones."""
    nocomment, masked = mask_rust(src)
    out = []
    for mm in re.finditer(r"macro_rules!\s+(\w+)\s*\{", masked):
        name = mm.group(1)
        bo = masked.find("{", mm.start())
        bc = match_close(masked, bo, "{", "}")
        if bc < 0:
            continue
        rule = nocomment[bo + 1:bc - 1]
        r = re.search(r"\(\s*\$\((.*?)\)\*\s*\)\s*=>\s*\{\s*\$\((.*)\)\*\s*\}", rule, re.S)
        if not r or 'extern "win64" fn' not in r.group(2):
            continue
        pattern, template = r.group(1), r.group(2)
        names = re.findall(r"\$(\w+):\w+", pattern)
        literals = re.split(r"\$\w+:\w+", pattern)
        rx = "(.+?)".join(r"\s*".join(re.escape(t) for t in lit.split()) for lit in literals)
        rx = r"\s*" + rx
        for inv in re.finditer(r"\b%s!\s*\{" % re.escape(name), masked):
            io = masked.find("{", inv.start())
            ic = match_close(masked, io, "{", "}")
            if ic < 0:
                continue
            for entry in re.finditer(rx, nocomment[io + 1:ic - 1], re.S):
                text = template
                for var, val in sorted(zip(names, entry.groups()), key=lambda p: -len(p[0])):
                    text = text.replace("$" + var, val.strip())
                out.append(text)
    return "\n".join(out)


def parse_win64_fns(path: str, src: str):
    nocomment, masked = mask_rust(src)
    fns = []
    for m in FN_RE.finditer(nocomment):
        po = m.end() - 1
        pc = match_close(masked, po, "(", ")")
        if pc < 0:
            continue
        bo = masked.find("{", pc)
        semi = masked.find(";", pc)
        if bo < 0 or (0 <= semi < bo):
            continue  # a declaration, not a definition
        bc = match_close(masked, bo, "{", "}")
        if bc < 0:
            continue
        params = []
        for p in split_top(masked[po + 1:pc - 1]):
            nm = p.split(":", 1)[0].strip().lstrip("mut ").strip()
            if nm:
                params.append(nm)
        fns.append(RustFn(m.group(1), path, params, masked[bo + 1:bc - 1], src[bo + 1:bc - 1]))
    return fns


def classify(fn: RustFn, index: dict, seen=None):
    """Static classification of an exported function body (see module doc)."""
    if fn.cls:
        return fn.cls
    seen = seen or set()
    if fn.name in seen:
        fn.cls, fn.reason = "unknown", "delegation cycle"
        return fn.cls
    seen = seen | {fn.name}
    body = re.sub(r"\s+", " ", fn.body).strip()
    raw = fn.raw
    if re.search(r"\b(unimplemented|todo)!\s*\(", body) or re.search(r"panic!\s*\(\s*\"[^\"]*not implemented", raw, re.I):
        fn.cls, fn.reason = "placeholder", "todo!/unimplemented!"
        return fn.cls
    stmts = [s.strip() for s in split_top(body, ";")]
    stmts = [s for s in stmts if s]
    last = re.sub(r"^return\s+", "", stmts[-1]).strip() if stmts else ""
    lead = stmts[:-1] if stmts else []
    inert = all(SETTER_RE.match(s) for s in lead)
    # Params that are only ignored or never named in the body.
    used = []
    probe = "; ".join(stmts)
    for p in fn.params:
        if p.startswith("_"):
            continue
        scrubbed = re.sub(r"let\s+_\w*\s*=\s*%s\b|_\s*=\s*%s\b" % (re.escape(p), re.escape(p)), "", probe)
        if re.search(r"\b%s\b" % re.escape(p), scrubbed):
            used.append(p)
    err = re.fullmatch(r"fail\s*\(\s*(\w+)\s*,.*\)", last, re.S)
    if err and err.group(1) in UNSUPPORTED_ERR and inert:
        fn.cls, fn.reason = "unsupported", "returns %s" % err.group(1)
        return fn.cls
    # `crate::kernel32::TRUE` is TRUE; a bare literal or constant name that
    # is the whole body, with the arguments ignored, is a constant answer.
    plain = re.sub(r"^(?:\w+::)+", "", last)
    sole = len(stmts) == 1 and re.fullmatch(r"[A-Za-z_]\w*|0[xX][0-9A-Fa-f_]+|\d[\d_]*(?:[ui]\d+|usize)?", plain)
    if sole and not used and fn.params and plain not in SUCCESS_CONST and plain not in EMPTY_CONST:
        error_name = re.match(r"(?:E_|OLE_E_|DV_E_|CLASS_E_|STG_E_|MMSYSERR_(?!NOERROR)|WAVERR_(?!NOERROR)|MIDIERR_(?!NOERROR)|STATUS_(?:NOT|INVALID|UNSUCC|ACCESS|BUFFER))|.*NOT_SUPPORTED|.*NOT_IMPL", plain)
        error_code = re.fullmatch(r"0[xX]8[0-9A-Fa-f_]{7}", plain.replace("_", ""))
        if error_name or error_code:
            fn.cls, fn.reason = "unsupported", "returns the error constant %s" % plain
        else:
            fn.cls, fn.reason = "stub_success", "returns constant %s; arguments unused" % plain
        return fn.cls
    if plain in SUCCESS_CONST or plain in EMPTY_CONST:
        last = plain
    if not stmts or (inert and (last in SUCCESS_CONST or last in EMPTY_CONST)):
        if used:
            pass  # the constant is returned but the arguments are used: look further
        elif last in SUCCESS_CONST:
            if fn.params or last in ("TRUE", "S_OK", "STATUS_SUCCESS", "Ok(())", "true"):
                fn.cls, fn.reason = "stub_success", "returns constant %s; arguments unused" % last if fn.params else "returns constant %s" % last
                return fn.cls
        else:
            fn.cls, fn.reason = "stub_empty", "returns constant %s without effect" % (last or "()")
            return fn.cls
    deleg = re.fullmatch(r"(?:return\s+)?(\w+)\s*\(.*\)", body.rstrip(";").strip(), re.S)
    if deleg and deleg.group(1) in index and deleg.group(1) != fn.name:
        target = index[deleg.group(1)]
        c = classify(target, index, seen)
        fn.cls, fn.reason = c, "delegates to %s" % target.name
        fn.wow64 = fn.wow64 or target.wow64
        return fn.cls
    low = fn.raw.lower()
    hits = [mk for mk in PARTIAL_MARKERS if (mk.lower() in low if mk[0].islower() else mk in fn.raw)]
    if hits:
        fn.cls, fn.reason = "partial", "mentions " + ", ".join(sorted(set(hits))[:3])
        return fn.cls
    fn.cls, fn.reason = "implemented", ""
    return fn.cls


# --------------------------------------------------------------------------
# OSyx export discovery
# --------------------------------------------------------------------------

class Osyx:
    """The built-in DLLs of compatibility/win32, as found in its sources."""

    def __init__(self, root: str):
        self.root = root
        self.src = os.path.join(root, WIN32, "src")
        self.files = {}      # path -> source
        self.modfiles = {}   # last module segment -> [paths]
        for p in sorted(glob.glob(os.path.join(self.src, "**", "*.rs"), recursive=True)):
            with open(p, encoding="utf-8", errors="replace") as f:
                self.files[p] = f.read()
            rel = os.path.relpath(p, self.src)[:-3].replace(os.sep, "/")
            parts = rel.split("/")
            if parts[-1] == "mod":
                parts = parts[:-1]
            self.modfiles.setdefault(parts[-1], []).append(p)
        self.fns = {}        # name -> [RustFn]
        for p, s in self.files.items():
            for fn in parse_win64_fns(p, s) + parse_win64_fns(p, expand_macros(s)):
                self.fns.setdefault(fn.name, []).append(fn)
        self._index_indirect()
        self.dlls = OrderedDict()      # dll -> {name: impl_ident}
        self.ordinals = {}             # dll -> [ordinals]
        self._parse_builtins()
        self.sigs, self.overrides = self._parse_wow64()

    def _index_indirect(self):
        """Implementations reached without a plain `extern "win64" fn NAME`:
        `xmm_abi!` shims (`name => name_soft [...]`: the real body is the _soft
        function), getter functions that return `Name as *const ()`, and
        routines in `global_asm!` declared through `#[link_name]`."""
        self.alias, self.getter, self.asm = {}, {}, {}
        labels = {}
        for path, src in self.files.items():
            for blk in re.finditer(r"xmm_abi!\s*\{(.*?)\n\}", src, re.S):
                for m in re.finditer(r"(\w+)\s*=>\s*(\w+)\s*\[", blk.group(1)):
                    self.alias[m.group(1)] = m.group(2)
            for m in re.finditer(r"\bfn\s+(\w+)\s*\(\s*\)\s*->\s*u64\s*\{\s*(?:crate::)?(?:\w+::)*(\w+)\s+as\s+\*const", src):
                self.getter[m.group(1)] = m.group(2)
            for g in re.finditer(r"global_asm!\((.*?)\n\);", src, re.S):
                text = g.group(1)
                for lm in re.finditer(r"^(\w+):\n(.*?)(?=^\.global|^\w+:\n|\Z)", text, re.S | re.M):
                    instr = [l for l in lm.group(2).split("\n") if l.strip() and not l.strip().startswith((".", "#", ";", "//"))]
                    labels[lm.group(1)] = len(instr)
            for m in re.finditer(r'#\[link_name\s*=\s*"(\w+)"\]\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)', src):
                self.asm[m.group(2)] = (m.group(1), path)
        self.asm = {n: (lab, p) for n, (lab, p) in self.asm.items() if labels.get(lab, 0) >= 3}
        self.labels = labels

    def pick(self, name: str, near: str = None):
        c = self.fns.get(name)
        if not c:
            for table, key in ((self.alias, name), (self.getter, name)):
                target = table.get(key)
                if target and target != name and self.fns.get(target):
                    return self.pick(target, near)
            if name in self.asm:
                label, path = self.asm[name]
                fn = RustFn(name, path, [], "", "")
                fn.cls, fn.reason = "implemented", "assembly routine %s (%d instructions)" % (label, self.labels[label])
                return fn
            return None
        if near:
            for fn in c:
                if fn.file == near:
                    return fn
        return c[0]

    def classify_all(self, allow=None):
        flat = {n: v[0] for n, v in self.fns.items()}
        self.allowlisted = []
        for lst in self.fns.values():
            for fn in lst:
                classify(fn, flat)
        for name, why in (allow or {}).items():
            for fn in self.fns.get(name, [])[:1]:
                if fn.cls in STUBS:
                    fn.cls, fn.reason = "implemented", "allowlisted constant: " + why
                    self.allowlisted.append({"name": name, "reason": why})

    def _candidates(self, mod, here):
        """Files of module `mod`, those nearest to `here` first (a child
        module directory, then the same directory)."""
        child = os.path.join(os.path.dirname(here), os.path.splitext(os.path.basename(here))[0])
        def near(p):
            d = os.path.dirname(p)
            return 0 if d == child else 1 if d == os.path.dirname(here) else 2
        return sorted(self.modfiles.get(mod, []), key=near)

    # -- exports() resolution
    def _fn_text(self, path: str, fname: str):
        src = self.files[path]
        nocomment, masked = mask_rust(src)
        m = re.search(r"\bfn\s+%s\s*\(" % re.escape(fname), masked)
        if not m:
            return None
        pc = match_close(masked, masked.find("(", m.start()), "(", ")")
        bo = masked.find("{", pc)
        bc = match_close(masked, bo, "{", "}")
        return nocomment[bo + 1:bc - 1]

    def resolve(self, text: str, here: str, depth=0, env=None):
        """{export name: impl ident} of an exports expression/body."""
        out = {}
        if depth > 8:
            return out
        for m in re.finditer(r"export_table!\s*\[(.*?)\]", text, re.S):
            for ident in re.findall(r"[A-Za-z_][\w:]*", m.group(1)):
                nm = ident.split("::")[-1]
                out[nm] = nm
        for m in re.finditer(r'\(\s*"(\w+)"\s*,\s*([\w:]+)\s+as\b', text):
            out[m.group(1)] = m.group(2).split("::")[-1]
        # ("Name", crate::m::getter()): exported, the function behind it is not visible.
        for m in re.finditer(r'\(\s*"(\w+)"\s*,\s*[\w:]+?(\w+)\s*\(\s*\)\s*\)', text):
            out.setdefault(m.group(1), m.group(2))
        # Named aliases in a loop, such as MSVCRT's decorated C++ operators.
        for m in re.finditer(r'for\s+(\w+)\s+in\s+\[([^\]]*)\]\s*\{\s*\w+\.push\(\(\s*\1\s*,\s*(\w+)\s*\)\)\s*;\s*\}', text, re.S):
            for name in re.findall(r'"([^"\\]+)"', m.group(2)):
                out[name] = m.group(3)
        for m in re.finditer(r"(?:crate::)?(?:(\w+)::)?(\w*exports\w*)\s*\(\s*\)", text):
            mod, fname = m.group(1), m.group(2)
            if fname == "exports" and mod is None and here is None:
                continue
            paths = self._candidates(mod, here) if mod else [here]
            for p in paths:
                body = self._fn_text(p, fname) if p else None
                if body is not None and not (p == here and body is text):
                    out.update(self.resolve(body, p, depth + 1))
                    break
        for m in re.finditer(r"\b(\w+)\.clone\(\)", text):
            if env and m.group(1) in env:
                out.update(self.resolve(env[m.group(1)], here, depth + 1, env))
        return out

    def _ordinals(self, text: str):
        out = []
        for m in re.finditer(r"(?:crate::)?(\w+)::(\w*ordinals\w*)\s*\(\s*\)", text):
            for p in self.modfiles.get(m.group(1), []):
                body = self._fn_text(p, m.group(2))
                if body:
                    out += [int(x) for x in re.findall(r"\(\s*(\d+)\s*,", body)]
                    break
        return sorted(set(out))

    def _parse_builtins(self):
        loader = os.path.join(self.src, "loader.rs")
        text = self.files[loader]
        nocomment, masked = mask_rust(text)
        m = re.search(r"\bfn\s+builtins\s*\(", masked)
        bo = masked.find("{", m.start())
        bc = match_close(masked, bo, "{", "}")
        body = nocomment[bo + 1:bc - 1]
        env = {}
        for lm in re.finditer(r"let\s+(\w+)\s*=\s*(.*?);", body, re.S):
            env[lm.group(1)] = lm.group(2)
        for cm in re.finditer(r"\bbuiltin\s*\(", body):
            po = cm.end() - 1
            pc = match_close(body, po, "(", ")")
            args = split_top(body[po + 1:pc - 1])
            if len(args) < 2:
                continue
            nm = re.fullmatch(r'\s*"([\w.\-]+)"\s*', args[0])
            if not nm:
                continue
            dll = nm.group(1).lower()
            exp = self.resolve(args[1], loader, env=env)
            bare = args[1].strip()
            if bare in env:
                exp.update(self.resolve(env[bare], loader, env=env))
            for v in re.findall(r"\b(\w+)\.clone\(\)", args[1]):
                if v in env:
                    exp.update(self.resolve(env[v], loader, env=env))
            self.dlls[dll] = exp
            self.ordinals[dll] = self._ordinals(args[2]) if len(args) > 2 else []

    def _parse_wow64(self):
        sigs, over = {}, set()
        p = os.path.join(self.src, "wow64", "sigs.rs")
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as fh:
                nocomment, _ = mask_rust(fh.read())
            for m in re.finditer(r"\b(cdecl_sig|sig)!\s*\(\s*(\w+)\s*,", nocomment):
                sigs[m.group(2)] = "cdecl" if m.group(1) == "cdecl_sig" else "stdcall"
            for m in re.finditer(r'\bcdecl_named!\s*\(\s*"([^"\\]+)"\s*,', nocomment):
                sigs[m.group(1)] = "cdecl"
        w = os.path.join(self.src, "wow64.rs")
        if os.path.exists(w):
            with open(w, encoding="utf-8", errors="replace") as fh:
                nocomment, _ = mask_rust(fh.read())
            over = set(re.findall(r'"(\w+)"\s*=>\s*Some\(', nocomment))
        return sigs, over

    def runtime_check(self, log_path: str):
        """Compare the static export tables with `WIN_EXPORT dll name` lines
        of a `winrun --capabilities` run. Returns a summary dict."""
        rt = {}
        with open(log_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.search(r"WIN_EXPORT (\S+) (\S+)", line)
                if m:
                    rt.setdefault(m.group(1).lower(), set()).add(m.group(2))
        res = {"log": log_path, "dlls": {}}
        for dll, names in rt.items():
            st = set(self.dlls.get(dll, {}))
            res["dlls"][dll] = {"runtime": len(names), "static": len(st), "only_runtime": sorted(names - st)[:50],
                                "only_static": sorted(st - names)[:50], "match": names == st}
        return res


# --------------------------------------------------------------------------
# Reference dataset
# --------------------------------------------------------------------------

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_reference(out_dir: str, dlls, windir: str):
    """Reads the export tables of real Windows DLLs and writes the dataset."""
    os.makedirs(out_dir, exist_ok=True)
    manifest = {"schema": SCHEMA, "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tool": "scripts/winparity.py reference", "windows_dir": windir, "windows_version": None, "dlls": {}}
    for arch, sub in (("x64", "System32"), ("x86", "SysWOW64")):
        d = os.path.join(out_dir, arch)
        os.makedirs(d, exist_ok=True)
        for dll in sorted(dlls):
            path = os.path.join(windir, sub, dll)
            if not os.path.isfile(path):
                manifest["dlls"].setdefault(dll, {})[arch] = None
                continue
            with open(path, "rb") as f:
                data = f.read()
            pe = PE(data)
            if (arch == "x64") != (pe.arch == "x64"):
                manifest["dlls"].setdefault(dll, {})[arch] = None
                continue
            named, only, fwd = pe.exports()
            ver = pe.file_version()
            if dll == "kernel32.dll" and arch == "x64":
                manifest["windows_version"] = ver
            entry = {"dll": dll, "arch": arch, "file_version": ver, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                     "exports": named, "ordinal_only": only, "forwarded": fwd}
            with open(os.path.join(d, dll + ".json"), "w", encoding="utf-8") as f:
                json.dump(entry, f, separators=(",", ":"), sort_keys=True)
            manifest["dlls"].setdefault(dll, {})[arch] = {"file_version": ver, "exports": len(named), "ordinal_only": len(only)}
    with open(os.path.join(out_dir, "MANIFEST.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
    return manifest


def load_reference(ref_dir: str):
    """{arch: {dll: entry}} and the manifest."""
    mp = os.path.join(ref_dir, "MANIFEST.json")
    if not os.path.isfile(mp):
        raise SystemExit("no reference dataset at %s (run: python scripts/winparity.py reference)" % ref_dir)
    with open(mp, encoding="utf-8") as f:
        manifest = json.load(f)
    data = {}
    for arch in ("x64", "x86"):
        data[arch] = {}
        for p in glob.glob(os.path.join(ref_dir, arch, "*.json")):
            with open(p, encoding="utf-8") as f:
                e = json.load(f)
            data[arch][e["dll"]] = e
    return data, manifest


# --------------------------------------------------------------------------
# Test evidence
# --------------------------------------------------------------------------

PROGRAM_RE = re.compile(r"win: (\S+?)\.exe exited with Some\((-?\d+)\)")
SUMMARY_RE = re.compile(r"\]\s+(\w+): (\d+) passed, (\d+) failed")
CHECK_RE = re.compile(r"\]\s+(?:(\w+): )?\s*(ok|FAIL)\s+(.*)$")
X86_PROGRAMS = {"hello32", "api32", "thread32", "gui32", "plugin32"}


def expected_exits(root: str):
    """Exit code each test program is expected to return: win_checks.rs
    asserts `run("x.exe", ..) == Some(N)`; 0 when it does not say otherwise."""
    out = {}
    p = os.path.join(root, "userspace", "apps", "src", "win_checks.rs")
    if os.path.isfile(p):
        with open(p, encoding="utf-8", errors="replace") as f:
            for m in re.finditer(r'run\("([\w.]+?)\.exe"[^)]*\)\s*==\s*Some\((\d+)\)', f.read()):
                out[m.group(1)] = int(m.group(2))
    return out


def parse_test_log(path: str, expected=None):
    """Executed test evidence from a win-test serial log."""
    expected = expected or {}
    progs = {}
    checks = []   # (program or None, "ok"|"FAIL", text)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = PROGRAM_RE.search(line)
            if m:
                progs.setdefault(m.group(1), {})["exit"] = int(m.group(2))
            m = SUMMARY_RE.search(line)
            if m:
                progs.setdefault(m.group(1), {}).update(passed=int(m.group(2)), failed=int(m.group(3)))
            m = CHECK_RE.search(line)
            if m:
                checks.append((m.group(1), m.group(2), m.group(3).strip()))
    for name, p in progs.items():
        want = expected.get(name, 0)
        p["expected_exit"] = want
        ok = p.get("exit") in (None, want) and p.get("failed", 0) == 0 and ("exit" in p or "passed" in p)
        p["pass"] = bool(ok)
    return {"log": path, "programs": progs, "checks": checks,
            "checks_ok": sum(1 for c in checks if c[1] == "ok"), "checks_fail": sum(1 for c in checks if c[1] == "FAIL")}


CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
DECL_RE = re.compile(r"__stdcall|WINAPI|APIENTRY|dllimport|__cdecl|^\s*typedef|^\s*#")


def c_calls(src: str):
    """Names called in C source: comments and string contents removed;
    declarations (a calling-convention keyword on the line) do not count."""
    _, masked = mask_rust(src)
    out = set()
    for line in masked.splitlines():
        if DECL_RE.search(line):
            continue
        out.update(CALL_RE.findall(line))
    return out


def test_sources(root: str):
    """{program: set of called names} of the C test programs."""
    out = {}
    for p in glob.glob(os.path.join(root, WIN32, "tests", "src", "*.c")):
        stem = os.path.splitext(os.path.basename(p))[0]
        with open(p, encoding="utf-8", errors="replace") as f:
            out[stem] = c_calls(f.read())
    return out


def win32_style(name: str) -> bool:
    """Names a check message can plausibly cite as an API: CamelCase or
    underscore-prefixed. Plain lowercase words (`remove`, `time`) are not
    evidence from message text."""
    return name[:1].isupper() and any(ch.islower() for ch in name) or name.startswith("_")


def behaviour_evidence(root: str, log):
    """Per arch: names with executed evidence.
    program: called by the source of a program that ran and passed.
    check:   cited by an `ok` check line (only CamelCase names).
    failing: called by a failed program or cited by a FAIL line."""
    srcs = test_sources(root)
    ev = {a: {"program": set(), "check": set(), "failing": set()} for a in ("x64", "x86")}
    unmapped = []
    for prog, res in log["programs"].items():
        ids = srcs.get(prog)
        if ids is None:
            unmapped.append(prog)
            continue
        arch = "x86" if prog in X86_PROGRAMS else "x64"
        (ev[arch]["program"] if res["pass"] else ev[arch]["failing"]).update(ids)
    for prog, status, text in log["checks"]:
        arch = "x86" if prog in X86_PROGRAMS else "x64"
        words = {w for w in re.findall(r"[A-Za-z_]\w*", text) if win32_style(w)}
        ev[arch]["check" if status == "ok" else "failing"].update(words)
    return ev, unmapped


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def pct(a, b):
    return round(100.0 * a / b, 1) if b else None


def export_class(dll, name, fn):
    if fn is None:
        return "unknown", "no function body found"
    if dll == "msvcrt.dll" and name in ("??2@YAPAXI@Z", "??2@YAPEAX_K@Z") and fn.cls in REAL:
        return "partial", "allocation works, but operator new does not throw on allocation failure"
    return fn.cls, fn.reason


def analyse_dll(arch, dll, ref, osyx: Osyx, ev):
    """Counts and name lists for one DLL of one architecture."""
    names = ref["exports"]
    table = osyx.dlls.get(dll)
    cls_names = {c: [] for c in CLASSES}
    reasons = {}
    nobridge, wow_aware = [], 0
    if table is None:
        cls_names["missing"] = list(names)
    for n in names if table is not None else []:
        if n not in table:
            cls_names["missing"].append(n)
            continue
        fn = osyx.pick(table[n])
        if fn is None:
            cls_names["unknown"].append(n)
            reasons[n] = "no `extern \"win64\" fn %s` found" % table[n]
            continue
        c, reason = export_class(dll, n, fn)
        if arch == "x86":
            if n not in osyx.sigs and n not in osyx.overrides:
                nobridge.append(n)
                cls_names["missing"].append(n)
                reasons[n] = "implemented for x64 (%s) but no WoW64 bridge signature" % c
                continue
            wow_aware += fn.wow64
        cls_names[c].append(n)
        if reason:
            reasons[n] = reason
    counts = {c: len(v) for c, v in cls_names.items()}
    total = len(names)
    full, part = counts["implemented"], counts["partial"]
    res = {
        "reference_exports": total, "ordinal_only_reference": len(ref["ordinal_only"]),
        "counts": counts, "coverage_pct": pct(full + part, total), "strict_pct": pct(full, total),
        "unknown_pct": pct(counts["unknown"], total),
        "osyx_only": sorted(n for n in (table or {}) if n not in set(names))[:200],
        "osyx_only_count": sum(1 for n in (table or {}) if n not in set(names)),
        "osyx_ordinals": osyx.ordinals.get(dll, []),
        "reference_file": {"version": ref.get("file_version"), "sha256": ref.get("sha256")},
    }
    if arch == "x86":
        res["wow64_adapter_aware"] = wow_aware
        res["x64_only_unbridged"] = len(nobridge)
    # Behavioural parity: only executed evidence, only for real implementations.
    if ev is not None:
        e = ev[arch]
        real = cls_names["implemented"] + cls_names["partial"]
        prog = [n for n in real if n in e["program"] and n not in e["failing"]]
        chk = [n for n in real if n in e["check"] and n not in e["failing"]]
        verified = sorted(set(prog) | set(chk))
        res["behaviour"] = {"verified": len(verified), "by_check": len(chk), "by_program": len(prog), "pct": pct(len(verified), total),
                            "failing_evidence": sorted(n for n in real if n in e["failing"])[:100]}
        res["verified_names"] = verified
    res["names"] = {c: v for c, v in cls_names.items() if c != "implemented" or True}
    res["reasons"] = reasons
    return res


def analyse(root, ref_dir, log_path, runtime_log, profiles_path, only_dlls):
    ref, manifest = load_reference(ref_dir)
    osyx = Osyx(root)
    allow = {}
    ap = os.path.join(root, WIN32, "parity", "allowlist.json")
    if os.path.isfile(ap):
        with open(ap, encoding="utf-8") as f:
            allow = json.load(f).get("entries", {})
    osyx.classify_all(allow)
    ev, tests, unmapped = None, None, []
    if log_path and os.path.isfile(log_path):
        tests = parse_test_log(log_path, expected_exits(root))
        ev, unmapped = behaviour_evidence(root, tests)
    report = OrderedDict()
    report["schema"] = SCHEMA
    report["generated"] = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report["git"] = git_state(root)
    report["reference"] = {"windows_version": manifest.get("windows_version"), "generated": manifest.get("generated"),
                           "source": "export tables of the Windows DLLs of the build above (System32 = x64, SysWOW64 = x86)",
                           "dlls": len(manifest.get("dlls", {}))}
    report["method"] = {
        "coverage": "(implemented + partial) / reference exports; stubs, explicit-unsupported and unknown never count",
        "strict": "implemented / reference exports",
        "classes": "static source heuristic: implemented, partial, stub_success (fake success), stub_empty, unsupported, placeholder, unknown",
        "x86": "an export counts only if it also has a WoW64 bridge signature (wow64/sigs.rs); layout adapters are not verified here",
        "behaviour": "executed evidence only: an `ok` check line naming the API, or a passing test program whose source references it; not measured without a test log",
    }
    arch_out = {}
    for arch in ("x64", "x86"):
        dlls = OrderedDict()
        for dll in sorted(ref[arch]):
            if only_dlls and dll not in only_dlls:
                continue
            if dll not in osyx.dlls:
                continue
            dlls[dll] = analyse_dll(arch, dll, ref[arch][dll], osyx, ev)
        tot = sum(d["reference_exports"] for d in dlls.values())
        agg = Counter()
        for d in dlls.values():
            agg.update(d["counts"])
        full, part = agg["implemented"], agg["partial"]
        o = {"dlls": dlls, "reference_exports": tot, "counts": dict(agg), "coverage_pct": pct(full + part, tot), "strict_pct": pct(full, tot)}
        if ev is not None:
            v = sum(d["behaviour"]["verified"] for d in dlls.values())
            o["behaviour_pct"] = pct(v, tot)
            o["behaviour_verified"] = v
        else:
            o["behaviour_pct"] = None
        arch_out[arch] = o
    report["arch"] = arch_out
    report["osyx_dlls"] = {d: len(t) for d, t in osyx.dlls.items()}
    report["dlls_without_reference"] = sorted(d for d in osyx.dlls if d not in ref["x64"])
    report["allowlisted"] = osyx.allowlisted
    report["fake_success"] = [{"name": n, "file": os.path.relpath(f.file, root).replace(os.sep, "/"), "class": f.cls, "reason": f.reason}
                              for n, lst in sorted(osyx.fns.items()) for f in lst[:1] if f.cls in STUBS]
    report["tests"] = None if tests is None else {"log": tests["log"], "programs": tests["programs"], "checks_ok": tests["checks_ok"],
                                                  "checks_fail": tests["checks_fail"], "programs_without_source": unmapped}
    if runtime_log and os.path.isfile(runtime_log):
        report["runtime_export_check"] = osyx.runtime_check(runtime_log)
    report["profiles"] = analyse_profiles(root, profiles_path, osyx, ref) if profiles_path and os.path.isfile(profiles_path) else None
    return report, osyx


def git_state(root):
    def run(*a):
        try:
            return subprocess.run(["git", *a], cwd=root, capture_output=True, text=True, timeout=20).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    head = run("rev-parse", "HEAD")
    return {"commit": head or None, "branch": run("rev-parse", "--abbrev-ref", "HEAD") or None, "dirty": bool(run("status", "--porcelain"))}


# --------------------------------------------------------------------------
# Application profiles (Steam, Zen)
# --------------------------------------------------------------------------

def analyse_profiles(root, path, osyx: Osyx, ref):
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    flat = {}   # name -> [(dll, cls, reason)]
    for dll, table in osyx.dlls.items():
        for n, impl in table.items():
            fn = osyx.pick(impl)
            cls, reason = export_class(dll, n, fn)
            flat.setdefault(n, []).append((dll, cls, reason))
    out = OrderedDict()
    for key, prof in cfg["profiles"].items():
        files, absent = [], []
        for pat in prof.get("pe", []):
            hits = sorted(glob.glob(os.path.join(root, pat), recursive=True))
            (files if hits else absent).extend(hits or [pat])
        use = {}   # (dll, name) -> set(files)
        arches = set()
        local = {os.path.basename(p).lower() for p in files}
        for p in files:
            with open(p, "rb") as fh:
                try:
                    pe = PE(fh.read())
                except ValueError:
                    absent.append(p + " (not a PE file)")
                    continue
            arches.add(pe.arch)
            for delay in (False, True):
                for dll, names in pe.imports(delay).items():
                    for n in names:
                        use.setdefault((dll, n, pe.arch, delay), set()).add(os.path.basename(p))
        rows = []
        for (dll, n, arch, delay), users in use.items():
            if dll in local:
                st, why = "app_local", "shipped with the application"
            elif n.startswith("#"):
                tbl = osyx.ordinals.get(dll)
                ordn = int(n[1:])
                st, why = ("implemented", "ordinal export") if tbl and ordn in tbl else ("missing", "ordinal %s not exported" % n)
            elif dll in osyx.dlls or dll.startswith("api-ms-win-") or dll.startswith("ext-ms-win-"):
                hits = [h for h in flat.get(n, []) if dll in osyx.dlls and h[0] == dll] or flat.get(n, [])
                if hits:
                    st, why = hits[0][1], hits[0][2]
                    if arch == "x86" and n not in osyx.sigs and n not in osyx.overrides and st in REAL + ("unknown",):
                        st, why = "no_wow64_bridge", "exported for x64 but no WoW64 signature"
                else:
                    st, why = "missing", "not exported by any OSyx built-in DLL"
            else:
                st, why = "external_dll", "not a built-in DLL: must be shipped with the app or present on the system image"
            rows.append({"dll": dll, "name": n, "arch": arch, "delay": delay, "status": st, "reason": why, "users": sorted(users)})
        cnt = Counter(r["status"] for r in rows)
        needed = [r for r in rows if r["status"] not in ("implemented", "partial", "app_local", "external_dll")]
        external = Counter(r["dll"] for r in rows if r["status"] == "external_dll")
        weight = {"missing": 3, "no_wow64_bridge": 3, "placeholder": 2, "stub_empty": 2, "stub_success": 2,
                  "unsupported": 2, "unknown": 1}
        needed.sort(key=lambda r: (-weight.get(r["status"], 1) * len(r["users"]) * (1 if r["delay"] else 2), r["dll"], r["name"]))
        out[key] = {"description": prof.get("description", ""), "files": [os.path.relpath(p, root).replace(os.sep, "/") for p in files],
                    "unavailable": absent, "arch": sorted(arches), "imports": len(rows), "counts": dict(cnt),
                    "ready_pct": pct(cnt["implemented"] + cnt["partial"] + cnt["app_local"], len(rows) - cnt["external_dll"]),
                    "priority": needed[:200], "priority_total": len(needed), "external_dlls": dict(external.most_common())}
    return out


# --------------------------------------------------------------------------
# History and regressions
# --------------------------------------------------------------------------

def snapshot(report):
    """Compact comparable form: arch -> dll -> name -> class, plus tests."""
    snap = {"generated": report["generated"], "commit": report["git"]["commit"], "arch": {}, "verified": {}, "failed_programs": [], "measured": report["tests"] is not None}
    for arch, a in report["arch"].items():
        snap["arch"][arch] = {}
        snap["verified"][arch] = {}
        for dll, d in a["dlls"].items():
            m = {}
            for c, names in d["names"].items():
                for n in names:
                    m[n] = c
            snap["arch"][arch][dll] = {"classes": m, "coverage_pct": d["coverage_pct"], "behaviour_pct": (d.get("behaviour") or {}).get("pct")}
            snap["verified"][arch][dll] = d.get("verified_names", [])
    if report["tests"]:
        snap["failed_programs"] = sorted(p for p, r in report["tests"]["programs"].items() if not r["pass"])
    return snap


def compare(prev, cur):
    out = {"previous": prev["generated"], "previous_commit": prev.get("commit"), "regressions": [], "improvements": [], "dll_delta": {}, "tests": {}}
    for arch, dlls in cur["arch"].items():
        for dll, d in dlls.items():
            p = prev.get("arch", {}).get(arch, {}).get(dll)
            if not p:
                continue
            if d["coverage_pct"] is not None and p["coverage_pct"] is not None:
                out["dll_delta"]["%s/%s" % (arch, dll)] = round(d["coverage_pct"] - p["coverage_pct"], 1)
            for n, c in d["classes"].items():
                pc = p["classes"].get(n)
                if pc is None or pc == c or pc == "unknown" or c == "unknown":
                    continue
                a, b = RANK.get(pc, -1), RANK.get(c, -1)
                item = {"arch": arch, "dll": dll, "name": n, "from": pc, "to": c}
                if b < a:
                    out["regressions"].append(item)
                elif b > a:
                    out["improvements"].append(item)
            if prev.get("measured") and cur.get("measured"):
                lost = set(prev["verified"].get(arch, {}).get(dll, [])) - set(cur["verified"][arch].get(dll, []))
                for n in sorted(lost):
                    if d["classes"].get(n) in ("implemented", "partial"):
                        out["regressions"].append({"arch": arch, "dll": dll, "name": n, "from": "verified", "to": "unverified"})
    pf, cf = set(prev.get("failed_programs", [])), set(cur.get("failed_programs", []))
    out["tests"] = {"newly_failing": sorted(cf - pf), "fixed": sorted(pf - cf)}
    for p in out["tests"]["newly_failing"]:
        out["regressions"].append({"arch": "-", "dll": "-", "name": p, "from": "passing test program", "to": "failing"})
    return out


def save_history(out_dir, report, snap, keep=50):
    hist = os.path.join(out_dir, "history")
    os.makedirs(hist, exist_ok=True)
    stamp = report["generated"].replace(":", "").replace("-", "")
    with open(os.path.join(hist, stamp + ".json"), "w", encoding="utf-8") as f:
        json.dump(snap, f, separators=(",", ":"))
    files = sorted(glob.glob(os.path.join(hist, "*.json")))
    for old in files[:-keep]:
        os.remove(old)


def load_previous(out_dir):
    files = sorted(glob.glob(os.path.join(out_dir, "history", "*.json")))
    if not files:
        return None
    with open(files[-1], encoding="utf-8") as f:
        return json.load(f)


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

def fmt(v):
    return "n/a" if v is None else "%.1f%%" % v


def terminal(report, cmp, top=15, color=None):
    color = sys.stdout.isatty() if color is None else color
    c = (lambda code, s: "\x1b[%sm%s\x1b[0m" % (code, s)) if color else (lambda code, s: s)
    L = []
    L.append("OSyx Win Parity Check")
    L.append("━" * 28)
    ref = report["reference"]
    L.append("Reference: Windows %s (export tables of %d DLLs)" % (ref["windows_version"] or "?", ref["dlls"]))
    g = report["git"]
    L.append("OSyx: %s%s" % ((g["commit"] or "?")[:10], " (dirty)" if g["dirty"] else ""))
    L.append("")
    for arch, label in (("x64", "x64"), ("x86", "x86 / WoW64")):
        a = report["arch"][arch]
        beh = "not measured (no test log)" if a["behaviour_pct"] is None else fmt(a["behaviour_pct"])
        L.append(c("1", "%s" % label))
        L.append("  Windows API Coverage: %s   (strict, fully implemented: %s)" % (fmt(a["coverage_pct"]), fmt(a["strict_pct"])))
        L.append("  Behavioral Parity:    %s" % beh)
        cn = a["counts"]
        L.append("  implemented %d  partial %d  stubbed %d  unsupported %d  missing %d  unknown %d  of %d reference exports" % (
            cn.get("implemented", 0), cn.get("partial", 0), sum(cn.get(k, 0) for k in STUBS), cn.get("unsupported", 0),
            cn.get("missing", 0), cn.get("unknown", 0), a["reference_exports"]))
        L.append("")
        L.append("  %-22s %9s %9s %9s %7s %7s" % ("dll", "coverage", "strict", "behavior", "stubs", "total"))
        rows = sorted(a["dlls"].items(), key=lambda kv: -(kv[1]["reference_exports"]))
        for dll, d in rows:
            b = d.get("behaviour", {}).get("pct")
            L.append("  %-22s %9s %9s %9s %7d %7d" % (dll, fmt(d["coverage_pct"]), fmt(d["strict_pct"]), fmt(b) if b is not None else "n/a",
                     sum(d["counts"].get(k, 0) for k in STUBS), d["reference_exports"]))
        L.append("")
    if report["allowlisted"]:
        L.append("Allowlisted constant-result functions counted as implemented: %s" % ", ".join(a["name"] for a in report["allowlisted"]))
        L.append("")
    if report["fake_success"]:
        L.append(c("33", "Stubs and fake-success functions (%d):" % len(report["fake_success"])))
        for s in report["fake_success"][:top]:
            L.append("  %-28s %-13s %s  [%s]" % (s["name"], s["class"], s["reason"], s["file"]))
        if len(report["fake_success"]) > top:
            L.append("  ... %d more (see JSON)" % (len(report["fake_success"]) - top))
        L.append("")
    for key, p in (report["profiles"] or {}).items():
        L.append(c("1", "Profile %s: %s imports, %s of the scored ones ready" % (key, p["imports"], fmt(p["ready_pct"]))))
        if p["unavailable"]:
            L.append("  not available: " + ", ".join(p["unavailable"][:4]))
        if p.get("external_dlls"):
            L.append("  external DLLs (not built in, not scored): " + ", ".join("%s (%d)" % kv for kv in list(p["external_dlls"].items())[:8]))
        if p["priority"]:
            L.append("  missing/stubbed, most needed first (%d total):" % p["priority_total"])
            for r in p["priority"][:top]:
                L.append("    %-24s %-12s %-14s %s" % (r["dll"], r["status"], r["name"], ",".join(r["users"])))
        L.append("")
    if report["tests"] is None:
        L.append("Tests: no log found; behavioral parity not measured.")
    else:
        t = report["tests"]
        bad = [p for p, r in t["programs"].items() if not r["pass"]]
        L.append("Tests: %d programs, %d failing%s; %d ok checks, %d failing checks" % (
            len(t["programs"]), len(bad), (": " + ", ".join(sorted(bad))) if bad else "", t["checks_ok"], t["checks_fail"]))
    if report.get("runtime_export_check"):
        bad = [d for d, r in report["runtime_export_check"]["dlls"].items() if not r["match"]]
        L.append("Compiled export tables vs source scan: %d DLLs compared, %d differ%s" % (
            len(report["runtime_export_check"]["dlls"]), len(bad), (": " + ", ".join(bad[:6])) if bad else ""))
    if cmp:
        L.append("")
        L.append("Since the previous scan (%s):" % cmp["previous"])
        ch = [(k, v) for k, v in sorted(cmp["dll_delta"].items()) if v]
        for k, v in ch[:top]:
            L.append("  %-30s %+.1f pts" % (k, v))
        L.append("  improvements: %d   regressions: %d" % (len(cmp["improvements"]), len(cmp["regressions"])))
        for r in cmp["regressions"][:top]:
            L.append(c("31", "  REGRESSION %s/%s %s: %s -> %s" % (r["arch"], r["dll"], r["name"], r["from"], r["to"])))
    return "\n".join(L)


CSS = """
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--line:#d0d7de;--card:#f6f8fa;--ok:#1a7f37;--part:#9a6700;--bad:#cf222e;--acc:#0969da}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--card:#161b22;--ok:#3fb950;--part:#d29922;--bad:#f85149;--acc:#58a6ff}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:1.6rem;margin:.2em 0}h2{font-size:1.2rem;margin:1.6em 0 .5em;border-bottom:1px solid var(--line);padding-bottom:.2em}
.cards{display:flex;flex-wrap:wrap;gap:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:200px;flex:1}
.big{font-size:1.9rem;font-weight:650}.mut{color:var(--mut)}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}th{color:var(--mut);font-weight:600}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.bar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--line);min-width:120px}.bar i{display:block}
.full{background:var(--ok)}.part{background:var(--part)}.stub{background:var(--bad)}
code{font-family:ui-monospace,Consolas,monospace;font-size:.88em}details{margin:.4em 0}summary{cursor:pointer}
.reg{color:var(--bad)}.imp{color:var(--ok)}
@media (max-width:600px){.hide-s{display:none}}
"""


def html_report(report, cmp):
    e = html.escape

    def bar(d):
        t = d["reference_exports"] or 1
        cn = d["counts"]
        f, p = cn.get("implemented", 0), cn.get("partial", 0)
        s = sum(cn.get(k, 0) for k in STUBS) + cn.get("unsupported", 0)
        return '<div class="bar" title="implemented %d, partial %d, stubbed/unsupported %d"><i class="full" style="width:%.2f%%"></i><i class="part" style="width:%.2f%%"></i><i class="stub" style="width:%.2f%%"></i></div>' % (
            f, p, s, 100 * f / t, 100 * p / t, 100 * s / t)

    ref = report["reference"]
    h = ["<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
         "<title>OSyx Win Parity</title><style>%s</style></head><body><main>" % CSS,
         "<h1>OSyx Win Parity Check</h1>",
         "<p class=mut>Reference: Windows %s, export tables of %d DLLs (x64 System32, x86 SysWOW64). OSyx %s%s. Generated %s.</p>" % (
             e(str(ref["windows_version"] or "?")), ref["dlls"], e((report["git"]["commit"] or "?")[:10]), " (dirty)" if report["git"]["dirty"] else "", e(report["generated"]))]
    h.append("<div class=cards>")
    for arch, label in (("x64", "x64"), ("x86", "x86 / WoW64")):
        a = report["arch"][arch]
        beh = "not measured" if a["behaviour_pct"] is None else fmt(a["behaviour_pct"])
        h.append("<div class=card><div class=mut>%s Windows API coverage</div><div class=big>%s</div><div class=mut>strict %s &middot; behavioral parity %s</div></div>" % (
            e(label), fmt(a["coverage_pct"]), fmt(a["strict_pct"]), e(beh)))
    h.append("</div>")
    h.append("<p class=mut>Coverage = (implemented + partial) / reference exports. Stubs, explicit-unsupported and unknown are never counted. "
             "Behavioral parity counts only APIs with executed passing test evidence. Classes come from a static source heuristic.</p>")
    for arch, label in (("x64", "x64"), ("x86", "x86 / WoW64 (needs a bridge signature)")):
        a = report["arch"][arch]
        h.append("<h2>%s per DLL</h2><div style='overflow-x:auto'><table><tr><th>DLL<th>coverage<th class=hide-s></th><th class=n>strict<th class=n>behavior<th class=n>impl<th class=n>partial<th class=n>stub<th class=n>unsup.<th class=n>missing<th class=n>unknown<th class=n>total</tr>" % e(label))
        for dll, d in sorted(a["dlls"].items(), key=lambda kv: -kv[1]["reference_exports"]):
            cn = d["counts"]
            b = (d.get("behaviour") or {}).get("pct")
            h.append("<tr><td><code>%s</code><td class=n>%s<td class=hide-s>%s<td class=n>%s<td class=n>%s<td class=n>%d<td class=n>%d<td class=n>%d<td class=n>%d<td class=n>%d<td class=n>%d<td class=n>%d</tr>" % (
                e(dll), fmt(d["coverage_pct"]), bar(d), fmt(d["strict_pct"]), fmt(b) if b is not None else "n/a", cn["implemented"], cn["partial"],
                sum(cn[k] for k in STUBS), cn["unsupported"], cn["missing"], cn["unknown"], d["reference_exports"]))
        h.append("</table></div>")
    h.append("<h2>Stubs and fake-success functions (%d)</h2>" % len(report["fake_success"]))
    h.append("<table><tr><th>function<th>class<th>reason<th>file</tr>")
    for s in report["fake_success"]:
        h.append("<tr><td><code>%s</code><td>%s<td>%s<td><code>%s</code></tr>" % (e(s["name"]), e(s["class"]), e(s["reason"]), e(s["file"])))
    h.append("</table>")
    for key, p in (report["profiles"] or {}).items():
        h.append("<h2>Profile: %s</h2><p>%s<br><span class=mut>%d imports, %s ready (implemented, partial or shipped with the app). Files: %s%s</span></p>" % (
            e(key), e(p["description"]), p["imports"], fmt(p["ready_pct"]), e(", ".join(p["files"]) or "none"),
            (" &middot; not available: " + e(", ".join(p["unavailable"]))) if p["unavailable"] else ""))
        if p.get("external_dlls"):
            h.append("<p class=mut>External DLLs (not built in, not scored): %s</p>" % e(", ".join("%s (%d)" % kv for kv in p["external_dlls"].items())))
        h.append("<table><tr><th>DLL<th>function<th>status<th>reason<th>needed by</tr>")
        for r in p["priority"]:
            h.append("<tr><td><code>%s</code><td><code>%s</code><td>%s<td>%s<td>%s</tr>" % (e(r["dll"]), e(r["name"]), e(r["status"]), e(r["reason"]), e(", ".join(r["users"]))))
        h.append("</table>")
    if report["tests"]:
        t = report["tests"]
        h.append("<h2>Executed tests</h2><p class=mut>Log %s: %d ok checks, %d failing checks.</p><table><tr><th>program<th>result<th class=n>passed<th class=n>failed</tr>" % (
            e(t["log"]), t["checks_ok"], t["checks_fail"]))
        for pn, r in sorted(t["programs"].items()):
            h.append("<tr><td><code>%s</code><td class=%s>%s<td class=n>%s<td class=n>%s</tr>" % (e(pn), "imp" if r["pass"] else "reg", "pass" if r["pass"] else "FAIL", r.get("passed", "-"), r.get("failed", "-")))
        h.append("</table>")
    else:
        h.append("<h2>Executed tests</h2><p>No test log: behavioral parity was not measured.</p>")
    if cmp:
        h.append("<h2>Since the previous scan (%s)</h2><p>%d improvements, <span class=reg>%d regressions</span>.</p>" % (e(cmp["previous"]), len(cmp["improvements"]), len(cmp["regressions"])))
        h.append("<table><tr><th>scope<th>API<th>change</tr>")
        for r in cmp["regressions"][:300]:
            h.append("<tr class=reg><td>%s/%s<td><code>%s</code><td>%s &rarr; %s</tr>" % (e(r["arch"]), e(r["dll"]), e(r["name"]), e(r["from"]), e(r["to"])))
        h.append("</table>")
    h.append("</main></body></html>")
    return "".join(h)


def write_reports(report, cmp, out_dir, formats):
    os.makedirs(out_dir, exist_ok=True)
    paths = {}
    if "json" in formats:
        p = os.path.join(out_dir, "report.json")
        doc = dict(report)
        doc["comparison"] = cmp
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        paths["json"] = p
    if "html" in formats:
        p = os.path.join(out_dir, "report.html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(html_report(report, cmp))
        paths["html"] = p
    return paths


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_reference(a):
    root = os.path.abspath(a.root)
    osyx = Osyx(root)
    dlls = sorted(set(osyx.dlls) | set(a.extra or []))
    windir = a.windir or os.environ.get("SystemRoot") or r"C:\Windows"
    if not os.path.isdir(os.path.join(windir, "SysWOW64")):
        raise SystemExit("%s has no SysWOW64: the reference needs a 64-bit Windows installation" % windir)
    out = os.path.join(root, a.out or DEFAULT_REFERENCE)
    m = build_reference(out, dlls, windir)
    n = sum(1 for d in m["dlls"].values() for v in d.values() if v)
    print("reference: Windows %s, %d export tables written to %s" % (m["windows_version"], n, out))
    return 0


def cmd_scan(a):
    root = os.path.abspath(a.root)
    out_dir = os.path.join(root, a.out)
    log = a.tests_log if a.tests_log is not None else os.path.join(root, DEFAULT_TEST_LOG)
    if log == "none":
        log = None
    report, _ = analyse(root, os.path.join(root, a.reference), log, a.runtime_exports, os.path.join(root, a.profiles) if a.profiles else None, set(a.dll or []))
    snap = snapshot(report)
    prev = load_previous(out_dir)
    cmp = compare(prev, snap) if prev else None
    formats = {f.strip() for f in a.format.split(",")}
    paths = write_reports(report, cmp, out_dir, formats)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if "terminal" in formats:
        print(terminal(report, cmp, a.top))
    for k, p in paths.items():
        print("%s report: %s" % (k, p))
    if not a.no_history:
        save_history(out_dir, report, snap)
    if a.fail_on_regression and cmp and cmp["regressions"]:
        print("%d regression(s) since the previous scan" % len(cmp["regressions"]), file=sys.stderr)
        return 2
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=REPO)
    r = sub.add_parser("reference", parents=[common], help="rebuild the reference dataset from a Windows installation")
    r.add_argument("--windir")
    r.add_argument("--out")
    r.add_argument("--extra", nargs="*", help="further DLLs to include")
    s = sub.add_parser("scan", parents=[common], help="analyse OSyx against the reference (default)")
    s.add_argument("--reference", default=DEFAULT_REFERENCE)
    s.add_argument("--profiles", default=DEFAULT_PROFILES)
    s.add_argument("--tests-log", help="win-test serial log (default build/test/win.serial.log; 'none' to skip)")
    s.add_argument("--runtime-exports", help="serial log of `winrun --capabilities` to cross-check the source scan")
    s.add_argument("--out", default=DEFAULT_OUT)
    s.add_argument("--format", default="terminal,json,html")
    s.add_argument("--dll", nargs="*")
    s.add_argument("--top", type=int, default=15)
    s.add_argument("--no-history", action="store_true")
    s.add_argument("--fail-on-regression", action="store_true")
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("reference", "scan", "-h", "--help"):
        argv = ["scan"] + argv
    a = ap.parse_args(argv)
    return {"reference": cmd_reference, "scan": cmd_scan}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
