"""Tests of scripts/winparity.py on synthetic sources, references and PE files.

Run: python -m unittest scripts/test_winparity.py   (from the repository root)
"""
import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import winparity as w  # noqa: E402


def make_pe(exports=(), imports=None, plus=True):
    """A tiny PE32+/PE32 image with an export and an import directory in one
    section at RVA 0x1000 (file offset 0x200)."""
    ptr = 8 if plus else 4
    base_rva, buf = 0x1000, bytearray()
    exp_rva = base_rva
    names = sorted(exports)
    # export directory (40 bytes) + functions + names + ordinals + strings
    n = len(names)
    fun_off, nam_off, ord_off = 40, 40 + 4 * n, 40 + 8 * n
    str_off = 40 + 10 * n + (n % 2) * 2
    strings, offs = bytearray(), []
    dllname = b"test.dll\0"
    for nm in names:
        offs.append(str_off + len(strings))
        strings += nm.encode() + b"\0"
    dll_off = str_off + len(strings)
    strings += dllname
    exp = bytearray(40 + 10 * n + (n % 2) * 2) + strings
    struct.pack_into("<IIIIIIIIII", exp, 0, 0, 0, 0, exp_rva + dll_off, 1, n, n, exp_rva + fun_off, exp_rva + nam_off, exp_rva + ord_off)
    for i in range(n):
        struct.pack_into("<I", exp, fun_off + 4 * i, 0x2000 + i)
        struct.pack_into("<I", exp, nam_off + 4 * i, exp_rva + offs[i])
        struct.pack_into("<H", exp, ord_off + 2 * i, i)
    buf += exp
    exp_size = len(exp)
    buf += b"\0" * (-len(buf) % 8)
    imp_rva, imp_size = 0, 0
    if imports:
        imp_rva = base_rva + len(buf)
        descs = len(imports) + 1
        body = bytearray(20 * descs)
        pos = len(body)
        for k, (dll, fnames) in enumerate(imports.items()):
            thunks_at = pos
            hn = []
            pos += ptr * (len(fnames) + 1)
            blob = bytearray()
            for f in fnames:
                hn.append(pos + len(blob))
                blob += b"\0\0" + f.encode() + b"\0"
                blob += b"\0" * (len(blob) % 2)
            name_at = pos + len(blob)
            blob += dll.encode() + b"\0"
            body += b"\0" * (ptr * (len(fnames) + 1))
            for j, h in enumerate(hn):
                struct.pack_into("<Q" if plus else "<I", body, thunks_at + ptr * j, imp_rva + h)
            body += blob
            pos += len(blob)
            struct.pack_into("<IIIII", body, 20 * k, imp_rva + thunks_at, 0, 0, imp_rva + name_at, imp_rva + thunks_at)
        buf += body
        imp_size = len(body)
    raw = bytes(buf)
    hdr = bytearray(0x200)
    hdr[0:2] = b"MZ"
    struct.pack_into("<I", hdr, 0x3C, 0x80)
    hdr[0x80:0x84] = b"PE\0\0"
    optsize = 240 if plus else 224
    struct.pack_into("<HHIIIHH", hdr, 0x84, 0x8664 if plus else 0x14C, 1, 0, 0, 0, optsize, 0x2022)
    opt = 0x98
    struct.pack_into("<H", hdr, opt, 0x20B if plus else 0x10B)
    if plus:
        struct.pack_into("<Q", hdr, opt + 24, 0x180000000)
    else:
        struct.pack_into("<I", hdr, opt + 28, 0x10000000)
    dd = opt + (112 if plus else 96)
    struct.pack_into("<I", hdr, dd - 4, 16)
    struct.pack_into("<II", hdr, dd, exp_rva, exp_size)
    struct.pack_into("<II", hdr, dd + 8, imp_rva, imp_size)
    sec = opt + optsize
    hdr[sec:sec + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", hdr, sec + 8, 0x4000, base_rva, len(raw), 0x200)
    return bytes(hdr) + raw + b"\0" * 8


class MaskTests(unittest.TestCase):
    def test_braces_ignore_strings_comments_lifetimes(self):
        src = 'fn f<\'a>(x: &\'a str) -> u32 { let s = "}{ not code"; /* } */ let c = \'}\'; // }\n 7 }\nfn g() {}'
        _, masked = w.mask_rust(src)
        end = w.match_close(masked, masked.find("{"), "{", "}")
        self.assertTrue(src[:end].rstrip().endswith("7 }"))

    def test_parse_win64_fns_params_and_body(self):
        src = 'pub(crate) extern "win64" fn Foo(_a: u32, b: *mut u8, mut c: u64) -> u32 { b as u32 }\nextern "win64" fn Bar();\n'
        fns = w.parse_win64_fns("x.rs", src)
        self.assertEqual([f.name for f in fns], ["Foo"])
        self.assertEqual(fns[0].params, ["_a", "b", "c"])
        self.assertEqual(fns[0].body.strip(), "b as u32")


class ClassifyTests(unittest.TestCase):
    def cls(self, src):
        fns = w.parse_win64_fns("x.rs", src)
        idx = {f.name: f for f in fns}
        for f in fns:
            w.classify(f, idx)
        return {f.name: f.cls for f in fns}

    def test_classes(self):
        got = self.cls('''
extern "win64" fn Real(h: u64, p: *mut u32) -> i32 { unsafe { *p = h as u32 }; TRUE }
extern "win64" fn FakeOk(_h: u64) -> i32 { TRUE }
extern "win64" fn FakeIgnores(h: u64, f: u32) -> i32 { let _ = h; let _ = f; 1 }
extern "win64" fn Empty(_h: u64) -> u64 { 0 }
extern "win64" fn Honest(_h: u64) -> i32 { fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE) }
extern "win64" fn Todo() -> u32 { todo!() }
extern "win64" fn Alias(h: u64, p: *mut u32) -> i32 { Real(h, p) }
extern "win64" fn AliasStub(h: u64) -> i32 { FakeOk(h) }
extern "win64" fn Part(h: u64, f: u32) -> i32 { if f != 0 { return fail(ERROR_NOT_SUPPORTED, FALSE); } Real(h, core::ptr::null_mut()) }
extern "win64" fn Const0() -> u64 { u64::MAX }
extern "win64" fn PathTrue(_h: u64) -> i32 { crate::kernel32::TRUE }
extern "win64" fn FakeHandle(_a: u32) -> u64 { 0x20_0001 }
extern "win64" fn Named(_a: u32) -> u32 { HKL_US }
extern "win64" fn ErrConst(_a: u32) -> u32 { E_NOTIMPL }
extern "win64" fn HexErr(_a: u32) -> u32 { 0x8000_4001 }
extern "win64" fn MmErr(_a: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn StgErr(_a: u32) -> u32 { STG_E_INVALIDFUNCTION }
extern "win64" fn MmOk(_a: u32) -> u32 { MMSYSERR_NOERROR }
extern "win64" fn Pass(c: u64) -> u64 { c }
''')
        self.assertEqual(got["Real"], "implemented")
        self.assertEqual(got["FakeOk"], "stub_success")
        self.assertEqual(got["FakeIgnores"], "stub_success")
        self.assertEqual(got["Empty"], "stub_empty")
        self.assertEqual(got["Honest"], "unsupported")
        self.assertEqual(got["Todo"], "placeholder")
        self.assertEqual(got["Alias"], "implemented")
        self.assertEqual(got["AliasStub"], "stub_success")
        self.assertEqual(got["Part"], "partial")
        self.assertEqual(got["Const0"], "implemented")
        self.assertEqual(got["Pass"], "implemented")
        self.assertEqual(got["PathTrue"], "stub_success")
        self.assertEqual(got["FakeHandle"], "stub_success")
        self.assertEqual(got["Named"], "stub_success")
        self.assertEqual(got["ErrConst"], "unsupported")
        self.assertEqual(got["MmErr"], "unsupported")
        self.assertEqual(got["StgErr"], "unsupported")
        self.assertEqual(got["MmOk"], "stub_success")
        self.assertEqual(got["HexErr"], "unsupported")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def make_tree(root):
    s = os.path.join(root, "compatibility", "win32", "src")
    write(os.path.join(s, "loader.rs"), '''
fn builtins() -> Vec<Arc<Builtin>> {
    let k32 = crate::a::exports();
    alloc::vec![
        builtin("a.dll", k32.clone(), Vec::new()),
        builtin("b.dll", [crate::b::exports(), crate::a::more_exports()].concat(), crate::b::ordinals()),
        builtin("c.dll", k32, Vec::new()),
    ]
}''')
    write(os.path.join(s, "a.rs"), '''
extern "win64" fn One(_x: u32) -> i32 { TRUE }
extern "win64" fn Two(x: u32) -> i32 { x as i32 + 1 }
extern "win64" fn Three(_x: u32) -> i32 { fail(ERROR_NOT_SUPPORTED, 0) }
pub fn exports() -> Vec<(&'static str, u64)> {
    let mut e = export_table![One, Two];
    e.push(("TwoAlias", Two as *const () as u64));
    e
}
pub fn more_exports() -> Vec<(&'static str, u64)> { export_table![Three] }
''')
    write(os.path.join(s, "b.rs"), '''
extern "win64" fn Bee(x: u32) -> i32 { x as i32 }
pub fn exports() -> Vec<(&'static str, u64)> { export_table![Bee] }
pub fn ordinals() -> Vec<(u16, u64)> { alloc::vec![(17, Bee as *const () as u64), (23, Bee as *const () as u64)] }
''')
    write(os.path.join(s, "wow64", "sigs.rs"), 'pub(super) static SIGNATURES: &[Signature] = &[ sig!(Two, [Uint], I32), cdecl_sig!(Bee, [Uint], I32), ];')
    write(os.path.join(s, "wow64.rs"), 'fn host_override(symbol: &str) -> Option<u64> { match symbol { "One" => Some(f as u64), _ => None } }')
    t = os.path.join(root, "compatibility", "win32", "tests", "src")
    write(os.path.join(t, "prog.c"), '''
/* Two(1) in a comment */
__declspec(dllimport) int __stdcall Two(int);
void start(void) { Two(3); check("remove works with time", 1); }
''')
    write(os.path.join(root, "userspace", "apps", "src", "win_checks.rs"), 't.check("x", || run("prog.exe", &[]) == Some(5));')
    ref = os.path.join(root, "ref")
    for arch in ("x64", "x86"):
        for dll, names in (("a.dll", ["One", "Two", "Three", "Four", "Five"]), ("b.dll", ["Bee", "Bea"]), ("c.dll", ["One", "Two"])):
            write(os.path.join(ref, arch, dll + ".json"), json.dumps({"dll": dll, "arch": arch, "file_version": "10.0.1.2", "sha256": "0", "exports": names, "ordinal_only": [], "forwarded": {}}))
    write(os.path.join(ref, "MANIFEST.json"), json.dumps({"windows_version": "10.0.1.2", "generated": "t", "dlls": {"a.dll": {}, "b.dll": {}, "c.dll": {}}}))
    return root


class OsyxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = make_tree(self.tmp.name)
        self.osyx = w.Osyx(self.root)
        self.osyx.classify_all()

    def tearDown(self):
        self.tmp.cleanup()

    def test_decorated_aliases_and_named_bridges(self):
        body = 'for n in ["??2@YAPAXI@Z", "??2@YAPEAX_K@Z"] { e.push((n, malloc)); }'
        self.assertEqual(self.osyx.resolve(body, None), {"??2@YAPAXI@Z": "malloc", "??2@YAPEAX_K@Z": "malloc"})
        sigs = os.path.join(self.root, "compatibility", "win32", "src", "wow64", "sigs.rs")
        with open(sigs, "a", encoding="utf-8") as f:
            f.write('\ncdecl_named!("??2@YAPAXI@Z", [Uint], Ptr);\n')
        self.assertEqual(w.Osyx(self.root).sigs["??2@YAPAXI@Z"], "cdecl")
        cls, reason = w.export_class("msvcrt.dll", "??2@YAPAXI@Z", self.osyx.pick("Two"))
        self.assertEqual(cls, "partial")
        self.assertIn("does not throw", reason)

    def test_indirect_implementations_are_found(self):
        root = tempfile.mkdtemp()
        src = os.path.join(root, "compatibility", "win32", "src")
        os.makedirs(src)
        with open(os.path.join(src, "loader.rs"), "w") as f:
            f.write("fn builtins() { builtin(\"x.dll\", crate::m::exports(), Vec::new()); }\n")
        with open(os.path.join(src, "m.rs"), "w") as f:
            f.write("""
pub fn exports() -> Vec<(&'static str, u64)> {
    let mut v = export_table![sin, RaiseException];
    v.push(("Path", crate::m::path_getter()));
    v
}
extern "win64" fn sin_soft(x: u64) -> u64 { x + 1 }
xmm_abi! {
    sin => sin_soft ["movq rcx, xmm0"] "movq xmm0, rax";
}
pub fn path_getter() -> u64 { Path_impl as *const () as u64 }
extern "win64" fn Path_impl(p: u64) -> u64 { p * 2 }
global_asm!(
r#"
.global osyx_raise
osyx_raise:
    push rbp
    mov rbp, rsp
    pop rbp
    ret
"#
);
extern "win64" {
    #[link_name = "osyx_raise"]
    pub(crate) fn RaiseException(code: u32);
}
""")
        osyx = w.Osyx(root)
        osyx.classify_all()
        self.assertEqual(osyx.pick("sin").cls, "implemented")
        self.assertEqual(osyx.pick("RaiseException").cls, "implemented")
        self.assertIn("assembly", osyx.pick("RaiseException").reason)
        self.assertEqual(osyx.pick("path_getter").cls, "implemented")

    def test_macro_generated_functions_are_found(self):
        src = """
macro_rules! unary {
    ($($s:ident = $f:ident;)*) => {$(
        extern "win64" fn $s(x: f64) -> f64 {
            $f(x)
        }
    )*};
}
unary! {
    sin_soft = sin_f; cos_soft = cos_f;
}
fn sin_f(x: f64) -> f64 { x }
"""
        fns = w.parse_win64_fns("m.rs", w.expand_macros(src))
        self.assertEqual(sorted(f.name for f in fns), ["cos_soft", "sin_soft"])
        self.assertIn("cos_f(x)", [f for f in fns if f.name == "cos_soft"][0].body)

    def test_export_resolution(self):
        d = self.osyx.dlls
        self.assertEqual(set(d["a.dll"]), {"One", "Two", "TwoAlias"})
        self.assertEqual(set(d["b.dll"]), {"Bee", "Three"})
        self.assertEqual(set(d["c.dll"]), {"One", "Two", "TwoAlias"})  # a bare variable argument
        self.assertEqual(self.osyx.ordinals["b.dll"], [17, 23])
        self.assertEqual(self.osyx.sigs, {"Two": "stdcall", "Bee": "cdecl"})
        self.assertEqual(self.osyx.overrides, {"One"})

    def test_coverage_counts_never_count_stubs(self):
        ref, _ = w.load_reference(os.path.join(self.root, "ref"))
        d = w.analyse_dll("x64", "a.dll", ref["x64"]["a.dll"], self.osyx, None)
        self.assertEqual(d["counts"]["implemented"], 1)      # Two
        self.assertEqual(d["counts"]["stub_success"], 1)     # One
        self.assertEqual(d["counts"]["missing"], 3)          # Three is not an export of a.dll
        self.assertEqual(d["coverage_pct"], 20.0)
        self.assertEqual(d["osyx_only"], ["TwoAlias"])
        self.assertNotIn("behaviour", d)

    def test_x86_needs_bridge(self):
        ref, _ = w.load_reference(os.path.join(self.root, "ref"))
        d = w.analyse_dll("x86", "a.dll", ref["x86"]["a.dll"], self.osyx, None)
        self.assertEqual(d["counts"]["implemented"], 1)  # Two has a signature
        self.assertEqual(d["counts"]["stub_success"], 1)  # One via host_override
        self.assertEqual(d["x64_only_unbridged"], 0)

    def test_full_report_without_tests_is_not_measured(self):
        rep, _ = w.analyse(self.root, os.path.join(self.root, "ref"), None, None, None, set())
        self.assertIsNone(rep["tests"])
        self.assertIsNone(rep["arch"]["x64"]["behaviour_pct"])
        text = w.terminal(rep, None, color=False)
        self.assertIn("not measured", text)

    def test_behaviour_from_executed_tests_only(self):
        log = os.path.join(self.root, "win.log")
        write(log, "[ 1.0] [winrun:1]   ok   Two accepts 3\n[ 1.1] [init:1] win: prog.exe exited with Some(5) after 3 ms\n")
        rep, _ = w.analyse(self.root, os.path.join(self.root, "ref"), log, None, None, set())
        a = rep["arch"]["x64"]["dlls"]["a.dll"]
        self.assertEqual(a["behaviour"]["verified"], 1)       # Two; One is a stub and never verified
        self.assertIn("Two", a["verified_names"])
        self.assertNotIn("One", a["verified_names"])
        write(log, "[ 1.1] [init:1] win: prog.exe exited with Some(0) after 3 ms\n")  # not the expected 5
        rep, _ = w.analyse(self.root, os.path.join(self.root, "ref"), log, None, None, set())
        self.assertEqual(rep["arch"]["x64"]["dlls"]["a.dll"]["behaviour"]["verified"], 0)
        self.assertFalse(rep["tests"]["programs"]["prog"]["pass"])

    def test_runtime_cross_check(self):
        log = os.path.join(self.root, "rt.log")
        write(log, "WIN_EXPORT a.dll One\nWIN_EXPORT a.dll Two\nWIN_EXPORT a.dll Extra\n")
        res = self.osyx.runtime_check(log)["dlls"]["a.dll"]
        self.assertFalse(res["match"])
        self.assertEqual(res["only_runtime"], ["Extra"])
        self.assertEqual(res["only_static"], ["TwoAlias"])


class EvidenceTests(unittest.TestCase):
    def test_c_calls_skip_comments_strings_declarations(self):
        src = '/* Hidden(1) */ int __stdcall Decl(int);\nvoid f(){ Real(1); printf("Quoted(2)"); }'
        self.assertEqual(w.c_calls(src), {"f", "Real", "printf"})

    def test_win32_style(self):
        self.assertTrue(w.win32_style("CreateFileW"))
        self.assertTrue(w.win32_style("_wcsicmp"))
        self.assertFalse(w.win32_style("remove"))
        self.assertFalse(w.win32_style("OK"))

    def test_parse_test_log(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "l")
            write(p, "[1.0] [winrun:3] foo: 4 passed, 0 failed\n[1.1] [init:1] win: foo.exe exited with Some(0) after 1 ms\n"
                     "[1.2] [winrun:4] bar: 3 passed, 1 failed\n[1.3] [init:1] win: bar.exe exited with Some(1) after 1 ms\n"
                     "[1.4] [init:1] win: odd.exe exited with Some(42) after 1 ms\n[1.5] [winrun:3] foo: ok CreateFileW works\n")
            r = w.parse_test_log(p, {"odd": 42})
            self.assertTrue(r["programs"]["foo"]["pass"])
            self.assertFalse(r["programs"]["bar"]["pass"])
            self.assertTrue(r["programs"]["odd"]["pass"])
            self.assertEqual(r["checks"], [("foo", "ok", "CreateFileW works")])


class PETests(unittest.TestCase):
    def test_exports_and_imports(self):
        for plus in (True, False):
            pe = w.PE(make_pe(["Beta", "Alpha"], {"kernel32.dll": ["Sleep", "ExitProcess"]}, plus))
            self.assertEqual(pe.arch, "x64" if plus else "x86")
            self.assertEqual(pe.exports()[0], ["Alpha", "Beta"])
            self.assertEqual(dict(pe.imports()), {"kernel32.dll": ["Sleep", "ExitProcess"]})

    @unittest.skipUnless(os.path.isfile(r"C:\Windows\System32\kernel32.dll"), "needs Windows")
    def test_real_kernel32(self):
        with open(r"C:\Windows\System32\kernel32.dll", "rb") as f:
            pe = w.PE(f.read())
        names, _, fwd = pe.exports()
        self.assertIn("CreateFileW", names)
        self.assertTrue(pe.file_version().startswith("10.0."))
        self.assertGreater(len(fwd), 0)


class HistoryTests(unittest.TestCase):
    def snap(self, classes, verified, failed=()):
        return {"generated": "t", "commit": None, "measured": True, "failed_programs": list(failed),
                "arch": {"x64": {"a.dll": {"classes": classes, "coverage_pct": 50.0, "behaviour_pct": None}}},
                "verified": {"x64": {"a.dll": verified}}}

    def test_regressions_and_improvements(self):
        prev = self.snap({"A": "implemented", "B": "stub_success", "C": "missing", "D": "implemented"}, ["A", "D"])
        cur = self.snap({"A": "stub_success", "B": "implemented", "C": "partial", "D": "implemented"}, ["B"], failed=["prog"])
        c = w.compare(prev, cur)
        reg = {(r["name"], r["to"]) for r in c["regressions"]}
        self.assertIn(("A", "stub_success"), reg)
        self.assertIn(("D", "unverified"), reg)
        self.assertIn(("prog", "failing"), reg)
        self.assertEqual({r["name"] for r in c["improvements"]}, {"B", "C"})

    def test_unknown_is_never_a_regression(self):
        c = w.compare(self.snap({"A": "implemented"}, []), self.snap({"A": "unknown"}, []))
        self.assertEqual(c["regressions"], [])


class ReportTests(unittest.TestCase):
    def test_html_escapes(self):
        with tempfile.TemporaryDirectory() as d:
            root = make_tree(d)
            rep, _ = w.analyse(root, os.path.join(root, "ref"), None, None, None, set())
            rep["fake_success"].append({"name": "<script>x</script>", "file": "a&b.rs", "class": "stub_empty", "reason": "\"q\""})
            h = w.html_report(rep, None)
            self.assertNotIn("<script>x", h)
            self.assertIn("&lt;script&gt;", h)
            self.assertIn("a&amp;b.rs", h)


if __name__ == "__main__":
    unittest.main()
