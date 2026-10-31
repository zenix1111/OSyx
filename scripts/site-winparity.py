#!/usr/bin/env python3
"""Writes site/winparity.json for the website from the report of
`python scripts/winparity.py scan` (build/winparity/report.json).

The numbers are copied, never computed here: coverage and class counts come
from the scan of the sources against Windows' export tables, behavioural
parity from the executed Windows tests (see docs/win-parity.md).

    python scripts/winparity.py scan
    python scripts/site-winparity.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(ROOT, "build", "winparity", "report.json")
OUT = os.path.join(ROOT, "site", "winparity.json")
TOP_DLLS = 8


def arch_block(report, arch):
    a = report["arch"][arch]
    counts = a["counts"]
    dlls = []
    for name, d in a["dlls"].items():
        dlls.append({
            "dll": name,
            "total": d["reference_exports"],
            "coverage": d["coverage_pct"],
            "behaviour": d["behaviour"]["pct"] if d.get("behaviour") else None,
        })
    dlls.sort(key=lambda d: -d["total"])
    return {
        "reference_exports": a["reference_exports"],
        "coverage": a["coverage_pct"],
        "strict": a["strict_pct"],
        "behaviour": a["behaviour_pct"],
        "implemented": counts["implemented"],
        "partial": counts["partial"],
        "stubs": counts["stub_empty"] + counts["stub_success"] + counts["placeholder"],
        "unsupported": counts["unsupported"],
        "unknown": counts["unknown"],
        "missing": counts["missing"],
        "dlls": dlls[:TOP_DLLS],
    }


def main():
    if not os.path.exists(REPORT):
        sys.exit("run `python scripts/winparity.py scan` first")
    with open(REPORT, encoding="utf-8") as f:
        report = json.load(f)
    tests = report["tests"]
    out = {
        "generated": report["generated"],
        "commit": report["git"]["commit"][:10],
        "windows": report["reference"]["windows_version"],
        "x64": arch_block(report, "x64"),
        "x86": arch_block(report, "x86"),
        "tests": {"programs": len(tests["programs"]), "checks_ok": tests["checks_ok"], "checks_fail": tests["checks_fail"]},
        "profiles": {name: p["ready_pct"] for name, p in report["profiles"].items()},
    }
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2)
        f.write("\n")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
