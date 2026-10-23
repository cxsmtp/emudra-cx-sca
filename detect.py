#!/usr/bin/env python3
"""
SCA-style detector for the eMudhra intermediate-CA key compromise
(EMUDHRA-CA-2026-10).

What it does — and deliberately does NOT do:
  * It matches INSTALLED package/runtime versions in a manifest against the
    confirmed fixed-version boundaries for this advisory. That is exactly the
    signal classic SCA produces: "this dependency version is still vulnerable."
  * It does NOT try to detect eMudhra's root-cause (weak key generation). That
    was bespoke logic in eMudhra's signing tooling, not a dependency, and is
    out of SCA scope by definition.

Output: a labeled dataset (dataset.jsonl) + a flat findings.csv, suitable as
ground-truth training/eval data. Every label traces to vuln_db.json.

Usage:  python3 detect.py <fixtures_dir>   (default: ./fixtures)
"""
import csv
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, "vuln_db.json")) as f:
    DB = json.load(f)

RULES = {r["package"]: r for r in DB["rules"]}


# ---------- version comparison helpers (per ecosystem) ----------

def cmp_semver(a, b):
    """Compare dotted numeric versions. Returns -1/0/1."""
    pa = [int(x) for x in re.findall(r"\d+", a)]
    pb = [int(x) for x in re.findall(r"\d+", b)]
    pa += [0] * (len(pb) - len(pa))
    pb += [0] * (len(pa) - len(pb))
    return (pa > pb) - (pa < pb)


def go_vulnerable(version, rule):
    """Go: fixed per-minor-line. 1.27.x needs >=1.27.3; 1.26.x needs >=1.26.10;
    anything on an older minor line is vulnerable (no backport)."""
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not m:
        return None, "unparseable go version"
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    line = f"{major}.{minor}"
    fixed = rule["fixed"].get(line)
    if fixed is None:
        # older than any patched line -> vulnerable
        min_safe = rule["min_safe_minor"]
        if cmp_semver(line, min_safe) < 0:
            return True, f"go {version} predates patched lines (min patched line {min_safe})"
        return None, f"go line {line} not in advisory"
    vuln = cmp_semver(version, fixed) < 0
    return vuln, f"go {version} {'<' if vuln else '>='} fixed {fixed}"


def certifi_vulnerable(version, rule):
    """certifi uses date versions YYYY.MM.DD."""
    cur = [int(x) for x in re.findall(r"\d+", version)]
    fix = [int(x) for x in re.findall(r"\d+", rule["fixed"])]
    vuln = cur < fix
    return vuln, f"certifi {version} {'<' if vuln else '>='} fixed {rule['fixed']}"


def brew_date_vulnerable(version, rule):
    """ca-certificates brew style: YYYY-MM-DD[_N]."""
    def key(v):
        parts = re.findall(r"\d+", v)
        return [int(x) for x in parts]
    vuln = key(version) < key(rule["fixed"])
    return vuln, f"ca-certificates {version} {'<' if vuln else '>='} fixed {rule['fixed']}"


def semver_vulnerable(version, rule):
    vuln = cmp_semver(version, rule["fixed"]) < 0
    return vuln, f"{version} {'<' if vuln else '>='} fixed {rule['fixed']}"


MATCHERS = {
    "go_toolchain": go_vulnerable,
    "date_version": certifi_vulnerable,
    "brew_date_version": brew_date_vulnerable,
    "semver": semver_vulnerable,
}


# ---------- manifest parsers ----------

def parse_go_mod(path):
    out = []
    with open(path) as f:
        for line in f:
            m = re.match(r"\s*go\s+(\d+\.\d+(?:\.\d+)?)", line)
            if m:
                out.append(("stdlib", m.group(1)))
    return out


def parse_requirements(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()
            m = re.match(r"([A-Za-z0-9_.\-]+)==([\w.\-]+)", line)
            if m:
                out.append((m.group(1).lower(), m.group(2)))
    return out


def parse_os_packages(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                out.append((parts[0].lower(), parts[1]))
    return out


PARSERS = [
    ("go.mod", parse_go_mod),
    ("requirements.txt", parse_requirements),
    ("packages.txt", parse_os_packages),
]


def scan_manifest(path):
    name = os.path.basename(path)
    for suffix, parser in PARSERS:
        if name == suffix:
            return parser(path)
    return []


# ---------- main scan ----------

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "fixtures")
    samples = []

    for dirpath, _, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            for pkg, version in scan_manifest(full):
                rule = RULES.get(pkg)
                if not rule:
                    continue  # package not in advisory -> not a sample
                vuln, reason = MATCHERS[rule["match"]](version, rule)
                if vuln is None:
                    continue
                samples.append({
                    "advisory": DB["advisory_id"],
                    "manifest": os.path.relpath(full, root),
                    "ecosystem": rule["ecosystem"],
                    "package": pkg,
                    "installed_version": version,
                    "fixed_version": rule["fixed"],
                    "cve": rule.get("cve"),
                    "label": "vulnerable" if vuln else "not_vulnerable",
                    "confidence": rule["confidence"],
                    "reason": reason,
                })

    out_dir = os.path.join(HERE, "out")
    os.makedirs(out_dir, exist_ok=True)

    # emit JSONL
    out_jsonl = os.path.join(out_dir, "dataset.jsonl")
    with open(out_jsonl, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    # emit CSV
    out_csv = os.path.join(out_dir, "findings.csv")
    if samples:
        with open(out_csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(samples[0].keys()))
            w.writeheader()
            w.writerows(samples)

    vuln_n = sum(1 for s in samples if s["label"] == "vulnerable")
    safe_n = len(samples) - vuln_n
    print(f"advisory : {DB['advisory_id']}")
    print(f"samples  : {len(samples)}  (vulnerable={vuln_n}, not_vulnerable={safe_n})")
    print(f"written  : {out_jsonl}")
    print(f"           {out_csv}")
    print("-" * 68)
    for s in samples:
        flag = "VULN" if s["label"] == "vulnerable" else "ok  "
        cve = f" [{s['cve']}]" if s["cve"] else ""
        print(f"[{flag}] {s['manifest']:30} {s['package']}=={s['installed_version']}{cve}")


if __name__ == "__main__":
    main()
