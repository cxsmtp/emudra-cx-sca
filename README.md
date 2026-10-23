# emudhra-sca-poc

An SCA-style detector and **labeled dataset** for the eMudhra intermediate-CA
key compromise (advisory `EMUDHRA-CA-2026-10`, disclosed 2026-10-20).

The detector matches installed package/runtime versions in a manifest against
confirmed fixed-version boundaries for the advisory — the same signal classic
Software Composition Analysis produces: *"this dependency version is still
vulnerable."* It does **not** attempt to detect eMudhra's root-cause weak-key
generation, which is out of SCA scope (see `docs/attack_vector.md`).

## Quick start

```bash
python3 detect.py                              # writes out/dataset.jsonl + out/findings.csv
python3 -m unittest discover -s tests -v       # run boundary + parser tests
```

No dependencies — standard library only (Python 3.8+).

## What you get

- `out/dataset.jsonl` — one JSON object per sample: ecosystem, package,
  installed version, fixed version, CVE, `label` (vulnerable / not_vulnerable),
  `confidence`, and a traceable `reason`.
- `out/findings.csv` — the same, flat.

Every label traces to a `certain` boundary in `vuln_db.json`. Unconfirmed
ecosystems (Electron, Rust `webpki-roots`, Bun, FreeBSD) are held in
`pending_confirmation` and never labeled.

## Covered ecosystems (confirmed boundaries)

| Ecosystem | Package | Fixed | CVE |
|---|---|---|---|
| Go | stdlib crypto/x509 | 1.27.3 / 1.26.10 | CVE-2026-111943 |
| PyPI | certifi | 2026.10.19 | — |
| OS | ca-certificates | 2026-09-25_1 | — |
| OS | nss | 3.131.1 | — |

## Project rules

See `CLAUDE.md` — root-cause is out of scope, labels are evidence-bound, and
boundaries live only in `vuln_db.json`.
