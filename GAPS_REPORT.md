# Checkmarx SCA vs the eMudhra CA Compromise — Evidence Report

**What this shows:** across six real Checkmarx One scans of this repo, Checkmarx
detected **zero** eMudhra-related exposure — while correctly flagging dozens of
unrelated CVEs on the same dependency trees and container image. The eMudhra
incident is a blind spot for version/CVE-keyed scanning, and this report proves
it with scan IDs and finding data, not assertion.

- **Project:** `emudra-cx-sca` (`9a24e485-1327-4810-b5d3-b4e71be80f03`)
- **Tenant region:** deu.ast.checkmarx.net
- **Date:** 2026-10-23
- **Method:** iterative — scan, inspect findings via CxMCP, course-correct the
  fixtures to remove alternative explanations, rescan. Five course-corrections.

> Scope caveat (Certain): these results are from one project in one tenant with
> default scan configuration. "Checkmarx did not surface X here" is what the
> evidence supports; a different engine config could change the Go result. The
> eMudhra-has-no-package-CVE facts (Gaps B and C) are not config-dependent.

---

## Scan log

| # | Scan ID | Commit | Engines | Findings | What it tested |
|---|---|---|---|---|---|
| 1 | `8989659f` | f392322 | sca | 11 | Baseline Python+Go tree |
| 2 | `f92060f2` | 6abf0ee | sca | 11 | Go control: x/crypto v0.16.0 (Terrapin) |
| 3 | `6090cff4` | 5e5ff22 | sca | 11 | Go + valid go.sum (jwt-go, CVE-2020-26160) |
| 4 | `611844fd` | 8701f4d | sca | 11 | Go buildable root module + main.go |
| 5 | `90b69e5f` | e2faa4d | sca, containers | 125 | Dockerfile (ca-certificates + libnss3) |
| 6 | `874b60f2` | 1ef7a6e | sca | 11 | CycloneDX SBOM in source tree |

Dashboard: `https://deu.ast.checkmarx.net/projects/9a24e485-1327-4810-b5d3-b4e71be80f03/scans?branch=main&id=<scanId>`

---

## Gap A — the one eMudhra CVE (Go) is unreachable

**eMudhra's only CVE is `CVE-2026-111943`, a Go stdlib/toolchain fix.**

Across scans 1–4, Checkmarx surfaced **0 Go findings**. To rule out "the deps
were just clean," three course-corrections planted known-vulnerable Go code:

1. `x/crypto v0.16.0` (CVE-2023-48795, Terrapin) — not flagged.
2. A valid `go.sum` for `jwt-go v3.2.0` (CVE-2020-26160) — not flagged.
3. A buildable root module with `main.go` importing jwt-go — not flagged.

Every scan returned the **same 11 Python CVEs**, LOC=0, no Go package of any
kind. Conclusion: in this project Checkmarx SCA resolves **no** Go dependencies,
so `CVE-2026-111943` — and the entire Go ecosystem — is invisible. The eMudhra
Go CVE cannot be reached even in principle here.

**Verdict: CONFIRMED (stronger than predicted).** Not just the toolchain — the
whole Go tree produced nothing.

---

## Gap B — certifi is resolved, but its eMudhra exposure is silent

The repo ships `certifi==2026.8.30` (pre-fix — still trusts the compromised
`emSign ECC Root CA – G3`). Checkmarx resolved the Python tree and flagged 11
CVEs on certifi's **siblings**:

- `CVE-2024-47081` — requests 2.32.3 (.netrc credential leak)
- `CVE-2025-50181`, `CVE-2025-50182`, `CVE-2026-21441` — urllib3 2.2.3 (SSRF/redirect, decompression bomb)
- …and 7 more on requests/urllib3.

**certifi findings: 0.** No `GHSA-6q48-6c7w-9gw2`, no emSign/eMudhra entry — on
either the pre-fix or fixed certifi in the repo.

**Why (Certain):** eMudhra produced **no certifi CVE**. The Python ecosystem
treats it as a trust-bundle content update (GHSA advisory only). CVE-keyed SCA
has nothing to match, so a scanner that flags four urllib3/requests issues on the
same tree says nothing about the certifi that still trusts a compromised CA.

**Verdict: CONFIRMED.** The tree is scanned, neighbours are flagged, eMudhra is
silently absent.

---

## Gap C — the container engine sees the trust packages, still no eMudhra signal

`packages.txt` is not a manifest (SCA resolves 0 from it). Course-correction: a
Dockerfile (`debian:bullseye` + `ca-certificates` + `libnss3`) scanned by the
containers engine, which builds a full OS-package SBOM.

Scan 5 returned **125 findings** (10 critical, 44 high), correctly attributed to
image packages — e.g. `CVE-2026-5450` (glibc 2.31), `CVE-2026-13221` /
`CVE-2026-8376` (perl 5.32.1), `CVE-2023-45853` (zlib), `CVE-2019-8457` (sqlite),
all tagged to `fixtures/os-vuln/Dockerfile`, image `debian:bullseye`.

So the engine resolves the image and enumerates its OS packages — including the
`ca-certificates` and `libnss3` explicitly installed. Yet **none of the 125 is an
eMudhra/emSign finding**, because the eMudhra fix (`ca-certificates 2026-09-25_1`,
`nss 3.131.1`) is a bundle-content change with **no package CVE**.

**Verdict: CONFIRMED.** Even the engine that *does* see ca-certificates/nss has
no eMudhra entry to report.

---

## Gap D — SBOM analysis (attempted): not reachable via source scan, and feed-bound anyway

A CycloneDX SBOM (`sbom/bom.json`) was committed listing positive controls
(`lodash 4.17.11` → CVE-2019-10744 critical, `requests 2.32.3`, `jwt-go 3.2.0`
→ CVE-2020-26160) plus the eMudhra targets (certifi 2026.8.30, Go stdlib/
toolchain 1.27.1, ca-certificates, nss).

Scan 6 returned the **same 11 Python CVEs, zero criticals** — the SBOM controls
did not fire. A normal SCA **source scan does not ingest a CycloneDX `bom.json`**
from the tree; Checkmarx's SBOM analysis is a separate import flow (UI / dedicated
API) not exposed through the CxMCP tools used here, so it could not be driven in
this loop.

Two conclusions:
- **Not reachable here:** SBOM risk analysis isn't triggered by committing an SBOM
  and running SCA; it needs the explicit import feature.
- **Even if reached, feed-bound:** SBOM analysis is still CVE/advisory matching
  against the same database. For certifi/ca-certificates/nss (no eMudhra package
  CVE) it would still report nothing. The single open question SBOM could answer
  is Gap A — whether an explicit `golang` toolchain component makes CVE-2026-111943
  matchable — and that requires Checkmarx's SBOM import path to test.

**Verdict: INCONCLUSIVE for Go via SBOM (import path unavailable here);
NEGATIVE for the bundle packages (same feed, no CVE to match).**

---

## Summary: what Checkmarx flagged vs. missed, on identical inputs

| | Flagged by Checkmarx | Missed by Checkmarx |
|---|---|---|
| Python tree | 11 CVEs (requests, urllib3) | certifi eMudhra exposure (GHSA-6q48-6c7w-9gw2) |
| Go tree | 0 (nothing resolved) | CVE-2026-111943 (the only eMudhra CVE) |
| Container image | 125 OS-package CVEs | ca-certificates / nss eMudhra bundle update |

**The through-line:** version/CVE-keyed SCA detects *known-vulnerable package
versions*. The eMudhra incident mostly did not produce package CVEs — it was a CA
failure remediated by trust-bundle content updates — and its one CVE lives in a
place (Go stdlib) this scanner did not resolve. Result: a serious,
internet-wide trust compromise is invisible to the dependency scan, even as that
same scan flags dozens of lesser, unrelated issues on the very same inputs.

**Implication:** trust-store / SBOM-content checks are needed *alongside*
CVE-based SCA. This repo's `vuln_db.json` + detector is a custom ruleset that
fills exactly that gap.

---

## Appendix — reproduce

```bash
# Local detector (the custom ruleset SCA lacks)
python3 detect.py && python3 -m unittest discover -s tests -v

# Re-run the Checkmarx scans (via CxMCP): project 9a24e485-1327-4810-b5d3-b4e71be80f03
# engines sca (+ containers for the Dockerfile fixture), commits per the scan log above.
```

Fixtures were iterated during the investigation (Go control deps, `go-app/`
buildable module, `os-vuln/Dockerfile`); see commit history f392322..e2faa4d.
