# SCOPE — what this detects, what real SCA misses, and why

Read this before using the labels. The dataset's value is the boundary it draws;
blur it and the labels become noise.

## The core finding

The eMudhra CA key compromise is **almost entirely invisible to version-based
SCA as it actually ships** — not because the tool is weak, but because of how
the incident was remediated. This repo's detector uses a **custom advisory**
(`vuln_db.json`) that CVE-keyed SCA feeds do not contain. It fills the gap; it
does not replicate a feed.

Confirmed against a live Checkmarx SCA scan of the fixtures (Oct 2026):

| Fixture | What SCA did | Why |
|---|---|---|
| `fixtures/go-vuln/go.mod` | resolved **0 packages** | The Go **toolchain/stdlib** is not a resolved dependency. CVE-2026-111943 lives there, so manifest SCA can't reach it. |
| `fixtures/go-patched/go.mod` | resolved **0 packages** | same — the `go` directive is a language version, not a package. |
| `fixtures/py-patched/requirements.txt` | resolved 5 packages, **0 eMudhra risk on certifi** | No certifi CVE exists for eMudhra (GHSA-6q48-6c7w-9gw2 only; treated as a bundle update). Correct: this is the fixed version anyway. |
| `fixtures/py-vuln/requirements.txt` | resolved 5 packages | **Pending user confirmation** — whether the older certifi carries any eMudhra finding, or the manifest warning is unrelated resolution noise (urllib3/requests carry their own, non-eMudhra CVEs). |

## `real_sca_status` on every sample

- `caught_by_feed` — a package CVE/advisory exists; a CVE-keyed feed matches it.
- `blind_no_advisory` — no package CVE; remediated by a trust-bundle content
  update. Feeds have nothing to match. (certifi, ca-certificates, nss)
- `blind_toolchain_unresolved` — a CVE exists, but in the stdlib/toolchain,
  which manifest SCA does not resolve as a package. (Go)

As of this commit, **0 of the covered samples are `caught_by_feed`.** That is the
headline, not a defect in the fixtures.

## Why the blind spots exist

1. **A CA compromise is not a code vulnerability in your dependency.** certifi,
   ca-certificates and nss were never "vulnerable" in the code sense — they
   *trusted* a CA that turned out to be compromised. Remediation = ship a new
   bundle with the root removed. SCA models known-vulnerable *code versions*,
   not trust-bundle *contents*.
2. **No CVE → no feed entry → no match.** certifi has received CVEs for past CA
   removals (TrustCor CVE-2022-23491, e-Tugra CVE-2023-37920, GLOBALTRUST
   CVE-2024-39689), but eMudhra was filed as GHSA-6q48-6c7w-9gw2 with no certifi
   CVE. The only CVE in the whole incident is the Go one.
3. **The one CVE is unreachable from a manifest.** CVE-2026-111943 is a Go
   stdlib fix. SCA resolves the `require` block, not the toolchain, so `go.mod`
   yields 0 relevant packages (observed above).

## Out of scope (unchanged)

- eMudhra's root cause (weak key generation) — bespoke CA tooling, not a
  dependency. No SCA engine sees it.
- Trust-store *presence* — whether an image/app actually ships the compromised
  certs in its CA bundle. That is an SBOM / filesystem / config scan.
- Runtime behavior — whether a client checks revocation (OneCRL/CRLSet/OCSP),
  or pins certs in code. Invisible in a manifest.
- Electron, Rust `webpki-roots`, Bun, FreeBSD `ca_root_nss` — no confirmed fixed
  version; held in `pending_confirmation`, never labeled.

## So what is this good for

A labeled corpus of **what dependency scanning structurally misses in a CA-
compromise event, and the detection basis each case would require** — the
trust-store blind spot the industry is now writing up. Use it to argue for
trust-store / SBOM-content checks alongside CVE-based SCA, not as a claim that
SCA catches eMudhra.
