# CLAUDE.md — working rules for this repo

PoC: an SCA-style detector + **labeled dataset** for the eMudhra intermediate-CA
key compromise (advisory `EMUDHRA-CA-2026-10`). The dataset is meant to be
shared as ground-truth learning data, so label integrity is the whole point.

## Non-negotiable constraints (do not relax without the maintainer's say-so)

1. **Root cause is OUT OF SCOPE.** eMudhra's weak key generation (P-384 keys
   that were integers below 256; one was `4`) was bespoke logic in their signing
   tooling, not a dependency. SCA cannot detect it. Never add a rule or sample
   that implies SCA catches the key-generation defect. The detectable vector is
   only: *a client/runtime version that still trusts the eight compromised
   intermediates because it predates the fix.*

2. **Labels are evidence-bound.** Every rule in `vuln_db.json` carries a
   `confidence`. Only `certain` boundaries may produce rows in the labeled
   dataset. Anything whose fixed version is not confirmed from a primary source
   (vendor advisory, root-program post, release notes) stays in
   `pending_confirmation` and MUST NOT be given a guessed boundary.

3. **One source of truth.** Version boundaries live only in `vuln_db.json`.
   Do not hardcode versions in `detect.py` or the fixtures' expected labels.

4. **Tests lock the boundaries.** If you change a boundary, update
   `tests/test_detect.py` in the same change and explain why in the commit.

## Confirmed boundaries (primary-sourced)
- Go stdlib crypto/x509 — fixed 1.27.3 (1.27.x) / 1.26.10 (1.26.x) — CVE-2026-111943
- PyPI `certifi` — fixed 2026.10.19
- OS `ca-certificates` (brew) — fixed 2026-09-25_1
- `nss` — fixed 3.131.1

## Pending (never label until confirmed)
Electron · Rust `webpki-roots` · Bun · FreeBSD `ca_root_nss`

## Layout
- `detect.py`        — SCA-style matcher; writes to `out/`
- `vuln_db.json`     — advisory rules (the only place boundaries live)
- `fixtures/`        — vulnerable/patched manifest pairs per ecosystem
- `tests/`           — boundary + parser unit tests (stdlib `unittest`)
- `docs/attack_vector.md` — the vector definition and provenance
- `out/`             — generated dataset/CSV (gitignored, reproducible)

## Commands
- Generate dataset: `python3 detect.py`
- Run tests:        `python3 -m unittest discover -s tests -v`

## Known modeling caveat
`go.mod`'s `go` directive is not the build toolchain version. Production SCA
reads the toolchain from build metadata/SBOM. The Go fixture uses `go.mod` for
simplicity — if you harden the corpus, add a CycloneDX SBOM fixture and note the
signal source in the sample.
