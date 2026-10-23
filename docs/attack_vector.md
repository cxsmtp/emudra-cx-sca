# eMudhra CA Key Compromise — SCA-Detectable Attack Vector

## Two separate failures (do not conflate in the dataset)

**1. Root cause @ eMudhra — NOT SCA-detectable.**
A modified key-generation script added a wrap/unwrap test for keys intended
for export. Strong P-384 keys were created in an HSM, but flawed code emitted
weaker alternatives. All eight affected private keys were integer values below
256 (one key = the number `4`). This is bespoke logic in eMudhra's own signing
tooling — a code defect, not a dependency vulnerability. SAST/secrets may touch
it; **SCA cannot**. Label these as `out_of_scope_sca`.

**2. Downstream exposure @ everyone else — SCA-detectable.**
Browsers, OSes, language runtimes and apps trusted the eight compromised
eMudhra intermediates. The fix is client-side: upgrade the runtime / trust
bundle so the compromised chain is rejected. Any build still on a pre-fix
version is the vulnerable sample. **This is the PoC target.**

## The vector, precisely

> A dependency or runtime whose version predates the eMudhra-distrust fix, and
> therefore still trusts (does not block) the eight compromised intermediate CAs.

SCA matches this exactly like any CVE: parse the manifest/lockfile/SBOM, read
the installed version, compare against the fixed version for that ecosystem.

## Confirmed version boundaries (use these as ground-truth labels)

| Ecosystem | Package | Fixed version | Vulnerable = version below | CVE / advisory | Confidence |
|---|---|---|---|---|---|
| Go (stdlib crypto/x509) | toolchain | 1.27.3 (1.27.x), 1.26.10 (1.26.x) | any 1.27.0–1.27.2, 1.26.0–1.26.9, ≤1.25.x | CVE-2026-111943 | Certain |
| PyPI | certifi | 2026.10.19 | any date < 2026.10.19 | drops emSign ECC Root CA – G3 | Certain |
| Homebrew / OS | ca-certificates | 2026-09-25_1 | any bundle < 2026-09-25_1 | excludes emSign roots + AAA Certificate Services | Certain |
| NSS | nss | 3.131.1 | < 3.131.1 | OneCRL / trust list update | Certain |
| Firefox (app, not pkg) | firefox | 158.0.1, ESR 115.43.1, ESR 153.5.1 | below those on each line | CVE-2026-113470 / MFSA 2026-111 | Certain |

## Pending confirmation — DO NOT label until version boundary verified

- Electron — "patched versions available," exact number not yet confirmed.
- Rust `webpki-roots` — patched, version not confirmed.
- Bun, FreeBSD `ca_root_nss` — listed pending as of 2026-10-21.

Keep these in `pending_confirmation` so they never produce ground-truth labels
with a guessed boundary.

## The eight compromised intermediates (for the adjacent trust-store check)

TLS: EM DV TLS CA – G3B (eMudhra BV, NL), EM DV TLS CA – G3C (eMudhra Inc, US),
EM OV TLS CA – G3C (the `4` key), plus three further TLS intermediates.
Code-signing: two intermediates trusted by Microsoft.
Roots: emSign ECC Root CA – G3 (distrust requested), emSign Root TLS CA – G3,
emSign Root CA – G1 (under review by Chrome).

> Note: detecting whether a container/app still *ships* these certs in its trust
> bundle is an SBOM / config scan, not classic version-based SCA. Kept separate
> in the dataset as `trust_store_scan` so SCA labels stay honest.

## Status facts (as of 2026-10-21)
- All eight intermediates revoked 2026-10-18. No malicious use confirmed.
- ~30,000 certificates estimated to need migration (97% issued via ACME).
