# Go fixtures — expected real-SCA result: 0 packages

Real manifest-based SCA (confirmed on Checkmarx, Oct 2026) resolves **0
packages** from these `go.mod` files, both vuln and patched. This is correct
behavior, not a fixture bug:

- The `go 1.27.x` directive is the **language/toolchain version**, not a
  dependency. SCA resolves the `require` block.
- CVE-2026-111943 is a **Go stdlib** fix, so it is not represented as any
  resolvable package — manifest SCA cannot reach it.

This repo's detector reads the `go` directive **on purpose**, to label the
toolchain exposure that SCA misses (`real_sca_status: blind_toolchain_unresolved`).
To detect it the way production tooling could, you need build metadata / an
SBOM that records the toolchain version — not `go.mod`.
