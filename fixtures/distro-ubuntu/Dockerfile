# Gap-flip strategy: detect eMudhra via the distro/container advisory path.
# USN-8944-1 removes "emSign ECC Root CA - G3" from ca-certificates (eMudhra),
# fixed in 20260816ubuntu0.22.04.1 on jammy. It has NO CVE — it is matched by
# package version. buildpack-deps:jammy (Ubuntu 22.04) ships ca-certificates
# pre-installed; an image predating the fix should match USN-8944-1.
FROM buildpack-deps:jammy
