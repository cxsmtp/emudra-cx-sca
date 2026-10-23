# Gap C fixture: an image that ships ca-certificates (and nss libs).
# The eMudhra remediation is a ca-certificates/nss bundle content update with
# NO package CVE. A container scan enumerates these OS packages, so if it had an
# eMudhra signal it would show here. It does not — that absence is the gap.
FROM debian:bullseye
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libnss3 \
 && rm -rf /var/lib/apt/lists/*
