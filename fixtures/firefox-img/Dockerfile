# CVE-2026-113470 test: Firefox before 158.0.1 still trusts the compromised
# emSign root (the eMudhra OneCRL fix landed in 158.0.1 / ESR 115.43.1).
# This Selenium image bundles an older Firefox, so it should be in range if
# Checkmarx carries the MFSA 2026-111 / CVE-2026-113470 mapping.
FROM selenium/standalone-firefox:4.27.0
