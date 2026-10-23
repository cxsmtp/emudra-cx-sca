"""Boundary + parser tests. These lock the version logic so a future change to
a boundary can't silently flip dataset labels. Run:

    python3 -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import detect  # noqa: E402

GO = detect.RULES["stdlib"]
CERTIFI = detect.RULES["certifi"]
CACERTS = detect.RULES["ca-certificates"]
NSS = detect.RULES["nss"]


class GoBoundary(unittest.TestCase):
    def v(self, ver):
        return detect.go_vulnerable(ver, GO)[0]

    def test_1_27_line(self):
        self.assertTrue(self.v("1.27.1"))
        self.assertTrue(self.v("1.27.2"))
        self.assertFalse(self.v("1.27.3"))
        self.assertFalse(self.v("1.27.4"))

    def test_1_26_line(self):
        self.assertTrue(self.v("1.26.9"))
        self.assertFalse(self.v("1.26.10"))
        self.assertFalse(self.v("1.26.11"))

    def test_older_lines_vulnerable(self):
        self.assertTrue(self.v("1.25.4"))
        self.assertTrue(self.v("1.20.0"))


class CertifiBoundary(unittest.TestCase):
    def test_date_compare(self):
        self.assertTrue(detect.certifi_vulnerable("2026.8.30", CERTIFI)[0])
        self.assertTrue(detect.certifi_vulnerable("2026.10.18", CERTIFI)[0])
        self.assertFalse(detect.certifi_vulnerable("2026.10.19", CERTIFI)[0])
        self.assertFalse(detect.certifi_vulnerable("2027.1.1", CERTIFI)[0])


class CaCertsBoundary(unittest.TestCase):
    def test_brew_date(self):
        self.assertTrue(detect.brew_date_vulnerable("2026-08-20", CACERTS)[0])
        self.assertTrue(detect.brew_date_vulnerable("2026-09-25", CACERTS)[0])
        self.assertFalse(detect.brew_date_vulnerable("2026-09-25_1", CACERTS)[0])
        self.assertFalse(detect.brew_date_vulnerable("2026-10-01", CACERTS)[0])


class NssBoundary(unittest.TestCase):
    def test_semver(self):
        self.assertTrue(detect.semver_vulnerable("3.130.0", NSS)[0])
        self.assertTrue(detect.semver_vulnerable("3.131.0", NSS)[0])
        self.assertFalse(detect.semver_vulnerable("3.131.1", NSS)[0])
        self.assertFalse(detect.semver_vulnerable("3.132.0", NSS)[0])


class Parsers(unittest.TestCase):
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_go_mod(self):
        got = detect.parse_go_mod(os.path.join(self.ROOT, "fixtures/go-vuln/go.mod"))
        self.assertIn(("stdlib", "1.27.1"), got)

    def test_requirements(self):
        got = detect.parse_requirements(os.path.join(self.ROOT, "fixtures/py-vuln/requirements.txt"))
        self.assertIn(("certifi", "2026.8.30"), got)

    def test_os_packages(self):
        got = detect.parse_os_packages(os.path.join(self.ROOT, "fixtures/os-vuln/packages.txt"))
        self.assertIn(("ca-certificates", "2026-08-20"), got)


class RootCauseStaysOutOfScope(unittest.TestCase):
    """Guard: no rule may claim to detect key-generation weakness."""

    def test_no_keygen_rules(self):
        banned = ("keygen", "key-generation", "weak-key", "p-384", "p384", "rng", "entropy")
        for r in detect.DB["rules"]:
            blob = (r.get("package", "") + r.get("note", "")).lower()
            for term in banned:
                self.assertNotIn(term, blob, f"root-cause term '{term}' leaked into rule {r}")


class ConfidenceGate(unittest.TestCase):
    def test_all_active_rules_certain(self):
        for r in detect.DB["rules"]:
            self.assertEqual(r["confidence"], "certain", f"active rule not certain: {r}")


if __name__ == "__main__":
    unittest.main()
