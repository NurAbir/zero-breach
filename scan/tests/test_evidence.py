"""Evidence grading is the field that stops this tool doing harm.

Collapsing "the browser connected to this host" and "this string appeared in a
cached web page" would be the tool's most damaging bug. Anyone who reads a news
article about AdFection, or who reads this project's own documentation, has those
domain names sitting in their browser cache. If that reported identically to a
real connection, the tool would send people who merely READ about the campaign to
a human-rights helpline that exists for actual victims.

So: connection-grade artifacts must grade as `contacted`, page content must grade
as `referenced`, and the report must say so plainly in both directions.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import iocs as iocmod  # noqa: E402
from adint_scan import report  # noqa: E402
from adint_scan.context import ScanContext  # noqa: E402
from adint_scan.modules import browser  # noqa: E402
from adint_scan.result import Hit, ModuleResult  # noqa: E402

TEST_DOMAIN = "synthetic-test-indicator.invalid"


def make_ctx(tmp):
    path = os.path.join(tmp, "iocs.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("{}\tdelivery\tprimary\ttest-source\n".format(TEST_DOMAIN))
    return ScanContext(iocs=iocmod.load(path), emit=lambda _m: None)


def run_browser_on(tmp, root):
    ctx = make_ctx(tmp)
    empty = os.path.join(tmp, "empty")
    os.makedirs(empty, exist_ok=True)
    saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
             browser.FIREFOX_ROOTS)
    try:
        browser.CHROMIUM_ROOTS = [("test", root)]
        browser.ROAMING = empty
        browser.LOCAL = empty
        browser.FIREFOX_ROOTS = []   # hermetic: never read the real Firefox
        return browser.run(ctx)
    finally:
        (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
         browser.FIREFOX_ROOTS) = saved


class TestHstsIsContactedGrade(unittest.TestCase):
    def test_hsts_entry_for_an_indicator_is_contacted_with_a_date(self):
        tmp = tempfile.mkdtemp(prefix="ev_")
        net = os.path.join(tmp, "User Data", "Default", "Network")
        os.makedirs(net)
        observed = datetime.datetime(2025, 3, 4, 12, 0, 0)
        wire = b""
        for label in TEST_DOMAIN.split("."):
            wire += bytes([len(label)]) + label.encode()
        wire += b"\x00"
        digest = base64.b64encode(hashlib.sha256(wire).digest()).decode()
        with open(os.path.join(net, "TransportSecurity"), "w",
                  encoding="utf-8") as fh:
            json.dump({"version": 2, "sts": [
                {"host": digest, "mode": "force-https",
                 "sts_observed": observed.timestamp(),
                 "expiry": observed.timestamp() + 31536000,
                 "sts_include_subdomains": False},
                {"host": "someOtherHashThatIsNotOurs=", "mode": "force-https",
                 "sts_observed": observed.timestamp(), "expiry": 0,
                 "sts_include_subdomains": False},
            ]}, fh)

        r = run_browser_on(tmp, os.path.join(tmp, "User Data"))
        hits = [h for h in r.hits if h.evidence == "contacted"]
        self.assertEqual(len(hits), 1, "the HSTS entry should be one contacted hit")
        self.assertEqual(hits[0].indicator, TEST_DOMAIN)
        self.assertTrue(hits[0].observed.startswith("2025-03-04"),
                        "HSTS records when it was observed; that date is the "
                        "most useful thing about this artifact")
        self.assertEqual(r.submetrics.get("hsts_entries"), 2)

    def test_unrelated_hsts_entries_do_not_match(self):
        tmp = tempfile.mkdtemp(prefix="ev_")
        net = os.path.join(tmp, "User Data", "Default", "Network")
        os.makedirs(net)
        with open(os.path.join(net, "TransportSecurity"), "w",
                  encoding="utf-8") as fh:
            json.dump({"sts": [{"host": "notOurHash=", "sts_observed": 0,
                                "expiry": 0}]}, fh)
        r = run_browser_on(tmp, os.path.join(tmp, "User Data"))
        self.assertEqual(r.hits, [])


class TestConnectionRecordsAreContactedGrade(unittest.TestCase):
    def test_connected_server_origin_is_contacted(self):
        tmp = tempfile.mkdtemp(prefix="ev_")
        net = os.path.join(tmp, "User Data", "Default", "Network")
        os.makedirs(net)
        with open(os.path.join(net, "Network Persistent State"), "w",
                  encoding="utf-8") as fh:
            json.dump({"net": {"http_server_properties": {
                "servers": [
                    {"server": "https://{}:443".format(TEST_DOMAIN),
                     "supports_spdy": True},
                    {"server": "https://unrelated.example:443"},
                ],
                "broken_alternative_services": [
                    {"host": "sub.{}".format(TEST_DOMAIN), "port": 443,
                     "protocol_str": "quic"},
                ]}}}, fh)
        r = run_browser_on(tmp, os.path.join(tmp, "User Data"))
        self.assertEqual(len(r.hits), 2,
                         "the connected origin and the subdomain in broken "
                         "alternative services should both be found")
        self.assertTrue(all(h.evidence == "contacted" for h in r.hits))
        self.assertEqual(r.submetrics.get("connection_records"), 3)

    def test_a_similar_but_different_host_does_not_match(self):
        tmp = tempfile.mkdtemp(prefix="ev_")
        net = os.path.join(tmp, "User Data", "Default", "Network")
        os.makedirs(net)
        with open(os.path.join(net, "Network Persistent State"), "w",
                  encoding="utf-8") as fh:
            # A host that merely ENDS with the indicator text, and one that
            # extends it. Neither is the indicator.
            json.dump({"net": {"http_server_properties": {"servers": [
                {"server": "https://not{}:443".format(TEST_DOMAIN)},
                {"server": "https://{}.evil.example:443".format(TEST_DOMAIN)},
            ]}}}, fh)
        r = run_browser_on(tmp, os.path.join(tmp, "User Data"))
        self.assertEqual(r.hits, [],
                         "host matching must be exact-or-subdomain, never a "
                         "substring")


class TestCacheContentIsOnlyReferenced(unittest.TestCase):
    def test_blob_match_is_referenced_not_contacted(self):
        tmp = tempfile.mkdtemp(prefix="ev_")
        cache = os.path.join(tmp, "User Data", "Default", "Cache", "Cache_Data")
        os.makedirs(cache)
        with open(os.path.join(cache, "f_000001"), "wb") as fh:
            fh.write(b"an article discussing " + TEST_DOMAIN.encode() + b" at length")
        r = run_browser_on(tmp, os.path.join(tmp, "User Data"))
        self.assertTrue(r.hits)
        self.assertTrue(all(h.evidence == "referenced" for h in r.hits),
                        "page content mentioning a domain is not contact with it")

    def test_cookie_is_contacted(self):
        tmp = tempfile.mkdtemp(prefix="ev_")
        net = os.path.join(tmp, "User Data", "Default", "Network")
        os.makedirs(net)
        con = sqlite3.connect(os.path.join(net, "Cookies"))
        con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                    "creation_utc INTEGER)")
        con.execute("INSERT INTO cookies VALUES (?, 'uid', 13300000000000000)",
                    ("." + TEST_DOMAIN,))
        con.commit()
        con.close()
        r = run_browser_on(tmp, os.path.join(tmp, "User Data"))
        self.assertTrue(r.hits)
        self.assertTrue(any(h.evidence == "contacted" for h in r.hits),
                        "a cookie exists only because that host responded")


class TestReportWording(unittest.TestCase):
    def doc(self, hits):
        m = ModuleResult("browser")
        m.ran("chromium:test")
        for h in hits:
            m.add_hit(h)
        s = iocmod.load(os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))), "iocs", "adfection_iocs.txt"))
        return report.build_document(s, [m], datetime.datetime.now())

    def test_referenced_only_result_is_explained_as_probably_not_compromise(self):
        text = report.render_human(self.doc([
            Hit("x.example", "cache", "binary match", "delivery", "primary",
                "s", "referenced")]))
        flat = " ".join(text.split())
        self.assertIn("reference-only", flat)
        self.assertIn("probably not a sign of compromise", flat)

    def test_contacted_result_is_called_out_first(self):
        text = report.render_human(self.doc([
            Hit("a.example", "cache", "binary", "delivery", "primary", "s",
                "referenced"),
            Hit("b.example", "hsts", "HSTS", "cc", "primary", "s", "contacted")]))
        self.assertIn("SERIOUS", text)
        # The contacted hit is the one surfaced in the summary; it must appear
        # before the merely-referenced one anywhere in the report.
        self.assertLess(text.index("b[.]example"), text.index("a[.]example"),
                        "the contacted hit must be listed before the merely "
                        "referenced one")

    def test_sample_on_disk_is_never_reported_as_harmless(self):
        """The whole reason the evidence contract exists: a file on disk whose
        fingerprint matches a published sample must be a SERIOUS finding with the
        preserve-the-evidence instructions, never 'probably not a sign of
        compromise'. This regressed once (hashscan set no evidence grade)."""
        from adint_scan.result import EV_ON_DISK
        text = report.render_human(self.doc([
            Hit("deadbeef" * 8, r"C:\Users\x\AppData\Roaming\evil.dll",
                "sample", "sample", "primary", "s", EV_ON_DISK)]))
        self.assertIn("serious", text.lower())
        self.assertIn("KNOWN SPYWARE FILE", text)
        self.assertNotIn("probably not a sign of compromise", text)
        self.assertIn("Do NOT delete", text)

    def test_persistence_is_never_reported_as_harmless(self):
        from adint_scan.result import EV_PERSISTENCE
        text = report.render_human(self.doc([
            Hit("b.example", r"HKCU\...\InprocServer32", "COM", "cc", "primary",
                "s", EV_PERSISTENCE)]))
        self.assertIn("serious", text.lower())
        self.assertNotIn("probably not a sign of compromise", text)
        self.assertIn("Do NOT delete", text)

    def test_unknown_evidence_grade_is_treated_as_serious(self):
        """A hit whose grade is missing or misspelled must default to SERIOUS,
        not harmless - the deny-list-of-benign design in result.is_serious."""
        text = report.render_human(self.doc([
            Hit("b.example", "somewhere", "d", "cc", "primary", "s", "")]))
        self.assertNotIn("probably not a sign of compromise", text)
        self.assertIn("serious", text.lower())

    def test_evidence_grade_is_shown_on_every_hit(self):
        text = report.render_human(self.doc([
            Hit("a.example", "loc", "d", "cc", "primary", "s", "contacted")]))
        self.assertIn("evidence: CONTACTED", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
