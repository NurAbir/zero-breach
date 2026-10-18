"""The known-fixed-path check (host module): HW.sys and similar driver drops.

A file at a known malware path is a lead, but the path alone is not proof - the
name can be legitimate. So the check must: find a present file, fingerprint it,
raise a serious hit ONLY when the fingerprint matches a known-bad hash, and
otherwise record a pointer note without alarming.
"""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import iocs as iocmod
from adint_scan.context import ScanContext
from adint_scan.modules import host
from adint_scan.result import EV_ON_DISK


def _ioc_set_with_hash(tmp, digest):
    p = os.path.join(tmp, "iocs.txt")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        # A harmless domain so the set is non-empty, plus the driver hash.
        fh.write("synthetic-indicator.invalid\tdelivery\tprimary\tt\n")
        fh.write("{}\tsample\tsecondary\tavast-2022\n".format(digest))
    return iocmod.load(p)


class TestKnownPaths(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32" or True,
                         "the check reads SystemRoot; the logic is platform-neutral")
    def _run_with_fake_sysroot(self, sysroot, ioc_set):
        r = host.ModuleResult("host")
        ctx = ScanContext(iocs=ioc_set, emit=lambda _m: None)
        saved = os.environ.get("SystemRoot")
        os.environ["SystemRoot"] = sysroot
        try:
            host._check_known_paths(r, ctx)
        finally:
            if saved is None:
                os.environ.pop("SystemRoot", None)
            else:
                os.environ["SystemRoot"] = saved
        return r

    def _plant_hwsys(self, sysroot, content):
        d = os.path.join(sysroot, "System32", "drivers")
        os.makedirs(d)
        with open(os.path.join(d, "HW.sys"), "wb") as fh:
            fh.write(content)

    def test_no_file_present_is_a_clean_ran_check(self):
        tmp = tempfile.mkdtemp(prefix="kp_")
        ioc = _ioc_set_with_hash(tmp, "a" * 64)
        r = self._run_with_fake_sysroot(tmp, ioc)
        self.assertEqual(r.hits, [])
        self.assertTrue(any(c.name == "known-paths" and c.ran for c in r.checks))

    def test_known_bad_hash_is_a_serious_on_disk_hit(self):
        tmp = tempfile.mkdtemp(prefix="kp_")
        content = b"this-is-the-known-bad-driver-build"
        digest = hashlib.sha256(content).hexdigest()
        self._plant_hwsys(tmp, content)
        ioc = _ioc_set_with_hash(tmp, digest)
        r = self._run_with_fake_sysroot(tmp, ioc)
        self.assertEqual(len(r.hits), 1, "the known-bad driver must be a hit")
        self.assertEqual(r.hits[0].evidence, EV_ON_DISK)
        self.assertIn("HW.sys", r.hits[0].location)

    def test_same_named_but_different_file_is_a_note_not_a_hit(self):
        tmp = tempfile.mkdtemp(prefix="kp_")
        self._plant_hwsys(tmp, b"a legitimate unrelated HW.sys driver")
        # The IOC set carries a DIFFERENT hash, so this file must not match.
        ioc = _ioc_set_with_hash(tmp, "b" * 64)
        r = self._run_with_fake_sysroot(tmp, ioc)
        self.assertEqual(r.hits, [], "a same-named file that does not match a "
                         "known-bad hash must not raise a hit")
        self.assertTrue(any("HW.sys" in n for n in r.notes),
                        "but its presence should be noted for a human to look at")


if __name__ == "__main__":
    unittest.main(verbosity=2)
