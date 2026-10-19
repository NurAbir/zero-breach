"""Vivaldi (Chromium-based) is discovered and scanned like the other Chromium browsers."""

import os
import sys
import unittest
from unittest.mock import patch

sys.path[:0] = [os.path.dirname(os.path.dirname(__file__)), os.path.dirname(__file__)]

from test_browser_launch import (BrowserLaunchBase, TEST_DOMAIN,
                                 chromium_history_db)
from adint_scan.modules import browser


class TestVivaldiRoots(unittest.TestCase):
    def roots(self, platform, **env):
        with patch.object(browser.sys, "platform", platform), \
                patch.object(browser, "LOCAL", env.get("local", "")), \
                patch.object(browser.os.path, "expanduser", lambda p: "/home/u"):
            return dict(browser._chromium_roots())

    def test_windows(self):
        roots = self.roots("win32", local="C:\\L")
        self.assertIn("vivaldi", roots)
        self.assertTrue(roots["vivaldi"].endswith(os.path.join("Vivaldi", "User Data")))

    def test_macos(self):
        roots = self.roots("darwin")
        self.assertTrue(roots["vivaldi"].endswith(os.path.join("Application Support", "Vivaldi")))

    def test_linux(self):
        roots = self.roots("linux")
        self.assertTrue(roots["vivaldi"].endswith(os.path.join(".config", "vivaldi")))
        self.assertIn("vivaldi-snapshot", roots)
        self.assertIn("vivaldi-flatpak", roots)


class TestVivaldiScan(BrowserLaunchBase):
    def test_history_hit_in_vivaldi_profile(self):
        ud = os.path.join(self.tmp, "Vivaldi", "User Data")
        chromium_history_db(os.path.join(ud, "Default", "History"),
                            "https://{}/x".format(TEST_DOMAIN))
        browser.CHROMIUM_ROOTS = [("vivaldi", ud)]
        browser.ROAMING = browser.LOCAL = self.empty
        result = browser.run(self.ctx)
        self.assertTrue(result.hits, "an indicator in Vivaldi history must be found")

    def test_locked_note_names_vivaldi(self):
        for path in (r"C:\Users\u\AppData\Local\Vivaldi\User Data\Default\History",
                     "/home/u/.config/vivaldi/Default/History"):
            note = browser._locked_note(path, PermissionError(13, "locked"))
            self.assertIn("Vivaldi", note)


if __name__ == "__main__":
    unittest.main()
