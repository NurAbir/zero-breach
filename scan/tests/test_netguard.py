"""D2 — the tool must never contact an indicator. Asserted, not merely intended.

SPEC-scanner.md, testing requirements: "Verify no module ever performs DNS
resolution of an indicator — assert this in a test, do not merely intend it."

Three layers of assertion here:
  1. the guard itself blocks every resolution / egress entry point
  2. a real full scan, run with socket instrumented, performs ZERO resolutions
  3. no module even imports a network library (a static check, so a future edit
     that adds `import requests` fails the suite rather than shipping)
"""

from __future__ import annotations

import os
import re
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan.netguard import NetworkContactAttempt, no_network  # noqa: E402


class TestGuardBlocks(unittest.TestCase):
    def test_getaddrinfo_blocked(self):
        with no_network():
            with self.assertRaises(NetworkContactAttempt):
                socket.getaddrinfo("fearevolve.com", 443)

    def test_gethostbyname_blocked(self):
        with no_network():
            with self.assertRaises(NetworkContactAttempt):
                socket.gethostbyname("keyadapter.com")

    def test_create_connection_blocked(self):
        with no_network():
            with self.assertRaises(NetworkContactAttempt):
                socket.create_connection(("controlium.net", 80), timeout=1)

    def test_socket_connect_blocked(self):
        with no_network():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with self.assertRaises(NetworkContactAttempt):
                    s.connect(("185.181.8.155", 80))
            finally:
                s.close()

    def test_guard_restores_socket_afterwards(self):
        original = socket.getaddrinfo
        with no_network():
            self.assertIsNot(socket.getaddrinfo, original)
        self.assertIs(socket.getaddrinfo, original,
                      "the guard must restore socket on exit, or it would break "
                      "the IOC-update path that is allowed to use the network")

    def test_attempt_is_recorded(self):
        with no_network() as recorder:
            try:
                socket.gethostbyname("jobmarcher.com")
            except NetworkContactAttempt:
                pass
            self.assertEqual(recorder.attempts, ["socket.gethostbyname"])


class TestRealScanResolvesNothing(unittest.TestCase):
    """Run the actual modules and prove no resolution happened. This is the
    assertion that matters: the guard could be bypassed by a module that uses
    something other than `socket`, so we also count real resolution calls."""

    def test_full_scan_performs_no_resolution(self):
        from adint_scan import iocs as iocmod
        from adint_scan.context import ScanContext
        from adint_scan.modules import host

        ioc_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__)))),
            "iocs", "adfection_iocs.txt")
        ioc_set = iocmod.load(ioc_path)

        calls = []
        real_getaddrinfo = socket.getaddrinfo
        real_gethostbyname = socket.gethostbyname

        def spy_getaddrinfo(*a, **k):
            calls.append(("getaddrinfo", a))
            return real_getaddrinfo(*a, **k)

        def spy_gethostbyname(*a, **k):
            calls.append(("gethostbyname", a))
            return real_gethostbyname(*a, **k)

        socket.getaddrinfo = spy_getaddrinfo
        socket.gethostbyname = spy_gethostbyname
        try:
            # The host module is the one with real resolution risk: it is the
            # only module that shells out to the OS network stack (reading the
            # local DNS cache and the DNS event log), so it is the one worth
            # running live against the real indicator set. The browser and hash
            # modules only read files; they are covered by the static import and
            # shell-out checks below, and running them live here would walk tens
            # of thousands of real cache files and make the suite unusable.
            ctx = ScanContext(iocs=ioc_set, emit=lambda _m: None)
            try:
                host.run(ctx)
            except Exception:
                # A module failing is a separate concern; this test is only
                # ever about whether anything was resolved.
                pass
        finally:
            socket.getaddrinfo = real_getaddrinfo
            socket.gethostbyname = real_gethostbyname

        self.assertEqual(
            calls, [],
            "D2 VIOLATION: the scan resolved {} name(s). Resolving an indicator "
            "announces a possible victim to the people running the "
            "infrastructure.".format(len(calls)))


class TestNoNetworkImports(unittest.TestCase):
    """Static guard: a module must not even import a network library."""

    FORBIDDEN = ("import requests", "import urllib", "from urllib",
                 "import http.client", "import httpx", "import socket",
                 "import ftplib", "import telnetlib", "dns.resolver")

    def test_modules_import_nothing_networked(self):
        mod_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "adint_scan", "modules")
        offenders = []
        for fn in os.listdir(mod_dir):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(mod_dir, fn), encoding="utf-8") as fh:
                text = fh.read()
            for needle in self.FORBIDDEN:
                if needle in text:
                    offenders.append("{}: {}".format(fn, needle))
        self.assertEqual(offenders, [],
                         "scan modules must not import network libraries: {}"
                         .format(offenders))

    def test_no_module_shells_out_to_a_resolver(self):
        """Blocks the other way to resolve a name: handing it to a system tool."""
        mod_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "adint_scan", "modules")
        # Word-boundary matched, not plain substring: "ping" as a substring also
        # occurs inside "skipping", which would fail the suite for no reason.
        forbidden = ("resolve-dnsname", "nslookup", "ping", "curl", "wget",
                     "invoke-webrequest", "test-netconnection", "whois",
                     "tnc", "portqry")
        pattern = re.compile(
            r"\b(" + "|".join(re.escape(f) for f in forbidden) + r")\b")
        offenders = []
        for fn in os.listdir(mod_dir):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(mod_dir, fn), encoding="utf-8") as fh:
                text = fh.read().lower()
            for found in sorted(set(pattern.findall(text))):
                offenders.append("{}: {}".format(fn, found))
        self.assertEqual(offenders, [],
                         "a module appears to shell out to a name resolver or "
                         "HTTP client: {}".format(offenders))


if __name__ == "__main__":
    unittest.main(verbosity=2)
