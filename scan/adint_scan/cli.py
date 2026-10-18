"""Command-line entry point and orchestration.

  adint-scan [--deep] [--quick] [--json <path>] [--iocs <path>]

Default behaviour (no flags): read-only tier-1 IOC match across the browser, hash
and host modules, under the no-network guard. Requires no administrator (D7).

The system-writing tier-5 feature (--arm / --undo) is HELD BACK from this release.
Its code is in arm.py but is not wired to the CLI: a review found its --undo path
could, from a journal file any program can write, delete every scheduled task on
the machine and still report success, and could shrink the DNS log and destroy the
history it had collected. None of that is acceptable in a tool at-risk people run,
and the one thing it was for - turning on DNS history - is a single manual command
the report already prints. It returns once the undo path has been rewritten with
the write-ahead journal and per-step safety the review specifies.

Exit codes: 0 = no indicators found (CLEAN or with gaps); 2 = indicators matched;
1 = the scan could not be set up (bad IOC file, etc.).
"""

from __future__ import annotations

import argparse
import datetime
import os
import sys
import time
from typing import List

from . import __version__
from .context import ScanContext
from .iocs import IocError, load
from .netguard import no_network
from .report import V_HITS, build_document, render_human, write_json
from .result import ModuleResult


def _force_utf8_io() -> None:
    """Make stdout/stderr encode UTF-8 regardless of the console code page.

    On a stock Windows Python the streams default to the legacy code page (cp1252
    in much of the world). Printing a non-Latin browser-profile name or username -
    Arabic, Hebrew, Persian, Cyrillic, CJK, i.e. exactly this tool's users - then
    raises UnicodeEncodeError and the whole scan dies with a traceback instead of
    a report, and worst of all when writing the report file AFTER the work is
    done. Reconfiguring here fixes it without depending on the caller remembering
    `-X utf8`. errors='backslashreplace' guarantees output can never crash."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass  # very old Python, or a stream that is not reconfigurable


def _default_ioc_path() -> str:
    # scan/adint_scan/cli.py -> repo root is two levels up; IOCs live in iocs/.
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    return os.path.join(repo, "iocs", "adfection_iocs.txt")


def _parse(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="adint-scan",
        description="Local, read-only check for AdFection / Candiru indicators. "
                    "A clean result is NOT a clean bill of health.")
    p.add_argument("--quick", action="store_true",
                   help="skip fingerprinting every file (roughly halves the "
                        "runtime). The skipped check is reported as a gap, not "
                        "as clean.")
    p.add_argument("--deep", action="store_true",
                   help="tier 2: full persistence sweep (noisy; most hits are "
                        "legitimate). Opens with a warning.")
    p.add_argument("--json", metavar="PATH",
                   help="also write the machine-readable report to PATH.")
    p.add_argument("--iocs", metavar="PATH", default=_default_ioc_path(),
                   help="indicator file (default: bundled adfection_iocs.txt).")
    p.add_argument("--version", action="version",
                   version="adint-scan {}".format(__version__))
    return p.parse_args(argv)


def _run_modules(ctx: ScanContext) -> List[ModuleResult]:
    # Imported lazily so a platform-specific import error degrades to UNKNOWN
    # rather than killing the whole run.
    from .modules import browser, hashscan, host

    results: List[ModuleResult] = []
    # The entire scan runs inside the no-network guard (D2).
    with no_network():
        for mod in (browser, hashscan, host):
            # --quick drops the file-fingerprint check. It costs ~45% of the
            # whole scan (345s of 774s measured) to look for ONE published file
            # hash, and Candiru compiles a fresh build per target, so another
            # victim's file would not match it anyway. Skipping is reported as a
            # GAP, never as clean (D3) - a check that did not run has not
            # cleared anything.
            if mod is hashscan and ctx.quick:
                r = ModuleResult(hashscan.NAME)
                r.could_not_run(
                    "file-fingerprints",
                    "skipped by --quick. No file on this machine was "
                    "fingerprinted, so a known sample sitting on disk would "
                    "not have been found. Re-run without --quick to include it")
                results.append(r)
                ctx.emit("[*] skipping file fingerprints (--quick)")
                continue
            ctx.emit("[*] running check: {}".format(mod.NAME))
            started = time.time()
            try:
                result = mod.run(ctx)
            except Exception as exc:  # a module must never crash the whole tool
                result = ModuleResult(mod.NAME)
                result.could_not_run(mod.NAME, "module error: {}".format(exc))
            result.duration_s = time.time() - started
            ctx.emit("[*]   {} finished in {:.0f}s".format(
                mod.NAME, result.duration_s))
            results.append(result)
        if ctx.deep:
            # Tier 2 is the last item in the build order and is not written yet.
            # An advertised flag must not crash, and it must not quietly report
            # a clean sweep it never performed: the honest result is UNKNOWN.
            try:
                from .modules import deep as deepmod
            except ImportError:
                r = ModuleResult("deep")
                r.could_not_run(
                    "persistence-sweep",
                    "tier 2 (--deep) is not implemented yet — no full "
                    "persistence sweep was performed. Use --arm --baseline and "
                    "--arm --baseline-diff, which answer a sharper question: "
                    "what changed since a known-good inventory")
                results.append(r)
            else:
                ctx.emit("[*] running module: {}".format(deepmod.NAME))
                try:
                    results.append(deepmod.run(ctx))
                except Exception as exc:
                    r = ModuleResult(deepmod.NAME)
                    r.could_not_run(deepmod.NAME, "module error: {}".format(exc))
                    results.append(r)
    return results


def main(argv: List[str] = None) -> int:
    _force_utf8_io()
    args = _parse(sys.argv[1:] if argv is None else argv)

    try:
        iocs = load(args.iocs)
    except IocError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1

    if args.deep:
        print("WARNING (--deep): a full persistence sweep lists many legitimate\n"
              "entries. Most findings are NOT malicious. Read each one; do not\n"
              "panic at an unsigned binary in a user-writable path.\n",
              file=sys.stderr)

    ctx = ScanContext(iocs=iocs, deep=args.deep, quick=args.quick)
    started = datetime.datetime.now()
    results = _run_modules(ctx)

    document = build_document(iocs, results, started)
    print(render_human(document))

    if args.json:
        try:
            write_json(document, args.json)
            print("\n[wrote JSON report to {}]".format(args.json), file=sys.stderr)
        except OSError as exc:
            # The human report already printed; a failed JSON write must not bury
            # it under a traceback. Report the failure and keep the verdict code.
            print("\n[could not write JSON report to {}: {}]".format(
                args.json, exc), file=sys.stderr)

    return 2 if document["verdict"]["status"] == V_HITS else 0


if __name__ == "__main__":
    raise SystemExit(main())
