"""Build a single-file, self-contained copy of the scanner.

One .py file someone can be emailed, read, and run. It embeds the indicator data
so there is no second file to lose, and it deliberately OMITS arm.py, so the
result cannot change anything on the machine it runs on - which is a much better
thing to be able to promise someone receiving a script from a friend.

The only transformation applied to the module sources is renaming the two names
that collide across the three scan modules (NAME and run), plus dropping the
package-internal imports, since everything lands in one namespace.
"""
import io
import os
import re
import sys
import time

# Defaults assume this file sits in <root>/build/. Both can still be overridden
# on the command line, which is how the one-off test builds were made.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = sys.argv[1] if len(sys.argv) > 1 else ROOT
OUT = (sys.argv[2] if len(sys.argv) > 2
       else os.path.join(SRC, "dist", "adint-scan-standalone.py"))

PKG = os.path.join(SRC, "scan", "adint_scan")
IOC = os.path.join(SRC, "iocs", "adfection_iocs.txt")


def read(path):
    return io.open(path, encoding="utf-8").read()


def strip_imports(text):
    """Remove package-internal imports and __future__ (re-emitted once at top).

    Handles a parenthesised multi-line import,
        from .result import (A, B,
                             C, D)
    by consuming lines until the parentheses balance. Dropping only the first
    line of such a statement would leave its continuation lines behind as stray
    indented text - a syntax error in the bundled file.
    """
    out = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        is_future = s.startswith("from __future__")
        is_local = bool(re.match(r"^from \.+[A-Za-z_. ]* import ", s)
                        or re.match(r"^from \.+ import ", s))
        if is_future or is_local:
            # If the import opens a parenthesis that does not close on this line,
            # skip the whole continuation.
            depth = line.count("(") - line.count(")")
            i += 1
            while depth > 0 and i < len(lines):
                depth += lines[i].count("(") - lines[i].count(")")
                i += 1
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def namespace(text, suffix):
    """Rename the two identifiers that collide between scan modules."""
    text = re.sub(r"(?<![A-Za-z0-9_])NAME(?![A-Za-z0-9_])",
                  "NAME_" + suffix.upper(), text)
    text = text.replace("def run(ctx)", "def run_{}(ctx)".format(suffix))
    return text


parts = []
A = parts.append

ioc_text = read(IOC)
ioc_mtime = os.path.getmtime(IOC)

A('#!/usr/bin/env python3')
A('# -*- coding: utf-8 -*-')
A('"""Zero Breach (single-file build) - local check for published AdFection /')
A('Candiru spyware indicators.')
A('')
A('WHAT THIS IS')
A('  A read-only checker. It searches this computer\'s own leftover records -')
A('  browser cache and cookies, file fingerprints, auto-start registrations, the')
A('  DNS resolver cache - for {} indicators published by The Citizen Lab'.format(
    len([l for l in ioc_text.split("\n")
         if l.strip() and not l.strip().startswith("#")])))
A('  (Exposing AdFection, 2026-10-15) and Recorded Future (CTA-2025-0805).')
A('')
A('WHAT IT WILL NOT DO')
A('  - It never changes anything. The only file it writes is its own report. No')
A('    registry writes, no settings touched: it has no code path of any kind')
A('    that can modify this machine.')
A('  - It never uses the network. Not to check for updates, not for telemetry,')
A('    and above all never to look up an indicator - resolving a spyware domain')
A('    would announce the person running this to whoever operates it. The whole')
A('    scan runs inside a guard that makes network access raise an error.')
A('  - It never decrypts anything. It reads cookie HOST NAMES only, never cookie')
A('    values. Decrypting those is what credential-stealing malware does; this')
A('    has no need for it and no code to do it.')
A('')
A('IMPORTANT - WHAT A CLEAN RESULT MEANS')
A('  "No known indicators found" means exactly that, and nothing more. It is not')
A('  a clean bill of health. Spyware of this grade is built to defeat this class')
A('  of check, most of the evidence it would leave expires within weeks, and')
A('  Windows does not record DNS history unless someone turned it on. If you have')
A('  real reason for concern, the answer is expert help, not this script:')
A('    Access Now Digital Security Helpline  https://www.accessnow.org/help/')
A('    Amnesty International Security Lab    https://securitylab.amnesty.org/')
A('    The Citizen Lab                       https://citizenlab.ca/')
A('')
A('LICENCE')
A('  Software: Apache License 2.0. Indicator data: CC0 1.0 (public domain).')
A('  Copyright 2026 archivegenocide.com. Provided AS IS, without warranty.')
A('  Full text, and the sources every indicator came from:')
A('    https://github.com/interplains/zero-breach')
A('  NOT affiliated with, and NOT endorsed by, The Citizen Lab, Confiant,')
A('  Recorded Future, Amnesty International or Access Now.')
A('')
A('USAGE')
A('  python -X utf8 adint-scan-standalone.py')
A('  python -X utf8 adint-scan-standalone.py --json report.json')
A('')
A('Requires Python 3.7 or newer. Needs no administrator. Windows gets all four')
A('checks; macOS and Linux get the browser and file checks.')
A('"""')
A('from __future__ import annotations')
A('')
A('import argparse')
A('import datetime')
A('import sys')
A('import time')
A('')
A('__version__ = "0.1.0 (single-file build)"')
A('')
A('# --- embedded indicator data ------------------------------------------------')
A('# The real file is iocs/adfection_iocs.txt in the project. Its provenance')
A('# comments are kept verbatim so every indicator can be traced to its report.')
A('IOC_BUILD_EPOCH = {!r}  # mtime of the indicator file at build time'.format(
    ioc_mtime))
A("IOC_DATA = r'''")
A(ioc_text.replace("'''", "' ' '"))
A("'''")
A('')

for label, fname in (("result", "result.py"),
                     ("iocs", "iocs.py"),
                     ("netguard", "netguard.py"),
                     ("context", "context.py"),
                     ("report", "report.py")):
    A('# --- {} {}'.format(label, '-' * max(0, 72 - len(label))))
    A(strip_imports(read(os.path.join(PKG, fname))))
    A('')

for label, fname, suffix in (("modules/browser", "browser.py", "browser"),
                             ("modules/hashscan", "hashscan.py", "hash"),
                             ("modules/host", "host.py", "host")):
    A('# --- {} {}'.format(label, '-' * max(0, 72 - len(label))))
    A(namespace(strip_imports(read(os.path.join(PKG, "modules", fname))), suffix))
    A('')

A('# --- entry point ------------------------------------------------------------')
A('''

def _load_embedded_iocs(path=None):
    """Parse the embedded indicator data, or an external file if one is given."""
    if path:
        return load(path)
    import tempfile
    tmp = tempfile.mkdtemp(prefix="adint_ioc_")
    try:
        p = os.path.join(tmp, "adfection_iocs.txt")
        with io.open(p, "w", encoding="utf-8", newline="\\n") as fh:
            fh.write(IOC_DATA)
        ioc_set = load(p)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # Report the age of the DATA, not of the temp file we just wrote, so the
    # staleness warning stays truthful in a single-file build.
    ioc_set.source_mtime = IOC_BUILD_EPOCH
    ioc_set.source_path = "(embedded in this script)"
    return ioc_set


def _hold(args):
    """Keep the window open when this was double-clicked.

    Double-clicking a .py in Explorer opens a console that closes the instant
    the script ends - so the entire report would flash past unread, which is the
    most likely way a non-technical person runs this. Pausing costs a keypress
    for anyone running it from a terminal, and saves the report for everyone else.
    """
    if getattr(args, "no_pause", False) or not sys.stdout.isatty():
        return
    try:
        input("\\nPress Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass


def _force_utf8_io():
    """Make stdout/stderr encode UTF-8 whatever the console code page is. On a
    stock Windows Python these default to cp1252, and printing a non-Latin
    profile name or username - Arabic, Hebrew, Persian, Cyrillic, CJK, i.e. this
    tool's users - then crashes with UnicodeEncodeError instead of producing a
    report, worst of all while writing the report file after the work is done.
    This makes the fix independent of the caller remembering `python -X utf8`."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    _force_utf8_io()
    p = argparse.ArgumentParser(
        prog="zero-breach",
        description="Read-only check for published AdFection / Candiru "
                    "indicators. A clean result is NOT a clean bill of health.")
    p.add_argument("--json", metavar="PATH",
                   help="also write a machine-readable report to PATH")
    p.add_argument("--iocs", metavar="PATH",
                   help="use an external indicator file instead of the "
                        "embedded one")
    p.add_argument("--version", action="version",
                   version="Zero Breach " + __version__)
    p.add_argument("--quick", action="store_true",
                   help="skip fingerprinting every file (roughly halves the "
                        "runtime). The skipped check is reported as a gap, not "
                        "as clean.")
    p.add_argument("--no-pause", action="store_true",
                   help="do not wait for a keypress before exiting")
    args = p.parse_args(sys.argv[1:] if argv is None else argv)

    if sys.version_info < (3, 7):
        print("This needs Python 3.7 or newer; this is {}.{}.".format(
            *sys.version_info[:2]), file=sys.stderr)
        _hold(args)
        return 1

    try:
        ioc_set = _load_embedded_iocs(args.iocs)
    except IocError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        _hold(args)
        return 1

    ctx = ScanContext(iocs=ioc_set, quick=args.quick)
    started = datetime.datetime.now()
    results = []
    # The whole scan runs inside the no-network guard (see the header).
    with no_network():
        for name, fn in (("browser", run_browser), ("hash", run_hash),
                         ("host", run_host)):
            if name == "hash" and args.quick:
                r = ModuleResult("hash")
                r.could_not_run(
                    "file-fingerprints",
                    "skipped by --quick. No file on this machine was "
                    "fingerprinted, so a known sample sitting on disk would "
                    "not have been found. Re-run without --quick to include it")
                results.append(r)
                print("[*] skipping file fingerprints (--quick)", file=sys.stderr)
                continue
            print("[*] running check: {}".format(name), file=sys.stderr)
            started_mod = time.time()
            try:
                result = fn(ctx)
            except Exception as exc:
                result = ModuleResult(name)
                result.could_not_run(name, "module error: {}".format(exc))
            result.duration_s = time.time() - started_mod
            print("[*]   {} finished in {:.0f}s".format(name, result.duration_s),
                  file=sys.stderr)
            results.append(result)

    document = build_document(ioc_set, results, started)
    print(render_human(document))

    if args.json:
        try:
            write_json(document, args.json)
            print("\\n[wrote JSON report to {}]".format(args.json),
                  file=sys.stderr)
        except OSError as exc:
            print("\\n[could not write JSON report to {}: {}]".format(
                args.json, exc), file=sys.stderr)

    _hold(args)
    return 2 if document["verdict"]["status"] == "INDICATORS_FOUND" else 0


if __name__ == "__main__":
    raise SystemExit(main())
''')

text = "\n".join(parts)
io.open(OUT, "w", encoding="utf-8", newline="\n").write(text)
print("wrote {} ({:,} bytes, {:,} lines)".format(
    OUT, len(text.encode("utf-8")), text.count("\n") + 1))
