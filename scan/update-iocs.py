#!/usr/bin/env python3
"""Refresh the indicator list from the project repository.

WHY THIS IS A SEPARATE SCRIPT, not part of the scanner. The scanner's strongest
guarantee is that it NEVER touches the network: it cannot be made to resolve or
contact an indicator, and that is enforced and tested. Putting an update feature
inside it would weaken that guarantee and the claim built on it. So updating is a
deliberate, separate act you run yourself, on a tool that plainly does reach the
network and does nothing else.

WHAT IT DOES
  Downloads the current indicator file from the project repo over HTTPS, checks
  it against a published SHA-256, confirms it actually parses as a valid, non-empty
  indicator set, shows you exactly what changed, and - only if you pass --apply -
  replaces your local copy. A dry run by default.

THE TRUST MODEL, STATED HONESTLY. This is a security tool for people who may be
targeted, so be clear about what the check does and does not prove:
  - HTTPS with certificate verification proves the bytes came from GitHub over an
    encrypted, authenticated channel. This is the same trust you place in GitHub
    when you download the tool in the first place.
  - The published SHA-256 catches a corrupted or truncated download. It does NOT,
    on its own, prove authenticity, because it is served from the same place as
    the file.
  - The new list is loaded and validated before it can replace your copy, so a
    malformed or empty download can never silently wipe out your indicators.
  - For STRONGER assurance than "trust GitHub over HTTPS", the maintainer also
    publishes a detached signature (adfection_iocs.txt.minisig) made with a key
    whose public half is in the repo. Verify it out of band with `minisign`:
        minisign -Vm adfection_iocs.txt -P <public key from the repo>
    This script does not verify that signature itself, because doing so needs a
    cryptography library and the scanner has a strict no-dependencies rule; the
    verification is a one-line manual step for anyone who wants it.

  If you are at meaningful risk, prefer downloading a tagged release and checking
  its signature over an automatic refresh.

USAGE
    python update-iocs.py                 # dry run: fetch, verify, show the diff
    python update-iocs.py --apply         # also replace the local indicator file
    python update-iocs.py --url <base>    # use a different base URL (e.g. a mirror)

Standard library only. Python 3.7+.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import ssl
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from adint_scan.iocs import IocError, load  # noqa: E402

DEFAULT_BASE = ("https://raw.githubusercontent.com/interplains/zero-breach/"
                "main/iocs/")
IOC_NAME = "adfection_iocs.txt"
LOCAL_IOC = os.path.join(os.path.dirname(HERE), "iocs", IOC_NAME)


def _fetch(url, timeout=30):
    """Fetch a URL over HTTPS with certificate verification on. Returns bytes."""
    if not url.lower().startswith("https://"):
        raise SystemExit("refusing to fetch over a non-HTTPS URL: {}".format(url))
    ctx = ssl.create_default_context()  # verifies the certificate chain + hostname
    req = urllib.request.Request(url, headers={"User-Agent": "adint-scan-update"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read()


def _values(path):
    s = load(path)
    return {i.value for i in s.indicators}, len(s)


def main(argv=None):
    p = argparse.ArgumentParser(description="Refresh the indicator list (dry run "
                                            "unless --apply).")
    p.add_argument("--apply", action="store_true",
                   help="replace the local indicator file if the new one is valid")
    p.add_argument("--url", default=DEFAULT_BASE,
                   help="base URL to fetch from (must end in /)")
    p.add_argument("--local", default=LOCAL_IOC,
                   help="path to the local indicator file to compare/replace")
    args = p.parse_args(argv)

    base = args.url if args.url.endswith("/") else args.url + "/"

    # 1. Download the indicator file and its published hash.
    try:
        print("fetching {}{} ...".format(base, IOC_NAME))
        data = _fetch(base + IOC_NAME)
        print("fetching published SHA-256 ...")
        published = _fetch(base + IOC_NAME + ".sha256").decode("ascii",
                                                               "replace").split()[0].strip().lower()
    except Exception as exc:
        print("error: download failed: {}".format(exc), file=sys.stderr)
        return 1

    # 2. Integrity: the bytes must match the published hash.
    got = hashlib.sha256(data).hexdigest()
    if got != published:
        print("error: downloaded file does not match the published SHA-256.\n"
              "  published: {}\n  got:       {}\n"
              "Not touching your local file.".format(published, got),
              file=sys.stderr)
        return 1
    print("SHA-256 verified: {}".format(got))

    # 3. Validity: it must parse as a non-empty indicator set BEFORE it can
    #    replace anything. A truncated or malformed download is refused here.
    tmp = tempfile.mkdtemp(prefix="adint_update_")
    newfile = os.path.join(tmp, IOC_NAME)
    with io.open(newfile, "wb") as fh:
        fh.write(data)
    try:
        new_values, new_count = _values(newfile)
    except IocError as exc:
        print("error: the downloaded file is not a valid indicator set ({}). "
              "Not touching your local file.".format(exc), file=sys.stderr)
        return 1
    print("downloaded list is valid: {} indicators".format(new_count))

    # 4. Diff against the local copy so the change is never silent.
    if os.path.exists(args.local):
        old_values, old_count = _values(args.local)
    else:
        old_values, old_count = set(), 0
        print("(no local indicator file at {} yet)".format(args.local))

    added = sorted(new_values - old_values)
    removed = sorted(old_values - new_values)
    print("\nchange since your copy: +{} new, -{} removed (you have {}, repo has {})"
          .format(len(added), len(removed), old_count, new_count))
    for v in added[:40]:
        print("  + {}".format(v))
    if len(added) > 40:
        print("  + ... and {} more".format(len(added) - 40))
    for v in removed[:40]:
        print("  - {}".format(v))
    if len(removed) > 40:
        print("  - ... and {} more".format(len(removed) - 40))

    if not added and not removed:
        print("\nYour indicator list is already up to date.")
        return 0

    # 5. Apply only on explicit request.
    if not args.apply:
        print("\nThis was a dry run. Re-run with --apply to replace:\n  {}"
              .format(args.local))
        return 0

    try:
        with io.open(args.local, "wb") as fh:
            fh.write(data)
    except OSError as exc:
        print("error: could not write {}: {}".format(args.local, exc),
              file=sys.stderr)
        return 1
    print("\nupdated {} ({} indicators).".format(args.local, new_count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
