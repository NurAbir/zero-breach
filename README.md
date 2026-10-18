# Zero Breach

[![tests](https://github.com/interplains/zero-breach/actions/workflows/tests.yml/badge.svg)](https://github.com/interplains/zero-breach/actions/workflows/tests.yml)

A local, read-only scanner that checks a computer for traces of the **AdFection /
Candiru** spyware campaign — the operation in which an ad-tech company used
real-time ad bidding to deliver zero-click spyware to targeted people. Tested on
Windows, macOS and Linux (Python 3.8–3.12) in CI.

It searches the machine's own leftover records — browser history, cookies, caches
and connection records, file fingerprints, auto-start registrations, known
malware file-paths and the DNS resolver cache — for 338 published indicators, and
reports what it found, how strong the evidence is, and just as importantly
**what it could not check**.

> **A clean result is not a clean bill of health.** Spyware of this grade is built
> to defeat exactly this kind of check, most of the evidence it leaves expires
> within weeks, and Windows does not record DNS history unless someone turned it
> on. This tool narrows uncertainty; it does not remove it. If you have real
> reason to believe you are a target, the right step is expert help — the
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/) or the
> [Amnesty International Security Lab](https://securitylab.amnesty.org/) — not a
> self-service script.

## Background

In October 2026 The Citizen Lab documented how the ad-tech firm Discover-Tech used
its **Controlium** platform to fingerprint and infect devices the moment an
advertisement was rendered, delivering Candiru spyware with no click required.
At least 45 devices at Al Jazeera were targeted across 2024–2025. The indicator
set here is drawn from that reporting and from Recorded Future's independent
tracking of the same infrastructure.

The delivery vector abuses real-time ad bidding. Keep operating systems and
browsers updated, reduce exposure with ad filtering, and investigate surviving
traces where appropriate. This tool checks those traces; it does not replace
updates or establish that a device is safe.

- The Citizen Lab, *Exposing AdFection* (2026-10-15)
- Recorded Future / Insikt Group, *Tracking Candiru's DevilsTongue Spyware* (CTA-2025-0805)

## What it checks

| area | what it reads |
|---|---|
| **Browser** | history, cookies (host names and timestamps only), favicons, HTTP cache, Local/Session Storage, Service Worker caches, and HSTS/connection records — across Chrome, Edge, Brave, Chromium and Firefox, every profile |
| **Files** | SHA-256 of candidate files under the user-writable locations spyware drops into, against known sample hashes — and, kept deliberately separate, the hash of a legitimate signed driver this actor abuses, which is reported as a lead rather than as proof |
| **Host** (Windows) | per-user COM registrations (this campaign's documented persistence), the DNS resolver cache, whether DNS history logging is even enabled, the hosts file, and known fixed-path driver drops (e.g. the `HW.sys` vulnerable driver) |

Every match is **evidence-graded**, because the artifact decides the meaning. A
cookie the browser set, or an HSTS record it stored, proves the device *contacted*
a host. A domain merely appearing in a cached web page usually means the person
*read an article about* the campaign. The tool keeps those apart so that reading
about this topic never produces a false alarm, and a real contact is never buried.

## Install and run

Requires Python 3.8 or newer. No administrator. No third-party packages.

**Single file (simplest):** download `zero-breach.py` and run

```
python -X utf8 zero-breach.py            # full scan
python -X utf8 zero-breach.py --quick    # faster; skips file fingerprinting
python -X utf8 zero-breach.py --json report.json
```

**From source:**

```
python -X utf8 scan/adint-scan.py
```

The scan changes no system settings and needs no administrator. It makes no
intentional network requests or indicator lookups. Remote and redirected paths
are skipped, and online certificate verification is disabled. Locked database
snapshots are temporary and removed after use; `--json` writes the requested report.

Exit codes: `0` nothing found, `2` an indicator matched, `1` the scan could not be
set up (e.g. a bad indicator file).

## Verifying what you downloaded

You should not run a security script on faith. Two independent checks:

**1. Match the published hash.** Every release lists the SHA-256 of `zero-breach.py`.
Confirm your download matches it:

```
# Windows PowerShell
Get-FileHash zero-breach.py -Algorithm SHA256
# macOS / Linux
shasum -a 256 zero-breach.py
```

**2. Rebuild it yourself and compare.** The single file is generated from this
repository, deterministically — the matching release tag rebuilds a byte-identical file. So
you do not have to trust the download at all; you can reproduce it:

```
git clone <this repo> && cd zero-breach
git checkout <the-tag-of-the-release-you-downloaded>
python build/build.py          # writes dist/zero-breach.py and prints its SHA-256
```

Compare the hash with that release's published hash. The development branch may
contain later changes and is not expected to reproduce an earlier release.

**Antivirus note.** `zero-breach.py` is plain-text Python — you can read every line
in a text editor. Some antivirus products flag *any* script that reads browser
databases, because that behaviour resembles an infostealer. Zero Breach reads
cookie **host names and timestamps** through its SQL queries, never cookie values,
and does not decrypt credentials. A locked database snapshot necessarily copies
the database bytes before querying that metadata. If your antivirus
objects, read the source, check the hash, and decide for yourself.

## Reading the result

The report opens with a plain-language summary: what was found, how serious it is,
what to do, and **what could not be checked**. Findings are ranked strongest-first:

- **on-disk** — a file matches a published fingerprint. A spyware-sample match
  identifies that sample; a `vuln-driver` match identifies legitimate software
  known to be abused and is not proof of infection.
- **persistence** — a name is registered to run automatically (serious)
- **contacted** — a connection record; its significance depends on the
  indicator's role, such as advertising delivery versus command-and-control
- **dns-record** — a name or address appears in local resolver data; a lookup
  may have failed, and resolution alone does not prove contact with the server
- **configured** — a name is mapped to a real address in local configuration
- **referenced** — the name appeared in saved content, such as page text,
  an unvisited bookmark or browser storage; this does not establish contact

Next steps depend on both the evidence and the indicator's role. Advertising
traces and legitimate-driver matches start with checking the saved context;
they do not automatically trigger a spyware-helpline referral. More concerning
infrastructure warrants qualified interpretation. Known spyware-file matches
and persistence findings call for prompt expert review and preservation of the
evidence. A credible targeting concern warrants direct help regardless of the
scan result. Multiple weak matches do not automatically become strong evidence.

Evidence locations are printed in full so they can be copied. Detailed findings
follow the coverage information and, where applicable, DNS-history instructions.

Domain and IP matches are printed defanged (`example[.]com`) so that forwarding a
report to a help organisation cannot cause a mail gateway to contact the
indicator on the reader's behalf.

DNS cache entries pointing at a blocking/sink address are described as protective
configuration, not attempted contact: the hosts file can preload them without
any lookup. For a more consistent SQLite snapshot, close browsers before scanning.
Local-path checks are not an OS sandbox: POSIX network mounts and concurrent
filesystem changes require an external isolation boundary for strict offline use.

### Example: a "nothing found" result

The most common outcome, and the one where reading carefully matters most — note
that it leads with the caveat and lists what it could *not* check:

```
========================================================================
  Zero Breach 0.1.0  —  AdFection / Candiru indicator check
  Checks for TRACES of ad-delivered spyware. A clean result is NOT a
  clean bill of health - see what could not be checked, below.
  2026-10-18T14:30:00   Windows 11
========================================================================
  SUMMARY  —  read this part
========================================================================
  RESULT: no known indicator was found in anything that could be
          checked.

  This is NOT a clean bill of health. See the two sections below for
  what was searched and, more importantly, what could not be.

  WHAT COULD NOT BE CHECKED  (2 gaps)
    - hash/file-fingerprints: skipped by --quick. Re-run without --quick
      to include it
    - host/dns-log: DNS-Client/Operational log is disabled (the Windows
      default) - there is no queryable DNS history, so past activity
      cannot be checked retrospectively from this host
========================================================================
```

A real match is shown under a `>> ` heading stating plainly what it is (a file on
disk, an auto-start entry, a proven connection), with the account and date, and a
numbered "what to do" that starts with *do not delete the evidence*.

## Indicator data and interoperability

The 338 indicators live in [`iocs/adfection_iocs.txt`](iocs/adfection_iocs.txt),
one per line with its tier, confidence and source. They cover the AdFection
campaign plus curated historical Candiru infrastructure (ESET 2021, Avast 2022,
Citizen Lab 2021). Each indicator is exported with its own citation, so an
indicator that came from ESET or Recorded Future is not attributed to anyone else.
They are exported to [`dist/`](dist/) in several formats:

- **STIX 2.1** and **MISP** — for MISP, a SIEM, or Amnesty International's Mobile
  Verification Toolkit: `mvt-ios check-backup --iocs dist/adfection.stix.json <backup>`
- **DNS/ad blocklists** — `hosts`, Adblock/uBlock/AdGuard, dnsmasq, and a plain
  domain list, for a phone's or router's DNS filter, Pi-hole or AdGuard Home.
  Only domains are blocked; shared cloud IPs are deliberately excluded.

Regenerate the exports with `python build/emit_stix.py`, `build/emit_misp.py` and
`build/emit_denylist.py`.

**Correction for existing STIX users:** the legitimate driver hash
`6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5`
is excluded from active STIX indicators. If you imported an earlier feed, process
`dist/adfection.withdrawals.stix.json` in a consumer that supports STIX revocation,
or explicitly remove the old driver rule and its relationship:
`indicator--80275ed1-64f2-58c7-97dc-9cdacac0ff5d` and
`relationship--66b188af-2489-5b41-a84f-b90c34f5fc73`.
The withdrawal file is for removing earlier objects, **not a detection/MVT feed**.
Continue using `dist/adfection.stix.json` for scanning. The scanner and MISP retain
the driver as a clearly labelled investigation lead; its presence is not proof
of spyware.

### Updating the indicators

The list goes stale — new infrastructure appears and old domains lapse. Refresh
it from this repository with a separate, explicitly-run script (the scanner itself
never touches the network):

```
python scan/update-iocs.py            # fetch, verify, show what changed (dry run)
python scan/update-iocs.py --apply    # also replace the local list
```

It downloads over HTTPS, checks the file against a published SHA-256, confirms it
parses before replacing anything, and shows a diff first. The trust model and the
current signing limitations are documented at the top of the script. Detached
signing is not configured for this release.

## Design principles

- **Never contact an indicator.** A Python socket guard blocks direct DNS and
  network calls. Local-path checks reject remote and redirected paths, and
  Authenticode checks that could retrieve certificates are disabled. The socket
  guard is not an operating-system network sandbox; use OS isolation when a
  strict offline execution boundary is required.
- **Measured, never inferred.** A check that could not run is reported as a gap,
  never as clean. This is enforced structurally, not by convention.
- **Precision over coverage.** An unsigned binary in a user-writable path is not a
  finding; plenty of honest software looks like that. Alarms that mean nothing
  teach people to ignore the tool.
- **Queries only required metadata.** Cookie queries select host names and
  timestamps, not values. Temporary snapshots copy entire locked database files;
  the scanner does not decrypt browser credentials.
- **Read-only, no administrator, no telemetry, no dependencies.**

## Tests

```
cd scan && python -m unittest discover -s tests
```

The suite covers the network guard, the evidence grading, the boundary matching
(so a longer name or number that merely contains an indicator does not match), the
loader's failure modes, and behavioural proofs that the tool never reads cookie
values or the browser's master key.

## Contact

Questions or feedback: the project's **Telegram** — https://t.me/+t9gq13mSKcE4NGI0.
To report a security problem, please see [SECURITY.md](SECURITY.md).

## Licence

The software is licensed under the **Apache License 2.0** (`LICENSE`). The
indicator data in `iocs/` and `dist/` is released into the public domain under
**CC0 1.0** (`iocs/LICENSE.md`), so it can be copied into blocklists, MISP, STIX
and other tools without restriction.

This project is **not affiliated with, and not endorsed by**, The Citizen Lab,
Confiant, Recorded Future, Amnesty International or Access Now. Their work is cited
as the source of the indicators and as the place to turn for expert help. See
`NOTICE` for details.
