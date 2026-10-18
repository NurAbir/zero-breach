# Zero Breach

A local, read-only scanner that checks a computer for traces of the **AdFection /
Candiru** spyware campaign — the operation in which an ad-tech company used
real-time ad bidding to deliver zero-click spyware to targeted people.

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
At least 45 devices at Al Jazeera were compromised across 2024–2025. The indicator
set here is drawn from that reporting and from Recorded Future's independent
tracking of the same infrastructure.

There is nothing to patch: the delivery vector is real-time ad bidding working as
designed. The practical defences are to reduce exposure (block ads at the device
or gateway) and to look for traces of contact — which is what this tool does.

- The Citizen Lab, *Exposing AdFection* (2026-10-15)
- Recorded Future / Insikt Group, *Tracking Candiru's DevilsTongue Spyware* (CTA-2025-0805)

## What it checks

| area | what it reads |
|---|---|
| **Browser** | history, cookies (host names and timestamps only), favicons, HTTP cache, Local/Session Storage, Service Worker caches, and HSTS/connection records — across Chrome, Edge, Brave, Chromium and Firefox, every profile |
| **Files** | SHA-256 of candidate files under the user-writable locations spyware drops into, against known sample hashes |
| **Host** (Windows) | per-user COM registrations (this campaign's documented persistence), the DNS resolver cache, whether DNS history logging is even enabled, the hosts file, and known fixed-path driver drops (e.g. the `HW.sys` vulnerable driver) |

Every match is **evidence-graded**, because the artifact decides the meaning. A
cookie the browser set, or an HSTS record it stored, proves the device *contacted*
a host. A domain merely appearing in a cached web page usually means the person
*read an article about* the campaign. The tool keeps those apart so that reading
about this topic never produces a false alarm, and a real contact is never buried.

## Install and run

Requires Python 3.7 or newer. No administrator. No third-party packages.

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

The scan is read-only: it changes nothing, needs no administrator, and never
touches the network — it will not even resolve an indicator, because resolving a
command-and-control domain would announce the person running it to whoever
operates the infrastructure.

Exit codes: `0` nothing found, `2` an indicator matched, `1` the scan could not be
set up (e.g. a bad indicator file).

## Reading the result

The report opens with a plain-language summary: what was found, how serious it is,
what to do, and **what could not be checked**. Findings are ranked strongest-first:

- **on-disk** — a file matches a known sample's fingerprint (conclusive)
- **persistence** — a name is registered to run automatically (serious)
- **contacted** — the device demonstrably communicated with the host (serious)
- **configured** — a name is mapped to a real address in local configuration
- **referenced** — the name only appeared in saved page text (usually benign)

Domain and IP matches are printed defanged (`example[.]com`) so that forwarding a
report to a help organisation cannot cause a mail gateway to contact the
indicator on the reader's behalf.

## Indicator data and interoperability

The 338 indicators live in [`iocs/adfection_iocs.txt`](iocs/adfection_iocs.txt),
one per line with its tier, confidence and source. They cover the AdFection
campaign plus curated historical Candiru infrastructure (ESET 2021, Avast 2022,
Citizen Lab 2021), and are exported to [`dist/`](dist/) in several formats:

- **STIX 2.1** and **MISP** — for MISP, a SIEM, or Amnesty International's Mobile
  Verification Toolkit: `mvt-ios check-backup --iocs dist/adfection.stix.json <backup>`
- **DNS/ad blocklists** — `hosts`, Adblock/uBlock/AdGuard, dnsmasq, and a plain
  domain list, for a phone's or router's DNS filter, Pi-hole or AdGuard Home.
  Only domains are blocked; shared cloud IPs are deliberately excluded.

Regenerate the exports with `python build/emit_stix.py`, `build/emit_misp.py` and
`build/emit_denylist.py`.

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
optional out-of-band signature check are documented at the top of the script.

## Design principles

- **Never contact an indicator.** The entire scan runs inside a guard that makes
  any network access raise an error; a bug that tried to resolve a domain crashes
  loudly rather than leaking a signal.
- **Measured, never inferred.** A check that could not run is reported as a gap,
  never as clean. This is enforced structurally, not by convention.
- **Precision over coverage.** An unsigned binary in a user-writable path is not a
  finding; plenty of honest software looks like that. Alarms that mean nothing
  teach people to ignore the tool.
- **Reads nothing it does not need.** It reads cookie *host names*, never cookie
  *values*, and never touches the credential-decryption paths that an infostealer
  would — a distinction asserted by the test suite, not just promised here.
- **Read-only, no administrator, no telemetry, no dependencies.**

## Tests

```
cd scan && python -m unittest discover -s tests
```

The suite covers the network guard, the evidence grading, the boundary matching
(so a longer name or number that merely contains an indicator does not match), the
loader's failure modes, and behavioural proofs that the tool never reads cookie
values or the browser's master key.

## Licence

The software is licensed under the **Apache License 2.0** (`LICENSE`). The
indicator data in `iocs/` and `dist/` is released into the public domain under
**CC0 1.0** (`iocs/LICENSE.md`), so it can be copied into blocklists, MISP, STIX
and other tools without restriction.

This project is **not affiliated with, and not endorsed by**, The Citizen Lab,
Confiant, Recorded Future, Amnesty International or Access Now. Their work is cited
as the source of the indicators and as the place to turn for expert help. See
`NOTICE` for details.
