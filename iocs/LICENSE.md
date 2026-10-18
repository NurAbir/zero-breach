# Indicator data — CC0 1.0 Universal (public domain dedication)

The files in this directory — `adfection_iocs.txt` and the generated exports in
`../dist/` — are dedicated to the public domain under
**[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/legalcode)**.

To the extent possible under law, archivegenocide.com has waived all copyright
and related or neighbouring rights to this indicator set. You may copy, modify,
distribute and use it, including commercially, without asking and without
attribution.

**The software in the rest of this repository is licensed separately**, under the
Apache License 2.0. See `../LICENSE`.

## Why CC0 and not Apache for the data

An indicator is a fact. Facts are not copyrightable, so a restrictive licence
here would be both unenforceable and obstructive. What *is* arguably protectable
is the curation — the tiering, the confidence grading, the per-indicator source
attribution — and CC0 waives that too, deliberately. The entire point of this
file is that other people put it in their own tools: DNS blocklists, MISP
instances, STIX bundles, SIEM rules, Amnesty's MVT. Any friction in that is
friction against the people the data exists to protect.

## Attribution is not required, but is appreciated and is good practice

Not for us — for the researchers. The indicators were published by:

- **The Citizen Lab** (University of Toronto), *"Exposing AdFection: How
  Discover-Tech Turned Targeted Ads Into a Pipeline for Zero-Click Mercenary
  Spyware"*, 2026-10-15.
- **Recorded Future / Insikt Group**, *Devil's Tongue* infrastructure reporting,
  CTA-2025-0805, August 2025.

Every line in `adfection_iocs.txt` carries its source in the fourth column, and
every object in the STIX and MISP exports carries it too, so this attribution
survives being copied into another tool. Please keep that column intact when you
redistribute.

## Please read the header of the indicator file before using it

`adfection_iocs.txt` documents what was **deliberately not imported** and why —
including the 305 validator domains Citizen Lab counted but did not publish, and
corporate domains that are attribution rather than indicators. It also explains
why the `candiru-ip` tier is weaker than the others: those are cloud-hosted
addresses from 2025 that are very likely reassigned to unrelated tenants by now,
and are only meaningful when a hit is dated within the reporting period.

Blocking them wholesale, or feeding them to a tool that alerts on any match, will
generate false positives against innocent people. The tiers exist precisely so
you do not have to do that. See also `VALIDATOR-GAP.md`.
