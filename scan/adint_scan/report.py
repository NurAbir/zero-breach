"""Human-readable + machine-readable reporting, and the overall verdict.

Doctrine enforced here:
  D1  Every run that finds nothing prints, verbatim, the mandatory closing line.
  D3  A module that could not run is UNKNOWN, never CLEAN; gaps are stated out
      loud in the interface, not buried.
  The verdict for a hit is "investigate", never "you are compromised" — an ad
  impression is not proof of infection (README / the IOC file header).
"""

from __future__ import annotations

import datetime
import json
import platform as _platform
from typing import Any, Dict, List

from . import __version__
from .iocs import IocSet
from .result import (CLEAN, HITS, PARTIAL, UNKNOWN, ModuleResult, is_serious,
                     EV_ON_DISK, EV_PERSISTENCE, EV_CONTACTED, EV_ATTEMPTED,
                     EV_CONFIGURED, EV_REFERENCED)

# The exact text required by D1. Do not reword.
D1_LINE = ("No known indicators were found in the places that can be checked. "
           "This is not a clean bill of health.")

V_HITS = "INDICATORS_FOUND"
V_NONE_WITH_GAPS = "NO_KNOWN_INDICATORS_WITH_GAPS"
V_NONE = "NO_KNOWN_INDICATORS"


def _windows_release(release: str, version: str) -> str:
    """Correct Python's release string on Windows 11.

    platform.release() reports "10" on Windows 11, because the underlying
    GetVersionEx still reports major version 10 for compatibility. Windows 11 is
    build 22000 and up, so the build number in platform.version() is what
    actually distinguishes them. This matters because the JSON report is meant to
    be evidence: a report that names the wrong OS is a report someone has to
    double-check by hand.
    """
    if release != "10":
        return release
    try:
        build = int(version.split(".")[2])
    except (IndexError, ValueError):
        return release
    return "11" if build >= 22000 else release


def _platform_info() -> Dict[str, str]:
    system = _platform.system()
    release = _platform.release()
    version = _platform.version()
    if system == "Windows":
        release = _windows_release(release, version)
    return {
        "system": system,
        "release": release,
        "version": version,
        "machine": _platform.machine(),
        "python": _platform.python_version(),
    }


def build_document(iocs: IocSet, modules: List[ModuleResult],
                   started: datetime.datetime) -> Dict[str, Any]:
    hits_total = sum(len(m.hits) for m in modules)
    gaps: List[str] = []
    for m in modules:
        for c in m.checks:
            if not c.ran:
                gaps.append("{}/{}: {}".format(m.name, c.name, c.reason))
        # A module that produced NO checks at all is UNKNOWN - it observed
        # nothing - but has no failed Check to turn into a gap, so without this it
        # is invisible to the verdict and a "nothing found" reads as clean. The
        # common cause is a browser module on a machine where no supported browser
        # is installed, or on macOS/Linux before the platform paths existed.
        if m.status == UNKNOWN and not m.checks:
            gaps.append("{}: nothing in this check could run, so it cleared "
                        "nothing".format(m.name))

    if hits_total > 0:
        status = V_HITS
    elif gaps:
        status = V_NONE_WITH_GAPS
    else:
        status = V_NONE

    age = iocs.age_days()
    return {
        "tool": {"name": "adint-scan", "version": __version__},
        "timestamp": started.replace(microsecond=0).isoformat(),
        "platform": _platform_info(),
        "ioc_set": {
            "path": iocs.source_path,
            "count": len(iocs),
            "age_days": age,
            "stale": iocs.is_stale(),
        },
        "modules": {m.name: m.to_dict() for m in modules},
        "verdict": {
            "status": status,
            "hits_total": hits_total,
            "gaps": gaps,
        },
        # D1 line is present whenever nothing was found (CLEAN or with gaps).
        "doctrine_line": None if hits_total > 0 else D1_LINE,
        # Whether a "HOW TO TURN ON DNS HISTORY" block will actually be rendered,
        # so the summary's pointer to it does not dangle on a host where no reach
        # entry carried how_to_enable (e.g. a non-Windows machine).
        "_dns_howto": any(
            info.get("how_to_enable")
            for m in modules for info in (m.reach or {}).values()),
    }


def write_json(document: Dict[str, Any], path: str) -> None:
    # The internal rendering flag is not part of the evidence record.
    doc = {k: v for k, v in document.items() if not k.startswith("_")}
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# --- human-readable rendering ----------------------------------------------

_RULE = "=" * 72


def _fmt_count(n: int) -> str:
    return "{:,}".format(n)


# Raw metric keys are developer shorthand. Say what each number is, in words,
# because "com_registrations=37" tells a reader nothing about whether 37 is bad.
_METRIC_LABELS = {
    "sqlite": "browser databases read",
    "blob": "cache / stored-data files searched",
    "hsts_entries": "HSTS security records checked (proof of past connections)",
    "connection_records": "saved connection records checked",
    "files_hashed": "files fingerprinted",
    "com_registrations": "auto-start COM registrations reviewed",
    "com_user_writable": "   of those, in a folder you can write to",
    "dns_cache_entries": "names in the DNS cache since last reboot",
    "dns_log_records": "DNS history records available",
    "dns_log_events_scanned": "DNS history events searched",
    "hosts_entries": "entries in the hosts file",
    "hosts_blocked_indicators": "   of those, indicators you are BLOCKING (good)",
}


def _describe_metrics(metrics: Dict[str, int]) -> List[str]:
    out = []
    for key, value in metrics.items():
        if key == "bytes_hashed":
            out.append("{:,.1f} GB of files read".format(value / 1e9))
            continue
        if key == "dns_log_enabled":
            out.append("Windows DNS history logging: {}".format(
                "ON" if value else "OFF (the Windows default)"))
            continue
        label = _METRIC_LABELS.get(key)
        if label is None:
            out.append("{}: {}".format(key, _fmt_count(value)))
        else:
            out.append("{}: {}".format(label, _fmt_count(value)))
    return out


def render_human(document: Dict[str, Any]) -> str:
    out: List[str] = []
    w = out.append

    w(_RULE)
    w("  adint-scan {}  —  AdFection / Candiru indicator check".format(
        document["tool"]["version"]))
    w("  {}   {} {}".format(document["timestamp"],
                            document["platform"]["system"],
                            document["platform"]["release"]))
    w(_RULE)
    w("")

    # The answer first. Everything after it is the supporting evidence.
    out.extend(render_summary(document).split("\n"))

    ioc = document["ioc_set"]
    age = ioc["age_days"]
    age_txt = "unknown age" if age is None else "{} day(s) old".format(age)
    w("Indicator set : {} indicators, {}".format(ioc["count"], age_txt))
    if ioc["stale"]:
        w("  ** WARNING: this indicator set is more than 30 days old. Update it "
          "before trusting a clean result. **")
    w("")

    w("DETAIL  —  what was examined, and the evidence behind the summary")
    w("")
    for name, m in document["modules"].items():
        took = (" in {:.0f}s".format(m["duration_s"])
                if m.get("duration_s") else "")
        w("--- {} check  [{}]{} ---".format(name, m["status"], took))
        w("    examined: {}    could not read: {}".format(
            _fmt_count(m["checked"]), _fmt_count(m["skipped"])))
        if m["submetrics"]:
            for line in _describe_metrics(m["submetrics"]):
                w("    {}".format(line))
        for note in m["notes"]:
            w("    note   : {}".format(note))
        if m["hits"]:
            # Strongest evidence first: someone reading this should see a sample
            # on disk or a proven contact before a string that merely appeared in
            # cached page text.
            order = {EV_ON_DISK: 0, EV_PERSISTENCE: 1, EV_CONTACTED: 2,
                     EV_ATTEMPTED: 3, EV_CONFIGURED: 4, EV_REFERENCED: 5, "": 0}
            for h in sorted(m["hits"], key=lambda x: order.get(x.get("evidence", ""), 0)):
                prov = "{}/{}".format(h["tier"], h["confidence"]) if h["tier"] else "?"
                ev = h.get("evidence") or "unclassified"
                w("    !! HIT  {}  [{}]  evidence: {}".format(
                    _defang(h["indicator"]), prov, ev.upper()))
                gloss = EVIDENCE_MEANING.get(ev)
                if gloss:
                    w("            meaning: {}".format(gloss))
                if h.get("profile"):
                    w("            account: {}".format(h["profile"]))
                w("            at     : {}".format(h["location"]))
                w("            detail : {}".format(h["detail"]))
                if h.get("observed"):
                    w("            when   : {}".format(h["observed"]))
                if h.get("source"):
                    w("            source : {}".format(h["source"]))
        w("")

    _render_reach(w, document)

    v = document["verdict"]
    w(_RULE)
    if v["status"] == V_HITS:
        w("VERDICT: {} indicator(s) matched.".format(v["hits_total"]))
        w("")
        counts = {}
        for m in document["modules"].values():
            for h in m["hits"]:
                key = h.get("evidence") or "unclassified"
                counts[key] = counts.get(key, 0) + 1
        serious_n = sum(n for k, n in counts.items() if is_serious(k))
        w("  By evidence strength: " + ", ".join(
            "{} {}".format(n, k) for k, n in sorted(counts.items())))
        w("")
        if serious_n:
            w("  {} of these {} SERIOUS - a file on disk, an auto-start entry, a".format(
                serious_n, "is" if serious_n == 1 else "are"))
            w("  proven connection, or a blocked attempt. Read those first; they")
            w("  are marked >> in the summary above. The rest are reference-only.")
        else:
            w("  ALL of these are reference-only: a string in cached page content,")
            w("  history or a blocklist - most often a page ABOUT this campaign (a")
            w("  news article, a report, this tool's own documentation) rather than")
            w("  any contact with the infrastructure. Check what the page was,")
            w("  without opening it, before drawing a conclusion.")
        w("")
        w("A match means INVESTIGATE, not 'you are compromised'. An ad impression")
        w("from this infrastructure is not proof of infection — the validator server")
        w("decided per device whether to proceed. If you have any concrete reason to")
        w("suspect this machine, the right answer is expert forensics, not this tool:")
        _referrals(w)
    else:
        if v["gaps"]:
            w("VERDICT: no known indicators found IN WHAT COULD BE CHECKED.")
            w("")
            w("Checks that could NOT run (a gap is not a clean result):")
            for g in v["gaps"]:
                w("  - {}".format(g))
            w("")
        else:
            w("VERDICT: no known indicators found in any check that ran.")
            w("")
        # D1: the mandatory closing line, verbatim.
        w(document["doctrine_line"])
        w("")
        w("This grade of spyware is purpose-built to defeat exactly this class of")
        w("check. If you are at risk, contact people who do this properly:")
        _referrals(w)
    w(_RULE)
    return "\n".join(out)


# The window the AdFection campaign was actually active, from the Citizen Lab
# report: 45 compromised Windows devices at Al Jazeera during 2024-2025. If the
# evidence on this machine does not reach back that far, the honest thing is to say
# the check could not have covered it, rather than let a clean result imply it did.
CAMPAIGN_FROM = datetime.date(2024, 1, 1)
CAMPAIGN_TO = datetime.date(2025, 12, 31)
CAMPAIGN_LABEL = "2024-2025 (the period in which the confirmed compromises happened)"


def overlap_statement(earliest: datetime.date, source: str) -> List[str]:
    """What the oldest surviving evidence means for the campaign window. Three
    cases, and the middle one is the common one: evidence that starts INSIDE the
    window covers only its tail, and only through whichever record reached it."""
    if earliest > CAMPAIGN_TO:
        return [
            "** The oldest evidence of any kind on this machine dates from {}.".format(
                earliest.isoformat()),
            "   The campaign this tool searches for was active in {}.".format(
                CAMPAIGN_LABEL),
            "   Those windows DO NOT OVERLAP. For that period this machine holds no",
            "   evidence either way, so a clean result above says nothing about it. **",
        ]
    if earliest > CAMPAIGN_FROM:
        return [
            "** The oldest evidence on this machine is {} ({}).".format(
                source, earliest.isoformat()),
            "   That reaches PART of the campaign period ({}),".format(CAMPAIGN_LABEL),
            "   from {} onwards, and only through that one kind of record.".format(
                earliest.isoformat()),
            "   Everything before it, and every other kind of record, is gone. A clean",
            "   result covers that partial window thinly - it does not cover 2024-2025. **",
        ]
    return [
        "** The oldest evidence on this machine is {} ({}), which predates".format(
            source, earliest.isoformat()),
        "   the campaign period. That record type spans the whole window - but only",
        "   for whatever survived in it, which is never everything. **",
    ]


def _render_reach(w, document: Dict[str, Any]) -> None:
    """Say how far back the evidence reaches. A clean result over 11 weeks and a
    clean result over 3 years are different findings, and the reader cannot tell
    them apart unless the tool says which one it just produced."""
    entries = []
    for mod_name, m in document["modules"].items():
        for label, info in (m.get("reach") or {}).items():
            entries.append((mod_name, label, info))
    if not entries:
        return

    w(_RULE)
    w("HOW FAR BACK THIS SCAN COULD SEE")
    w("")
    w("  A clean result only covers the window the evidence survives in. These are")
    w("  the measured windows on THIS machine, not general estimates:")
    w("")

    earliest_overall = None
    earliest_source = ""
    for mod_name, label, info in entries:
        earliest = info.get("earliest")
        days = info.get("days")
        when = "nothing recorded" if not earliest else earliest[:10]
        age = ""
        if isinstance(days, int) and earliest:
            age = "  ({} days ago)".format(days)
        w("  {}/{}".format(mod_name, label))
        w("      reaches back to : {}{}".format(when, age))
        w("      basis           : {}".format(info.get("basis", "")))
        if info.get("note"):
            w("      {}".format(info["note"]))
        w("")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if earliest_overall is None or d < earliest_overall:
                    earliest_overall = d
                    earliest_source = "{}/{}".format(mod_name, label)
            except ValueError:
                pass

    # How many artifacts actually date from inside the campaign window. This is
    # the number that answers "could this scan have seen it?", where the oldest
    # surviving file only answers "how far back does anything reach?".
    in_window = 0
    total_dated = 0
    for _mod_name, _label, info in entries:
        by_year = info.get("by_year") or {}
        for year, count in by_year.items():
            year = int(year)
            total_dated += count
            if CAMPAIGN_FROM.year <= year <= CAMPAIGN_TO.year:
                in_window += count

    if earliest_overall is not None:
        for line in overlap_statement(earliest_overall, earliest_source):
            w("  " + line)
        w("")

    # Does ANY reach record - cookie ages, DNS, not just the cache files that
    # carry by_year - reach into the campaign window? This decides whether the
    # absolute "nothing dates from the campaign period" sentence is even true.
    something_in_window = False
    for _mod_name, _label, info in entries:
        earliest = info.get("earliest")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if d <= CAMPAIGN_TO:
                    something_in_window = True
            except ValueError:
                pass

    if total_dated:
        merged = {}
        for _mod_name, _label, info in entries:
            for year, count in (info.get("by_year") or {}).items():
                year = int(year)
                merged[year] = merged.get(year, 0) + count

        w("  Age of the browser cache files searched, by year (cache files only,")
        w("  not cookies or DNS - those are summarised above):")
        w("      " + "   ".join("{}: {:,}".format(y, merged[y])
                                for y in sorted(merged)))
        w("")
        pct = 100.0 * in_window / total_dated
        w("  Of those cache files, dating from the campaign period ({}-{}): "
          "{:,} of {:,} ({:.1f}%).".format(
              CAMPAIGN_FROM.year, CAMPAIGN_TO.year, in_window, total_dated, pct))

        # A per-year floor matters more than the total: the campaign ran across
        # several years, and a year with almost nothing left is a year this scan
        # cannot speak about, however healthy the overall percentage looks.
        sparse = [y for y in range(CAMPAIGN_FROM.year, CAMPAIGN_TO.year + 1)
                  if merged.get(y, 0) < 100]
        if in_window == 0 and not something_in_window:
            # Only make the absolute claim when NOTHING of any kind - no cookie,
            # no cache file, no DNS record - reaches the window. Otherwise it
            # would contradict the overlap statement printed just above.
            w("  NOTHING on this machine dates from the campaign period. A clean")
            w("  result cannot speak to it at all.")
        elif in_window == 0 and something_in_window:
            w("  No browser CACHE file dates from the campaign period, though some")
            w("  older evidence (shown above) does. Cache is the thinnest record;")
            w("  the window above is the one to read.")
        elif sparse:
            w("  BUT cache coverage is uneven. These campaign years have almost no")
            w("  surviving cache, so a clean result says little about them:")
            for y in sparse:
                w("      {}: {:,} cache file(s)".format(y, merged.get(y, 0)))
        w("")

    # The actionable part: if any check reported how to extend its window, print it.
    for _mod_name, _label, info in entries:
        for line in info.get("how_to_enable") or []:
            w("  " + line)
    w("")


# What a hit in each tier actually MEANS, in plain language. The tier is the
# whole point of curating the indicator set: contact with an ad tracker and
# contact with a command-and-control server are different events, and a report
# that renders them identically has failed the person reading it.
TIER_MEANING = {
    "delivery": ("An advertising/tracking server belonging to this network "
                 "reached this device. That is the mass-profiling layer: it "
                 "happened to millions of people. It is NOT evidence of "
                 "infection."),
    "cc": ("A Candiru command-and-control server. This is the most serious "
           "class of indicator - it is the address an active implant talks to."),
    "validator": ("A Candiru validator server. These profiled a device and "
                  "decided, per device, whether to deliver an exploit. Contact "
                  "suggests this device was being assessed as a target."),
    "candiru": ("A server attributed to Candiru by Recorded Future. Its exact "
                "role is not published, so treat it as serious but unspecified."),
    "candiru-ip": ("An IP address attributed to Candiru infrastructure in 2025. "
                   "Weak on its own: cloud IP addresses are reassigned to "
                   "unrelated, innocent customers within months."),
    "historical": ("Infrastructure from the separate, older 2021 Candiru "
                   "campaign. A hit would still be significant."),
    "sample": ("The file fingerprint of a published Candiru sample. A match "
               "here is conclusive, not circumstantial."),
}

EVIDENCE_MEANING = {
    EV_ON_DISK: ("a file on this machine has the fingerprint of a published "
                 "spyware sample - this is conclusive, not circumstantial"),
    EV_PERSISTENCE: ("the name is registered to run automatically on this "
                     "machine - a hallmark of installed spyware"),
    EV_CONTACTED: "this device demonstrably communicated with it",
    EV_ATTEMPTED: ("something on this device looked the name up, but a filter "
                   "blocked the connection"),
    EV_CONFIGURED: ("the name is in local configuration pointing at a real "
                    "address (a protective block entry is not reported at all)"),
    EV_REFERENCED: ("the name appeared in saved page content - most often a page "
                    "ABOUT this campaign, not contact with it"),
}

# A short imperative headline per grade, used in the summary. The ones that are
# not EV_REFERENCED are serious and each gets its own, so a sample on disk and a
# persistence entry can never be rendered as "probably nothing".
EVIDENCE_HEADLINE = {
    EV_ON_DISK: "A KNOWN SPYWARE FILE IS ON THIS MACHINE",
    EV_PERSISTENCE: "SOMETHING IS SET TO RUN AUTOMATICALLY FROM THIS INFRASTRUCTURE",
    EV_CONTACTED: "THIS DEVICE CONTACTED THIS INFRASTRUCTURE",
    EV_ATTEMPTED: "THIS DEVICE TRIED TO REACH THIS INFRASTRUCTURE (a filter blocked it)",
    EV_CONFIGURED: "THIS INFRASTRUCTURE IS CONFIGURED ON THIS MACHINE",
}


def _defang(indicator: str) -> str:
    """Make an indicator safe to paste into an email or chat without a client,
    gateway or link scanner auto-fetching it. The report is designed to be
    forwarded to Access Now / Amnesty, and the tool's own rule is never to
    contact an indicator - so it must not ship them in a fetchable form. The JSON
    report keeps the raw value; only the human text is defanged."""
    out = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Neuter the last dot (domains) or wrap every dot (IPs) so nothing resolves.
    if any(c.isalpha() for c in indicator) and "." in out:
        head, _, tail = out.rpartition(".")
        return "{}[.]{}".format(head, tail)
    return out.replace(".", "[.]")


def render_summary(document: Dict[str, Any]) -> str:
    """The part a person actually reads. Answers, in order: what was found, what
    it means, what to do, and what this scan could not check.

    Everything below this in the report is the evidence for these few lines."""
    out: List[str] = []
    w = out.append
    v = document["verdict"]

    all_hits = [h for _m, m in document["modules"].items() for h in m["hits"]]
    serious = [h for h in all_hits if is_serious(h.get("evidence", ""))]
    benign = [h for h in all_hits if not is_serious(h.get("evidence", ""))]

    w(_RULE)
    w("  SUMMARY  —  read this part")
    w(_RULE)

    if not all_hits:
        w("  RESULT: no known indicator was found in anything that could be")
        w("          checked.")
        w("")
        w("  This is NOT a clean bill of health. See the two sections below for")
        w("  what was searched and, more importantly, what could not be.")
    elif serious:
        n = len(serious)
        w("  RESULT: {} serious finding{} that need{} a person to look.".format(
            n, "" if n == 1 else "s", "s" if n == 1 else ""))
        if benign:
            nb = len(benign)
            w("          ({} further match{} {} only {} in saved page "
              "content.)".format(
                  nb, "" if nb == 1 else "es", "is" if nb == 1 else "are",
                  "a reference" if nb == 1 else "references"))
        w("")
        w("  WHAT WAS FOUND")
        # Strongest grade first; collapse repeats of the same indicator+grade so
        # one domain in three cache files is not three lines.
        for h in _dedup_serious(serious):
            headline = EVIDENCE_HEADLINE.get(h["evidence"], "A SERIOUS INDICATOR MATCHED")
            w("    >> {}".format(headline))
            w("       {}  [{}]".format(_defang(h["indicator"]), h["tier"]))
            meaning = TIER_MEANING.get(h["tier"])
            if meaning:
                for line in _wrap(meaning, 64):
                    w("          " + line)
            if h.get("profile"):
                w("          Account: {}".format(h["profile"]))
            if h.get("observed"):
                w("          When: {}".format(h["observed"][:19].replace("T", " ")))
            w("          Where: {}".format(_short_path(h["location"])))
            w("")
        w("  WHAT TO DO")
        w("    1. Do NOT delete, move or \"clean\" anything named above. It is the")
        w("       evidence a forensic examiner would need, and deleting it cannot")
        w("       be undone.")
        w("    2. Do NOT open, visit or look up any name above - not even to")
        w("       check it. Contacting it tells whoever runs it that someone is")
        w("       looking. The names are written with [.] so they cannot be")
        w("       clicked by accident; keep them that way if you forward this.")
        w("    3. Contact one of the organisations at the end of this report. A")
        w("       serious finding here is a reason to get expert help, not a")
        w("       verdict this tool can give on its own.")
        w("")
        w("    Before you forward this report: it contains your Windows username,")
        w("    your browser profile names, and the web addresses of matching")
        w("    records - personal information. That is fine to send to the help")
        w("    organisations below, who need it; think before posting it in public.")
        if benign:
            n_b = len(benign)
            w("")
            w("    The {} reference-only match{} {} listed in the detail section "
              "below; {} most likely {} you read about this campaign.".format(
                  n_b, "" if n_b == 1 else "es", "is" if n_b == 1 else "are",
                  "it is" if n_b == 1 else "they are",
                  "a page" if n_b == 1 else "pages"))
    else:
        n = len(benign)
        w("  RESULT: {} match{} found, all of them reference-only.".format(
            n, "" if n == 1 else "es"))
        w("")
        w("  WHAT THIS PROBABLY IS")
        for line in _wrap(
                "Every match is a string found in saved page content - no sign "
                "that this device ever contacted the infrastructure, ran a "
                "sample, or was configured to. The usual cause is reading about "
                "this campaign: a news article, a research report, a blocklist "
                "or this tool's own documentation puts these names in a browser "
                "cache. Check the page's own title in the DETAIL section below - "
                "do not open the page - before drawing any conclusion. This is "
                "probably not a sign of compromise.", 68):
            w("    " + line)

    gaps = v.get("gaps") or []
    if gaps:
        w("")
        w("  WHAT COULD NOT BE CHECKED  ({} gap{})".format(
            len(gaps), "" if len(gaps) == 1 else "s"))
        shown = gaps[:4]
        for g in shown:
            for i, line in enumerate(_wrap(g, 66)):
                w("    " + ("- " if i == 0 else "  ") + line)
        if len(gaps) > len(shown):
            w("    ... and {} more, listed in full at the end of this report."
              .format(len(gaps) - len(shown)))
        # The DNS gap is the one a reader can actually close - but only point at
        # the instructions if they were actually rendered (they are not on a
        # non-Windows host), or the pointer dangles.
        if document.get("_dns_howto") and any("dns" in g.lower() for g in gaps):
            w("")
            w("    -> You can fix the DNS gap for next time, in one command.")
            w("       See \"HOW TO TURN ON DNS HISTORY\" further down. It tells you")
            w("       nothing about the past, but it means a future check can")
            w("       actually answer the question.")
    w(_RULE)
    w("")
    return "\n".join(out)


def _dedup_serious(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeats of the same indicator at the same grade, strongest grade
    first, so one domain found in three cache files is one line, not three."""
    order = {g: i for i, g in enumerate(
        [EV_ON_DISK, EV_PERSISTENCE, EV_CONTACTED, EV_ATTEMPTED, EV_CONFIGURED])}
    seen = {}
    for h in hits:
        key = (h["indicator"], h.get("evidence", ""))
        if key not in seen:
            seen[key] = h
    return sorted(seen.values(),
                  key=lambda h: order.get(h.get("evidence", ""), 99))


def _wrap(text: str, width: int) -> List[str]:
    words, lines, cur = text.split(), [], ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        lines.append(cur)
    return lines


def _short_path(path: str) -> str:
    """Keep a path readable without losing which browser or profile it came from.
    The old version cut at "User Data", so Chrome, Edge and Brave all rendered as
    "...\\Default\\Network\\Cookies" and the reader could not tell them apart."""
    p = str(path)
    for marker in ("User Data", "Profiles"):
        if marker in p:
            head, _, tail = p.partition(marker)
            # Keep the last directory before the marker - the vendor folder, e.g.
            # "...\\Google\\Chrome\\User Data\\Default\\...".
            lead = [part for part in head.replace("/", "\\").split("\\") if part]
            vendor = ("\\".join(lead[-2:]) + "\\") if len(lead) >= 2 else ""
            return "...\\" + vendor + marker + tail
    return p if len(p) < 70 else "..." + p[-67:]


def _referrals(w) -> None:
    w("  - Access Now Digital Security Helpline  https://www.accessnow.org/help/")
    w("  - Amnesty International Security Lab     https://securitylab.amnesty.org/")
    w("  - The Citizen Lab                        https://citizenlab.ca/")
