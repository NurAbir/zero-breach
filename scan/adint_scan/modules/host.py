"""Host module — per-user COM persistence, DNS cache, DNS history, hosts file.

Ported from scripts/scan_host.ps1. Four checks, and the reason each one exists:

  1. com-persistence. Citizen Lab's write-up of this Candiru chain says it
     persists via a COM hijack. The technique registers a CLSID under HKCU,
     and Windows resolves HKCU\\Software\\Classes before the machine-wide HKLM
     registration — so a *per-user* InprocServer32 pointing at a DLL in a
     user-writable directory gets loaded into every process that instantiates
     that class, with no admin rights and no service or Run key to find.
     That is the whole appeal of the technique, and it is why this check looks
     at HKCU and not HKLM.
     Legitimate per-user COM registrations absolutely do exist (the reference
     machine had 37 of them), so this check LISTS them for review; it does not
     call them malicious. Per D4 (precision over coverage) an unsigned DLL in
     %LOCALAPPDATA% is not a finding on its own — plenty of honest software
     ships exactly that — so a Hit is emitted only when a registered path
     contains an actual indicator string.

  2. dns-cache. The local resolver cache, which is a record of what this boot
     has already looked up. Reading it resolves nothing: the entries are
     answers the OS kept from queries that already happened (D2).

  3. dns-log. This is the check that matters most in the whole project, and it
     usually FAILS. Microsoft-Windows-DNS-Client/Operational is disabled by
     default on Windows, so on a typical machine there is no DNS history to
     query at all — meaning past contact with a C&C domain cannot be ruled out
     retrospectively, only *future* contact can. Reporting that gap out loud is
     the point; silently reporting "clean" here would be a lie (D3). The report
     prints the one manual command that turns the log on for next time.

  4. hosts-file. Cheap. An indicator pointed at a sink address is a deliberate
     *block* (protective, not reported as a hit); only a mapping to a real
     address is a finding.

Read-only throughout: this module never writes the registry, never enables the
log, and needs no administrator (D7). (A system-writing "arm" helper exists in
arm.py but is deliberately not wired to the CLI in this release.)
"""

from __future__ import annotations

import io
import json
import os
import platform
import subprocess

from ..result import (Hit, ModuleResult, EV_CONTACTED, EV_PERSISTENCE,
                      EV_CONFIGURED, EV_REFERENCED, EV_ON_DISK)

NAME = "host"

# winreg is Windows-only; a non-Windows import must not break the package.
try:
    import winreg  # type: ignore
except ImportError:  # pragma: no cover - non-Windows
    winreg = None  # type: ignore

_PS = ["powershell", "-NoProfile", "-NonInteractive",
       "-ExecutionPolicy", "Bypass", "-Command"]

_DNS_LOG = "Microsoft-Windows-DNS-Client/Operational"

# The sub-keys under a CLSID that name a server binary, in the order the PoC
# checks them. InprocHandler32 is included because it is loaded the same way
# and is the quieter of the three.
_SERVER_KINDS = ("InprocServer32", "LocalServer32", "InprocHandler32")

# HKCU CLSID. Both the 64-bit and 32-bit registry views must be read, and the
# right way is explicit KEY_WOW64_*KEY flags on the ONE logical path - not two
# literal paths. Opening the literal "...\WOW6432Node\CLSID" works only from a
# 64-bit interpreter; from a 32-bit one the plain path is itself redirected into
# WOW6432Node and the literal WOW6432Node path becomes a doubly-nested key that
# does not exist, so the native view - where a hijack lives on a 64-bit box - goes
# unread. winreg may lack the flags on a 32-bit-only build, hence the getattr.
_CLSID_PATH = r"Software\Classes\CLSID"
_REG_VIEWS = [("native", getattr(winreg, "KEY_WOW64_64KEY", 0)),
              ("wow6432", getattr(winreg, "KEY_WOW64_32KEY", 0))]
# ERROR_NO_MORE_ITEMS: the only winerror that means "enumeration finished" rather
# than "enumeration failed". Anything else mid-walk is a truncation, not an end.
_ERROR_NO_MORE_ITEMS = 259

# Exact text required when there is no DNS history to query. Do not reword:
# this gap is the single most important finding the tool can report.
_DNS_LOG_GAP = (
    "DNS-Client/Operational log is disabled (the Windows default) — there is "
    "no queryable DNS history, so past activity cannot be checked "
    "retrospectively from this host")

_ARM_HINT = ("dns-log: Windows is not recording DNS history on this machine. See "
             "\"HOW TO TURN ON DNS HISTORY\" below to start a record a future scan "
             "can search. It cannot answer the question for the past.")

# Spelled out, because "enable DNS logging" is not an instruction most people can
# act on, and this is the single highest-value thing a reader can actually do.
# One manual command only: the tool deliberately does not write to the system in
# this release, so there is nothing here that could get the step wrong or need an
# undo. Turn it off again with the same command and /e:false.
_HOW_TO_ENABLE = [
    "HOW TO TURN ON DNS HISTORY (so a future scan can answer this):",
    "  One command, in an Administrator PowerShell:",
    "    1. Click Start, type \"PowerShell\", right-click it, \"Run as administrator\".",
    "    2. Paste this line and press Enter:",
    "         wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864",
    "  (/e:true turns the log on; /ms sets it to 64 MB so it holds months, not",
    "   hours. To turn it back off later, run the same line with /e:false.)",
    "  This does NOT protect you and tells you nothing about the past. It means that",
    "  next time, there is a record to search instead of an empty attic.",
]


# --- PowerShell plumbing ----------------------------------------------------

def _ps(cmd: str, timeout: int = 60):
    """Run one PowerShell command. Returns (returncode, stdout, stderr).
    Never raises for a non-zero exit; callers decide what a failure means.

    errors="replace" is load-bearing, not defensive dressing. PowerShell writes
    in the console's code page, not UTF-8, and a certificate subject with an
    accented character in it (Proton AG's, for one) emits a byte that is not
    valid UTF-8. With strict decoding that raises inside subprocess's own reader
    thread, the whole check degrades to could_not_run, and the tool reports a gap
    it does not actually have. A mangled character in a signer name is a far
    better outcome than a phantom gap.
    """
    # Ask PowerShell to actually write UTF-8, so the decode above usually has
    # nothing to repair in the first place.
    cmd = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    proc = subprocess.run(_PS + [cmd], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def _ps_json(cmd: str, timeout: int = 60):
    """Run a PowerShell command whose output is ConvertTo-Json.

    Returns (rows, error). `rows` is always a list: ConvertTo-Json emits a bare
    object (not an array) for a single result and nothing at all for an empty
    one, so both shapes are normalised here. `error` is "" on success.
    """
    try:
        rc, out, err = _ps(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], "PowerShell timed out after {}s".format(timeout)
    except OSError as exc:
        return [], "PowerShell could not be launched: {}".format(exc)

    text = out.strip()
    if rc != 0:
        reason = err.strip().splitlines()
        return [], (reason[0] if reason else
                    "PowerShell exited {}".format(rc))
    if not text or text == "null":
        return [], ""
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], "unparseable JSON from PowerShell: {}".format(exc)
    if isinstance(data, dict):      # single object, not a list
        return [data], ""
    if isinstance(data, list):
        return data, ""
    return [], "unexpected JSON shape from PowerShell: {}".format(type(data))


def _ps_literal(value: str) -> str:
    """Quote a path for a PowerShell single-quoted string literal."""
    return "'{}'".format(value.replace("'", "''"))


def _str(row, *names) -> str:
    """Pull the first present, non-null field from a ConvertTo-Json row."""
    if not isinstance(row, dict):
        return "" if row is None else str(row)
    for name in names:
        val = row.get(name)
        if val not in (None, ""):
            return val if isinstance(val, str) else str(val)
    return ""


# --- shared matching --------------------------------------------------------

def _match(r: ModuleResult, ctx, haystack: str, location: str,
           detail_fmt: str, evidence: str = EV_REFERENCED,
           observed: str = "") -> int:
    """Case-insensitive substring match of every network IOC against one blob
    of local text. Each hit carries its own tier/confidence provenance.

    `detail_fmt` is substituted with a plain replace rather than str.format so
    that artifact text containing braces can never break the detail line."""
    found = 0
    low = (haystack or "").lower()
    if not low:
        return 0
    for ind in ctx.iocs.search(low):
        r.add_hit(Hit(indicator=ind.value, location=location,
                      detail=detail_fmt.replace("{ioc}", ind.value),
                      tier=ind.tier, confidence=ind.confidence,
                      source=ind.source, evidence=evidence, observed=observed))
        found += 1
    return found


# --- 1. per-user COM registrations -----------------------------------------

def _boot_time():
    """Last boot time, which is the entire window the DNS resolver cache covers.
    Returns (iso_string_or_None, error)."""
    rows, err = _ps_json(
        "Get-CimInstance Win32_OperatingSystem"
        " | Select-Object @{n='Boot';e={$_.LastBootUpTime.ToString('o')}}"
        " | ConvertTo-Json -Depth 2 -Compress", timeout=60)
    if err or not rows:
        return None, err or "no result"
    boot = _str(rows[0], "Boot")
    return (boot or None), ""


def _user_writable_dirs():
    """Directories a normal user can drop a DLL into without elevation. A COM
    server living under one of these is the shape the Candiru hijack takes."""
    home = os.path.expanduser("~")
    candidates = [
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("TEMP"),
        os.environ.get("PROGRAMDATA"),
        os.path.join(home, "Downloads") if home else None,
    ]
    return [d.rstrip("\\/").lower() for d in candidates if d]


def _enum_com_registrations(r: ModuleResult):
    """Walk HKCU CLSID (both views) and collect every registered server path.

    Uses winreg rather than PowerShell: this is thousands of key opens and
    spawning a shell for it would dominate the module's runtime.
    """
    entries = []
    partial = []  # views where the walk could not be completed
    for view_name, view_flag in _REG_VIEWS:
        access = winreg.KEY_READ | view_flag
        try:
            base = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _CLSID_PATH, 0, access)
        except FileNotFoundError:
            continue  # this view genuinely has no CLSID key - not a failure
        except OSError as exc:
            partial.append("{} view could not be opened ({})".format(
                view_name, exc))
            continue
        try:
            index = 0
            while True:
                try:
                    clsid = winreg.EnumKey(base, index)
                except OSError as exc:
                    if getattr(exc, "winerror", None) not in (None, _ERROR_NO_MORE_ITEMS):
                        # ACCESS_DENIED / KEY_DELETED / transient: the list was
                        # ABORTED, not exhausted. Record how far we got so the
                        # check cannot pass off a truncated walk as complete.
                        partial.append("{} view enumeration stopped after {} "
                                       "keys ({})".format(view_name, index, exc))
                    break
                index += 1
                for kind in _SERVER_KINDS:
                    sub = "{}\\{}".format(clsid, kind)
                    try:
                        with winreg.OpenKey(base, sub, 0, access) as key:
                            value, _type = winreg.QueryValueEx(key, "")
                    except OSError:
                        continue  # no such sub-key, or no default value
                    if not isinstance(value, str) or not value.strip():
                        continue
                    entries.append({
                        "clsid": clsid,
                        "kind": kind,
                        "raw": value,
                        "view": view_name,
                    })
        finally:
            base.Close()
    return entries, partial


def _server_path(raw: str, kind: str) -> str:
    """Turn a registered server value into the path of the binary it names.

    InprocServer32/InprocHandler32 hold a bare DLL path. LocalServer32 holds a
    COMMAND LINE: `"C:\\...\\App.exe" -Embedding`. The PoC only trimmed outer
    quotes, which leaves the switches attached and makes every such entry test
    as "not on disk" — three false review entries on the reference machine. The
    binary is extracted properly here so the on-disk and signature answers are
    about the real file.
    """
    s = os.path.expandvars(raw).strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return s[1:end].strip()
    s = s.strip('"').strip()
    if kind == "LocalServer32" and s:
        try:
            if os.path.exists(s):      # unquoted path with spaces, no switches
                return s
        except OSError:
            pass
        low = s.lower()
        for ext in (".exe", ".com", ".bat", ".cmd"):
            idx = low.find(ext)
            if idx != -1:
                return s[:idx + len(ext)].strip()
    return s


def _signature_status(paths, timeout: int = 180):
    """Authenticode status for many files in ONE PowerShell call.

    Get-AuthenticodeSignature takes an array for -LiteralPath, so the whole
    inventory costs a single subprocess instead of one per file. The reference
    machine had 37 registrations; a process per file is the module's hot path.
    Status is cast to [string] because ConvertTo-Json renders a bare .NET enum
    as its integer value.
    """
    out = {}
    if not paths:
        return out, ""
    ordered = sorted(set(paths))
    error = ""
    # Chunked only to keep the command line well inside its length limit.
    for start in range(0, len(ordered), 100):
        chunk = ordered[start:start + 100]
        cmd = (
            "$p = @({});"
            " Get-AuthenticodeSignature -LiteralPath $p -ErrorAction SilentlyContinue"
            " | Select-Object @{{n='Path';e={{[string]$_.Path}}}},"
            " @{{n='Status';e={{[string]$_.Status}}}},"
            " @{{n='Signer';e={{[string]$_.SignerCertificate.Subject}}}}"
            " | ConvertTo-Json -Depth 3 -Compress"
        ).format(",".join(_ps_literal(p) for p in chunk))
        rows, err = _ps_json(cmd, timeout=timeout)
        if err and not rows:
            error = err
            continue
        for row in rows:
            path = _str(row, "Path")
            if path:
                out[path.lower()] = (_str(row, "Status") or "Unknown",
                                     _str(row, "Signer"))
    return out, error


def _check_com(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] enumerating per-user COM registrations (HKCU CLSID)")
    entries, partial = _enum_com_registrations(r)

    # Expand, de-quote and test each registered path before asking about
    # signatures, so the batched call only covers files that exist on disk.
    writable = _user_writable_dirs()
    on_disk = []
    for e in entries:
        expanded = _server_path(e["raw"], e["kind"])
        e["path"] = expanded
        low = expanded.lower()
        try:
            e["exists"] = bool(expanded) and os.path.exists(expanded)
        except OSError:
            e["exists"] = False
        e["user_writable"] = any(low.startswith(d) for d in writable)
        if e["exists"]:
            on_disk.append(expanded)

    sigs, sig_err = _signature_status(on_disk)
    if sig_err:
        r.note("com-persistence: Authenticode status unavailable for some "
               "entries ({}); treat their signature as unknown".format(sig_err))

    user_writable = 0
    reviewable = []
    for e in entries:
        if e["exists"]:
            status, signer = sigs.get(e["path"].lower(), ("Unknown", ""))
        else:
            status, signer = "n/a (not on disk)", ""
        e["sig"] = status
        e["signer"] = signer
        if e["user_writable"]:
            user_writable += 1

        location = "HKCU\\{}\\{}\\{}".format(
            "Software\\Classes\\WOW6432Node\\CLSID" if e["view"] == "wow6432"
            else "Software\\Classes\\CLSID", e["clsid"], e["kind"])

        # D4: the only COM finding worth calling a Hit is a registered path
        # that actually contains an indicator. "Unsigned DLL in AppData" is a
        # description of a lot of legitimate software, not of this implant.
        _match(r, ctx, "{} {}".format(e["raw"], e["path"]), location,
               "per-user COM server registration references indicator "
               "{ioc} — a COM hijack is this chain's documented persistence; "
               "investigate the registration and the binary",
               EV_PERSISTENCE)

        # Reviewable inventory, deliberately narrowed: an entry is only worth a
        # human's attention if it is BOTH in a user-writable directory AND not
        # validly signed. Collected rather than noted inline, so the list can be
        # capped - 8 full-width "not validly signed" lines in the DETAIL channel
        # read as 8 alarms next to the real hits.
        if e["user_writable"] and status != "Valid":
            reviewable.append((location, e))

    if reviewable:
        r.note("com-persistence: {} per-user COM registration(s) are in a folder "
               "you can write to and are not validly signed. Legitimate software "
               "does this too - these are pointers for a reviewer, NOT findings, "
               "and none of them matched an indicator.".format(len(reviewable)))
        for location, e in reviewable[:3]:
            r.note("    - {} -> {} [on disk: {}; signature: {}{}]".format(
                location, e["path"] or "(empty)",
                "yes" if e["exists"] else "no", e["sig"],
                "; signer: " + e["signer"] if e["signer"] else ""))
        if len(reviewable) > 3:
            r.note("    - ... and {} more, listed in full in the JSON report."
                   .format(len(reviewable) - 3))

    r.checked += len(entries)
    r.submetrics["com_registrations"] = len(entries)
    r.submetrics["com_user_writable"] = user_writable

    # A truncated enumeration must not pass as a complete one (D3). If a registry
    # view could not be fully walked, the COM surface was only partly checked.
    if partial:
        r.could_not_run("com-persistence",
                        "the registry could not be fully enumerated, so an "
                        "auto-start entry may have been missed: {}".format(
                            "; ".join(partial)))
    else:
        r.ran("com-persistence")
    ctx.emit("[host] COM registrations: {} ({} in user-writable dirs)"
             .format(len(entries), user_writable))


# --- 2. DNS resolver cache --------------------------------------------------

def _check_dns_cache(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] reading local DNS resolver cache")
    # Reads the cache the OS already holds. It issues no query and resolves
    # nothing, which is exactly why D2 permits it.
    rows, err = _ps_json(
        "Get-DnsClientCache -ErrorAction Stop"
        " | Select-Object Entry,Name,Data,Type"
        " | ConvertTo-Json -Depth 3 -Compress", timeout=60)
    if err:
        r.could_not_run("dns-cache", "Get-DnsClientCache unavailable: {}".format(err))
        return

    hits = 0
    for row in rows:
        entry = _str(row, "Entry")
        name = _str(row, "Name")
        data = _str(row, "Data")
        hits += _match(
            r, ctx, " ".join((entry, name, data)),
            "DNS resolver cache",
            "indicator {ioc} is in this boot's DNS resolver cache "
            "(Entry=" + (entry or "-") + " Name=" + (name or "-") +
            " Data=" + (data or "-") + ") — something on this host resolved "
            "it since the last reboot",
            EV_CONTACTED)

    r.checked += len(rows)
    r.submetrics["dns_cache_entries"] = len(rows)

    # The resolver cache is wiped by a reboot, so its whole window is "since last
    # boot". Stating that plainly stops a clean cache being read as a clean history.
    boot, boot_err = _boot_time()
    r.reach["dns-cache"] = {
        "earliest": boot,
        "days": None,
        "basis": "the resolver cache holds only this boot session"
                 + ("" if boot else " (boot time unavailable: {})".format(boot_err)),
        "note": "Rebooting empties this entirely. It can say what was looked up "
                "since you last restarted, and nothing before that.",
    }
    r.ran("dns-cache")
    ctx.emit("[host] DNS cache entries: {} ({} indicator matches)"
             .format(len(rows), hits))


# --- 3. retrospective DNS history ------------------------------------------

def _check_dns_log(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] checking whether DNS-Client/Operational history exists")
    rows, err = _ps_json(
        "Get-WinEvent -ListLog '{}' -ErrorAction Stop"
        " | Select-Object @{{n='IsEnabled';e={{[bool]$_.IsEnabled}}}},"
        " @{{n='RecordCount';e={{[int]$_.RecordCount}}}}"
        " | ConvertTo-Json -Depth 3 -Compress".format(_DNS_LOG), timeout=60)

    if err or not rows:
        # Log absent or unreadable: the consequence for the user is identical
        # to it being disabled, so it is reported as the same gap, not as an
        # incidental error.
        r.submetrics["dns_log_enabled"] = 0
        r.submetrics["dns_log_records"] = 0
        r.could_not_run("dns-log", _DNS_LOG_GAP)
        r.note("dns-log: {} could not be queried ({})".format(
            _DNS_LOG, err or "log not present on this host"))
        r.note(_ARM_HINT)
        r.reach["dns-log"] = {
            "earliest": None,
            "days": 0,
            "basis": "no DNS history exists on this host",
            "note": "Nothing was ever recorded, so there is no window at all — "
                    "not a short one.",
            "how_to_enable": _HOW_TO_ENABLE,
        }
        return

    row = rows[0]
    enabled = bool(row.get("IsEnabled"))
    try:
        records = int(row.get("RecordCount") or 0)
    except (TypeError, ValueError):
        records = 0
    r.submetrics["dns_log_enabled"] = 1 if enabled else 0
    r.submetrics["dns_log_records"] = records

    if not enabled or records <= 0:
        # The important branch, and the common one. This must never read clean.
        r.could_not_run("dns-log", _DNS_LOG_GAP)
        r.note("dns-log: {} enabled={} records={} — forward-looking checks are "
               "possible, retrospective ones are not.".format(
                   _DNS_LOG, enabled, records))
        r.note(_ARM_HINT)
        r.reach["dns-log"] = {
            "earliest": None,
            "days": 0,
            "basis": "DNS logging is {} and holds {} records".format(
                "enabled" if enabled else "disabled", records),
            "note": "Nothing was ever recorded, so there is no window at all — "
                    "not a short one. This is the Windows default, on every PC.",
            "how_to_enable": _HOW_TO_ENABLE,
        }
        return

    ctx.emit("[host] DNS-Client/Operational is enabled ({} records); "
             "scanning messages".format(records))
    # -ErrorAction Stop, not SilentlyContinue: with SilentlyContinue a failure to
    # read the channel (ACL, corrupt .evtx, Event Log service degraded) exits 0
    # with no output, so `events` is [] and `ev_err` is "" - and the log, which is
    # ENABLED and holds records, gets reported as a check that ran and found
    # nothing. That rolls up to CLEAN: the one check the whole tool exists for,
    # silently certifying an unread log as clean history. ToString('o') gives ISO
    # 8601 so min()/max() sort chronologically rather than by locale date string.
    events, ev_err = _ps_json(
        "Get-WinEvent -LogName '{}' -MaxEvents 20000"
        " -ErrorAction Stop"
        " | Select-Object @{{n='Time';e={{$_.TimeCreated.ToString('o')}}}},"
        " @{{n='Message';e={{[string]$_.Message}}}}"
        " | ConvertTo-Json -Depth 3 -Compress".format(_DNS_LOG), timeout=300)
    if (ev_err and not events) or (records > 0 and not events):
        reason = ("log is enabled with {} records but none could be read{} - this "
                  "machine's DNS history was NOT searched, so nothing here is "
                  "cleared".format(records, ": " + ev_err if ev_err else ""))
        r.could_not_run("dns-log", reason)
        r.note(_ARM_HINT)
        return

    hits = 0
    times = [t for t in (_str(ev, "Time") for ev in events) if t]
    if times:
        # The log IS on, so there is a real window. Report its true extent rather
        # than implying the whole history of the machine.
        r.reach["dns-log"] = {
            "earliest": min(times),
            "days": None,
            "basis": "oldest of {:,} DNS events read (cap 20,000)".format(
                len(times)),
            "note": "Queries before this are either rotated out of the log or "
                    "beyond the 20,000-event read cap.",
        }
    for ev in events:
        when = _str(ev, "Time")
        hits += _match(
            r, ctx, _str(ev, "Message"),
            "{} @ {}".format(_DNS_LOG, when or "unknown time"),
            "indicator {ioc} appears in a DNS-Client/Operational event" +
            (" at " + when if when else "") +
            " — this host queried that name",
            EV_CONTACTED, when)

    r.checked += len(events)
    r.submetrics["dns_log_events_scanned"] = len(events)
    r.ran("dns-log")
    if records > len(events):
        # Honest about the window actually examined (D3): a capped read is not
        # the same as having read the whole log.
        r.note("dns-log: examined the most recent {} of {} records (cap is "
               "20000); older entries were not checked.".format(
                   len(events), records))
    ctx.emit("[host] DNS log events scanned: {} ({} indicator matches)"
             .format(len(events), hits))


# --- 4. hosts file ----------------------------------------------------------

def _check_hosts(r: ModuleResult, ctx) -> None:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    path = os.path.join(root, "System32", "drivers", "etc", "hosts")
    ctx.emit("[host] reading {}".format(path))
    if not os.path.exists(path):
        r.could_not_run("hosts-file", "no hosts file at {}".format(path))
        return
    try:
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.readlines()
    except OSError as exc:
        r.could_not_run("hosts-file", "could not read {}: {}".format(path, exc))
        return

    active = [ln.strip() for ln in raw
              if ln.strip() and not ln.strip().startswith("#")]
    # A hosts line is "<address> <hostname...>". Pointing an indicator at one of
    # these sink addresses is a deliberate BLOCK - protective, the OPPOSITE of a
    # compromise - so it is not reported as a hit at all, only counted. Only a
    # mapping to a REAL address is a finding (EV_CONFIGURED).
    _SINKS = {"0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:1"}
    hits = 0
    blocked = 0
    for line in active:
        parts = line.split()
        addr = parts[0] if parts else ""
        if addr in _SINKS:
            # Still check it DOES contain an indicator, for the block count, but
            # never raise a hit on a protective entry.
            if ctx.iocs.search(line.lower()):
                blocked += 1
            continue
        hits += _match(
            r, ctx, line, path,
            "indicator {ioc} is mapped in the hosts file to " + addr +
            " (line: " + line + "). This is NOT a sink/block address, so the "
            "name has been pointed at a real host on this machine - unusual, "
            "and worth checking who added it.",
            EV_CONFIGURED)

    r.checked += 1
    r.submetrics["hosts_entries"] = len(active)
    if blocked:
        r.submetrics["hosts_blocked_indicators"] = blocked
        r.note("hosts-file: {} indicator(s) are BLOCKED in the hosts file "
               "(pointed at a sink address). That is protective, not a finding."
               .format(blocked))
    r.ran("hosts-file")
    ctx.emit("[host] active hosts entries: {} ({} indicator matches, {} blocked)"
             .format(len(active), hits, blocked))


# --- 5. known fixed-path file drops -----------------------------------------

# Files this campaign and its tooling drop at a FIXED path, where the path itself
# is the lead. HW.sys is the signed-but-vulnerable kernel driver Candiru brings to
# disable protections (bring-your-own-vulnerable-driver); Avast documented its
# path and the exact hash. The path is a generic name, so presence alone is only a
# pointer - the check hashes the file and says whether it is the KNOWN-BAD build
# (hash in the IOC set) or merely a same-named file to look at.
_KNOWN_DROPS = [
    (r"System32\drivers\HW.sys",
     "the signed-but-vulnerable driver Candiru uses to disable protections "
     "(bring-your-own-vulnerable-driver); documented by Avast, CVE-2022-2294"),
]


def _check_known_paths(r: ModuleResult, ctx) -> None:
    import hashlib
    root = os.environ.get("SystemRoot", r"C:\Windows")
    known_hashes = {h.value for h in ctx.iocs.hashes}
    found = 0
    for rel, why in _KNOWN_DROPS:
        path = os.path.join(root, rel)
        try:
            present = os.path.isfile(path)
        except OSError:
            present = False
        if not present:
            continue
        found += 1
        digest = ""
        try:
            h = hashlib.sha256()
            with io.open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        except OSError:
            # Present but unreadable (locked / permissions): still report it, but
            # say the hash could not be taken so the grade is honest.
            r.note("known-paths: {} exists but could not be read to fingerprint "
                   "it".format(path))
        if digest and digest in known_hashes:
            ind = ctx.iocs.lookup(digest)
            r.add_hit(Hit(
                indicator=digest, location=path,
                detail="the file at {} is the KNOWN-BAD build - {}. Its SHA-256 "
                       "matches a published indicator. Do not delete it; it is "
                       "evidence.".format(path, why),
                tier=ind.tier if ind else "sample",
                confidence=ind.confidence if ind else "secondary",
                source=ind.source if ind else "", evidence=EV_ON_DISK))
        else:
            # Present, but not the known-bad hash (or unreadable). A legitimate
            # driver of the same name exists, so this is a POINTER, not a hit:
            # recorded as a note, graded nowhere, so it never alarms on its own.
            r.note("known-paths: a file exists at {} ({}). This path is {}. "
                   "Its fingerprint does NOT match the known-bad build{}, so it "
                   "is most likely a legitimate same-named file - but given the "
                   "path it is worth a look.".format(
                       path, "SHA-256 " + digest[:16] + "..." if digest else
                       "unreadable", why,
                       "" if digest else " (could not read it)"))
    r.checked += len(_KNOWN_DROPS)
    r.submetrics["known_paths_checked"] = len(_KNOWN_DROPS)
    if found:
        r.submetrics["known_paths_present"] = found
    r.ran("known-paths")
    ctx.emit("[host] known fixed-path drops: {} checked, {} present".format(
        len(_KNOWN_DROPS), found))


# --- module entry point -----------------------------------------------------

def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)

    system = platform.system()
    if system != "Windows" or winreg is None:
        # Never a fake CLEAN on a platform where nothing was observed.
        reason = "not supported on {}".format(system or "unknown platform")
        for name in ("com-persistence", "dns-cache", "dns-log", "hosts-file",
                     "known-paths"):
            r.could_not_run(name, reason)
        return r

    # Each check is isolated: one failure must not cost the others.
    for name, fn in (("com-persistence", _check_com),
                     ("dns-cache", _check_dns_cache),
                     ("dns-log", _check_dns_log),
                     ("hosts-file", _check_hosts),
                     ("known-paths", _check_known_paths)):
        try:
            fn(r, ctx)
        except Exception as exc:
            r.skipped += 1
            r.could_not_run(name, "{}: {}".format(type(exc).__name__, exc))

    return r
