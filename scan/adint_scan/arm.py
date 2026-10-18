"""Tier 5 — `--arm`: make this machine answerable next time.

Why this is the most valuable thing in the tool
-----------------------------------------------
The reference run found that `Microsoft-Windows-DNS-Client/Operational` is
DISABLED by default on Windows. On a normal machine there is therefore no DNS
history at all, which is why the 2024-2025 window in which the Al Jazeera devices
were hit cannot be checked retrospectively from the host. We cannot fix that
backwards. We can make the *next* campaign answerable — and a machine that is a
tripwire is worth more to an at-risk person than one that searches an empty attic.

Doctrine
--------
D5  Nothing here runs without an explicit flag. `--arm` on its own is a DRY RUN:
    it prints precisely what each step would change, whether it needs
    administrator, and how to undo it — and changes nothing. You opt into each
    step by name (or `--all`).
D2  Still no network. Note what is deliberately NOT here: we do not download
    Sysmon. An auto-updating security tool with this adversary is itself a
    target, and fetching a binary at arm time would be exactly the supply-chain
    exposure DESIGN.md warns about. We detect Sysmon and print the manual step.
D3  Every change is journalled with its PRIOR value, so `--undo` restores the
    previous state rather than guessing a default.
"""

from __future__ import annotations

import ctypes
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

STATE_DIRNAME = "adint-scan"
STATE_FILE = "arm-state.json"
BASELINE_FILE = "persistence-baseline.json"

DNS_LOG = "Microsoft-Windows-DNS-Client/Operational"
DNS_LOG_SIZE_BYTES = 64 * 1024 * 1024   # 64 MB of retention, ~months of queries
RESCAN_TASK_NAME = "adint-scan-periodic"

# --- small helpers ----------------------------------------------------------


def state_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, STATE_DIRNAME)


def _state_path() -> str:
    return os.path.join(state_dir(), STATE_FILE)


def _baseline_path() -> str:
    return os.path.join(state_dir(), BASELINE_FILE)


def is_admin() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ps(cmd: str, timeout: int = 120) -> Tuple[int, str, str]:
    """Run a PowerShell command. Used for local system state only — never for
    anything that would resolve or contact an indicator.

    encoding/errors are explicit because PowerShell and the Windows console
    tools write in the console code page, not UTF-8; strict decoding raises
    inside subprocess's reader thread on any non-ASCII byte.
    """
    cmd = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def _run(argv: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    # wevtutil and schtasks emit the console code page; decode leniently so a
    # localised Windows cannot crash an undo.
    proc = subprocess.run(argv, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def _load_state() -> Dict[str, Any]:
    try:
        with open(_state_path(), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"actions": []}


def _save_state(state: Dict[str, Any]) -> None:
    os.makedirs(state_dir(), exist_ok=True)
    with open(_state_path(), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(state, fh, indent=2)
        fh.write("\n")


def _journal(state: Dict[str, Any], action: Dict[str, Any]) -> None:
    action["at"] = datetime.datetime.now().replace(microsecond=0).isoformat()
    state.setdefault("actions", []).append(action)
    _save_state(state)


# --- step 1: DNS-Client operational logging ---------------------------------


def dns_log_state() -> Dict[str, Any]:
    """Read the log's current config with wevtutil, so --undo can restore it."""
    rc, out, err = _run(["wevtutil", "gl", DNS_LOG])
    if rc != 0:
        return {"present": False, "error": (err or out).strip()}
    cfg: Dict[str, Any] = {"present": True, "enabled": None, "maxsize": None}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("enabled:"):
            cfg["enabled"] = line.split(":", 1)[1].strip().lower() == "true"
        elif line.startswith("maxSize:"):
            try:
                cfg["maxsize"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
    return cfg


def enable_dns_log(state: Dict[str, Any], apply: bool) -> List[str]:
    msgs: List[str] = []
    before = dns_log_state()
    if not before.get("present"):
        msgs.append("  [dns-log] log not present on this system: {}"
                    .format(before.get("error", "unknown")))
        return msgs

    msgs.append("  [dns-log] WILL CHANGE: enable {}".format(DNS_LOG))
    msgs.append("            current: enabled={} maxSize={}"
                .format(before.get("enabled"), before.get("maxsize")))
    msgs.append("            after  : enabled=True maxSize={}".format(DNS_LOG_SIZE_BYTES))
    msgs.append("            needs administrator: YES")
    msgs.append("            undo   : restores the two values printed above")
    if not apply:
        return msgs

    if not is_admin():
        msgs.append("  [dns-log] SKIPPED — needs an elevated shell. Re-run the same "
                    "command from an Administrator prompt.")
        return msgs

    rc, out, err = _run(["wevtutil", "sl", DNS_LOG, "/e:true",
                         "/ms:{}".format(DNS_LOG_SIZE_BYTES)])
    if rc != 0:
        msgs.append("  [dns-log] FAILED: {}".format((err or out).strip()))
        return msgs
    _journal(state, {"action": "dns_log", "prior": before})
    after = dns_log_state()
    msgs.append("  [dns-log] DONE — enabled={} maxSize={}"
                .format(after.get("enabled"), after.get("maxsize")))
    msgs.append("            From now on this machine keeps DNS query history. That "
                "is what makes a future check possible at all.")
    return msgs


def undo_dns_log(prior: Dict[str, Any]) -> str:
    if not is_admin():
        return "  [dns-log] SKIPPED — needs an elevated shell."
    enabled = "true" if prior.get("enabled") else "false"
    argv = ["wevtutil", "sl", DNS_LOG, "/e:{}".format(enabled)]
    if prior.get("maxsize"):
        argv.append("/ms:{}".format(prior["maxsize"]))
    rc, out, err = _run(argv)
    if rc != 0:
        return "  [dns-log] undo FAILED: {}".format((err or out).strip())
    return "  [dns-log] restored enabled={} maxSize={}".format(
        enabled, prior.get("maxsize"))


# --- step 2: persistence baseline -------------------------------------------
#
# A list of persistence entries is noise (D4: the reference machine had 37
# per-user COM registrations, every one legitimate). A DIFF against a known-good
# baseline is signal. This records the inventory now so a later run can say
# "these three things appeared since", which is a question worth answering.


def _sha256_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _iter_com_registrations() -> List[Dict[str, Any]]:
    """Per-user COM servers — the documented Candiru persistence technique."""
    if platform.system() != "Windows":
        return []
    import winreg

    found: List[Dict[str, Any]] = []
    for sub in (r"Software\Classes\CLSID", r"Software\Classes\WOW6432Node\CLSID"):
        try:
            root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub)
        except OSError:
            continue
        with root:
            i = 0
            while True:
                try:
                    clsid = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                for kind in ("InprocServer32", "LocalServer32", "InprocHandler32"):
                    try:
                        with winreg.OpenKey(root, clsid + "\\" + kind) as k:
                            val, _ = winreg.QueryValueEx(k, "")
                    except OSError:
                        continue
                    if not val:
                        continue
                    target = os.path.expandvars(str(val)).strip('"')
                    found.append({
                        "kind": "com",
                        "id": "{}\\{}[{}]".format(sub, clsid, kind),
                        "target": target,
                        "sha256": _sha256_file(target) if os.path.isfile(target) else None,
                    })
    return found


def _iter_run_keys() -> List[Dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    import winreg

    hives = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    out: List[Dict[str, Any]] = []
    for hive, sub in hives:
        try:
            key = winreg.OpenKey(hive, sub)
        except OSError:
            continue
        with key:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(key, i)
                except OSError:
                    break
                i += 1
                out.append({
                    "kind": "run",
                    "id": "{}\\{}::{}".format(
                        "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                        sub, name),
                    "target": str(val),
                    "sha256": None,
                })
    return out


def _iter_scheduled_tasks() -> List[Dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    rc, out, _err = _run(["schtasks", "/query", "/fo", "csv", "/nh"], timeout=180)
    if rc != 0:
        return []
    tasks: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip('"') for p in line.split('","')]
        if not parts:
            continue
        name = parts[0].strip('"')
        if not name or name.lower() == "taskname":
            continue
        tasks.append({"kind": "task", "id": name, "target": None, "sha256": None})
    return tasks


def collect_inventory() -> Dict[str, Any]:
    entries = _iter_com_registrations() + _iter_run_keys() + _iter_scheduled_tasks()
    entries.sort(key=lambda e: (e["kind"], e["id"]))
    return {
        "taken_at": datetime.datetime.now().replace(microsecond=0).isoformat(),
        "host": platform.node(),
        "counts": {
            "com": sum(1 for e in entries if e["kind"] == "com"),
            "run": sum(1 for e in entries if e["kind"] == "run"),
            "task": sum(1 for e in entries if e["kind"] == "task"),
        },
        "entries": entries,
    }


def write_baseline(state: Dict[str, Any], apply: bool) -> List[str]:
    msgs: List[str] = []
    path = _baseline_path()
    existed = os.path.exists(path)
    msgs.append("  [baseline] WILL CHANGE: write a persistence inventory to")
    msgs.append("             {}".format(path))
    msgs.append("             (this writes only inside the tool's own state dir — "
                "nothing on the system is modified)")
    msgs.append("             needs administrator: NO")
    msgs.append("             undo   : {}".format(
        "restores the previous baseline" if existed else "deletes that file"))
    if not apply:
        return msgs

    prior = None
    if existed:
        try:
            with open(path, encoding="utf-8") as fh:
                prior = fh.read()
        except OSError:
            prior = None

    inv = collect_inventory()
    os.makedirs(state_dir(), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(inv, fh, indent=2)
        fh.write("\n")
    _journal(state, {"action": "baseline", "path": path, "prior_contents": prior})
    msgs.append("  [baseline] DONE — {} COM, {} Run, {} scheduled tasks recorded"
                .format(inv["counts"]["com"], inv["counts"]["run"],
                        inv["counts"]["task"]))
    msgs.append("             A later `--arm --baseline-diff` now reports what "
                "APPEARED since, instead of dumping a list you cannot judge.")
    return msgs


def baseline_diff() -> List[str]:
    path = _baseline_path()
    try:
        with open(path, encoding="utf-8") as fh:
            old = json.load(fh)
    except (OSError, ValueError):
        return ["  [baseline-diff] no baseline recorded yet — run `--arm --baseline` "
                "first. Without one there is nothing to compare against, and this "
                "tool does not guess."]
    new = collect_inventory()
    old_map = {e["id"]: e for e in old.get("entries", [])}
    new_map = {e["id"]: e for e in new.get("entries", [])}

    added = [i for i in new_map if i not in old_map]
    removed = [i for i in old_map if i not in new_map]
    changed = [i for i in new_map
               if i in old_map and new_map[i].get("sha256") != old_map[i].get("sha256")]

    msgs = ["  [baseline-diff] baseline taken {}".format(old.get("taken_at", "?"))]
    if not (added or removed or changed):
        msgs.append("  [baseline-diff] no change in the persistence set since then.")
        return msgs
    for i in sorted(added):
        msgs.append("  !! APPEARED : {}  -> {}".format(i, new_map[i].get("target")))
    for i in sorted(changed):
        msgs.append("  !! REPLACED : {}  (binary hash changed)".format(i))
    for i in sorted(removed):
        msgs.append("     gone     : {}".format(i))
    msgs.append("  Appeared/replaced entries are worth READING, not panicking about: "
                "software updates legitimately change these.")
    return msgs


# --- step 3: periodic re-scan ----------------------------------------------


def register_rescan(state: Dict[str, Any], apply: bool) -> List[str]:
    msgs: List[str] = []
    launcher = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "adint-scan.py")
    cmd = '"{}" -X utf8 "{}"'.format(sys.executable, launcher)
    msgs.append("  [rescan] WILL CHANGE: create a weekly Scheduled Task named "
                "'{}'".format(RESCAN_TASK_NAME))
    msgs.append("           running: {}".format(cmd))
    msgs.append("           needs administrator: NO (per-user task)")
    msgs.append("           undo   : deletes that scheduled task")
    if not apply:
        return msgs

    rc, out, err = _run(["schtasks", "/create", "/tn", RESCAN_TASK_NAME,
                         "/tr", cmd, "/sc", "weekly", "/f"])
    if rc != 0:
        msgs.append("  [rescan] FAILED: {}".format((err or out).strip()))
        return msgs
    _journal(state, {"action": "rescan_task", "name": RESCAN_TASK_NAME})
    msgs.append("  [rescan] DONE — re-runs weekly against whatever indicator set is "
                "on disk at that time.")
    return msgs


def undo_rescan(name: str) -> str:
    rc, out, err = _run(["schtasks", "/delete", "/tn", name, "/f"])
    if rc != 0:
        return "  [rescan] undo FAILED: {}".format((err or out).strip())
    return "  [rescan] scheduled task '{}' deleted".format(name)


# --- step 4: Sysmon, detected but deliberately NOT installed ----------------


def sysmon_status() -> List[str]:
    msgs: List[str] = []
    rc, out, _err = _run(["sc", "query", "Sysmon64"])
    if rc != 0:
        rc, out, _err = _run(["sc", "query", "Sysmon"])
    if rc == 0 and "RUNNING" in out.upper():
        msgs.append("  [sysmon] already installed and running — good. Its process and "
                    "network events are the best retrospective record you can have.")
    else:
        msgs.append("  [sysmon] not installed. This tool deliberately does NOT download "
                    "it: fetching a binary at arm time is the supply-chain exposure")
        msgs.append("           DESIGN.md warns about, and we will not add a network "
                    "fetch to a tool used by targeted people.")
        msgs.append("           To do it yourself: get Sysmon from Microsoft "
                    "Sysinternals and a vetted config (e.g. SwiftOnSecurity's or")
        msgs.append("           olafhartong's), then `Sysmon64.exe -accepteula -i "
                    "sysmonconfig.xml` from an elevated prompt.")
    return msgs


# --- dispatch ---------------------------------------------------------------


def _print(lines: List[str]) -> None:
    for line in lines:
        print(line)


def dispatch(args) -> int:
    if platform.system() != "Windows":
        print("--arm is Windows-only for now (the confirmed sample is a Windows DLL "
              "and the documented persistence is a Windows COM hijack).",
              file=sys.stderr)
        return 1

    if getattr(args, "undo", False):
        return _do_undo()

    if getattr(args, "baseline_diff", False):
        _print(baseline_diff())
        return 0

    want_dns = getattr(args, "enable_dns_log", False) or getattr(args, "all", False)
    want_base = getattr(args, "baseline", False) or getattr(args, "all", False)
    want_rescan = getattr(args, "rescan", False) or getattr(args, "all", False)
    apply = want_dns or want_base or want_rescan

    print("=" * 72)
    print("  adint-scan --arm   {}".format(
        "APPLYING the steps selected below" if apply else "DRY RUN — nothing will change"))
    print("=" * 72)
    print("Administrator: {}".format("yes" if is_admin() else "no"))
    print("State/undo journal: {}".format(_state_path()))
    print("")

    state = _load_state()

    print("Step 1 — DNS query logging (the one that matters most)")
    _print(enable_dns_log(state, apply and want_dns))
    print("")
    print("Step 2 — persistence baseline, so later runs can show a diff")
    _print(write_baseline(state, apply and want_base))
    print("")
    print("Step 3 — periodic re-scan")
    _print(register_rescan(state, apply and want_rescan))
    print("")
    print("Step 4 — Sysmon (informational only)")
    _print(sysmon_status())
    print("")

    if not apply:
        print("-" * 72)
        print("Nothing was changed. Opt into steps explicitly, e.g.:")
        print("  adint-scan --arm --baseline                 (no admin needed)")
        print("  adint-scan --arm --enable-dns-log           (needs admin)")
        print("  adint-scan --arm --all                      (all of the above)")
        print("Reverse everything later with:  adint-scan --undo")
    else:
        print("-" * 72)
        print("Applied. Undo everything with:  adint-scan --undo")
        print("Enabling DNS logging does not protect you — it only means that next "
              "time,\nthere is something to look at. That is the whole point.")
    print("=" * 72)
    return 0


def _do_undo() -> int:
    state = _load_state()
    actions = state.get("actions", [])
    if not actions:
        print("Nothing to undo — no recorded --arm actions in {}"
              .format(_state_path()))
        return 0

    print("Reversing {} recorded action(s), most recent first:".format(len(actions)))
    remaining: List[Dict[str, Any]] = []
    for action in reversed(actions):
        kind = action.get("action")
        if kind == "dns_log":
            print(undo_dns_log(action.get("prior", {})))
        elif kind == "baseline":
            path = action.get("path", _baseline_path())
            prior = action.get("prior_contents")
            try:
                if prior is None:
                    if os.path.exists(path):
                        os.remove(path)
                    print("  [baseline] {} deleted".format(path))
                else:
                    with open(path, "w", encoding="utf-8", newline="\n") as fh:
                        fh.write(prior)
                    print("  [baseline] previous baseline restored")
            except OSError as exc:
                print("  [baseline] undo FAILED: {}".format(exc))
                remaining.append(action)
        elif kind == "rescan_task":
            print(undo_rescan(action.get("name", RESCAN_TASK_NAME)))
        else:
            print("  (unknown action {!r}, left alone)".format(kind))
            remaining.append(action)

    state["actions"] = list(reversed(remaining))
    _save_state(state)
    if remaining:
        print("\n{} action(s) could not be reversed and remain journalled — most "
              "likely they need an elevated shell.".format(len(remaining)))
        return 1
    print("\nAll recorded changes reversed.")
    return 0
