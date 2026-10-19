#!/usr/bin/env python3
"""Small, offline pre-release gate. Never runs a scan against the real host."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = ("clean", "contact", "reference", "hash", "corrupt", "hit-and-gap", "quick",
         "dns-cap-hit", "dns-cap-gap", "bad-feed", "patterns")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-patterns", action="store_true",
                        help="require the pinned optional engine (use for releases)")
    parser.add_argument("--e2e-only", action="store_true",
                        help="CI: unit suite already ran in the same job")
    parser.add_argument("--scanner", type=Path,
                        help="also require this staged download to match the fresh build")
    parser.add_argument("--web-dir", type=Path,
                        help="Scan-page directory; require its logic test and checksum to pass")
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "findings" / "release-checks")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    steps = []
    summary = {"status": "FAIL", "steps": steps, "skipped": [],
               "scope": "Offline fixtures; OS collection is simulated; no personal scan"}
    env = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")

    def run(name, command, timeout=60):
        tick = time.monotonic()
        try:
            proc = subprocess.run(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=timeout)
            text = proc.stdout.decode("utf-8", errors="replace")
            (output / (name + ".log")).write_text(text, encoding="utf-8")
            if proc.returncode:
                raise RuntimeError("{} failed (exit {}); see {}".format(
                    name, proc.returncode, output / (name + ".log")))
        except subprocess.TimeoutExpired:
            raise RuntimeError("{} exceeded {}s; release check failed".format(name, timeout))
        steps.append({"name": name, "seconds": round(time.monotonic() - tick, 2)})
        print("PASS {} ({:.1f}s)".format(name, time.monotonic() - tick), flush=True)

    try:
        sys.path.insert(0, str(ROOT / "scan"))
        from adint_scan.candiru_rules import CANDIRU_ENGINE_VERSION
        engine = importlib.util.find_spec("yara_x") is not None
        if engine:
            from importlib.metadata import version
            if version("yara-x") != CANDIRU_ENGINE_VERSION:
                raise RuntimeError("optional engine version differs from requirements-patterns.txt")
        elif args.require_patterns:
            raise RuntimeError("pinned YARA-X missing; install requirements-patterns.txt "
                               "in this interpreter's virtual environment first")
        else:
            summary["skipped"].append("Real YARA-X positives: engine not installed")

        if not args.e2e_only:
            run("unit-tests", [sys.executable, "-B", "-m", "unittest", "discover",
                               "-s", "scan/tests"], timeout=180)

        with tempfile.TemporaryDirectory(prefix="zb_release_") as temp:
            work = Path(temp)
            first, second = work / "scanner.py", work / "scanner-again.py"
            for name, path in (("build", first), ("rebuild", second)):
                run(name, [sys.executable, "-B", str(ROOT / "build/bundle.py"),
                           str(ROOT), str(path)])
            if first.read_bytes() != second.read_bytes():
                raise RuntimeError("two single-file builds differ")
            digest = hashlib.sha256(first.read_bytes()).hexdigest()
            summary["scanner_sha256"] = digest
            scanner = first
            if args.scanner:
                scanner = args.scanner.resolve()
                if scanner.read_bytes() != first.read_bytes():
                    raise RuntimeError("staged scanner differs from the tested source build")
            run("scanner-help", [sys.executable, "-B", str(scanner), "--help"])
            run("scanner-version", [sys.executable, "-B", str(scanner), "--version"])

            for case in CASES:
                pair = []
                for target in ("source", "bundle"):
                    case_root = work / (target + "-" + case)
                    result = case_root / "result.json"
                    run(target + "-" + case,
                        [sys.executable, "-B", str(ROOT / "tools/release_fixture.py"),
                         target, case, str(case_root), str(scanner)], timeout=45)
                    pair.append(json.loads(result.read_text(encoding="utf-8")))
                if pair[0] != pair[1]:
                    raise RuntimeError("source/download results disagree for " + case)

            web = args.web_dir
            if web is None and (ROOT / "web/scan").is_dir():
                web = ROOT / "web/scan"
            if web is not None:
                web = web.resolve()
                test = web / "ops/test_scan_logic.js"
                if not test.is_file() or not shutil.which("node"):
                    raise RuntimeError("web check requires Node and ops/test_scan_logic.js")
                run("web-logic", ["node", str(test)])
                html = (web / "index.html").read_text(encoding="utf-8")
                if digest not in html:
                    raise RuntimeError("Scan page checksum differs from the candidate download")
                steps.append({"name": "web-download-checksum", "seconds": 0})
            else:
                summary["skipped"].append("Website: separate site source not supplied (--web-dir)")

        summary["status"] = "PASS_WITH_SKIPS" if summary["skipped"] else "PASS"
        print("\nPASS: source/download fixtures agree; inputs unchanged; "
              "no socket/subprocess activity during fixture scans.")
        for skip in summary["skipped"]:
            print("NOT RUN: " + skip)
        print("Scanner SHA-256: " + digest)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        summary["error"] = str(exc)
        print("\nFAIL: " + str(exc), file=sys.stderr)
        return 1
    finally:
        summary["seconds"] = round(time.monotonic() - started, 2)
        (output / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print("Results: " + str(output / "summary.json"))


if __name__ == "__main__":
    raise SystemExit(main())
