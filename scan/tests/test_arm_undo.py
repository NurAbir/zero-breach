"""Tier 5 — verify `--undo` restores every change `--arm` made.

SPEC-scanner.md, testing requirements: "Verify --undo restores every change
--arm made." Doctrine under test:

  D5  Read-only by default. `--arm` with no step selected is a DRY RUN: it
      states exactly what WOULD change, whether administrator is needed, and
      how to undo it, and it changes nothing at all.
  D3  Every change is journalled with its PRIOR value, so undo restores the
      previous state instead of guessing a default. A missing baseline is not
      invented; it is reported as "run --arm --baseline first".

SAFETY — this test suite must not change the real machine.
  * `enable_dns_log(..., apply=True)` and `register_rescan(..., apply=True)` are
    NEVER called: they need administrator / create a real Scheduled Task. Only
    the dry-run paths of those two steps are exercised.
  * The one step applied for real is the baseline, and only after
    `LOCALAPPDATA` has been redirected to a temp dir, so every file written
    lands under that temp dir. `arm.state_dir()` reads the variable at call
    time (asserted below), so patching os.environ is sufficient and no module
    attribute caches the path.
  * The dry-run tests additionally replace `arm._run` with a tripwire that
    fails the test if anything shells out, so a dry run provably cannot touch
    wevtutil or schtasks.
  * The inventory shape check supplies synthetic collector inputs. No test
    enumerates the real registry, hashes registered targets, or invokes schtasks.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adint_scan import arm                                 # noqa: E402

_SENTINEL = object()


def stub_inventory(tag="one"):
    return {
        "taken_at": "2025-01-01T00:00:0" + ("0" if tag == "one" else "1"),
        "host": "test-host",
        "counts": {"com": 1, "run": 1, "task": 1},
        "entries": [
            {"kind": "com", "id": "CLSID/{test}[InprocServer32]",
             "target": r"C:\fake\benign.dll", "sha256": "ab" * 32},
            {"kind": "run", "id": "HKCU\\...\\Run::thing",
             "target": r"C:\fake\thing.exe", "sha256": None},
            {"kind": "task", "id": "\\test\\task", "target": None,
             "sha256": None},
        ],
    }


class ArmSandbox(unittest.TestCase):
    """Redirects the tool's state dir into a temp dir for every test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="adint_arm_")
        self._saved_local = os.environ.get("LOCALAPPDATA", _SENTINEL)
        os.environ["LOCALAPPDATA"] = self.tmp
        # Prove the redirection actually took effect before anything is run:
        # if state_dir() were resolved at import time this would fail loudly
        # instead of writing to the user's real AppData.
        self.assertTrue(
            os.path.abspath(arm.state_dir()).startswith(os.path.abspath(self.tmp)),
            "arm.state_dir() must honour LOCALAPPDATA at call time; refusing to "
            "run a test that would write to the real machine")
        self.state_path = arm._state_path()
        self.baseline_path = arm._baseline_path()

    def tearDown(self):
        if self._saved_local is _SENTINEL:
            os.environ.pop("LOCALAPPDATA", None)
        else:
            os.environ["LOCALAPPDATA"] = self._saved_local
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers -----------------------------------------------------------

    @contextlib.contextmanager
    def no_subprocess(self):
        """Any shell-out during the block fails the test."""
        def tripwire(*a, **k):
            self.fail("a dry run must not shell out; got {!r}".format(a))
        saved_run, saved_ps = arm._run, arm._ps
        arm._run, arm._ps = tripwire, tripwire
        try:
            yield
        finally:
            arm._run, arm._ps = saved_run, saved_ps

    @contextlib.contextmanager
    def stubbed_inventory(self, tag="one"):
        saved = arm.collect_inventory
        arm.collect_inventory = lambda: stub_inventory(tag)
        try:
            yield
        finally:
            arm.collect_inventory = saved

    def undo(self):
        """Run _do_undo() with its printing captured; returns (rc, output)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = arm._do_undo()
        return rc, buf.getvalue()

    def files_under_state_dir(self):
        d = arm.state_dir()
        if not os.path.isdir(d):
            return []
        return sorted(os.listdir(d))


class TestStateDirRedirection(ArmSandbox):
    def test_state_dir_is_read_from_the_environment_at_call_time(self):
        self.assertEqual(os.path.dirname(arm.state_dir()),
                         os.path.abspath(self.tmp))
        self.assertTrue(arm.state_dir().endswith(arm.STATE_DIRNAME))
        other = os.path.join(self.tmp, "second")
        os.environ["LOCALAPPDATA"] = other
        self.assertEqual(arm.state_dir(),
                         os.path.join(other, arm.STATE_DIRNAME))
        os.environ["LOCALAPPDATA"] = self.tmp

    def test_sandbox_starts_with_no_state(self):
        self.assertEqual(self.files_under_state_dir(), [])
        self.assertEqual(arm._load_state(), {"actions": []})


class TestDryRunChangesNothing(ArmSandbox):
    """D5: `--arm` without an explicit step must change nothing, and must say
    what it would change, whether admin is needed, and how to undo it."""

    def setUp(self):
        super().setUp()
        self.state = {"actions": []}
        # dns_log_state() only *reads* config via wevtutil, but stubbing it
        # keeps the message contract deterministic on any Windows build and
        # lets the no-subprocess tripwire stay armed.
        self._saved_dns_state = arm.dns_log_state
        arm.dns_log_state = lambda: {"present": True, "enabled": False,
                                     "maxsize": 1052672}

    def tearDown(self):
        arm.dns_log_state = self._saved_dns_state
        super().tearDown()

    def _assert_dry_run_contract(self, msgs, label):
        text = "\n".join(msgs).lower()
        self.assertIn("will change", text,
                      "{}: a dry run must state what WOULD change".format(label))
        self.assertIn("administrator", text,
                      "{}: a dry run must say whether admin is needed"
                      .format(label))
        self.assertIn("undo", text,
                      "{}: a dry run must say how to undo it".format(label))

    def _assert_nothing_happened(self):
        self.assertEqual(self.state.get("actions", []), [],
                         "a dry run must journal no action")
        self.assertFalse(os.path.exists(self.state_path),
                         "a dry run must not write the state/journal file")
        self.assertFalse(os.path.exists(self.baseline_path),
                         "a dry run must not write a baseline")
        self.assertEqual(self.files_under_state_dir(), [],
                         "a dry run must create no files at all")

    def test_dns_log_dry_run(self):
        with self.no_subprocess():
            msgs = arm.enable_dns_log(self.state, apply=False)
        self._assert_dry_run_contract(msgs, "dns-log")
        self.assertIn("yes", "\n".join(msgs).lower().split(
            "needs administrator:")[1][:8],
            "dns-log must say administrator is required")
        self.assertIn(arm.DNS_LOG, "\n".join(msgs))
        self._assert_nothing_happened()

    def test_baseline_dry_run(self):
        with self.no_subprocess():
            msgs = arm.write_baseline(self.state, apply=False)
        self._assert_dry_run_contract(msgs, "baseline")
        joined = "\n".join(msgs)
        self.assertIn(self.baseline_path, joined,
                      "the dry run must name the exact file it would write")
        self.assertIn("needs administrator: NO", joined)
        self._assert_nothing_happened()

    def test_rescan_dry_run(self):
        with self.no_subprocess():
            msgs = arm.register_rescan(self.state, apply=False)
        self._assert_dry_run_contract(msgs, "rescan")
        joined = "\n".join(msgs)
        self.assertIn(arm.RESCAN_TASK_NAME, joined,
                      "the dry run must name the task it would create")
        self._assert_nothing_happened()

    def test_all_three_dry_runs_together_still_change_nothing(self):
        with self.no_subprocess():
            arm.enable_dns_log(self.state, apply=False)
            arm.write_baseline(self.state, apply=False)
            arm.register_rescan(self.state, apply=False)
        self._assert_nothing_happened()


class TestBaselineRoundTrip(ArmSandbox):
    def test_apply_then_undo_removes_the_file_and_empties_the_journal(self):
        state = {"actions": []}
        with self.stubbed_inventory():
            msgs = arm.write_baseline(state, apply=True)
        self.assertIn("DONE", "\n".join(msgs))
        self.assertTrue(os.path.exists(self.baseline_path))

        # Exactly one journalled action, carrying the prior value (none).
        self.assertEqual(len(state["actions"]), 1)
        action = state["actions"][0]
        self.assertEqual(action["action"], "baseline")
        self.assertIsNone(action["prior_contents"],
                          "there was no previous baseline, so the prior value "
                          "must be recorded as None")
        self.assertEqual(action["path"], self.baseline_path)
        self.assertIn("at", action, "every action must be timestamped")
        self.assertEqual(arm._load_state()["actions"], state["actions"],
                         "the journal must be persisted, or undo cannot work")

        # baseline_diff against the same inventory reports no change.
        with self.stubbed_inventory():
            diff = "\n".join(arm.baseline_diff())
        self.assertIn("no change in the persistence set", diff)
        self.assertNotIn("APPEARED", diff)

        rc, out = self.undo()
        self.assertEqual(rc, 0)
        self.assertIn("deleted", out)
        self.assertFalse(os.path.exists(self.baseline_path),
                         "--undo must remove the baseline it created")
        self.assertEqual(arm._load_state()["actions"], [],
                         "a reversed action must leave the journal empty")

    def test_baseline_diff_reports_what_appeared(self):
        state = {"actions": []}
        with self.stubbed_inventory("one"):
            arm.write_baseline(state, apply=True)

        def grown():
            inv = stub_inventory("two")
            inv["entries"].append({"kind": "com", "id": "CLSID/{new}[Inproc]",
                                   "target": r"C:\fake\new.dll",
                                   "sha256": "cd" * 32})
            return inv

        saved = arm.collect_inventory
        arm.collect_inventory = grown
        try:
            diff = "\n".join(arm.baseline_diff())
        finally:
            arm.collect_inventory = saved
        self.assertIn("APPEARED", diff)
        self.assertIn("CLSID/{new}[Inproc]", diff)

    def test_undo_restores_the_previous_baseline_rather_than_deleting_it(self):
        # Two armed sessions. Each caller passes its own freshly-loaded journal;
        # here the second session's journal holds only its own action, which is
        # the case that must RESTORE the prior file instead of removing it.
        with self.stubbed_inventory("one"):
            arm.write_baseline({"actions": []}, apply=True)
        with open(self.baseline_path, encoding="utf-8") as fh:
            first = fh.read()

        with self.stubbed_inventory("two"):
            second_state = {"actions": []}
            arm.write_baseline(second_state, apply=True)
        with open(self.baseline_path, encoding="utf-8") as fh:
            second = fh.read()
        self.assertNotEqual(first, second, "the two baselines must differ, or "
                                           "the restore proves nothing")
        self.assertEqual(second_state["actions"][0]["prior_contents"], first,
                         "the journal must record the PRIOR contents")

        rc, out = self.undo()
        self.assertEqual(rc, 0)
        self.assertIn("previous baseline restored", out)
        self.assertTrue(os.path.exists(self.baseline_path),
                        "undo of an overwrite must restore, not delete")
        with open(self.baseline_path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), first,
                             "undo must restore the FIRST baseline byte for "
                             "byte, not just delete the file")
        self.assertEqual(json.loads(first)["taken_at"],
                         stub_inventory("one")["taken_at"])

    def test_undoing_every_journalled_action_returns_to_the_pristine_state(self):
        # Both writes journalled in one session: reversing EVERY recorded action
        # (newest first) restores the file to the first baseline and then
        # removes it, because before --arm ran there was no baseline at all.
        state = {"actions": []}
        with self.stubbed_inventory("one"):
            arm.write_baseline(state, apply=True)
        with self.stubbed_inventory("two"):
            arm.write_baseline(state, apply=True)
        self.assertEqual(len(state["actions"]), 2)

        rc, out = self.undo()
        self.assertEqual(rc, 0)
        self.assertIn("previous baseline restored", out)
        self.assertIn("deleted", out)
        self.assertFalse(os.path.exists(self.baseline_path),
                         "undoing every change must leave the machine as it was "
                         "before --arm ran: no baseline file")
        self.assertEqual(arm._load_state()["actions"], [])


class TestUndoEdgeCases(ArmSandbox):
    def test_undo_with_an_empty_journal_is_a_no_op(self):
        rc, out = self.undo()
        self.assertEqual(rc, 0)
        self.assertIn("Nothing to undo", out)
        self.assertEqual(self.files_under_state_dir(), [],
                         "a no-op undo must not create state of its own")

    def test_undo_leaves_an_unknown_action_alone_and_reports_it(self):
        arm._save_state({"actions": [{"action": "something-new-and-unknown"}]})
        rc, out = self.undo()
        self.assertEqual(rc, 1, "an action that could not be reversed must not "
                                "be reported as success")
        self.assertIn("unknown action", out)
        self.assertEqual(len(arm._load_state()["actions"]), 1,
                         "an unreversed action must stay journalled")

    def test_baseline_diff_without_a_baseline_does_not_invent_a_result(self):
        def tripwire():
            self.fail("baseline_diff must not collect an inventory when there "
                      "is no baseline to compare it against")
        saved = arm.collect_inventory
        arm.collect_inventory = tripwire
        try:
            msgs = arm.baseline_diff()
        finally:
            arm.collect_inventory = saved
        text = "\n".join(msgs)
        self.assertIn("no baseline recorded yet", text)
        self.assertIn("--arm --baseline", text,
                      "the user must be told the exact command to run")
        self.assertNotIn("no change", text,
                         "absence of a baseline must never be reported as 'no "
                         "change' — that would be an inferred result (D3)")
        self.assertNotIn("APPEARED", text)


class TestRealInventoryShape(ArmSandbox):
    """The real inventory aggregator receives hermetic collector results."""

    def test_collect_inventory_returns_the_documented_shape(self):
        def row(kind):
            return [{"kind": kind, "id": kind + "-synthetic", "target": None,
                     "sha256": None}]
        with patch.object(arm, "_iter_com_registrations", return_value=row("com")), \
             patch.object(arm, "_iter_run_keys", return_value=row("run")), \
             patch.object(arm, "_iter_scheduled_tasks", return_value=row("task")), \
             self.no_subprocess():
            inv = arm.collect_inventory()
        self.assertEqual(sorted(inv), ["counts", "entries", "host", "taken_at"])
        self.assertIsInstance(inv["taken_at"], str)
        self.assertIsInstance(inv["host"], str)
        self.assertEqual(sorted(inv["counts"]), ["com", "run", "task"])
        for key in ("com", "run", "task"):
            self.assertIsInstance(inv["counts"][key], int)
        self.assertIsInstance(inv["entries"], list)
        for e in inv["entries"]:
            self.assertIn(e["kind"], ("com", "run", "task"))
            self.assertIn("id", e)
            self.assertIn("target", e)
            self.assertIn("sha256", e)
        self.assertEqual(
            sum(inv["counts"].values()), len(inv["entries"]),
            "the counts must describe the entries actually collected")
        # Collecting an inventory is read-only: nothing is written anywhere.
        self.assertEqual(self.files_under_state_dir(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
