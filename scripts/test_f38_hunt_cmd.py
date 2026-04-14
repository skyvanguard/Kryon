"""
F3.8 /hunt REPL command — end-to-end test (no REPL, direct command dispatch).

Exercises the command tree the same way the REPL would:
  /hunt                          -> usage panel
  /hunt status                   -> empty / clean state
  /hunt <repo_url>               -> positional launch via heuristic runner
  /hunt report                   -> reads the last report back from disk
  /hunt stop <id>                -> cancel a hunter that doesn't exist (safe)
"""
import json
import os

# Ensure KRYON_HUNTS_DIR points to a tmp we can inspect
os.environ["KRYON_HUNTS_DIR"] = "/tmp/kryon_hunts_test"

# Fresh import so the command picks up the new env
from kryon.repl.commands import COMMANDS
from kryon.repl.commands.hunt import _LAST_REPORT_PATH  # reset for repeatability

# Clear any prior state
if _LAST_REPORT_PATH.exists():
    _LAST_REPORT_PATH.unlink()

cmd = COMMANDS["/hunt"]
assert cmd is not None

print("=" * 60)
print("F3.8 /hunt command — dispatch tests")
print("=" * 60)

# Test 1: no-arg shows usage
print("\n[1/5] /hunt with no args")
ok = cmd.handle([])
assert ok is True  # usage panel printed

# Test 2: status with nothing running
print("\n[2/5] /hunt status (clean state)")
ok = cmd.handle(["status"])
assert ok is True

# Test 3: report when none exists
print("\n[3/5] /hunt report (none yet)")
ok = cmd.handle(["report"])
assert ok is False  # we return False when no report

# Test 4: launch a hunt (positional URL -> routes to handle_launch)
print("\n[4/5] /hunt <url> (positional -> heuristic runner)")
ok = cmd.handle([
    "https://github.com/madler/zlib.git",
    "--runner", "heuristic",
    "--parallel", "2",
    "--budget", "3",   # keep test quick
])
assert ok is True, "launch should succeed"

# Verify the report was saved
assert _LAST_REPORT_PATH.exists(), f"expected {_LAST_REPORT_PATH} to exist"
data = json.loads(_LAST_REPORT_PATH.read_text())
assert data["repo_url"].endswith("zlib.git")
assert data["runner_type"] == "heuristic"
assert data["parallelism"] == 2
assert data["files_scored"] > 0
print(f"   hunters spawned: {data['hunters_spawned']}")
print(f"   confirmed: {data['confirmed_findings']}, rejected: {data['rejected_findings']}")

# Test 5: report reads the saved file
print("\n[5/5] /hunt report (after launch)")
ok = cmd.handle(["report"])
assert ok is True

# Bonus: /hunt stop with bogus id
print("\n[+]   /hunt stop <bogus-id> (graceful failure)")
ok = cmd.handle(["stop", "h_nonexistent"])
# returns False since hunter wasn't found -- that's correct
assert ok is False

print()
print("ALL /hunt DISPATCH TESTS PASSED")
