"""End-to-end checks against the real, committed profiles.

These tie the committed profiles/hardened-seccomp.json to the current upstream snapshots and
deny-list, so a regression guard fires if someone edits deny-list.json (or the vendored
profiles) without re-running scripts/merge_profiles.py.
"""

import json
import unittest
from pathlib import Path

import merge_profiles as merge
import seccomp_lib as lib

REPO_ROOT = Path(__file__).resolve().parent.parent


class RealProfilesIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.docker = lib.load(REPO_ROOT / "profiles/upstream/docker-default.json")
        self.podman = lib.load(REPO_ROOT / "profiles/upstream/podman-default.json")
        self.deny_list = merge.load_deny_list(REPO_ROOT / "profiles/hardening/deny-list.json")

    def test_merge_of_real_profiles_validates_cleanly(self):
        merged, decisions = merge.build_merge(self.docker, self.podman, self.deny_list)
        self.assertEqual(merge.validate(merged, decisions, self.deny_list), [])
        self.assertGreater(len(merged.syscalls), 0)

    def test_committed_output_matches_a_fresh_merge(self):
        merged, _ = merge.build_merge(self.docker, self.podman, self.deny_list)
        fresh_names = {n for r in merged.syscalls for n in r.names}

        committed = json.loads((REPO_ROOT / "profiles/hardened-seccomp.json").read_text())
        committed_names = {n for rule in committed["syscalls"] for n in rule["names"]}

        self.assertEqual(
            fresh_names,
            committed_names,
            "profiles/hardened-seccomp.json is stale -- re-run scripts/merge_profiles.py",
        )

    def test_denylisted_syscalls_are_absent_from_committed_output(self):
        committed = json.loads((REPO_ROOT / "profiles/hardened-seccomp.json").read_text())
        allowed = {n for rule in committed["syscalls"] for n in rule["names"]}
        for name in self.deny_list:
            self.assertNotIn(name, allowed)


if __name__ == "__main__":
    unittest.main()
