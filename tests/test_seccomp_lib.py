"""Unit tests for scripts/seccomp_lib.py."""

import json
import tempfile
import unittest
from pathlib import Path

import seccomp_lib as lib


class LoadTests(unittest.TestCase):
    def test_load_parses_syscalls_and_defaults(self):
        data = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "defaultErrnoRet": 38,
            "defaultErrno": "ENOSYS",
            "archMap": [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": []}],
            "syscalls": [
                {"names": ["read", "write"], "action": "SCMP_ACT_ALLOW"},
                {
                    "names": ["mount"],
                    "action": "SCMP_ACT_ALLOW",
                    "includes": {"caps": ["CAP_SYS_ADMIN"]},
                },
            ],
        }
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "profile.json"
            path.write_text(json.dumps(data))
            profile = lib.load(path)

        self.assertEqual(profile.default_action, "SCMP_ACT_ERRNO")
        self.assertEqual(profile.default_errno_ret, 38)
        self.assertEqual(profile.default_errno, "ENOSYS")
        self.assertEqual(len(profile.syscalls), 2)
        self.assertEqual(profile.syscalls[0].names, ["read", "write"])
        self.assertIsNone(profile.syscalls[0].includes)
        self.assertEqual(profile.syscalls[1].includes, {"caps": ["CAP_SYS_ADMIN"]})

    def test_load_normalizes_falsy_gates_to_none(self):
        data = {
            "defaultAction": "SCMP_ACT_ERRNO",
            "archMap": [],
            "syscalls": [
                {
                    "names": ["ptrace"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [],
                    "includes": {},
                    "excludes": {},
                    "comment": "",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "profile.json"
            path.write_text(json.dumps(data))
            profile = lib.load(path)

        rule = profile.syscalls[0]
        self.assertIsNone(rule.args)
        self.assertIsNone(rule.includes)
        self.assertIsNone(rule.excludes)
        self.assertIsNone(rule.comment)
        self.assertTrue(rule.is_unconditional())


class SyscallRuleTests(unittest.TestCase):
    def test_is_unconditional(self):
        self.assertTrue(lib.SyscallRule(names=["read"], action=lib.ALLOW).is_unconditional())
        self.assertFalse(
            lib.SyscallRule(
                names=["mount"], action=lib.ALLOW, includes={"caps": ["CAP_SYS_ADMIN"]}
            ).is_unconditional()
        )
        self.assertFalse(
            lib.SyscallRule(
                names=["socket"], action=lib.ALLOW, args=[{"index": 0, "value": 1}]
            ).is_unconditional()
        )

    def test_group_key_ignores_names_but_not_conditions(self):
        a = lib.SyscallRule(names=["read"], action=lib.ALLOW, includes={"caps": ["X"]})
        b = lib.SyscallRule(names=["write"], action=lib.ALLOW, includes={"caps": ["X"]})
        c = lib.SyscallRule(names=["write"], action=lib.ALLOW, includes={"caps": ["Y"]})
        self.assertEqual(a.group_key(), b.group_key())
        self.assertNotEqual(a.group_key(), c.group_key())


class RulesBySyscallTests(unittest.TestCase):
    def _profile(self):
        return lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=1,
            default_errno=None,
            arch_map=[],
            syscalls=[
                lib.SyscallRule(names=["read", "write"], action=lib.ALLOW),
                lib.SyscallRule(names=["swapon"], action=lib.ERRNO),
                lib.SyscallRule(
                    names=["ptrace"], action=lib.ALLOW, includes={"caps": ["CAP_SYS_PTRACE"]}
                ),
            ],
        )

    def test_rules_by_syscall_includes_all_actions(self):
        by_name = lib.rules_by_syscall(self._profile())
        self.assertIn("swapon", by_name)
        self.assertEqual(by_name["swapon"][0].action, lib.ERRNO)

    def test_allow_rules_by_syscall_excludes_errno_only_names(self):
        # swapon only has an SCMP_ACT_ERRNO rule -- it must not show up as "allowed".
        by_name = lib.allow_rules_by_syscall(self._profile())
        self.assertNotIn("swapon", by_name)
        self.assertIn("read", by_name)
        self.assertIn("ptrace", by_name)


class IntersectArchMapsTests(unittest.TestCase):
    def test_keeps_only_common_architectures(self):
        a = [{"architecture": "SCMP_ARCH_X86_64"}, {"architecture": "SCMP_ARCH_RISCV64"}]
        b = [{"architecture": "SCMP_ARCH_X86_64"}]
        self.assertEqual(lib.intersect_arch_maps(a, b), [{"architecture": "SCMP_ARCH_X86_64"}])

    def test_empty_when_no_overlap(self):
        a = [{"architecture": "SCMP_ARCH_X86_64"}]
        b = [{"architecture": "SCMP_ARCH_AARCH64"}]
        self.assertEqual(lib.intersect_arch_maps(a, b), [])


class DumpTests(unittest.TestCase):
    def test_dump_regroups_rules_with_identical_conditions(self):
        profile = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=38,
            default_errno="ENOSYS",
            arch_map=[{"architecture": "SCMP_ARCH_X86_64"}],
            syscalls=[
                lib.SyscallRule(names=["read"], action=lib.ALLOW),
                lib.SyscallRule(names=["write"], action=lib.ALLOW),
                lib.SyscallRule(
                    names=["mount"], action=lib.ALLOW, includes={"caps": ["CAP_SYS_ADMIN"]}
                ),
            ],
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.json"
            lib.dump(profile, path)
            data = json.loads(path.read_text())

        self.assertEqual(data["defaultErrno"], "ENOSYS")
        combined = [e for e in data["syscalls"] if set(e["names"]) == {"read", "write"}]
        self.assertEqual(len(combined), 1, "read/write share identical conditions and should merge")
        mount_entry = next(e for e in data["syscalls"] if e["names"] == ["mount"])
        self.assertEqual(mount_entry["includes"], {"caps": ["CAP_SYS_ADMIN"]})

    def test_dump_round_trips_through_json(self):
        profile = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=1,
            default_errno=None,
            arch_map=[],
            syscalls=[lib.SyscallRule(names=["read"], action=lib.ALLOW)],
        )
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "out.json"
            lib.dump(profile, path)
            reloaded = lib.load(path)
        self.assertEqual(reloaded.default_action, lib.ERRNO)
        self.assertEqual([r.names for r in reloaded.syscalls], [["read"]])


if __name__ == "__main__":
    unittest.main()
