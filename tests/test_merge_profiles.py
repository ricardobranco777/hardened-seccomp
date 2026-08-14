"""Unit tests for scripts/merge_profiles.py."""

import json
import tempfile
import unittest
from pathlib import Path

import merge_profiles as merge
import seccomp_lib as lib


def allow(names, **gate):
    return lib.SyscallRule(names=names, action=lib.ALLOW, **gate)


class BuildMergeTests(unittest.TestCase):
    def setUp(self):
        self.docker = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=1,
            default_errno=None,
            arch_map=[
                {"architecture": "SCMP_ARCH_X86_64"},
                {"architecture": "SCMP_ARCH_RISCV64"},
            ],
            syscalls=[
                allow(["read"]),
                allow(["mount"], includes={"caps": ["CAP_SYS_ADMIN"]}),
                allow(["ptrace"], includes={"caps": ["CAP_SYS_PTRACE"]}),
                allow(["docker_only_call"]),
                allow(["swapon"], includes={"caps": ["CAP_SYS_ADMIN"]}),
            ],
        )
        self.podman = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=38,
            default_errno="ENOSYS",
            arch_map=[{"architecture": "SCMP_ARCH_X86_64"}],
            syscalls=[
                allow(["read"]),
                allow(["mount"]),
                allow(["ptrace"]),
                allow(["podman_only_call"]),
                allow(["swapon"]),
            ],
        )
        self.deny_list = {"ptrace": "test reason"}

    def test_ungated_both_kept_unconditional(self):
        _, decisions = merge.build_merge(self.docker, self.podman, self.deny_list)
        self.assertIn("read", decisions["kept_unconditional"])

    def test_docker_gate_wins_when_podman_ungated(self):
        merged, decisions = merge.build_merge(self.docker, self.podman, self.deny_list)
        self.assertIn("mount", decisions["tightened_docker"])
        mount_rules = [r for r in merged.syscalls if r.names == ["mount"]]
        self.assertEqual(len(mount_rules), 1)
        self.assertEqual(mount_rules[0].includes, {"caps": ["CAP_SYS_ADMIN"]})

    def test_podman_gate_wins_when_docker_ungated(self):
        merged, decisions = merge.build_merge(self.docker, self.podman, self.deny_list)
        self.assertIn("swapon", decisions["tightened_docker"])  # docker is the gated side here too
        swapon_rules = [r for r in merged.syscalls if r.names == ["swapon"]]
        self.assertEqual(swapon_rules[0].includes, {"caps": ["CAP_SYS_ADMIN"]})

    def test_deny_list_blocks_regardless_of_gating(self):
        merged, decisions = merge.build_merge(self.docker, self.podman, self.deny_list)
        self.assertIn("ptrace", decisions["denied_by_policy"])
        self.assertFalse(any("ptrace" in r.names for r in merged.syscalls))

    def test_engine_only_syscalls_are_dropped(self):
        merged, decisions = merge.build_merge(self.docker, self.podman, self.deny_list)
        self.assertIn("docker_only_call", decisions["dropped_docker_only"])
        self.assertIn("podman_only_call", decisions["dropped_podman_only"])
        allowed_names = {n for r in merged.syscalls for n in r.names}
        self.assertNotIn("docker_only_call", allowed_names)
        self.assertNotIn("podman_only_call", allowed_names)

    def test_default_errno_follows_podman(self):
        merged, _ = merge.build_merge(self.docker, self.podman, self.deny_list)
        self.assertEqual(merged.default_errno_ret, 38)
        self.assertEqual(merged.default_errno, "ENOSYS")

    def test_arch_map_is_union(self):
        merged, _ = merge.build_merge(self.docker, self.podman, self.deny_list)
        arches = {e["architecture"] for e in merged.arch_map}
        self.assertEqual(arches, {"SCMP_ARCH_X86_64", "SCMP_ARCH_RISCV64"})

    def test_both_gated_different_conditions_are_unioned(self):
        docker = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=1,
            default_errno=None,
            arch_map=[],
            syscalls=[allow(["perf_event_open"], includes={"caps": ["CAP_SYS_ADMIN"]})],
        )
        podman = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=38,
            default_errno="ENOSYS",
            arch_map=[],
            syscalls=[allow(["perf_event_open"], includes={"caps": ["CAP_PERFMON"]})],
        )
        merged, decisions = merge.build_merge(docker, podman, {})
        self.assertIn("perf_event_open", decisions["union_both_gated"])
        gates = {json.dumps(r.includes, sort_keys=True) for r in merged.syscalls}
        self.assertEqual(
            gates, {json.dumps({"caps": ["CAP_SYS_ADMIN"]}), json.dumps({"caps": ["CAP_PERFMON"]})}
        )

    def test_socket_is_special_cased_and_combines_both_restrictions(self):
        # Regression test: the generic "both gated, union the rules" strategy is unsound
        # for socket() -- Docker's domain filter has no protocol check and Podman's
        # protocol filter has no domain check, so naively unioning them re-admits both
        # AF_ALG/AF_VSOCK (Docker's restriction) and unrestricted netlink-audit sockets
        # (Podman's restriction). socket() must go through the special case instead.
        docker = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=1, default_errno=None, arch_map=[],
            syscalls=[
                allow(["socket"], args=[{"index": 0, "value": 38, "op": "SCMP_CMP_LT"}]),
            ],
        )
        podman = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=38, default_errno="ENOSYS", arch_map=[],
            syscalls=[
                allow(
                    ["socket"],
                    args=[{"index": 0, "value": 16, "op": "SCMP_CMP_NE"}],
                    excludes={"caps": ["CAP_AUDIT_WRITE"]},
                ),
            ],
        )
        merged, decisions = merge.build_merge(docker, podman, {})
        self.assertIn("socket", decisions["special_cased"])

        socket_rules = [r for r in merged.syscalls if r.names == ["socket"]]
        # every rule must exclude AF_ALG (38) and AF_VSOCK (40), regardless of capability
        for rule in socket_rules:
            values = {a["value"] for a in rule.args if a["index"] == 0 and a["op"] == "SCMP_CMP_NE"}
            self.assertTrue({38, 40} <= values, rule)
        # the CAP_AUDIT_WRITE-gated rule must not bypass the AF_ALG/AF_VSOCK restriction
        cap_gated = [r for r in socket_rules if r.includes == {"caps": ["CAP_AUDIT_WRITE"]}]
        self.assertEqual(len(cap_gated), 1)

    def test_clone_mask_gains_clone_newtime_bit(self):
        CLONE_NEWTIME = 0x80
        docker = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=1, default_errno=None, arch_map=[],
            syscalls=[
                allow(
                    ["clone"],
                    args=[{"index": 0, "value": 0x7E020000, "op": "SCMP_CMP_MASKED_EQ"}],
                ),
            ],
        )
        podman = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=38, default_errno="ENOSYS", arch_map=[],
            syscalls=[allow(["clone"])],
        )
        merged, decisions = merge.build_merge(docker, podman, {})
        self.assertIn("clone", decisions["hardened_beyond_source"])
        clone_rule = next(r for r in merged.syscalls if r.names == ["clone"])
        self.assertTrue(clone_rule.args[0]["value"] & CLONE_NEWTIME)


class ValidateTests(unittest.TestCase):
    def test_no_errors_for_a_consistent_merge(self):
        docker = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=1, default_errno=None, arch_map=[],
            syscalls=[allow(["read"])],
        )
        podman = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=38, default_errno="ENOSYS", arch_map=[],
            syscalls=[allow(["read"])],
        )
        merged, decisions = merge.build_merge(docker, podman, {})
        self.assertEqual(merge.validate(merged, decisions, {}), [])

    def test_detects_denylisted_syscall_leaking_into_output(self):
        merged = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=1, default_errno=None, arch_map=[],
            syscalls=[allow(["ptrace"])],
        )
        decisions = {
            "denied_by_policy": [],
            "kept_unconditional": ["ptrace"],
            "tightened_docker": [],
            "tightened_podman": [],
            "union_both_gated": [],
            "special_cased": [],
            "hardened_beyond_source": [],
            "dropped_docker_only": [],
            "dropped_podman_only": [],
        }
        errors = merge.validate(merged, decisions, {"ptrace": "blocked"})
        self.assertTrue(any("deny-list" in e for e in errors))

    def test_empty_profile_is_an_error(self):
        merged = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=1, default_errno=None, arch_map=[], syscalls=[]
        )
        decisions = {
            "denied_by_policy": [], "kept_unconditional": [], "tightened_docker": [],
            "tightened_podman": [], "union_both_gated": [], "special_cased": [],
            "hardened_beyond_source": [], "dropped_docker_only": [], "dropped_podman_only": [],
        }
        errors = merge.validate(merged, decisions, {})
        self.assertTrue(any("no syscall rules" in e for e in errors))


class LoadDenyListTests(unittest.TestCase):
    def test_loads_name_to_reason_mapping(self):
        data = {"syscalls": [{"name": "ptrace", "reason": "why"}]}
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "deny.json"
            path.write_text(json.dumps(data))
            result = merge.load_deny_list(path)
        self.assertEqual(result, {"ptrace": "why"})


if __name__ == "__main__":
    unittest.main()
