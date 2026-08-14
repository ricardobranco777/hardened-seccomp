"""Unit tests for scripts/analyze_profiles.py."""

import unittest

import analyze_profiles as analyze
import seccomp_lib as lib


def allow(names, **gate):
    return lib.SyscallRule(names=names, action=lib.ALLOW, **gate)


class ClassifyCommonTests(unittest.TestCase):
    def test_both_unconditional(self):
        label = analyze.classify_common([allow(["read"])], [allow(["read"])])
        self.assertEqual(label, "both-unconditional")

    def test_docker_stricter(self):
        docker = [allow(["ptrace"], includes={"caps": ["CAP_SYS_PTRACE"]})]
        podman = [allow(["ptrace"])]
        self.assertEqual(analyze.classify_common(docker, podman), "docker-stricter")

    def test_podman_stricter(self):
        docker = [allow(["swapon"])]
        podman = [allow(["swapon"], includes={"caps": ["CAP_SYS_ADMIN"]})]
        self.assertEqual(analyze.classify_common(docker, podman), "podman-stricter")

    def test_both_gated_same(self):
        docker = [allow(["chroot"], includes={"caps": ["CAP_SYS_CHROOT"]})]
        podman = [allow(["chroot"], includes={"caps": ["CAP_SYS_CHROOT"]})]
        self.assertEqual(analyze.classify_common(docker, podman), "both-gated-same")

    def test_both_gated_different(self):
        docker = [allow(["perf_event_open"], includes={"caps": ["CAP_SYS_ADMIN"]})]
        podman = [allow(["perf_event_open"], includes={"caps": ["CAP_PERFMON"]})]
        self.assertEqual(analyze.classify_common(docker, podman), "both-gated-different")


class TotalsForTests(unittest.TestCase):
    def test_counts_unconditional_and_gated(self):
        profile = lib.Profile(
            default_action=lib.ERRNO, default_errno_ret=1, default_errno=None, arch_map=[], syscalls=[]
        )
        by_name = {
            "read": [allow(["read"])],
            "mount": [allow(["mount"], includes={"caps": ["CAP_SYS_ADMIN"]})],
        }
        totals = analyze.totals_for(profile, by_name)
        self.assertEqual(totals["unique_syscalls_allowed"], 2)
        self.assertEqual(totals["unconditional"], 1)
        self.assertEqual(totals["gated"], 1)


class ErrnoCarveoutsTests(unittest.TestCase):
    def test_splits_redundant_and_deny_only(self):
        profile = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=1,
            default_errno=None,
            arch_map=[],
            syscalls=[
                allow(["chroot"], includes={"caps": ["CAP_SYS_CHROOT"]}),
                lib.SyscallRule(
                    names=["chroot"], action=lib.ERRNO, excludes={"caps": ["CAP_SYS_CHROOT"]}
                ),
                lib.SyscallRule(names=["swapon"], action=lib.ERRNO),
            ],
        )
        allow_by_name = lib.allow_rules_by_syscall(profile)
        result = analyze.errno_carveouts(profile, allow_by_name)
        self.assertEqual(result["redundant"], ["chroot"])
        self.assertEqual(result["deny_only"], ["swapon"])


class BuildReportTests(unittest.TestCase):
    def test_build_report_end_to_end(self):
        docker = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=1,
            default_errno=None,
            arch_map=[{"architecture": "SCMP_ARCH_X86_64"}],
            syscalls=[
                allow(["read"]),
                allow(["mount"], includes={"caps": ["CAP_SYS_ADMIN"]}),
                allow(["docker_only_call"]),
            ],
        )
        podman = lib.Profile(
            default_action=lib.ERRNO,
            default_errno_ret=38,
            default_errno="ENOSYS",
            arch_map=[{"architecture": "SCMP_ARCH_X86_64"}],
            syscalls=[
                allow(["read"]),
                allow(["mount"]),
                allow(["podman_only_call"]),
            ],
        )
        report = analyze.build_report(docker, podman)

        self.assertEqual(report["syscalls"]["docker_only"], ["docker_only_call"])
        self.assertEqual(report["syscalls"]["podman_only"], ["podman_only_call"])
        self.assertIn("read", report["syscalls"]["classification"]["both-unconditional"])
        self.assertIn("mount", report["syscalls"]["classification"]["docker-stricter"])

        # render_markdown must run without error on whatever build_report produces.
        markdown = analyze.render_markdown(report)
        self.assertIn("Seccomp profile analysis report", markdown)
        self.assertIn("docker_only_call", markdown)


if __name__ == "__main__":
    unittest.main()
