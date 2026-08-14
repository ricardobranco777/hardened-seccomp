#!/usr/bin/env python3
"""Merge Docker's and Podman's default seccomp profiles into one hardened profile.

Policy (see ANALYSIS.md for the full rationale):
  - A syscall is allowed in the output only if BOTH Docker's and Podman's defaults allow
    it (strict intersection). This alone drops everything either engine keeps to itself,
    including the legacy/rare syscalls unique to one engine.
  - Within that intersection, whichever engine gates the syscall (capability/kernel/arg
    condition) wins over an unconditional ALLOW on the other side -- the stricter rule
    always wins.
  - A curated deny-list (profiles/hardening/deny-list.json) hard-blocks a further set of
    historically dangerous syscalls regardless of the above; they stay blocked even if a
    capability is later granted to the container (e.g. via --cap-add).
  - defaultErrnoRet/defaultErrno follow Podman's ENOSYS -- the modern recommended choice,
    since it lets callers treat a blocked syscall as "not implemented" and feature-detect,
    rather than "permission denied".
  - archMap is the union of both engines' declared architectures (an entry for an
    architecture you aren't running on doesn't weaken the profile on the one you are).
  - A couple of syscalls need a hand-derived rule instead of the generic policy above --
    see SPECIAL_CASES and _harden_clone_mask below, and ANALYSIS.md for why.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import seccomp_lib as lib

REPO_ROOT = Path(__file__).resolve().parent.parent

AF_NETLINK = 16
AF_ALG = 38
AF_VSOCK = 40
NETLINK_AUDIT = 9
CLONE_NEWTIME = 0x80


def load_deny_list(path: Path) -> dict[str, str]:
    """Load the curated deny-list config into a syscall-name -> reason mapping."""
    data = json.loads(path.read_text())
    return {entry["name"]: entry["reason"] for entry in data["syscalls"]}


def _merge_socket_rules() -> list[lib.SyscallRule]:
    """Hand-derived socket() policy combining both engines' restrictions.

    The generic "both engines gate it, rules differ -> union both rule sets" strategy is
    unsound here. Docker's filter is purely domain-based (blocks AF_ALG=38 and
    AF_VSOCK=40, no protocol check); Podman's is purely audit-capability-based (blocks
    AF_NETLINK=16 + NETLINK_AUDIT=9 unless CAP_AUDIT_WRITE is granted, no domain-38/40
    check). Naively unioning both rule sets means the syscall is allowed if EITHER side's
    rule matches -- so Podman's broad "any domain but netlink" rule re-admits AF_ALG and
    AF_VSOCK, and Docker's broad "domain < 38" rule (which never checks the protocol arg)
    re-admits the netlink-audit socket. The union ends up *more* permissive than either
    source profile alone, which is the opposite of this project's policy.

    This constructs the actual combination instead: domain not in {AF_ALG, AF_VSOCK} is
    required unconditionally (Docker's restriction has no capability gate), AND the
    netlink-audit socket additionally requires CAP_AUDIT_WRITE (Podman's restriction).
    """
    not_banned_domain = [
        {"index": 0, "value": AF_ALG, "op": "SCMP_CMP_NE"},
        {"index": 0, "value": AF_VSOCK, "op": "SCMP_CMP_NE"},
    ]
    return [
        lib.SyscallRule(
            names=["socket"],
            action=lib.ALLOW,
            args=[{"index": 2, "value": NETLINK_AUDIT, "op": "SCMP_CMP_NE"}, *not_banned_domain],
            excludes={"caps": ["CAP_AUDIT_WRITE"]},
        ),
        lib.SyscallRule(
            names=["socket"],
            action=lib.ALLOW,
            args=[{"index": 0, "value": AF_NETLINK, "op": "SCMP_CMP_NE"}, *not_banned_domain],
            excludes={"caps": ["CAP_AUDIT_WRITE"]},
        ),
        lib.SyscallRule(
            names=["socket"],
            action=lib.ALLOW,
            args=list(not_banned_domain),
            includes={"caps": ["CAP_AUDIT_WRITE"]},
        ),
    ]


SPECIAL_CASES = {"socket": _merge_socket_rules}


def _harden_clone_mask(rule: lib.SyscallRule) -> lib.SyscallRule:
    """Add CLONE_NEWTIME to clone()'s CLONE_NEW*-flags mask filter.

    clone() is tightened to Docker's gate (see ANALYSIS.md), which blocks an unprivileged
    (no CAP_SYS_ADMIN) clone() from setting any CLONE_NEW* namespace flag by masking the
    flags argument against a fixed bitmask and requiring the result to be zero. That mask
    predates CLONE_NEWTIME (added in Linux 5.6) and doesn't include its bit (0x80), so an
    unprivileged clone() can currently create a new time namespace even though every other
    namespace type is blocked. Since this only narrows an already-narrow unprivileged
    allowance -- with no legitimate application workload depending on unprivileged time
    namespace creation -- there's no reason not to close it.
    """
    if not rule.args:
        return rule
    patched_args = [
        {**arg, "value": arg["value"] | CLONE_NEWTIME}
        if arg.get("op") == "SCMP_CMP_MASKED_EQ"
        else arg
        for arg in rule.args
    ]
    return lib.SyscallRule(
        names=rule.names,
        action=rule.action,
        args=patched_args,
        comment=rule.comment,
        includes=rule.includes,
        excludes=rule.excludes,
    )


def build_merge(
    docker: lib.Profile, podman: lib.Profile, deny_list: dict[str, str]
) -> tuple[lib.Profile, dict]:
    """Apply the intersection + stricter-gate-wins + deny-list policy described in this
    module's docstring, returning the merged profile and a decisions dict recording why
    every syscall ended up in or out of it (used for validation and the merge report).
    """
    docker_by_name = lib.allow_rules_by_syscall(docker)
    podman_by_name = lib.allow_rules_by_syscall(podman)
    docker_names = set(docker_by_name)
    podman_names = set(podman_by_name)
    common = docker_names & podman_names

    merged_syscalls: list[lib.SyscallRule] = []
    decisions = {
        "denied_by_policy": [],
        "kept_unconditional": [],
        "tightened_docker": [],
        "tightened_podman": [],
        "union_both_gated": [],
        "special_cased": [],
        "hardened_beyond_source": [],
        "dropped_docker_only": sorted(docker_names - podman_names),
        "dropped_podman_only": sorted(podman_names - docker_names),
    }

    def add_gated(name: str, rules: list[lib.SyscallRule]) -> None:
        """Append one ALLOW rule per distinct condition in `rules`, de-duplicated."""
        seen: set[str] = set()
        for r in rules:
            rule = lib.SyscallRule(
                names=[name], action=lib.ALLOW, args=r.args, includes=r.includes, excludes=r.excludes
            )
            key = rule.group_key()
            if key in seen:
                continue
            seen.add(key)
            merged_syscalls.append(rule)

    for name in sorted(common):
        if name in deny_list:
            decisions["denied_by_policy"].append(name)
            continue

        if name in SPECIAL_CASES:
            merged_syscalls.extend(SPECIAL_CASES[name]())
            decisions["special_cased"].append(name)
            continue

        docker_rules = docker_by_name[name]
        podman_rules = podman_by_name[name]
        docker_uncond = any(r.is_unconditional() for r in docker_rules)
        podman_uncond = any(r.is_unconditional() for r in podman_rules)

        if docker_uncond and podman_uncond:
            merged_syscalls.append(lib.SyscallRule(names=[name], action=lib.ALLOW))
            decisions["kept_unconditional"].append(name)
        elif docker_uncond and not podman_uncond:
            add_gated(name, podman_rules)
            decisions["tightened_podman"].append(name)
        elif podman_uncond and not docker_uncond:
            add_gated(name, docker_rules)
            decisions["tightened_docker"].append(name)
        else:
            add_gated(name, docker_rules + podman_rules)
            decisions["union_both_gated"].append(name)

    for i, rule in enumerate(merged_syscalls):
        if rule.names == ["clone"]:
            merged_syscalls[i] = _harden_clone_mask(rule)
            if "clone" not in decisions["hardened_beyond_source"]:
                decisions["hardened_beyond_source"].append("clone")

    merged = lib.Profile(
        default_action=lib.ERRNO,
        default_errno_ret=podman.default_errno_ret,
        default_errno=podman.default_errno,
        arch_map=lib.union_arch_maps(docker.arch_map, podman.arch_map),
        syscalls=merged_syscalls,
    )
    return merged, decisions


def validate(merged: lib.Profile, decisions: dict, deny_list: dict[str, str]) -> list[str]:
    """Check the merge invariants: non-empty output, and every allowed name is one that
    the decisions dict says should be allowed (not denied, not engine-only, not stray).
    Returns a list of human-readable error strings; empty means the merge is consistent.
    """
    errors = []
    if not merged.syscalls:
        errors.append("merged profile has no syscall rules")

    denied = set(deny_list)
    dropped = set(decisions["dropped_docker_only"]) | set(decisions["dropped_podman_only"])
    allowed_elsewhere = (
        set(decisions["kept_unconditional"])
        | set(decisions["tightened_docker"])
        | set(decisions["tightened_podman"])
        | set(decisions["union_both_gated"])
        | set(decisions["special_cased"])
    )

    for rule in merged.syscalls:
        for name in rule.names:
            if name in denied:
                errors.append(f"{name}: present in output but on the deny-list")
            if name in dropped:
                errors.append(f"{name}: present in output but was an engine-only syscall")
            if name not in allowed_elsewhere:
                errors.append(f"{name}: present in output but not tracked in any merge decision")

    return errors


def render_report(decisions: dict, deny_list: dict[str, str]) -> str:
    """Render the merge decisions as a human-readable Markdown report."""
    lines = ["# Merge report", ""]
    lines.append("Generated by `scripts/merge_profiles.py`.")
    lines.append("")
    lines.append("| Decision | Count |")
    lines.append("|---|---|")
    lines.append(f"| Kept, unconditional (both engines allow it ungated) | {len(decisions['kept_unconditional'])} |")
    lines.append(f"| Tightened to Docker's gate (Podman was ungated) | {len(decisions['tightened_docker'])} |")
    lines.append(f"| Tightened to Podman's gate (Docker was ungated) | {len(decisions['tightened_podman'])} |")
    lines.append(f"| Both gated, rules unioned (manual review recommended) | {len(decisions['union_both_gated'])} |")
    lines.append(f"| Special-cased (hand-derived rule, see merge_profiles.py) | {len(decisions['special_cased'])} |")
    lines.append(f"| Hard-blocked by curated deny-list | {len(decisions['denied_by_policy'])} |")
    lines.append(f"| Dropped, Docker-only | {len(decisions['dropped_docker_only'])} |")
    lines.append(f"| Dropped, Podman-only | {len(decisions['dropped_podman_only'])} |")
    lines.append("")

    lines.append("## Tightened to Docker's gate")
    lines.append("")
    lines.append(", ".join(f"`{n}`" for n in decisions["tightened_docker"]) or "(none)")
    lines.append("")

    lines.append("## Tightened to Podman's gate")
    lines.append("")
    lines.append(", ".join(f"`{n}`" for n in decisions["tightened_podman"]) or "(none)")
    lines.append("")

    lines.append("## Both gated with different conditions (unioned; review recommended)")
    lines.append("")
    lines.append(", ".join(f"`{n}`" for n in decisions["union_both_gated"]) or "(none)")
    lines.append("")

    lines.append("## Special-cased (generic policy would be unsound; see merge_profiles.py docstrings)")
    lines.append("")
    lines.append(", ".join(f"`{n}`" for n in decisions["special_cased"]) or "(none)")
    lines.append("")

    lines.append("## Hardened beyond what either source profile does")
    lines.append("")
    lines.append(", ".join(f"`{n}`" for n in decisions["hardened_beyond_source"]) or "(none)")
    lines.append("")

    lines.append("## Hard-blocked by the curated deny-list")
    lines.append("")
    lines.append("| Syscall | Reason |")
    lines.append("|---|---|")
    for name in decisions["denied_by_policy"]:
        lines.append(f"| `{name}` | {deny_list[name]} |")
    lines.append("")

    lines.append("## Dropped for being engine-only")
    lines.append("")
    lines.append(f"- Docker-only ({len(decisions['dropped_docker_only'])}): " + ", ".join(f"`{n}`" for n in decisions["dropped_docker_only"]))
    lines.append(f"- Podman-only ({len(decisions['dropped_podman_only'])}): " + ", ".join(f"`{n}`" for n in decisions["dropped_podman_only"]))
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    """CLI entry point: load inputs, build and validate the merge, write the profile + report."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--docker", default=REPO_ROOT / "profiles/upstream/docker-default.json", type=Path)
    parser.add_argument("--podman", default=REPO_ROOT / "profiles/upstream/podman-default.json", type=Path)
    parser.add_argument("--deny-list", default=REPO_ROOT / "profiles/hardening/deny-list.json", type=Path)
    parser.add_argument("--out", default=REPO_ROOT / "profiles/hardened-seccomp.json", type=Path)
    parser.add_argument("--report", default=REPO_ROOT / "reports/merge_report.md", type=Path)
    parser.add_argument(
        "--strategy",
        default="intersection",
        choices=["intersection"],
        help="Merge strategy. Only strict intersection + deny-list is implemented today.",
    )
    args = parser.parse_args()

    docker = lib.load(args.docker)
    podman = lib.load(args.podman)
    deny_list = load_deny_list(args.deny_list)

    merged, decisions = build_merge(docker, podman, deny_list)

    errors = validate(merged, decisions, deny_list)
    if errors:
        print("Validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    lib.dump(merged, args.out)

    # round-trip check: the file we just wrote must be valid JSON
    json.loads(args.out.read_text())

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render_report(decisions, deny_list))

    allowed_count = len({name for rule in merged.syscalls for name in rule.names})
    print(f"Wrote {args.out} ({allowed_count} syscalls allowed)")
    print(f"Wrote {args.report}")


if __name__ == "__main__":
    main()
