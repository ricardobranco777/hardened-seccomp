#!/usr/bin/env python3
"""Diff Docker's and Podman's default seccomp profiles.

Writes a structured JSON report and a rendered Markdown report describing:
  - per-engine totals (syscalls allowed, unconditional vs. gated)
  - syscalls allowed only by Docker / only by Podman
  - for syscalls both allow, whether one engine gates it more strictly than the other
  - defaultAction / defaultErrnoRet / defaultErrno and archMap differences
  - a fixed watchlist of security-sensitive syscalls showing how each engine treats them

This is read-only analysis; it does not decide policy. See merge_profiles.py for that.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import seccomp_lib as lib

REPO_ROOT = Path(__file__).resolve().parent.parent

# Security-sensitive syscalls worth calling out explicitly, regardless of how the set
# arithmetic above classifies them. Chosen because they're either well-known
# container-escape/kernel-LPE primitives or because they best illustrate the two engines'
# differing approach to capability gating.
WATCHLIST = [
    "ptrace", "process_vm_readv", "process_vm_writev",
    "perf_event_open", "bpf",
    "userfaultfd",
    "keyctl", "add_key", "request_key",
    "mount", "umount2", "pivot_root", "unshare", "setns",
    "clone", "clone3",
    "reboot", "syslog", "acct",
    "swapon", "swapoff", "nfsservctl",
    "kexec_load", "kexec_file_load",
    "uselib", "vm86", "vm86old",
    "query_module", "init_module", "delete_module", "finit_module",
    "iopl", "ioperm",
    "fanotify_init", "lookup_dcookie", "name_to_handle_at", "open_by_handle_at",
    "personality",
]


def rule_gate_summary(rule: lib.SyscallRule) -> dict:
    return {
        "includes": rule.includes,
        "excludes": rule.excludes,
        "args": rule.args,
    }


def is_allowed_unconditionally(rules: list[lib.SyscallRule]) -> bool:
    return any(r.is_unconditional() for r in rules)


def classify_common(
    docker_rules: list[lib.SyscallRule], podman_rules: list[lib.SyscallRule]
) -> str:
    docker_uncond = is_allowed_unconditionally(docker_rules)
    podman_uncond = is_allowed_unconditionally(podman_rules)
    if docker_uncond and podman_uncond:
        return "both-unconditional"
    if docker_uncond and not podman_uncond:
        return "podman-stricter"
    if podman_uncond and not docker_uncond:
        return "docker-stricter"
    docker_gates = {json.dumps(rule_gate_summary(r), sort_keys=True) for r in docker_rules}
    podman_gates = {json.dumps(rule_gate_summary(r), sort_keys=True) for r in podman_rules}
    return "both-gated-same" if docker_gates == podman_gates else "both-gated-different"


def totals_for(profile: lib.Profile, by_name: dict[str, list[lib.SyscallRule]]) -> dict:
    unconditional = sum(1 for rules in by_name.values() if is_allowed_unconditionally(rules))
    return {
        "unique_syscalls_allowed": len(by_name),
        "unconditional": unconditional,
        "gated": len(by_name) - unconditional,
        "default_action": profile.default_action,
        "default_errno_ret": profile.default_errno_ret,
        "default_errno": profile.default_errno,
    }


def watchlist_entry(
    name: str,
    docker_by_name: dict[str, list[lib.SyscallRule]],
    podman_by_name: dict[str, list[lib.SyscallRule]],
) -> dict:
    def side(by_name: dict[str, list[lib.SyscallRule]]) -> dict:
        rules = by_name.get(name)
        if not rules:
            return {"allowed": False}
        return {
            "allowed": True,
            "unconditional": is_allowed_unconditionally(rules),
            "gates": [rule_gate_summary(r) for r in rules],
        }

    return {"name": name, "docker": side(docker_by_name), "podman": side(podman_by_name)}


def errno_carveouts(profile: lib.Profile, allow_by_name: dict[str, list[lib.SyscallRule]]) -> dict:
    """Names with an explicit per-syscall SCMP_ACT_ERRNO rule (not the profile defaultAction).

    Split into "redundant" (the name also has an ALLOW rule — the ERRNO rule just restates
    that ALLOW rule's capability gate as an explicit exclude, defense-in-depth) and
    "deny-only" (no ALLOW rule at all — the syscall is blocked; the ERRNO rule adds nothing
    beyond the profile's default-deny but documents that the block is intentional).
    """
    all_by_name = lib.rules_by_syscall(profile)
    redundant, deny_only = [], []
    for name, rules in all_by_name.items():
        if not any(r.action == lib.ERRNO for r in rules):
            continue
        (redundant if name in allow_by_name else deny_only).append(name)
    return {"redundant": sorted(redundant), "deny_only": sorted(deny_only)}


def build_report(docker: lib.Profile, podman: lib.Profile) -> dict:
    docker_by_name = lib.allow_rules_by_syscall(docker)
    podman_by_name = lib.allow_rules_by_syscall(podman)
    docker_names = set(docker_by_name)
    podman_names = set(podman_by_name)
    common = sorted(docker_names & podman_names)

    classification: dict[str, list[str]] = {}
    for name in common:
        label = classify_common(docker_by_name[name], podman_by_name[name])
        classification.setdefault(label, []).append(name)

    docker_arches = {e["architecture"] for e in docker.arch_map}
    podman_arches = {e["architecture"] for e in podman.arch_map}

    return {
        "totals": {
            "docker": totals_for(docker, docker_by_name),
            "podman": totals_for(podman, podman_by_name),
        },
        "syscalls": {
            "docker_only": sorted(docker_names - podman_names),
            "podman_only": sorted(podman_names - docker_names),
            "common_count": len(common),
            "classification_counts": {k: len(v) for k, v in classification.items()},
            "classification": classification,
        },
        "arch_map": {
            "docker_only": sorted(docker_arches - podman_arches),
            "podman_only": sorted(podman_arches - docker_arches),
            "common": sorted(docker_arches & podman_arches),
        },
        "watchlist": [watchlist_entry(n, docker_by_name, podman_by_name) for n in WATCHLIST],
        "errno_carveouts": {
            "docker": errno_carveouts(docker, docker_by_name),
            "podman": errno_carveouts(podman, podman_by_name),
        },
    }


def render_markdown(report: dict) -> str:
    lines = ["# Seccomp profile analysis report", ""]
    lines.append("Generated by `scripts/analyze_profiles.py`. See `ANALYSIS.md` for the narrative writeup.")
    lines.append("")

    lines.append("## Totals")
    lines.append("")
    lines.append("| | Docker | Podman |")
    lines.append("|---|---|---|")
    dt, pt = report["totals"]["docker"], report["totals"]["podman"]
    lines.append(f"| Unique syscalls allowed | {dt['unique_syscalls_allowed']} | {pt['unique_syscalls_allowed']} |")
    lines.append(f"| ...allowed unconditionally | {dt['unconditional']} | {pt['unconditional']} |")
    lines.append(f"| ...allowed with a gate (caps/args/minKernel) | {dt['gated']} | {pt['gated']} |")
    lines.append(f"| defaultAction | `{dt['default_action']}` | `{pt['default_action']}` |")
    lines.append(f"| defaultErrnoRet | `{dt['default_errno_ret']}` | `{pt['default_errno_ret']}` |")
    lines.append(f"| defaultErrno | `{dt['default_errno']}` | `{pt['default_errno']}` |")
    lines.append("")

    lines.append("## archMap")
    lines.append("")
    am = report["arch_map"]
    lines.append(f"- Common to both: {', '.join(am['common'])}")
    lines.append(f"- Docker only: {', '.join(am['docker_only']) or '(none)'}")
    lines.append(f"- Podman only: {', '.join(am['podman_only']) or '(none)'}")
    lines.append("")

    sc = report["syscalls"]
    lines.append("## Syscall overlap")
    lines.append("")
    lines.append(f"- Common to both: {sc['common_count']}")
    lines.append(f"- Docker only ({len(sc['docker_only'])}): {', '.join(sc['docker_only'])}")
    lines.append(f"- Podman only ({len(sc['podman_only'])}): {', '.join(sc['podman_only'])}")
    lines.append("")

    lines.append("### Classification of syscalls allowed by both engines")
    lines.append("")
    lines.append("| Classification | Count | Meaning |")
    lines.append("|---|---|---|")
    meanings = {
        "both-unconditional": "Neither engine gates it",
        "docker-stricter": "Podman allows it unconditionally; Docker requires a capability/kernel/arg condition",
        "podman-stricter": "Docker allows it unconditionally; Podman requires a capability/kernel/arg condition",
        "both-gated-same": "Both gate it, with equivalent conditions",
        "both-gated-different": "Both gate it, but with different conditions (manual review)",
    }
    for label, names in sorted(sc["classification"].items()):
        lines.append(f"| `{label}` | {len(names)} | {meanings.get(label, '')} |")
    lines.append("")
    for label, names in sorted(sc["classification"].items()):
        if label == "both-unconditional":
            continue
        lines.append(f"<details><summary>{label} ({len(names)})</summary>\n")
        lines.append(", ".join(f"`{n}`" for n in names))
        lines.append("\n</details>\n")

    lines.append("## Sensitive syscall watchlist")
    lines.append("")
    lines.append("| Syscall | Docker | Podman |")
    lines.append("|---|---|---|")

    def fmt_side(side: dict) -> str:
        if not side["allowed"]:
            return "blocked (not in default allow-list)"
        if side["unconditional"]:
            return "**allowed, unconditional**"
        gates = []
        for gate in side["gates"]:
            parts = []
            if gate["includes"]:
                parts.append(f"includes={gate['includes']}")
            if gate["excludes"]:
                parts.append(f"excludes={gate['excludes']}")
            if gate["args"]:
                parts.append("args-restricted")
            gates.append(" & ".join(parts) if parts else "gated")
        return "allowed if " + " OR ".join(gates)

    for entry in report["watchlist"]:
        lines.append(f"| `{entry['name']}` | {fmt_side(entry['docker'])} | {fmt_side(entry['podman'])} |")
    lines.append("")

    lines.append("## Explicit SCMP_ACT_ERRNO carve-outs")
    lines.append("")
    lines.append(
        "Both profiles mix a handful of explicit per-syscall `SCMP_ACT_ERRNO` rules in among "
        "the `SCMP_ACT_ALLOW` rules, rather than relying only on the profile's default-deny. "
        "\"Redundant\" means the same name also has an ALLOW rule elsewhere (the ERRNO rule "
        "just restates that rule's capability gate as an explicit exclude). \"Deny-only\" "
        "means there is no ALLOW rule at all for that name — it's blocked, and the ERRNO rule "
        "adds nothing beyond the default-deny but documents the block as intentional."
    )
    lines.append("")
    lines.append("| | Docker | Podman |")
    lines.append("|---|---|---|")
    dc, pc = report["errno_carveouts"]["docker"], report["errno_carveouts"]["podman"]
    lines.append(f"| Redundant (also has an ALLOW rule) | {len(dc['redundant'])} | {len(pc['redundant'])} |")
    lines.append(f"| Deny-only (no ALLOW rule at all) | {len(dc['deny_only'])} | {len(pc['deny_only'])} |")
    lines.append("")
    lines.append(f"- Docker deny-only: {', '.join(f'`{n}`' for n in dc['deny_only']) or '(none)'}")
    lines.append(f"- Podman deny-only: {', '.join(f'`{n}`' for n in pc['deny_only']) or '(none)'}")
    lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--docker", default=REPO_ROOT / "profiles/upstream/docker-default.json", type=Path
    )
    parser.add_argument(
        "--podman", default=REPO_ROOT / "profiles/upstream/podman-default.json", type=Path
    )
    parser.add_argument(
        "--out-json", default=REPO_ROOT / "reports/analysis_report.json", type=Path
    )
    parser.add_argument(
        "--out-md", default=REPO_ROOT / "reports/analysis_report.md", type=Path
    )
    args = parser.parse_args()

    docker = lib.load(args.docker)
    podman = lib.load(args.podman)
    report = build_report(docker, podman)

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(report, indent=2) + "\n")
    args.out_md.write_text(render_markdown(report))

    print(f"Wrote {args.out_json}")
    print(f"Wrote {args.out_md}")


if __name__ == "__main__":
    main()
