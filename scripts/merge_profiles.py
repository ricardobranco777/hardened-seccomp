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
  - archMap is the intersection of both engines' declared architectures.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import seccomp_lib as lib

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_deny_list(path: Path) -> dict[str, str]:
    """Load the curated deny-list config into a syscall-name -> reason mapping."""
    data = json.loads(path.read_text())
    return {entry["name"]: entry["reason"] for entry in data["syscalls"]}


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

    merged = lib.Profile(
        default_action=lib.ERRNO,
        default_errno_ret=podman.default_errno_ret,
        default_errno=podman.default_errno,
        arch_map=lib.intersect_arch_maps(docker.arch_map, podman.arch_map),
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
    allowed_elsewhere = set(decisions["kept_unconditional"]) | set(
        decisions["tightened_docker"]
    ) | set(decisions["tightened_podman"]) | set(decisions["union_both_gated"])

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
