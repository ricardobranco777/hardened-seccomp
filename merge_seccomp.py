#!/usr/bin/env python3
"""Merge Docker's and Podman's default seccomp profiles into one profile that works with
both: a syscall is allowed only if BOTH default profiles allow it, and whichever side
gates it more strictly (capability, kernel version, or argument) wins.

Two things follow from "take the stricter combination" rather than a plain per-name
comparison:
  - `socket()` needs a hand-derived rule (see _merge_socket_rules): Docker and Podman each
    restrict a different argument of the same call, so combining them isn't a matter of
    picking one side's rule -- both restrictions have to hold at once.
  - defaultErrnoRet/defaultErrno follow Podman's ENOSYS (the modern recommended choice over
    Docker's EPERM), and archMap is the union of both engines' declared architectures (an
    arch entry only affects whether the profile can load on that architecture, not what's
    allowed on the one a container is actually running on).

Inputs are fetched live from GitHub on every run (see DOCKER_URL/PODMAN_URL below) --
tracking each engine's default branch, not a pinned commit, so the merge always reflects
the current upstream defaults. Edit those constants to a local file path instead if you
want to run against a fixed snapshot. Prints the merged profile JSON to stdout.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DOCKER_URL = "https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json"
PODMAN_URL = "https://raw.githubusercontent.com/containers/common/main/pkg/seccomp/seccomp.json"

ALLOW = "SCMP_ACT_ALLOW"
ERRNO = "SCMP_ACT_ERRNO"

AF_NETLINK = 16
AF_ALG = 38
AF_VSOCK = 40
NETLINK_AUDIT = 9


@dataclass
class SyscallRule:
    """One entry from a seccomp profile's `syscalls` list: one or more syscall names
    sharing the same action and gating (args/includes/excludes)."""

    names: list[str]
    action: str
    args: list[dict[str, Any]] | None = None
    comment: str | None = None
    includes: dict[str, Any] | None = None
    excludes: dict[str, Any] | None = None

    def is_unconditional(self) -> bool:
        """True if this rule applies with no capability/kernel/arg gating at all."""
        return not self.args and not self.includes and not self.excludes

    def group_key(self) -> str:
        """Identity of this rule ignoring `names`, for merging same-condition rules."""
        return json.dumps(
            {
                "action": self.action,
                "args": self.args,
                "comment": self.comment,
                "includes": self.includes,
                "excludes": self.excludes,
            },
            sort_keys=True,
        )


@dataclass
class Profile:
    """A parsed OCI Linux seccomp profile: defaults plus a list of `SyscallRule`s."""

    default_action: str
    default_errno_ret: int | None
    default_errno: str | None
    arch_map: list[dict[str, Any]]
    syscalls: list[SyscallRule]


def fetch_text(source: str) -> str:
    """Read JSON text from an http(s) URL or a local file path."""
    if source.startswith(("http://", "https://")):
        try:
            with urllib.request.urlopen(source, timeout=30) as response:
                return response.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SystemExit(f"failed to fetch {source}: {exc}") from exc
    return Path(source).read_text(encoding="utf-8")


def load_profile(source: str) -> Profile:
    """Parse an OCI seccomp profile JSON, fetched from a URL or read from a local path."""
    data = json.loads(fetch_text(source))
    syscalls = [
        SyscallRule(
            names=list(rule["names"]),
            action=rule["action"],
            args=rule.get("args") or None,
            comment=rule.get("comment") or None,
            includes=rule.get("includes") or None,
            excludes=rule.get("excludes") or None,
        )
        for rule in data.get("syscalls", [])
    ]
    return Profile(
        default_action=data["defaultAction"],
        default_errno_ret=data.get("defaultErrnoRet"),
        default_errno=data.get("defaultErrno"),
        arch_map=data.get("archMap", []),
        syscalls=syscalls,
    )


def allow_rules_by_syscall(profile: Profile) -> dict[str, list[SyscallRule]]:
    """Map syscall name -> its SCMP_ACT_ALLOW rules.

    Both profiles mix a handful of explicit per-syscall SCMP_ACT_ERRNO rules in among the
    ALLOW rules (redundant capability restatements, or explicit always-on denies). Only
    ALLOW rules define what a profile actually allows, so those are ignored here.
    """
    out: dict[str, list[SyscallRule]] = {}
    for rule in profile.syscalls:
        if rule.action != ALLOW:
            continue
        for name in rule.names:
            out.setdefault(name, []).append(rule)
    return out


def union_arch_maps(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Combine architecture entries declared by either profile (see module docstring)."""
    by_arch: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for entry in a + b:
        arch = entry["architecture"]
        if arch not in by_arch:
            by_arch[arch] = dict(entry)
            order.append(arch)
            continue
        merged_subs = sorted(
            set(by_arch[arch].get("subArchitectures") or [])
            | set(entry.get("subArchitectures") or [])
        )
        if merged_subs:
            by_arch[arch]["subArchitectures"] = merged_subs
    return [by_arch[arch] for arch in order]


def _merge_socket_rules() -> list[SyscallRule]:
    """Hand-derived socket() policy: the generic "union both gated rule sets" strategy is
    unsound here because Docker's filter is purely domain-based (blocks AF_ALG=38 and
    AF_VSOCK=40, no protocol check) while Podman's is purely protocol-and-capability-based
    (blocks the netlink-audit socket unless CAP_AUDIT_WRITE is granted, no domain-38/40
    check). Naively unioning both rule sets means the syscall is allowed if EITHER side's
    rule matches, so each side's broad rule silently re-admits what the other blocks. This
    builds the actual combination instead: domain not in {AF_ALG, AF_VSOCK} always, AND
    the netlink-audit socket additionally requires CAP_AUDIT_WRITE.

    Known gap: this only covers the socket(2) syscall. `socketcall` reaches the same
    socket-creation paths through a single multiplexed syscall whose real arguments are
    behind a userspace pointer seccomp/BPF can't dereference, so it bypasses this filtering
    entirely. Docker tried blocking socketcall outright to close that gap (moby/profiles
    commit 7158007a8300) and reverted it (3c2832431472) because it broke x86 binaries more
    than expected; this profile leaves it allowed for the same reason rather than
    second-guessing that field experience. Closing this gap for real requires AppArmor or
    SELinux (an LSM hook at security_socket_create sees the real socket domain regardless
    of which syscall reached it; seccomp can't).
    """
    not_banned_domain = [
        {"index": 0, "value": AF_ALG, "op": "SCMP_CMP_NE"},
        {"index": 0, "value": AF_VSOCK, "op": "SCMP_CMP_NE"},
    ]
    return [
        SyscallRule(
            names=["socket"],
            action=ALLOW,
            args=[{"index": 2, "value": NETLINK_AUDIT, "op": "SCMP_CMP_NE"}, *not_banned_domain],
            excludes={"caps": ["CAP_AUDIT_WRITE"]},
        ),
        SyscallRule(
            names=["socket"],
            action=ALLOW,
            args=[{"index": 0, "value": AF_NETLINK, "op": "SCMP_CMP_NE"}, *not_banned_domain],
            excludes={"caps": ["CAP_AUDIT_WRITE"]},
        ),
        SyscallRule(
            names=["socket"],
            action=ALLOW,
            args=list(not_banned_domain),
            includes={"caps": ["CAP_AUDIT_WRITE"]},
        ),
    ]


SPECIAL_CASES = {"socket": _merge_socket_rules}


def build_merge(docker: Profile, podman: Profile) -> Profile:
    """Apply the merge policy described in the module docstring."""
    docker_by_name = allow_rules_by_syscall(docker)
    podman_by_name = allow_rules_by_syscall(podman)
    common = set(docker_by_name) & set(podman_by_name)

    merged: list[SyscallRule] = []

    def add_gated(name: str, rules: list[SyscallRule]) -> None:
        """Append one ALLOW rule per distinct condition in `rules`, de-duplicated."""
        seen: set[str] = set()
        for r in rules:
            rule = SyscallRule([name], ALLOW, r.args, None, r.includes, r.excludes)
            key = rule.group_key()
            if key in seen:
                continue
            seen.add(key)
            merged.append(rule)

    for name in sorted(common):
        if name in SPECIAL_CASES:
            merged.extend(SPECIAL_CASES[name]())
            continue

        docker_rules, podman_rules = docker_by_name[name], podman_by_name[name]
        docker_uncond = any(r.is_unconditional() for r in docker_rules)
        podman_uncond = any(r.is_unconditional() for r in podman_rules)

        if docker_uncond and podman_uncond:
            merged.append(SyscallRule([name], ALLOW))
        elif docker_uncond:
            add_gated(name, podman_rules)
        elif podman_uncond:
            add_gated(name, docker_rules)
        else:
            add_gated(name, docker_rules + podman_rules)

    return Profile(
        default_action=ERRNO,
        default_errno_ret=podman.default_errno_ret,
        default_errno=podman.default_errno,
        arch_map=union_arch_maps(docker.arch_map, podman.arch_map),
        syscalls=merged,
    )


def to_json(profile: Profile) -> dict[str, Any]:
    """Build a canonical, upstream-style JSON profile dict, regrouping rules that share
    action/args/comment/includes/excludes into one entry with a combined `names` list.
    """
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for rule in profile.syscalls:
        key = rule.group_key()
        if key not in groups:
            groups[key] = {
                "names": set(),
                "action": rule.action,
                "args": rule.args,
                "comment": rule.comment,
                "includes": rule.includes,
                "excludes": rule.excludes,
            }
            order.append(key)
        groups[key]["names"].update(rule.names)

    syscalls_json = []
    for key in order:
        g = groups[key]
        entry: dict[str, Any] = {"names": sorted(g["names"]), "action": g["action"]}
        if g["comment"]:
            entry["comment"] = g["comment"]
        if g["includes"]:
            entry["includes"] = g["includes"]
        if g["excludes"]:
            entry["excludes"] = g["excludes"]
        if g["args"]:
            entry["args"] = g["args"]
        syscalls_json.append(entry)

    data: dict[str, Any] = {"defaultAction": profile.default_action}
    if profile.default_errno_ret is not None:
        data["defaultErrnoRet"] = profile.default_errno_ret
    if profile.default_errno is not None:
        data["defaultErrno"] = profile.default_errno
    data["archMap"] = profile.arch_map
    data["syscalls"] = syscalls_json
    return data


def validate(merged: Profile, docker: Profile, podman: Profile) -> list[str]:
    """Check that every allowed syscall is actually allowed by both source profiles.
    Returns human-readable errors; empty means the merge is consistent.
    """
    errors = []
    if not merged.syscalls:
        errors.append("merged profile has no syscall rules")

    docker_names = set(allow_rules_by_syscall(docker))
    podman_names = set(allow_rules_by_syscall(podman))

    for rule in merged.syscalls:
        for name in rule.names:
            if name not in docker_names or name not in podman_names:
                errors.append(f"{name}: present in output but not allowed by both engines")

    return errors


def main() -> None:
    """Load both profiles, merge, validate, and print the result to stdout."""
    docker = load_profile(DOCKER_URL)
    podman = load_profile(PODMAN_URL)
    merged = build_merge(docker, podman)

    errors = validate(merged, docker, podman)
    if errors:
        print("Validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(to_json(merged), indent=2))


if __name__ == "__main__":
    main()
