"""Shared model for loading, normalizing, and serializing OCI Linux seccomp profiles.

Used by both analyze_profiles.py and merge_profiles.py so the two scripts agree on how a
profile's `syscalls` list (whose entries can each name multiple syscalls) is parsed and
re-serialized.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class SyscallRule:
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
    default_action: str
    default_errno_ret: int | None
    default_errno: str | None
    arch_map: list[dict[str, Any]]
    syscalls: list[SyscallRule]


def load(path: str | Path) -> Profile:
    """Parse an OCI seccomp profile JSON file into a `Profile`."""
    data = json.loads(Path(path).read_text())
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


ALLOW = "SCMP_ACT_ALLOW"
ERRNO = "SCMP_ACT_ERRNO"


def rules_by_syscall(profile: Profile) -> dict[str, list[SyscallRule]]:
    """Expand multi-name rules so each syscall name maps to every rule referencing it.

    Includes rules of ANY action (ALLOW or ERRNO). Both profiles mix a handful of explicit
    per-syscall SCMP_ACT_ERRNO rules in among the ALLOW rules — sometimes as a redundant,
    defense-in-depth restatement of an ALLOW rule's capability gate (e.g. an ERRNO rule with
    `excludes.caps` alongside an ALLOW rule with the matching `includes.caps`), sometimes as
    the *only* rule for that name (an explicit, always-on deny that adds nothing beyond the
    profile's default-deny, but documents intent). Use `allow_rules_by_syscall` for "is this
    syscall in the allow-list" questions — treating any rule mentioning a name as meaning
    "allowed", regardless of its action, silently misclassifies ERRNO-only names as allowed.
    """
    out: dict[str, list[SyscallRule]] = {}
    for rule in profile.syscalls:
        for name in rule.names:
            out.setdefault(name, []).append(rule)
    return out


def allow_rules_by_syscall(profile: Profile) -> dict[str, list[SyscallRule]]:
    """Like `rules_by_syscall`, but only rules with action SCMP_ACT_ALLOW.

    This is the correct source of truth for "which syscalls does this profile allow" and
    "under what gating" — a name with only SCMP_ACT_ERRNO rules is not allowed.
    """
    out: dict[str, list[SyscallRule]] = {}
    for rule in profile.syscalls:
        if rule.action != ALLOW:
            continue
        for name in rule.names:
            out.setdefault(name, []).append(rule)
    return out


def union_arch_maps(
    a: list[dict[str, Any]], b: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Combine architecture entries declared by either profile.

    Unlike the syscalls list, an archMap entry only affects whether a profile can be
    loaded at all on that architecture -- it doesn't change what's allowed on whichever
    architecture a given container is actually running on. So, unlike syscalls, taking
    the union here (rather than the intersection) widens portability without weakening
    the profile anywhere.
    """
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


def dump(profile: Profile, path: str | Path) -> None:
    """Write a canonical, upstream-style JSON profile.

    Rules that share action/args/comment/includes/excludes are regrouped into one entry
    with a combined, sorted `names` list, matching the style of the upstream files so the
    output stays reviewable/diffable.
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

    Path(path).write_text(json.dumps(data, indent=2) + "\n")
