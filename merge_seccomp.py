#!/usr/bin/env python3
"""Merge Docker's and Podman's default seccomp profiles into one profile that works with
both: the strictest rule from either runtime wins.

A syscall is allowed only if BOTH profiles allow it, and only when the conditions of the
rule that allows it in each profile hold at the same time. Each profile lists several
ALLOW rules per syscall (alternatives), so the merge intersects them pairwise: every
Docker rule is ANDed with every Podman rule (capabilities and arches required by either,
kernel version the newer of the two, argument checks from both), and contradictory or
redundant combinations are dropped. This is what makes e.g. `socket()` come out right --
Docker restricts the address family, Podman the netlink protocol, and both have to hold --
with no per-syscall special cases.

Other choices:
  - defaultErrnoRet/defaultErrno follow Podman's ENOSYS (the modern recommended choice over
    Docker's EPERM), and archMap is the union of both engines' declared architectures (an
    arch entry only affects whether the profile can load on that architecture, not what's
    allowed on the one a container is actually running on).
  - `socketcall` (legacy multiplexed socket syscall, mostly 32-bit x86) is left as both
    upstreams have it: seccomp can't see its real arguments, so the socket() restrictions
    don't apply to it. Docker tried blocking it outright (moby/profiles 7158007a8300) and
    reverted (3c2832431472) because it broke too much x86 userland. Closing that gap needs
    AppArmor or SELinux.

Inputs are fetched live from GitHub on every run (see DOCKER_URL/PODMAN_URL below) --
tracking each engine's default branch, not a pinned commit, so the merge always reflects
the current upstream defaults. Edit those constants to a local file path instead if you
want to run against a fixed snapshot. Prints the merged profile JSON to stdout.
"""

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

ARG_MAX = 2**64 - 1
# Condition keys the runtimes understand and this merge knows how to combine. Anything
# else in an upstream profile aborts the merge rather than being silently mishandled.
KNOWN_INCLUDES = {"caps", "arches", "minKernel"}
KNOWN_EXCLUDES = {"caps", "arches"}


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
    syscalls = []
    for rule in data.get("syscalls", []):
        includes = rule.get("includes") or None
        excludes = rule.get("excludes") or None
        unknown = (set(includes or {}) - KNOWN_INCLUDES) | (set(excludes or {}) - KNOWN_EXCLUDES)
        if unknown:
            raise SystemExit(
                f"{source}: unsupported condition(s) {sorted(unknown)} in {rule['names']}"
            )
        # Podman writes `valueTwo: 0` explicitly; it is the default, so drop it to make
        # equivalent comparisons from both profiles textually identical.
        args = [
            {k: v for k, v in arg.items() if not (k == "valueTwo" and v == 0)}
            for arg in rule.get("args") or []
        ]
        syscalls.append(
            SyscallRule(
                names=list(rule["names"]),
                action=rule["action"],
                args=args or None,
                comment=rule.get("comment") or None,
                includes=includes,
                excludes=excludes,
            )
        )
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


def _reduce_comparisons(
    index: int, comparisons: list[dict[str, Any]]
) -> list[dict[str, Any]] | None:
    """AND together plain comparisons (EQ/NE/LT/LE/GT/GE) on one argument.

    Returns the minimal equivalent list, or None if no value can satisfy them all.
    """
    lo, hi = 0, ARG_MAX
    for cmp in comparisons:
        value = cmp["value"]
        match cmp["op"]:
            case "SCMP_CMP_EQ":
                lo, hi = max(lo, value), min(hi, value)
            case "SCMP_CMP_LT":
                hi = min(hi, value - 1)
            case "SCMP_CMP_LE":
                hi = min(hi, value)
            case "SCMP_CMP_GT":
                lo = max(lo, value + 1)
            case "SCMP_CMP_GE":
                lo = max(lo, value)
    excluded = {c["value"] for c in comparisons if c["op"] == "SCMP_CMP_NE"}
    if lo > hi or (lo == hi and lo in excluded):
        return None
    if lo == hi:
        return [{"index": index, "value": lo, "op": "SCMP_CMP_EQ"}]
    bounds = [c for c in comparisons if c["op"] not in ("SCMP_CMP_NE",)]
    return bounds + [c for c in comparisons if c["op"] == "SCMP_CMP_NE" and lo <= c["value"] <= hi]


def _combine_args(args: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """AND together argument comparisons from two rules; None if they contradict."""
    unique = []
    for arg in args:
        if arg not in unique:
            unique.append(arg)
    by_index: dict[int, list[dict[str, Any]]] = {}
    for arg in unique:
        by_index.setdefault(arg["index"], []).append(arg)
    combined = []
    for index, group in by_index.items():
        plain = [a for a in group if a["op"] != "SCMP_CMP_MASKED_EQ"]
        reduced = _reduce_comparisons(index, plain) if plain else []
        if reduced is None:
            return None
        combined += reduced + [a for a in group if a["op"] == "SCMP_CMP_MASKED_EQ"]
    return combined


def _kernel_key(version: str) -> tuple[int, ...]:
    """Sort key for a dotted kernel version like "4.8"."""
    return tuple(int(part) for part in version.split("."))


def _non_empty(conditions: dict[str, Any]) -> dict[str, Any] | None:
    """Drop empty entries; None if nothing is left."""
    return {k: v for k, v in conditions.items() if v} or None


def intersect_rules(name: str, a: SyscallRule, b: SyscallRule) -> SyscallRule | None:
    """A rule allowing `name` only when both `a` and `b` would; None if that's never.

    Runtime semantics: includes.caps needs ALL listed caps, excludes.caps drops the rule if
    ANY is present; includes.arches / excludes.arches are matched against the container arch;
    includes.minKernel needs kernel >= version; a rule's args must all match.
    """
    inc_a, inc_b = a.includes or {}, b.includes or {}
    exc_a, exc_b = a.excludes or {}, b.excludes or {}

    inc_caps = set(inc_a.get("caps", [])) | set(inc_b.get("caps", []))
    exc_caps = set(exc_a.get("caps", [])) | set(exc_b.get("caps", []))
    if inc_caps & exc_caps:
        return None

    exc_arches = set(exc_a.get("arches", [])) | set(exc_b.get("arches", []))
    inc_arch_sets = [set(inc["arches"]) for inc in (inc_a, inc_b) if "arches" in inc]
    inc_arches = None
    if inc_arch_sets:
        inc_arches = set.intersection(*inc_arch_sets) - exc_arches
        if not inc_arches:
            return None
        exc_arches = set()

    args = _combine_args((a.args or []) + (b.args or []))
    if args is None:
        return None

    includes = {
        "caps": sorted(inc_caps),
        "arches": sorted(inc_arches or ()),
        "minKernel": max(
            (inc["minKernel"] for inc in (inc_a, inc_b) if "minKernel" in inc),
            key=_kernel_key,
            default=None,
        ),
    }
    excludes = {"caps": sorted(exc_caps), "arches": sorted(exc_arches)}
    return SyscallRule(
        names=[name],
        action=ALLOW,
        args=args or None,
        includes=_non_empty(includes),
        excludes=_non_empty(excludes),
    )


def _is_no_stricter(a: SyscallRule, b: SyscallRule) -> bool:
    """True if every call rule `b` allows is also allowed by rule `a`."""
    inc_a, inc_b = a.includes or {}, b.includes or {}
    exc_a, exc_b = a.excludes or {}, b.excludes or {}
    return (
        set(inc_a.get("caps", [])) <= set(inc_b.get("caps", []))
        and set(exc_a.get("caps", [])) <= set(exc_b.get("caps", []))
        and set(exc_a.get("arches", [])) <= set(exc_b.get("arches", []))
        and _kernel_key(inc_a.get("minKernel", "0")) <= _kernel_key(inc_b.get("minKernel", "0"))
        and ("arches" not in inc_a or set(inc_b.get("arches", [])) <= set(inc_a["arches"]))
        and all(arg in (b.args or []) for arg in a.args or [])
    )


def _drop_redundant(rules: list[SyscallRule]) -> list[SyscallRule]:
    """Remove rules (alternatives) already covered by a less strict rule in the list."""
    kept = []
    for i, rule in enumerate(rules):
        covered = any(
            j != i
            and _is_no_stricter(other, rule)
            and (j < i or not _is_no_stricter(rule, other))
            for j, other in enumerate(rules)
        )
        if not covered:
            kept.append(rule)
    return kept


def build_merge(docker: Profile, podman: Profile) -> Profile:
    """Apply the merge policy described in the module docstring."""
    docker_by_name = allow_rules_by_syscall(docker)
    podman_by_name = allow_rules_by_syscall(podman)

    merged: list[SyscallRule] = []
    for name in sorted(set(docker_by_name) & set(podman_by_name)):
        alternatives = [
            rule
            for d in docker_by_name[name]
            for p in podman_by_name[name]
            if (rule := intersect_rules(name, d, p))
        ]
        merged.extend(_drop_redundant(alternatives))

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
