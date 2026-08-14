# Analysis: Docker vs. Podman default seccomp profiles

This document explains what `scripts/analyze_profiles.py` found when comparing Docker's and
Podman's default seccomp profiles, and why `scripts/merge_profiles.py` makes the choices it
does when building `profiles/hardened-seccomp.json`. The full machine-generated data backing
this document lives in `reports/analysis_report.json` / `reports/analysis_report.md`; re-run
the analyze script to refresh it after updating the vendored profiles.

## Sources

| Engine | Repo | Path | Commit | Fetched |
|---|---|---|---|---|
| Docker | `moby/moby` | `vendor/github.com/moby/profiles/seccomp/default.json` | `75cfc884e5dd194e6bbb1fda79563dcaa7419c4d` (master) | 2026-08-14 |
| Podman | `containers/common` | `pkg/seccomp/seccomp.json` | `a5ccdae846b629b5ceaefa6ffd5c6511409c3487` (main) | 2026-08-14 |

Full details, including why Docker's profile is vendored from `moby/moby` rather than the
historical `profiles/seccomp/default.json` path, are in `profiles/upstream/SOURCES.md`.

## Schema

Both profiles are OCI runtime-spec Linux seccomp profiles: `defaultAction` sets the fallback
for anything not explicitly matched (both use `SCMP_ACT_ERRNO` — deny by default), and
`syscalls` is a list of rules, each naming one or more syscalls plus an `action` and optional
gating:

- `args`: a runtime argument comparison (e.g. "only allow `socket()` when the domain argument
  is less than 38").
- `includes` / `excludes`: evaluated once, at container-creation time, against the container's
  granted capabilities, kernel version, and architecture — they decide whether a rule is
  compiled into the container's seccomp filter at all, not a per-call runtime check.

A subtlety that shaped this analysis: both profiles mix a handful of explicit per-syscall
`SCMP_ACT_ERRNO` rules in among the `SCMP_ACT_ALLOW` rules, rather than relying only on the
profile's default-deny. Naively treating "any rule mentions this syscall" as "this syscall is
allowed" — which an early pass of this analysis did — silently misclassifies syscalls that
*only* have an `SCMP_ACT_ERRNO` rule as allowed. `scripts/seccomp_lib.py` fixes this with
`allow_rules_by_syscall`, which filters to `SCMP_ACT_ALLOW` rules before deciding what a
profile allows. See "Explicit ERRNO carve-outs" below for what those extra rules are for.

## Headline numbers

| | Docker | Podman |
|---|---|---|
| Unique syscalls allowed | 426 | 408 |
| ...allowed unconditionally | 361 | 370 |
| ...allowed with a gate | 65 | 38 |
| `defaultAction` | `SCMP_ACT_ERRNO` | `SCMP_ACT_ERRNO` |
| `defaultErrnoRet` | `1` (EPERM) | `38` (ENOSYS) |

- **404 syscalls are allowed by both.** 22 are Docker-only, 4 are Podman-only.
- Docker-only allow-listed syscalls are mostly newer syscalls Podman's list hasn't picked up
  yet (`mseal`, `uretprobe`, `statmount`, `listmount`, `getxattrat`, `listxattrat`,
  `removexattrat`, `setxattrat`, `lsm_get_self_attr`, `lsm_list_modules`,
  `lsm_set_self_attr`, `riscv_hwprobe`, `set_mempolicy_home_node`, `map_shadow_stack`,
  `io_pgetevents(_time64)`, `futex_requeue/wait/waitv/wake`, `cachestat`, `vmsplice`).
  Notably, several of these (`vmsplice`, `cachestat`, `futex_requeue`, `map_shadow_stack`) are
  syscalls Podman explicitly *blocks* with a deny-only `SCMP_ACT_ERRNO` rule rather than
  simply not having gotten to yet — see below, this is one place Podman is the stricter engine.
- Podman-only allow-listed syscalls: `keyctl`, `pivot_root`, `query_module`, `signal`.

Since the merge policy is a strict intersection, all 26 engine-only syscalls above are
excluded from `hardened-seccomp.json` regardless of which direction the asymmetry runs.

## Finding: Docker seccomp-gates more of the shared syscalls than Podman

For syscalls both engines allow, classifying by whether either side attaches a
capability/kernel/arg gate:

| Classification | Count | Meaning |
|---|---|---|
| Both ungated | 343 | Neither engine restricts it |
| Docker gates, Podman doesn't | 24 | Docker requires a capability/kernel condition Podman doesn't |
| Podman gates, Docker doesn't | 0 | (no cases found) |
| Both gate, same condition | 34 | Equivalent restriction, different JSON shape |
| Both gate, different condition | 3 | Flagged for manual review (see below) |

The 24 "Docker gates, Podman doesn't" syscalls include some of the most consequential ones in
either profile: `ptrace`, `process_vm_readv`, `process_vm_writev`, `clone`, `clone3`,
`unshare`, `setns`, `mount`, `umount`, `umount2`, `mount_setattr`, `move_mount`, `open_tree`,
`fsopen`, `fsconfig`, `fsmount`, `fspick`, `reboot`, `syslog`, `fanotify_init`, `get_mempolicy`,
`mbind`, `set_mempolicy`, `pidfd_getfd`.

Concretely: Docker only allows `ptrace` when `CAP_SYS_PTRACE` is granted (or an old-kernel
compatibility path); Podman allows it to every container unconditionally, relying solely on
the separate Linux capability check to stop it in a default (non-privileged) container. That
capability check is real and does stop a default container — but it's not defense-in-depth: if
a container is later given `CAP_SYS_PTRACE` for a legitimate reason (e.g. attaching a
debugger), Podman's seccomp filter places no additional restriction on `ptrace`, while
Docker's still requires the capability to actually be present. The same pattern holds for the
mount/namespace family (`mount`, `unshare`, `setns`, ...): Docker's seccomp layer double-checks
the capability; Podman's doesn't. **The merge keeps whichever side's gate exists** — see
"Merge algorithm" below — so all 24 of these end up at least as restricted as Docker's default
in `hardened-seccomp.json` (several are also on the curated deny-list and blocked outright).

This is not a one-way street: Podman is the stricter engine for a few less-common syscalls.
`vmsplice`, `cachestat`, `futex_requeue/wait/waitv/wake`, and `map_shadow_stack` are all
allowed unconditionally by Docker but blocked outright by Podman (deny-only `SCMP_ACT_ERRNO`
rules, no matching `SCMP_ACT_ALLOW`). Because these are Docker-only syscalls from the
intersection's point of view, the strict-intersection merge drops them regardless — the net
effect is the same hardening outcome either way, but it's worth knowing Docker isn't
uniformly the more conservative profile.

### Both gate it, but differently (manual review)

`perf_event_open`, `personality`, `socket` are flagged as "both gated, different conditions."
Manual review found:

- **`personality` / most of `socket`**: cosmetic only. Podman's `args` conditions carry an
  extra `valueTwo: 0` key that Docker's omit; `valueTwo` is unused for an `SCMP_CMP_EQ`
  comparison, so the two are functionally identical. The merge unions both variants rather
  than trying to detect this, so the output profile carries some harmless duplicate rules for
  these two syscalls (see "Known limitations").
- **`perf_event_open`**: a genuine structural difference. Docker expresses its
  `CAP_SYS_ADMIN`-or-`CAP_PERFMON` gate as two `SCMP_ACT_ALLOW` rules with `includes.caps`.
  Podman expresses the `CAP_PERFMON` path the same way, but achieves the `CAP_SYS_ADMIN`
  path through an `SCMP_ACT_ERRNO` rule with `excludes.caps` layered on top of a broader
  unconditional-ALLOW rule elsewhere in its profile — net effect equivalent to Docker's, just
  encoded differently. This is moot for the merged profile: `perf_event_open` is on the
  curated deny-list and blocked outright regardless of gating.

## Finding: `defaultErrnoRet` differs, and the modern choice is Podman's

Docker returns `EPERM` (1) for blocked syscalls; Podman returns `ENOSYS` (38,
`defaultErrno: "ENOSYS"`). `ENOSYS` ("function not implemented") is the choice recommended by
current OCI runtime-spec / libseccomp guidance: it lets a program's own feature-detection
treat a blocked syscall as unsupported and fall back to an alternative, rather than treating
it as a permission failure (which some programs handle as a fatal, unrecoverable error). The
merged profile adopts Podman's `ENOSYS`.

## Finding: `archMap` differs

Docker additionally declares `SCMP_ARCH_RISCV64` and `SCMP_ARCH_LOONGARCH64`; Podman declares
neither. The merge takes the intersection, so the hardened profile only claims support for
architectures both engines' defaults jointly recognize:
`SCMP_ARCH_X86_64, SCMP_ARCH_AARCH64, SCMP_ARCH_MIPS64, SCMP_ARCH_MIPS64N32,
SCMP_ARCH_MIPSEL64, SCMP_ARCH_MIPSEL64N32, SCMP_ARCH_S390X`. RISC-V and LoongArch users should
add those arch entries back manually if needed — see the README's compatibility notes.

## Explicit `SCMP_ACT_ERRNO` carve-outs

Beyond the profile-wide `defaultAction`, both profiles include specific `SCMP_ACT_ERRNO`
rules:

| | Docker | Podman |
|---|---|---|
| Redundant (also has an ALLOW rule elsewhere) | 1 | 25 |
| Deny-only (no ALLOW rule at all) | 0 | 35 |

Docker's one redundant carve-out is `clone3` (blocked via `excludes.caps: CAP_SYS_ADMIN`,
matching its `includes.caps: CAP_SYS_ADMIN` ALLOW rule). Podman uses this pattern much more
heavily — 25 syscalls (`chroot`, `quotactl`, `setdomainname`, `sethostname`, `acct`,
`ioperm`/`iopl`, the module syscalls, `open_by_handle_at`, `lookup_dcookie`, and others) get an
ALLOW-with-`includes.caps` rule *and* a matching ERRNO-with-`excludes.caps` rule that restates
the same gate — for these, Podman is exactly as strict as Docker, just doubly encoded. Podman
also has 35 deny-only names — syscalls with an `SCMP_ACT_ERRNO` rule and no ALLOW rule at all,
i.e. explicitly and intentionally blocked (`swapon`, `swapoff`, `nfsservctl`, `kexec_load`,
`kexec_file_load`, `uselib`, `vm86`, `vm86old`, `userfaultfd`, several legacy `old*` syscalls,
`vmsplice`, and others) — functionally identical to the default-deny but documenting intent.

## Curated hard-deny list

`profiles/hardening/deny-list.json` hard-blocks the following syscalls in the merged profile
regardless of capability gating — they stay blocked even if a container is later granted the
matching capability (e.g. `--cap-add`):

| Syscall(s) | Why |
|---|---|
| `ptrace`, `process_vm_readv`, `process_vm_writev` | Process-introspection primitives used to read/inject into sibling processes and steal credentials. A capability grant for debugging shouldn't double as a general-purpose introspection primitive. |
| `perf_event_open`, `bpf` | Recurring source of Linux kernel privilege-escalation CVEs (verifier bugs, Spectre-class side channels). |
| `userfaultfd` | Race-condition/heap-grooming timing primitive used in numerous public kernel-exploit proofs of concept. Already blocked by Podman; blocked here too regardless of upstream changes. |
| `keyctl`, `add_key`, `request_key` | Kernel keyring manipulation, implicated in past kernel privilege-escalation CVEs (e.g. CVE-2016-0728). |
| `mount`, `umount2`, `pivot_root`, `unshare`, `setns` | Mount/namespace manipulation, central to most container-breakout techniques. Ordinary application containers don't call these themselves. |
| `kexec_load`, `kexec_file_load`, `reboot`, `acct`, `swapon`, `swapoff`, `nfsservctl`, `uselib`, `vm86`, `vm86old`, `query_module`, `init_module`, `delete_module`, `finit_module`, `iopl`, `ioperm` | System-management / legacy syscalls with no legitimate use in an application container. |

Several of these (`userfaultfd`, `keyctl`, `add_key`, `request_key`, `kexec_load`,
`kexec_file_load`, `swapon`, `swapoff`, `nfsservctl`, `uselib`, `vm86`, `vm86old`,
`query_module`) are already excluded by the strict intersection today, since at least one
engine doesn't allow them. They're listed explicitly anyway so the block holds even if a
future upstream default starts allowing them on both sides.

This list is opinionated. Workloads that legitimately need one of these — nested
containers/Docker-in-Docker (`mount`, `unshare`, `setns`, `pivot_root`), debuggers/profilers
(`ptrace`, `perf_event_open`, `bpf`) — will need to remove the relevant entries from
`deny-list.json` and re-run `merge_profiles.py`. See the README for the exact steps.

## Merge algorithm

For each syscall name in the intersection of both engines' allow-lists (404 names):

1. If it's on the deny-list → excluded.
2. If both engines allow it with no gate at all → keep one unconditional `ALLOW` rule.
3. If one side is ungated and the other gates it → keep only the gated side's rule(s).
4. If both sides gate it → keep the union of both sides' conditional rules (deduplicated by
   exact `args`/`includes`/`excludes` match).

`defaultAction` stays `SCMP_ACT_ERRNO`; `defaultErrnoRet`/`defaultErrno` follow Podman's
`ENOSYS`; `archMap` is the intersection of both engines' declared architectures.

Applied to the current vendored snapshots:

| Decision | Count |
|---|---|
| Kept, unconditional | 343 |
| Tightened to Docker's gate | 16 |
| Tightened to Podman's gate | 0 |
| Both gated, unioned | 29 |
| Hard-blocked by deny-list | 16 |
| Dropped (Docker-only) | 22 |
| Dropped (Podman-only) | 4 |
| **Total allowed in `hardened-seccomp.json`** | **388** |

(16 of the 24 "Docker gates, Podman doesn't" syscalls from the classification above end up
"tightened to Docker's gate"; the other 8 — `mount`, `umount2`, `unshare`, `setns`, `ptrace`,
`process_vm_readv`, `process_vm_writev`, `reboot` — are also on the deny-list and counted
there instead, since the deny-list check runs first.)

Full before/after detail is in `reports/merge_report.md`, regenerated on every
`merge_profiles.py` run.

## Known limitations

- **Argument-predicate intersection isn't solved.** When both engines gate the same syscall
  with *different* conditions (the "both-gated-different" bucket), the merge takes the union
  of both rule sets rather than computing a true intersection of the allowed argument space.
  For `perf_event_open` this is moot (deny-listed anyway). For `personality` and `socket` the
  difference is cosmetic (an unused `valueTwo: 0` field), so the union produces a few harmless
  duplicate rules rather than a real over-permission. A profile with many more
  differently-gated shared syscalls would need real per-argument intersection logic; today's
  three cases don't justify building it.
- **`includes`/`excludes` gating is evaluated per-rule, not simulated end-to-end.** The
  classifier treats "has at least one fully unconditional ALLOW rule for this name" as
  "effectively unconditional." `setns` in Podman has both an unconditional ALLOW rule and a
  redundant capability-gated pair (ALLOW+includes / ERRNO+excludes) for the same name; the
  unconditional rule makes the pair dead weight in practice, and the classifier reports it as
  unconditional, which matches Podman's actual behavior.
- **Vendored snapshots go stale.** The comparison and merge are only as current as the commits
  pinned in `profiles/upstream/SOURCES.md`. Re-run the refresh steps there periodically.
