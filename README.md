# hardened-seccomp

A single seccomp profile that works with both Docker and Podman, built by comparing the two
engines' upstream default profiles and keeping only the safest common ground — plus a curated
deny-list that hard-blocks a further set of historically dangerous syscalls.

The ready-to-use profile is [`profiles/hardened-seccomp.json`](profiles/hardened-seccomp.json).
The full rationale for every decision it makes is in [`ANALYSIS.md`](ANALYSIS.md).

## Layout

```
profiles/
  upstream/               vendored, pinned copies of Docker's and Podman's default profiles
    docker-default.json
    podman-default.json
    SOURCES.md            exact commit/URL for each, and how to refresh them
  hardening/
    deny-list.json        curated syscalls hard-blocked regardless of capability gating
  hardened-seccomp.json   generated output — the profile you actually use
scripts/
  seccomp_lib.py          shared OCI seccomp JSON model (load/normalize/serialize)
  analyze_profiles.py     diffs the two upstream profiles -> reports/analysis_report.{json,md}
  merge_profiles.py       builds hardened-seccomp.json from the two profiles + deny-list
reports/
  analysis_report.{json,md}   generated comparison data behind ANALYSIS.md
  merge_report.md             generated before/after detail behind the merge decisions
tests/                    unit tests (stdlib unittest, no dependencies)
ANALYSIS.md               narrative writeup of the comparison and the merge policy
```

## Using the profile

```sh
docker run --rm --security-opt seccomp="$(pwd)/profiles/hardened-seccomp.json" alpine echo ok
podman run --rm --security-opt seccomp=./profiles/hardened-seccomp.json alpine echo ok
```

On Kubernetes, copy the file into the kubelet's seccomp root and reference it with:

```yaml
securityContext:
  seccompProfile:
    type: Localhost
    localhostProfile: hardened-seccomp.json
```

## Regenerating

Both scripts are plain Python 3 with no third-party dependencies.

```sh
python3 scripts/analyze_profiles.py   # refresh reports/analysis_report.{json,md}
python3 scripts/merge_profiles.py     # refresh profiles/hardened-seccomp.json + reports/merge_report.md
```

`merge_profiles.py` validates its own output before writing (non-empty, round-trips through
`json.load`, and every allowed syscall is traceable to a specific merge decision) and exits
non-zero if anything looks wrong.

## Tests

Unit tests use Python's stdlib `unittest`, no third-party dependencies:

```sh
python3 -m unittest discover
```

`tests/test_seccomp_lib.py` and `tests/test_analyze_profiles.py` / `tests/test_merge_profiles.py`
exercise the loading/serialization and classification/merge logic against small synthetic
profiles. `tests/test_integration.py` runs the real merge against the committed vendored
profiles and deny-list, and fails if `profiles/hardened-seccomp.json` is stale relative to
them (i.e. you edited an input and forgot to re-run `merge_profiles.py`).

## Refreshing the vendored upstream profiles

The two files under `profiles/upstream/` are pinned snapshots, not fetched live. To update
them to the latest upstream defaults, see the exact commands and the commit-pinning convention
in [`profiles/upstream/SOURCES.md`](profiles/upstream/SOURCES.md), then re-run both scripts
above and review `reports/merge_report.md` for anything that changed.

## How the merge policy works

In short (full detail in [`ANALYSIS.md`](ANALYSIS.md)):

1. A syscall is allowed only if **both** Docker's and Podman's defaults allow it.
2. If one engine gates it (by capability, kernel version, or argument) and the other doesn't,
   the gate wins.
3. `profiles/hardening/deny-list.json` hard-blocks a further set of syscalls
   (`ptrace`, `mount`, `unshare`, `bpf`, `perf_event_open`, kernel-module syscalls, ...)
   regardless of capability gating — they stay blocked even if the container is later granted
   the matching capability.
4. The result uses Podman's `ENOSYS` error return (the modern recommended default) and the
   intersection of both engines' declared architectures.

## Compatibility caveats

This profile is intentionally more restrictive than either engine's own default. Workloads
that need one of the following will need to trim `profiles/hardening/deny-list.json` and
re-run `merge_profiles.py`:

- **Nested containers / Docker-in-Docker / Podman-in-Podman**: needs `mount`, `unshare`,
  `setns`, `pivot_root`.
- **Debuggers or process introspection**: needs `ptrace`, `process_vm_readv`,
  `process_vm_writev`.
- **Profilers / eBPF tooling**: needs `perf_event_open`, `bpf`.

RISC-V and LoongArch hosts: the merged `archMap` only includes architectures both engines'
defaults declare (Podman's default doesn't list either yet). Add the arch entries back from
`profiles/upstream/docker-default.json` manually if you need them.

## License

BSD-2-Clause — see [`LICENSE`](LICENSE).
