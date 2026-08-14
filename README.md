# hardened-seccomp

A single seccomp profile that works with both Docker and Podman: only allows a syscall if
both engines' defaults allow it (whichever side gates it more strictly wins), plus a curated
deny-list that hard-blocks a further set of historically dangerous syscalls regardless of
capability gating. The full policy and rationale are documented in `merge_seccomp.py`.

The ready-to-use profile is [`profiles/hardened-seccomp.json`](profiles/hardened-seccomp.json).

## Layout

```
profiles/
  hardened-seccomp.json    generated output -- the profile you actually use
merge_seccomp.py           everything: fetching, parsing, merge policy, deny-list, CLI
```

Docker's and Podman's default profiles are fetched live from GitHub on every run (each
engine's default branch, not a pinned commit) -- there's nothing to vendor or keep in sync.

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

Plain Python 3, no third-party dependencies. Fetches both upstream profiles from GitHub and
writes the merged result:

```sh
python3 merge_seccomp.py
```

Validates its own output before writing (non-empty, every allowed syscall traceable to the
deny-list-free intersection of both engines or a documented special case) and exits non-zero
if anything looks wrong -- including if either fetch fails.

Pass a local file path instead of fetching, e.g. to pin against a known-good snapshot or run
offline:

```sh
python3 merge_seccomp.py --docker docker-default.json --podman podman-default.json
```

## Compatibility caveats

This profile is intentionally more restrictive than either engine's own default. Workloads
that need one of the following will need to trim `DENY_LIST` in `merge_seccomp.py`:

- **Nested containers / Docker-in-Docker / Podman-in-Podman**: needs `mount`, `unshare`,
  `setns`, `pivot_root`.
- **Debuggers or process introspection**: needs `ptrace`, `process_vm_readv`,
  `process_vm_writev`.
- **Profilers / eBPF tooling**: needs `perf_event_open`, `bpf`.

Newer syscalls that only one engine's default has picked up so far (e.g. Docker-only `mseal`,
`uretprobe`, `listmount`/`statmount`) are dropped even when they'd be safe to allow -- that's
the deliberate trade-off of a strict-intersection policy (minimalism over currency), not an
oversight.

## License

BSD-2-Clause — see [`LICENSE`](LICENSE).
