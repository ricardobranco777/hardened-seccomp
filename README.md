# hardened-seccomp

A single seccomp profile that works with both Docker and Podman: only allows a syscall if
both engines' defaults allow it (whichever side gates it more strictly wins), plus a curated
deny-list that hard-blocks a further set of historically dangerous syscalls regardless of
capability gating. The full policy and rationale are documented in `merge_seccomp.py`.

The ready-to-use profile is [`profiles/hardened-seccomp.json`](profiles/hardened-seccomp.json).

## Layout

```
profiles/
  upstream/
    docker-default.json    vendored copy of Docker's default seccomp profile
    podman-default.json    vendored copy of Podman's default seccomp profile
  hardened-seccomp.json    generated output -- the profile you actually use
merge_seccomp.py           everything: parsing, merge policy, deny-list, CLI
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

Plain Python 3, no third-party dependencies:

```sh
python3 merge_seccomp.py
```

Validates its own output before writing (non-empty, every allowed syscall traceable to the
deny-list-free intersection of both engines or a documented special case) and exits non-zero
if anything looks wrong.

## Refreshing the vendored upstream profiles

The two files under `profiles/upstream/` are pinned snapshots, not fetched live:

```sh
curl -sL "https://raw.githubusercontent.com/moby/moby/master/vendor/github.com/moby/profiles/seccomp/default.json" \
  | python3 -m json.tool > profiles/upstream/docker-default.json

curl -sL "https://raw.githubusercontent.com/containers/common/main/pkg/seccomp/seccomp.json" \
  | python3 -m json.tool > profiles/upstream/podman-default.json

python3 merge_seccomp.py
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
