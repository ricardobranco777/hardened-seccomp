# hardened-seccomp

A single seccomp profile that works with both Docker and Podman: only allows a syscall if
both engines' defaults allow it, and the strictest rule from either runtime wins -- every
condition (capability, kernel version, argument) from both sides has to hold at once. The
full policy is documented at the top of `merge.go`.

The ready-to-use profile is [`profiles/hardened-seccomp.json`](profiles/hardened-seccomp.json).

## Layout

```
main.go, merge.go               fetching, parsing, merge policy (Go)
merge_test.go, testdata/        tests; golden output checked against the Python version
merge_seccomp.py                the original Python implementation, same output
profiles/hardened-seccomp.json  generated output -- the profile you actually use
```

Docker's and Podman's default profiles are fetched live from GitHub every run (each engine's
default branch, not a pinned commit) -- there's nothing to vendor or keep in sync.

## Regenerating

Fetches both upstream profiles from GitHub, merges them, and prints the result to stdout:

```sh
go run . > profiles/hardened-seccomp.json
```

`-docker` and `-podman` take a URL or a local file instead, for a fixed snapshot:

```sh
go run . -docker testdata/docker.json -podman testdata/podman.json
```

Validates the merge before printing (non-empty, every allowed syscall present in both
engines' defaults) and exits non-zero without printing anything if that fails --
including if either fetch fails or a profile has a condition the merge doesn't know how
to combine. `go test .` checks the output byte for byte against `testdata/`.

`python3 merge_seccomp.py` still works, with no third-party dependencies, and prints the
same profile.

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

## Known limitations

`socketcall` (the legacy multiplexed socket syscall used mainly by 32-bit x86 binaries)
bypasses the `socket()` address-family and netlink-audit restrictions entirely, since seccomp
can't filter arguments hidden behind a userspace pointer. Docker tried blocking `socketcall`
outright upstream (moby/profiles `7158007a8300`) and reverted it (`3c2832431472`) because it
broke more legitimate x86 userland than expected; this profile leaves it allowed for the same
reason. Closing this gap for real needs AppArmor or SELinux,
not seccomp -- only an LSM hook at `security_socket_create` sees the real socket domain
regardless of which syscall reached it.

Syscalls that only one engine's default allows (e.g. Docker-only `mseal`, `uretprobe`,
`listmount`/`statmount`, or Podman-only `keyctl`, `pivot_root`) are dropped even when they'd
be safe to allow on the engine that has them -- that's the intersection policy working as
intended, not a bug.

A seccomp profile can't stop kernel bugs that are reachable through syscalls every container
needs. For example, the AF_UNIX `SCM_RIGHTS` and reuseport cBPF escapes described in
[Containers Are No Longer a Security Boundary](https://depthfirst.com/research/containers-are-no-longer-safe)
use only ordinary sockets; the fix for those is a patched host kernel.

## License

BSD-2-Clause — see [`LICENSE`](LICENSE).
