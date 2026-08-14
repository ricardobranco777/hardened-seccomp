# Upstream sources

These files are vendored, pinned snapshots — not fetched live at run time. `analyze_profiles.py` and
`merge_profiles.py` both read them from disk by default.

| File | Upstream repo | Path | Commit | Fetched |
|---|---|---|---|---|
| `docker-default.json` | [`moby/moby`](https://github.com/moby/moby) | `vendor/github.com/moby/profiles/seccomp/default.json` | `75cfc884e5dd194e6bbb1fda79563dcaa7419c4d` (master) | 2026-08-14 |
| `podman-default.json` | [`containers/common`](https://github.com/containers/common) | `pkg/seccomp/seccomp.json` | `a5ccdae846b629b5ceaefa6ffd5c6511409c3487` (main) | 2026-08-14 |

Note: Docker's default seccomp profile used to live directly in `moby/moby` at
`profiles/seccomp/default.json`. It has since moved into the standalone
[`moby/profiles`](https://github.com/moby/profiles) repo and is vendored back into `moby/moby` under
`vendor/github.com/moby/profiles/seccomp/default.json` — that vendored copy is what the running Docker
daemon actually ships, so it's the correct source to track.

## Refreshing

```sh
curl -sL "https://raw.githubusercontent.com/moby/moby/master/vendor/github.com/moby/profiles/seccomp/default.json" \
  | python3 -m json.tool > profiles/upstream/docker-default.json

curl -sL "https://raw.githubusercontent.com/containers/common/main/pkg/seccomp/seccomp.json" \
  | python3 -m json.tool > profiles/upstream/podman-default.json
```

Update the commit SHAs and date in the table above (find them with `git ls-remote` or the GitHub API
`/repos/<owner>/<repo>/commits/<branch>` endpoint), then re-run:

```sh
python3 scripts/analyze_profiles.py
python3 scripts/merge_profiles.py
```

and review `reports/merge_report.md` for anything that changed.
