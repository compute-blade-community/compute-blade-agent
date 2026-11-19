# Contributing

## Development Setup

The toolchain (Go, TinyGo, buf and its protoc plugins, golangci-lint, goreleaser, actionlint, shellcheck) is pinned in
[`mise.toml`](mise.toml), and so are the build tasks. With [mise](https://mise.jdx.dev/) installed, run this from the
repository root:

```sh
mise install
```

The CI pipeline runs the same tasks, so a local run reproduces it:

```sh
mise tasks              # list all tasks
mise run ci             # every check the pipeline runs
mise run test           # unit tests, writes coverage.txt
mise run lint           # golangci-lint for linux/arm64, the release target
mise run fmt            # format the code (fmt:check only checks)
mise run generate       # regenerate the gRPC code after changing api/**/*.proto
mise run build:fanunit  # TinyGo firmware for the smart fan unit
mise run snapshot       # all release artifacts, without publishing (needs Docker, or add -- --skip=docker)
```

The `Makefile` is deprecated: its targets forward to these tasks and will be removed in a future release.

## Releases

This project uses [release-please](https://github.com/googleapis/release-please) and [goreleaser](https://goreleaser.com/) to automate releases based on conventional commits.

Releases are **semi-automated** and follow this flow:

### 1. Merge Code to `main`

All new features, fixes, and changes are merged into the `main` branch via pull requests using [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

Examples:

- `feat: add new API endpoint`
- `fix: correct off-by-one error`
- `chore: update dependencies`

### 2. Release PR is Auto-Created

Once a commit is merged into `main`, a GitHub Action runs `release-please`, which:

- Calculates the next version (e.g., `v0.9.1`)
- Creates a pull request (e.g., `chore: release v0.9.1`)
- Includes a generated changelog in `CHANGELOG.md`

> 📌 Note:
> This PR should **not be edited manually**. If something is wrong, fix the commit messages instead.

### 3. Merge the Release PR

Once the release PR is approved and merged:

- The changelog and version bump are committed to `main`
- `release-please` pushes a new tag with the version-number the merged commit on `main`

### 4. Tag Triggers `goreleaser`

A GitHub Action watches for `v*` tags and runs `goreleaser`, which:

- Builds all binaries and artifacts
- Publishes them to GitHub Releases
- Optionally signs and pushes container images (if configured)
- Attaches additional files (e.g., firmware, config) as release assets

Once complete, the new GitHub Release is available at: [github.com/compute-blade-community/compute-blade-agent/releases](https://github.com/compute-blade-community/compute-blade-agent/releases)

## Notes

- Never push tags manually.
- Only edit the changelog through conventional commits and `release-please`.
- You can retry failed releases by deleting the failed tag and re-merging the release PR or re-running the workflow.
