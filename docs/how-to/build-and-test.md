# Build, test and lint

*For developers.*

All tools and build commands are pinned in [`mise.toml`](../../mise.toml). CI runs the same tasks, so a green
`mise run ci` locally means a green pipeline, give or take the Docker image build.

## Set up

Install [mise](https://mise.jdx.dev), then from the repository root:

```bash
mise install
```

This installs Go, TinyGo, buf with its protoc plugins, golangci-lint, goreleaser, actionlint and shellcheck in the
versions the project uses. Inside the repository they're on your `PATH`.

## Everyday tasks

```bash
mise run ci              # everything CI checks: generated code, formatting, lint, tests, firmware build
mise run test            # unit tests, writes coverage.txt
mise run lint            # golangci-lint for linux/arm64
mise run fmt             # format the code
mise run generate        # regenerate api/ from the .proto files
mise run build:fanunit   # fan unit firmware, fanunit.uf2
mise tasks               # list all tasks
```

`lint` checks the code as built for linux/arm64, the only target the agent ships for, even on a Mac. Code behind
`//go:build linux` is linted that way, and unused code on other platforms doesn't trip it.

`build:fanunit` skips the build when no Go file changed since the last `fanunit.uf2`.

## Build the binaries

For a quick agent build to copy to a blade:

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o compute-blade-agent ./cmd/agent
go build -o bladectl ./cmd/bladectl
```

To build every release target into `dist/` the way a release does:

```bash
mise run build      # binaries only
mise run snapshot   # binaries, packages and container image, without publishing
```

`snapshot` needs Docker for the container image. Without Docker, skip it: `mise run snapshot -- --skip=docker`.

## Run a single test

```bash
go test ./internal/agent -run TestWatchEvents -v
go test -race ./pkg/ledengine
```

## Fuzz the fan unit protocol

```bash
mise run fuzz
```

## CI caches

The workflows install mise and the tools with `jdx/mise-action` (cached by `mise.toml`) and restore the Go module and
build caches, the golangci-lint cache and the TinyGo cache per job, keyed by `mise.toml`, `go.sum` and the commit. A
pull request restores the newest cache of its branch, falling back to `main`.
