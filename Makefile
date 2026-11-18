FUZZ_TARGETS := ./pkg/smartfanunit/proto

all: lint test

.PHONY: run
run:
	go run cmd/agent/main.go

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test ./... -v


.PHONY: fuzz
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		go test  -fuzz="Fuzz" -fuzztime=5s -fuzzminimizetime=10s  $$target; \
	done


# buf is pinned in mise.toml
.PHONY: generate
generate:
	buf generate

.PHONY: build-fanunit
build-fanunit:
	tinygo build -target=pico -o fanunit.uf2 ./cmd/fanunit/

.PHONY: build-agent
build-agent: generate
	goreleaser build --snapshot --clean

.PHONY: snapshot
snapshot:
	goreleaser release --snapshot --skip=publish --clean
