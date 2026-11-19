# Deprecated: the build tasks moved to mise.toml, run `mise tasks` to list them.
# These targets only forward to mise and will be removed in a future release.

define deprecated
	@echo "warning: 'make $@' is deprecated, use 'mise run $(1)'" >&2
	@mise run $(1)
endef

all: ; $(call deprecated,ci)

.PHONY: run lint test fuzz generate build-fanunit build-agent snapshot
run: ; $(call deprecated,run)
lint: ; $(call deprecated,lint)
test: ; $(call deprecated,test)
fuzz: ; $(call deprecated,fuzz)
generate: ; $(call deprecated,generate)
build-fanunit: ; $(call deprecated,build:fanunit)
build-agent: ; $(call deprecated,build)
snapshot: ; $(call deprecated,snapshot)
