SHELL := /bin/bash
.DEFAULT_GOAL := help

VERSION ?=
DIST_DIR ?= dist
COVERAGE_THRESHOLD ?= 85
COVERAGE_PROFILE ?= coverage.out
BENCHTIME ?= 2s
COUNT ?= 5
SOURCE_DATE_EPOCH ?=

BINARY := bin/api_datagram
RELEASE_BINARY := ./cmd/api_datagram
COVERAGE_PACKAGES := ./internal/... ./pkg/...
BENCHMARK_PACKAGE := ./pkg/dgpv1
BENCHMARK_REGEX := ^BenchmarkMessengerWireFormats$$
BENCHMARK_RESULTS := benchmarks/results
MODULE := github.com/tr1xdev/datagram-server.git
RELEASE_TARGETS := linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64

.PHONY: help build test coverage benchmark release verify-release clean check-go check-release-tools check-version

help: ## Show this help.
	@echo Usage: make ^<target^> [VARIABLE=value]
	@echo.
	@echo Targets:
	@echo   help             Show this help.
	@echo   build            Build api_datagram for the host platform.
	@echo   test             Run all Go tests.
	@echo   coverage         Run coverage and enforce COVERAGE_THRESHOLD.
	@echo   benchmark        Run benchmarks and save result files.
	@echo   release          Build cross-platform release archives.
	@echo   verify-release   Verify checksums in DIST_DIR.
	@echo   clean            Remove generated files.

check-go:
	@command -v go >/dev/null 2>&1 || { echo "required tool not found: go" >&2; exit 1; }

check-release-tools:
	@for tool in go git tar gzip sha256sum mktemp date find touch; do \
		command -v "$$tool" >/dev/null 2>&1 || { echo "required tool not found: $$tool" >&2; exit 1; }; \
	done

check-version:
	@printf '%s\n' '$(VERSION)' | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$' || { \
		echo "invalid version: $(VERSION) (expected vMAJOR.MINOR.PATCH)" >&2; exit 2; \
	}

build: check-go ## Build api_datagram for the host platform.
	@mkdir -p "$(dir $(BINARY))"
	go build -o "$(BINARY)" $(RELEASE_BINARY)

test: check-go ## Run all Go tests.
	go test ./...

coverage: check-go ## Run core-package coverage and enforce COVERAGE_THRESHOLD.
	@case '$(COVERAGE_THRESHOLD)' in ''|*[!0-9.]*|.*|*.*.*) \
		echo "coverage threshold must be a non-negative number" >&2; exit 2;; esac
	@packages="$$(go list $(COVERAGE_PACKAGES))"; \
	[[ -n "$$packages" ]] || { echo "no coverage packages found" >&2; exit 1; }; \
	go test -covermode=atomic -coverprofile='$(COVERAGE_PROFILE)' $$packages; \
	total="$$(go tool cover -func='$(COVERAGE_PROFILE)' | awk '/^total:/ {gsub(/%/, "", $$3); print $$3}')"; \
	[[ -n "$$total" ]] || { echo "could not determine total coverage" >&2; exit 1; }; \
	printf 'total coverage: %s%% (required: %s%%)\n' "$$total" '$(COVERAGE_THRESHOLD)'; \
	awk -v actual="$$total" -v required='$(COVERAGE_THRESHOLD)' 'BEGIN { exit !(actual + 0 >= required + 0) }' || { \
		echo "coverage is below the required threshold" >&2; exit 1; \
	}

benchmark: check-go ## Run wire-format benchmarks and save the raw result files.
	@[[ -f go.mod && -d pkg/dgpv1 && -d benchmarks ]] || { echo "run make from the repository root" >&2; exit 1; }
	@mkdir -p '$(BENCHMARK_RESULTS)'
	@go version > '$(BENCHMARK_RESULTS)/go-version.txt'
	@go test $(BENCHMARK_PACKAGE) -run '^$$' -bench '$(BENCHMARK_REGEX)' -benchmem -benchtime '$(BENCHTIME)' -count '$(COUNT)' | tee '$(BENCHMARK_RESULTS)/latest.txt'
	@go test $(BENCHMARK_PACKAGE) -run '^$$' -bench '$(BENCHMARK_REGEX)' -benchmem -benchtime '$(BENCHTIME)' -count '$(COUNT)' -json > '$(BENCHMARK_RESULTS)/latest.jsonl'

# Release archives use stable ordering, ownership, timestamps, and gzip headers
# so identical source inputs produce identical artifacts.
release: check-release-tools check-version ## Build reproducible cross-platform archives and SHA256SUMS.
	@set -euo pipefail; \
	repo="$$(git rev-parse --show-toplevel)"; \
	case '$(DIST_DIR)' in /*) out='$(DIST_DIR)';; *) out="$$PWD/$(DIST_DIR)";; esac; \
	[[ "$$out" != "$$repo" && "$$out" != "$$repo/" ]] || { echo "DIST_DIR must not be the repository root" >&2; exit 2; }; \
	commit="$$(git -C "$$repo" rev-parse HEAD)"; \
	epoch='$(SOURCE_DATE_EPOCH)'; \
	[[ -n "$$epoch" ]] || epoch="$$(git -C "$$repo" show -s --format=%ct HEAD)"; \
	[[ "$$epoch" =~ ^[0-9]+$$ ]] || { echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2; exit 2; }; \
	build_date="$$(date -u -d "@$$epoch" '+%Y-%m-%dT%H:%M:%SZ')"; \
	work="$$(mktemp -d)"; trap 'rm -rf "$$work"' EXIT HUP INT TERM; \
	rm -rf "$$out"; mkdir -p "$$out"; \
	ldflags="-s -w -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$$commit -X $(MODULE)/internal/buildinfo.BuildDate=$$build_date"; \
	for target in $(RELEASE_TARGETS); do \
		goos="$${target%/*}"; goarch="$${target#*/}"; ext=''; [[ "$$goos" == windows ]] && ext='.exe'; \
		name="api_datagram_$(VERSION)_$${goos}_$${goarch}"; stage="$$work/$$name"; mkdir -p "$$stage"; \
		echo "building $$goos/$$goarch"; \
		CGO_ENABLED=0 GOOS="$$goos" GOARCH="$$goarch" go build -trimpath -buildvcs=false -ldflags "$$ldflags" -o "$$stage/api_datagram$$ext" $(RELEASE_BINARY); \
		cp LICENSE README.md config.example.yaml "$$stage/"; \
		find "$$stage" -exec touch -d "@$$epoch" {} +; \
		tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$$epoch" -C "$$work" -cf - "$$name" | gzip -n > "$$out/$$name.tar.gz"; \
	done; \
	(cd "$$out" && LC_ALL=C sha256sum api_datagram_* | sort -k2 > SHA256SUMS); \
	echo "release artifacts written to $$out"

verify-release: ## Verify archive checksums in DIST_DIR.
	@command -v sha256sum >/dev/null 2>&1 || { echo "required tool not found: sha256sum" >&2; exit 1; }
	cd '$(DIST_DIR)' && sha256sum --check SHA256SUMS

clean: ## Remove local build, coverage, and release outputs.
	rm -rf bin '$(DIST_DIR)' '$(COVERAGE_PROFILE)'
