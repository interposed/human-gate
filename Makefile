# nono-bio-gate. Built with Go 1.26 (auto-downloaded via the go directive).
# Never build to the repo root: dev builds land in builds/bin, releases are
# retained per-version under builds/releases/<version>/.
#
# Run `make` (or `make help`) to see every target.

BIN       := builds/bin
DIST      := builds/releases
PID       := $(BIN)/biogate.pid
VERSION   ?= v0.1.0
ARGS      ?= start
LDFLAGS   := -s -w -X main.version=$(VERSION)

# GOWORK=off keeps this module out of the parent sec/ workspace.
# GOTOOLCHAIN=auto lets `go 1.26.0` in go.mod fetch the 1.26 toolchain.
GO        := GOWORK=off GOTOOLCHAIN=auto go

IMAGE     := nono-bio-gate
TAG       ?= $(VERSION)
CONTAINER := nono-bio-gate

.DEFAULT_GOAL := help

## ---- local ----
.PHONY: help build test run start stop status install fmt vet tidy release clean

help: ## Show this help
	@echo "nono-bio-gate - make targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "vars: VERSION=$(VERSION)  ARGS=\"$(ARGS)\"  TAG=$(TAG)"

build: ## Build biogate into builds/bin
	@mkdir -p $(BIN)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN)/biogate ./cmd/biogate
	@echo "built $(BIN)/biogate"

test: ## Run the test suite
	$(GO) test ./...

run: build ## Build and run in the foreground (ARGS="start -- echo hi")
	$(BIN)/biogate $(ARGS)

start: build ## Start biogate in the background (writes a PID file)
	@$(BIN)/biogate $(ARGS) & echo $$! > $(PID); echo "started pid $$(cat $(PID)) [$(ARGS)]"

stop: ## Stop the background biogate
	@if [ -f $(PID) ]; then kill $$(cat $(PID)) 2>/dev/null && echo "stopped $$(cat $(PID))"; rm -f $(PID); else echo "not running"; fi

status: ## Show whether the background biogate is running
	@if [ -f $(PID) ] && kill -0 $$(cat $(PID)) 2>/dev/null; then echo "running pid $$(cat $(PID))"; else echo "stopped"; fi

install: ## go install biogate to GOBIN
	$(GO) install -ldflags "$(LDFLAGS)" ./cmd/biogate

fmt: ## gofmt the tree
	$(GO) fmt ./...

vet: ## go vet
	$(GO) vet ./...

tidy: ## go mod tidy
	$(GO) mod tidy

release: test ## Cross-compile and retain builds/releases/<VERSION>
	@mkdir -p $(DIST)/$(VERSION)
	GOWORK=off GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(VERSION)/biogate-darwin-arm64 ./cmd/biogate
	GOWORK=off GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(VERSION)/biogate-linux-amd64  ./cmd/biogate
	GOWORK=off GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(VERSION)/biogate-linux-arm64  ./cmd/biogate
	cd $(DIST)/$(VERSION) && shasum -a 256 biogate-* > checksums.sha256
	@echo "released $(VERSION) -> $(DIST)/$(VERSION)"

clean: ## Remove dev builds and the PID file
	rm -rf $(BIN)

## ---- docker ----
.PHONY: docker-build docker-run docker-start docker-stop docker-logs docker-shell

docker-build: ## Build the Docker image ($(IMAGE):$(TAG))
	docker build -t $(IMAGE):$(TAG) -t $(IMAGE):latest .

docker-run: ## Run the image in the foreground (ARGS="version")
	docker run --rm -it $(IMAGE):$(TAG) $(ARGS)

docker-start: ## Run the image detached as a named container
	docker run -d --name $(CONTAINER) $(IMAGE):$(TAG) $(ARGS)
	@echo "started container $(CONTAINER)"

docker-stop: ## Stop and remove the container
	-docker rm -f $(CONTAINER)

docker-logs: ## Tail the container logs
	docker logs -f $(CONTAINER)

docker-shell: ## Open a shell in a fresh container (needs a shell in the image)
	docker run --rm -it --entrypoint sh $(IMAGE):$(TAG)
