# kai build and install.
#
# `go install` puts the binary in $GOPATH/bin, which is not on root's PATH on
# most boxes. `make install` puts it where a bare `kai` finds it.

PREFIX ?= /usr/local
BINDIR  = $(PREFIX)/bin
GO      ?= go

.PHONY: all build install uninstall test race vet fmt check demo clean

all: check build

build:
	$(GO) build -o kai ./cmd/kai

install: build
	install -d $(BINDIR)
	install -m 0755 kai $(BINDIR)/kai
	@echo "installed $(BINDIR)/kai"

uninstall:
	rm -f $(BINDIR)/kai

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w ./cmd ./internal ./pkg

# What CI runs.
check: fmt vet test

# Render the workspace layout without a terminal: make demo, or
# make demo SIZE=140x40 FRAMES=4
SIZE   ?= 104x24
FRAMES ?= 4
demo:
	KAI_TUI_SIZE=$(SIZE) $(GO) run ./cmd/kai tui --demo --frames $(FRAMES)

clean:
	rm -f kai
