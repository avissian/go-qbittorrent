# Makefile for go-qbittorrent
#
# Targets
#   make              - build shared library for the current platform
#   make linux        - build .so  (requires Linux or cross-compiler)
#   make darwin       - build .dylib (requires macOS or cross-compiler)
#   make windows      - build .dll  (requires Windows or MinGW cross-compiler)
#   make header       - generate C header only (no library)
#   make test         - run unit tests
#   make clean        - remove build artefacts

CLIB_PKG  := ./clib
OUT_DIR   := dist

# Detect current OS and pick the default output name.
UNAME := $(shell uname -s 2>/dev/null || echo Windows)
ifeq ($(UNAME),Linux)
  DEFAULT_OUT  := $(OUT_DIR)/libqbt.so
  DEFAULT_FLAG := -buildmode=c-shared
else ifeq ($(UNAME),Darwin)
  DEFAULT_OUT  := $(OUT_DIR)/libqbt.dylib
  DEFAULT_FLAG := -buildmode=c-shared
else
  DEFAULT_OUT  := $(OUT_DIR)/libqbt.dll
  DEFAULT_FLAG := -buildmode=c-shared
endif

HEADER_OUT := $(OUT_DIR)/libqbt.h

.PHONY: all linux darwin windows header test clean

all: $(DEFAULT_OUT)

$(DEFAULT_OUT): $(OUT_DIR)
	go build $(DEFAULT_FLAG) -o $@ $(CLIB_PKG)
	@echo "Built: $@"
	@echo "Header: $(HEADER_OUT)"

## Platform-specific cross-build targets ─────────────────────────────────────

linux: $(OUT_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
	  go build -buildmode=c-shared -o $(OUT_DIR)/libqbt.so $(CLIB_PKG)

darwin: $(OUT_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 \
	  go build -buildmode=c-shared -o $(OUT_DIR)/libqbt.dylib $(CLIB_PKG)

windows: $(OUT_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
	  go build -buildmode=c-shared -o $(OUT_DIR)/libqbt.dll $(CLIB_PKG)

## Header only (useful for IDE integration without a full build) ──────────────

header: $(OUT_DIR)
	go tool cgo -exportheader $(HEADER_OUT) $(CLIB_PKG)/*.go

## Utilities ──────────────────────────────────────────────────────────────────

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

test:
	go test ./qbt/...

clean:
	rm -rf $(OUT_DIR)
