#!/usr/bin/env bash
set -euo pipefail

# Build script for the native TOOLSEAL × Bifrost MCP security dynamic plugin (.so)
# Pinned Bifrost release: transports/v2.5.1 (github.com/maximhq/bifrost/core v1.15.2)
# Required Go version: go1.27.3 (must match the compiler used to build bifrost-http DYNAMIC=1)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_OUT="${SCRIPT_DIR}/build/toolseal_plugin.so"
PINNED_GO="1.27.3"
PINNED_BIFROST_TAG="transports/v2.5.1"

OS_NAME="$(uname -s)"
if [[ "${OS_NAME}" != "Linux" && "${OS_NAME}" != "Darwin" ]]; then
  echo "ERROR: Go -buildmode=plugin (.so) is only supported on Linux and macOS (detected: ${OS_NAME})."
  echo "On Windows, build and run inside WSL2 (Ubuntu Linux)."
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: Go compiler not found in PATH."
  echo "Install Go ${PINNED_GO} (matching maximhq/bifrost ${PINNED_BIFROST_TAG}) and re-run this script."
  exit 1
fi

GO_VER_RAW="$(go version | awk '{print $3}')"
echo "Detected Go toolchain: ${GO_VER_RAW}"
if [[ "${GO_VER_RAW}" != "go${PINNED_GO}" ]]; then
  echo "WARNING: Expected go${PINNED_GO} to guarantee ABI compatibility with bifrost-http (${PINNED_BIFROST_TAG})."
  echo "         Go plugin.Open rejects plugins built with a mismatched Go version or dependency graph."
fi

mkdir -p "${SCRIPT_DIR}/build"

pushd "${SCRIPT_DIR}" >/dev/null
echo "Resolving Go module dependencies (github.com/maximhq/bifrost/core v1.15.2)..."
go mod tidy

echo "Building dynamic Bifrost MCP plugin -> ${PLUGIN_OUT}"
CGO_ENABLED=1 go build -buildmode=plugin -o "${PLUGIN_OUT}" .
popd >/dev/null

echo "SUCCESS: Built ${PLUGIN_OUT}"
echo ""
echo "Next steps to run with Bifrost Gateway (${PINNED_BIFROST_TAG}):"
echo "  1. Clone & build dynamically-linked bifrost-http (one-time):"
echo "       git clone --depth 1 --branch ${PINNED_BIFROST_TAG} https://github.com/maximhq/bifrost.git /tmp/bifrost"
echo "       make -C /tmp/bifrost/transports build DYNAMIC=1"
echo "  2. Export matching secret & start Bifrost with config:"
echo "       export BIFROST_SHARED_SECRET='<your-secret>'"
echo "       /tmp/bifrost/transports/bifrost-http -config ./bifrost-plugin/config.example.json -port 8080"
