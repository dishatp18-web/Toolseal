# TOOLSEAL × Bifrost Native MCP Security Plugin

Native dynamic Go MCP plugin (`toolseal-mcp-security`) for Maxim AI's Bifrost Gateway.

## Phase 1 — Pinned Official Bifrost Compatibility

- **Pinned Bifrost Release**: `transports/v2.5.1`
- **Pinned Core Module**: `github.com/maximhq/bifrost/core v1.15.2`
- **Pinned Go Toolchain**: `go1.27.3` (`CGO_ENABLED=1`)
- **Platform Requirement**: Linux or macOS (`go build -buildmode=plugin` is unsupported on Windows; use WSL2 Ubuntu on Windows)
- **Dynamic Host Requirement**: Bifrost must be built with `make build DYNAMIC=1` in `transports/` (`framework/plugins/soloader.go`)

### Official Hook & Loader Symbols Implemented (`core/schemas/plugin.go` & `framework/plugins/soloader.go`)

- `Init(config any) error`
- `GetName() string` (`"toolseal-mcp-security"`)
- `Cleanup() error`
- `PreMCPHook(ctx *schemas.BifrostContext, req *schemas.BifrostMCPRequest) (*schemas.BifrostMCPRequest, *schemas.MCPPluginShortCircuit, error)`
- `PostMCPHook(ctx *schemas.BifrostContext, resp *schemas.BifrostMCPResponse, bifrostErr *schemas.BifrostError) (*schemas.BifrostMCPResponse, *schemas.BifrostError, error)`
- `MarshalConfigForStorage(map[string]any) (map[string]any, error)` & `RedactConfig(map[string]any) (map[string]any, error)` (`schemas.ConfigMarshallerPlugin`)

### Incompatibilities Resolved From Earlier Template

1. Replaced Go interface receiver methods with **package-level exported functions** required by Bifrost's `plugin.Open` dynamic loader (`soloader.go`).
2. Switched request inspection from guessed structs to real `schemas.BifrostMCPRequest` (`req.RequestType.IsExecuteTool()`, `req.GetToolName()`, `req.GetToolArguments()`, `req.ClientName`).
3. Stripped Bifrost's `{ClientName}-` tool prefix via `normalizeToolName` so `weather-get_weather` maps cleanly to `get_weather` in TOOLSEAL's Tool DNA Registry.
4. Added `ctxKeyShortCircuited` context guard because Bifrost's MCP plugin pipeline (`core/mcp/pluginpipeline.go`) executes `PostMCPHook` even after a `PreMCPHook` short-circuit.
5. Enforced fail-closed `schemas.MCPPluginShortCircuit` with `AllowFallbacks: false` when TOOLSEAL returns `BLOCK`, `REVIEW`, HTTP `401`, HTTP `503`, `5xx`, or when `BIFROST_SHARED_SECRET` is unset / TOOLSEAL is unreachable.
6. Note on schema inspection: in `bifrost/core v1.15.2`, `BifrostMCPRequest` carries runtime tool name, client name, and arguments (not the upstream JSON parameter definition), so argument/drift/registry rules run natively on every call while schema diffing triggers whenever an upstream schema payload is supplied.

## Phase 3 — Build & Run Instructions (Linux / macOS / WSL2)

```bash
# 1. Build toolseal_plugin.so
chmod +x bifrost-plugin/build.sh bifrost-plugin/verify_plugin.sh
./bifrost-plugin/build.sh

# 2. Build dynamically-linked Bifrost Gateway at pinned tag transports/v2.5.1
git clone --depth 1 --branch transports/v2.5.1 https://github.com/maximhq/bifrost.git /tmp/bifrost
make -C /tmp/bifrost/transports build DYNAMIC=1

# 3. Export matching HMAC secret in BOTH TOOLSEAL and Bifrost environments
export BIFROST_SHARED_SECRET="replace-with-random-32-byte-secret"

# 4. Run Bifrost Gateway with toolseal-mcp-security plugin + mock MCP server
/tmp/bifrost/transports/bifrost-http \
  -config ./bifrost-plugin/config.example.json \
  -port 8080
```

## Phase 5 — Verification

```bash
export BIFROST_SHARED_SECRET="replace-with-random-32-byte-secret"
export TOOLSEAL_URL="http://127.0.0.1:3000"
./bifrost-plugin/verify_plugin.sh

# When a live bifrost-http DYNAMIC=1 gateway is running on port 8080:
VERIFY_LIVE_BIFROST=1 BIFROST_GATEWAY_URL="http://127.0.0.1:8080" ./bifrost-plugin/verify_plugin.sh
```
