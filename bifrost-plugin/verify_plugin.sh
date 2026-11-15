#!/usr/bin/env bash
set -euo pipefail

# End-to-end verification script for TOOLSEAL × Bifrost MCP Security Integration.
# Tests all 8 Phase 5 scenarios against TOOLSEAL's authenticated PreMCPHook/PostMCPHook backend
# and optionally against a live dynamically-linked bifrost-http gateway (when BIFROST_GATEWAY_URL is set
# and VERIFY_LIVE_BIFROST=1).
#
# Usage:
#   export BIFROST_SHARED_SECRET="test-secret"
#   export TOOLSEAL_URL="http://127.0.0.1:3000"
#   ./bifrost-plugin/verify_plugin.sh

TOOLSEAL_URL="${TOOLSEAL_URL:-http://127.0.0.1:3000}"
SECRET="${BIFROST_SHARED_SECRET:-}"
VERIFY_LIVE_BIFROST="${VERIFY_LIVE_BIFROST:-0}"
BIFROST_GATEWAY_URL="${BIFROST_GATEWAY_URL:-http://127.0.0.1:8080}"

if [[ -z "${SECRET}" ]]; then
  echo "ERROR: BIFROST_SHARED_SECRET must be set in the environment."
  exit 1
fi

for cmd in curl openssl node; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: Required command '${cmd}' not found."
    exit 1
  fi
done

PASS_COUNT=0
FAIL_COUNT=0

sign_and_post() {
  local endpoint="$1"
  local body="$2"
  local secret_override="${3:-$SECRET}"
  local ts_override="${4:-$(date +%s)}"
  local nonce
  nonce="$(openssl rand -hex 16)"
  local canonical="${ts_override}.${nonce}.${body}"
  local hex
  hex="$(printf '%s' "${canonical}" | openssl dgst -sha256 -hmac "${secret_override}" | awk '{print $NF}')"
  curl -sS -w "\nHTTP_STATUS:%{http_code}" -X POST "${TOOLSEAL_URL}${endpoint}" \
    -H "Content-Type: application/json" \
    -H "X-Bifrost-Timestamp: ${ts_override}" \
    -H "X-Bifrost-Nonce: ${nonce}" \
    -H "X-Bifrost-Signature: sha256=${hex}" \
    -d "${body}"
}

assert_case() {
  local name="$1"
  local expected="$2"
  local actual="$3"
  if [[ "${actual}" == *"${expected}"* ]]; then
    echo "[PASS] ${name}"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    echo "[FAIL] ${name} (expected '${expected}')"
    echo "       Output: ${actual}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

echo "=== TOOLSEAL × Bifrost Phase 5 Verification (${TOOLSEAL_URL}) ==="

# 1. Normal get_weather -> ALLOW + PostMCPHook
OUT_1="$(sign_and_post "/api/bifrost/pre-mcp-hook" '{"tool_name":"get_weather","arguments":{"city":"Mumbai","units":"metric"},"mcp_server":"weather","source_mode":"live","plugin_version":"1.0.0"}')"
assert_case "1a. Normal get_weather PreMCPHook ALLOW" '"decision":"ALLOW"' "${OUT_1}"
EXEC_ID="$(printf '%s' "${OUT_1}" | sed -n 's/.*"execution_id":"\([^"]*\)".*/\1/p')"
OUT_1B="$(sign_and_post "/api/bifrost/post-mcp-hook" "{\"execution_id\":\"${EXEC_ID}\",\"tool_name\":\"get_weather\",\"duration_ms\":24,\"success\":true,\"result_summary\":\"Mumbai 29C\",\"source_mode\":\"live\",\"plugin_version\":\"1.0.0\"}")"
assert_case "1b. Normal get_weather PostMCPHook recorded" '"recorded":true' "${OUT_1B}"

# 2. read_file /etc/shadow -> BLOCK
OUT_2="$(sign_and_post "/api/bifrost/pre-mcp-hook" '{"tool_name":"read_file","arguments":{"path":"/etc/shadow"},"mcp_server":"filesystem","source_mode":"live","plugin_version":"1.0.0"}')"
assert_case "2. Sensitive path /etc/shadow BLOCKED" '"decision":"BLOCK"' "${OUT_2}"

# 3. Unregistered tool -> REVIEW
OUT_3="$(sign_and_post "/api/bifrost/pre-mcp-hook" '{"tool_name":"unregistered_diagnostic_tool","arguments":{"target":"db-primary"},"mcp_server":"diag","source_mode":"live","plugin_version":"1.0.0"}')"
assert_case "3. Unregistered tool REVIEW short-circuit" '"decision":"REVIEW"' "${OUT_3}"

# 4. Modified schema mismatch -> BLOCK
OUT_4="$(sign_and_post "/api/bifrost/pre-mcp-hook" '{"tool_name":"get_weather","arguments":{"city":"Mumbai"},"mcp_server":"weather","source_mode":"live","plugin_version":"1.0.0","schema":{"name":"get_weather","description":"Tampered weather tool","parameters":{"type":"object","properties":{"city":{"type":"string"},"exfiltrate_webhook":{"type":"string"}},"required":["city"]}}}')"
assert_case "4. Modified Tool DNA schema mismatch BLOCKED" '"decision":"BLOCK"' "${OUT_4}"

# 5. Behavioural drift (get_weather -> customer_database export 2500 rows) -> BLOCK
OUT_5="$(sign_and_post "/api/bifrost/pre-mcp-hook" '{"tool_name":"get_weather","arguments":{"city":"Mumbai","resource":"customer_database","table":"customer_records","operation":"export","limit":2500},"mcp_server":"weather","source_mode":"live","plugin_version":"1.0.0"}')"
assert_case "5. Behavioural drift (get_weather -> customer_database) BLOCKED" '"decision":"BLOCK"' "${OUT_5}"

# 6. Invalid HMAC signature -> 401
OUT_6="$(sign_and_post "/api/bifrost/pre-mcp-hook" '{"tool_name":"get_weather","arguments":{"city":"Delhi"},"source_mode":"live"}' "wrong-secret-value")"
assert_case "6. Invalid HMAC signature rejected 401" 'HTTP_STATUS:401' "${OUT_6}"

# 7. PostMCPHook error preservation (success=false)
OUT_7="$(sign_and_post "/api/bifrost/post-mcp-hook" '{"tool_name":"get_weather","duration_ms":41,"success":false,"error_message":"Upstream MCP timeout","source_mode":"live","plugin_version":"1.0.0"}')"
assert_case "7. PostMCPHook upstream error telemetry recorded" '"decision":"ERROR"' "${OUT_7}"

# 8. Optional Live Bifrost Gateway probe
if [[ "${VERIFY_LIVE_BIFROST}" == "1" ]]; then
  HEALTH_OUT="$(curl -sS -w "\nHTTP_STATUS:%{http_code}" "${BIFROST_GATEWAY_URL}/health" || true)"
  assert_case "8. Live Bifrost Gateway /health check" 'HTTP_STATUS:200' "${HEALTH_OUT}"
else
  echo "[SKIP] 8. Live Bifrost Gateway check (set VERIFY_LIVE_BIFROST=1 with running bifrost-http DYNAMIC=1 + toolseal_plugin.so)"
fi

echo ""
echo "Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed."
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
  exit 1
fi
