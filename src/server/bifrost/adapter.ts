import fs from 'fs';
import path from 'path';
import { db, uid } from '../db/database.ts';
import { inspectAndProcessToolCall } from '../security/engine.ts';
import { broadcaster } from '../ws/broadcaster.ts';
import type {
  BifrostConfig,
  BifrostLiveVerificationResult,
  BifrostTelemetry,
  CanonicalToolSchema,
  IntegrationLog,
} from '../../types/toolseal.ts';

export function getBifrostConfig(): BifrostConfig {
  const secretConfigured = Boolean((process.env.BIFROST_SHARED_SECRET || '').trim());
  const parsedTtl = Number(process.env.BIFROST_SIGNATURE_TTL_SECONDS);
  const signatureTtlSeconds =
    Number.isFinite(parsedTtl) && parsedTtl >= 30 && parsedTtl <= 3600 ? Math.round(parsedTtl) : 300;
  const webhookAuthStatus = secretConfigured ? 'hmac_configured' : 'secret_missing';

  const row = db.prepare("SELECT * FROM integration_configs WHERE provider = 'bifrost'").get() as
    | BifrostConfig
    | undefined;
  if (row) {
    return {
      ...row,
      shared_secret_configured: secretConfigured ? 1 : 0,
      signature_ttl_seconds: signatureTtlSeconds,
      webhook_auth_status: webhookAuthStatus,
    };
  }

  return {
    id: 'int-bifrost',
    provider: 'bifrost',
    mode: 'demo',
    endpoint_url: 'http://localhost:8080',
    shared_secret_configured: secretConfigured ? 1 : 0,
    signature_ttl_seconds: signatureTtlSeconds,
    webhook_auth_status: webhookAuthStatus,
    enabled: 1,
    last_test_status: 'demo_mode',
    last_test_message: 'Running in standalone DEMO MODE.',
    last_tested_at: null,
    updated_at: new Date().toISOString(),
  };
}

export function logBifrostEvent(params: {
  hookType: IntegrationLog['hook_type'];
  sourceMode: 'demo' | 'live';
  toolName?: string | null;
  decision?: string | null;
  statusCode: number;
  message: string;
  payload: Record<string, unknown>;
}): IntegrationLog {
  const id = uid('bflog');
  db.prepare(`
    INSERT INTO integration_logs (
      id, provider, hook_type, source_mode, tool_name, decision, status_code, message, payload_json
    ) VALUES (?, 'bifrost', ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    params.hookType,
    params.sourceMode,
    params.toolName ?? null,
    params.decision ?? null,
    params.statusCode,
    params.message,
    JSON.stringify(params.payload)
  );

  const row = db.prepare('SELECT * FROM integration_logs WHERE id = ?').get(id) as IntegrationLog;
  broadcaster.broadcast('bifrost:log', row);
  return row;
}

/**
 * Handles Bifrost PreMCPHook inspection request.
 * In Bifrost's Go MCPPlugin pipeline, PreMCPHook intercepts MCP tool invocations
 * and can short-circuit blocked calls before they reach the downstream MCP server.
 */
export function handlePreMcpHook(payload: {
  tool_name: string;
  arguments: Record<string, unknown>;
  agent_id?: string;
  session_id?: string;
  mcp_server?: string;
  schema?: CanonicalToolSchema;
  source_mode?: 'demo' | 'live';
  plugin_version?: string;
}) {
  const cfg = getBifrostConfig();
  const mode = payload.source_mode ?? cfg.mode;
  const source = mode === 'live' ? 'bifrost' : 'demo_simulator';

  const result = inspectAndProcessToolCall({
    toolName: payload.tool_name,
    arguments: payload.arguments ?? {},
    source,
    agentId: payload.agent_id || `bifrost:${payload.mcp_server || 'mcp-gateway'}`,
    sessionId: payload.session_id || uid('bf-sess'),
    incomingSchema: payload.schema,
  });

  const shortCircuit = result.decision === 'BLOCK' || result.decision === 'REVIEW';

  logBifrostEvent({
    hookType: 'PreMCPHook',
    sourceMode: mode,
    toolName: payload.tool_name,
    decision: result.decision,
    statusCode: result.decision === 'ALLOW' ? 200 : result.decision === 'REVIEW' ? 202 : 403,
    message: `PreMCPHook ${result.decision} (risk ${result.riskScore}/100): ${result.reason}`,
    payload: {
      mcp_server: payload.mcp_server ?? 'default',
      execution_id: result.executionId,
      short_circuit: shortCircuit,
      risk_score: result.riskScore,
      plugin_version: payload.plugin_version ?? null,
    },
  });

  return {
    allow: result.decision === 'ALLOW',
    short_circuit: shortCircuit,
    decision: result.decision,
    risk_score: result.riskScore,
    reason: result.reason,
    triggered_rules: result.triggeredRules,
    execution_id: result.executionId,
    execution_uid: result.executionUid,
    incident_id: result.incidentId,
    approval_request_id: result.approvalRequestId,
    source_mode: mode,
  };
}

/**
 * Handles Bifrost PostMCPHook telemetry after an allowed MCP tool completes execution.
 */
export function handlePostMcpHook(payload: {
  execution_id?: string;
  tool_name: string;
  duration_ms?: number;
  success: boolean;
  error_message?: string;
  result_summary?: string;
  source_mode?: 'demo' | 'live';
  plugin_version?: string;
}) {
  const cfg = getBifrostConfig();
  const mode = payload.source_mode ?? cfg.mode;

  if (payload.execution_id && typeof payload.duration_ms === 'number') {
    db.prepare(`UPDATE tool_executions SET duration_ms = ? WHERE id = ?`).run(
      Math.max(1, Math.round(payload.duration_ms)),
      payload.execution_id
    );
  }

  const log = logBifrostEvent({
    hookType: 'PostMCPHook',
    sourceMode: mode,
    toolName: payload.tool_name,
    decision: payload.success ? 'COMPLETED' : 'ERROR',
    statusCode: payload.success ? 200 : 500,
    message: payload.success
      ? `PostMCPHook recorded completion in ${payload.duration_ms ?? 0}ms.`
      : `PostMCPHook recorded MCP execution error: ${payload.error_message || 'unknown error'}`,
    payload: {
      execution_id: payload.execution_id ?? null,
      duration_ms: payload.duration_ms ?? 0,
      success: payload.success,
      result_summary: payload.result_summary ?? null,
      plugin_version: payload.plugin_version ?? null,
    },
  });

  return { recorded: true, log };
}

/**
 * Queries real SQLite records to compute live Bifrost vs. Demo/Simulator telemetry.
 * Never fabricates live counts or plugin activation state.
 */
export function getBifrostTelemetry(): BifrostTelemetry {
  const cfg = getBifrostConfig();

  const liveExecStats = db
    .prepare(`
      SELECT
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END), 0) as allowCount,
        COALESCE(SUM(CASE WHEN decision = 'REVIEW' THEN 1 ELSE 0 END), 0) as reviewCount,
        COALESCE(SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END), 0) as blockCount
      FROM tool_executions
      WHERE source = 'bifrost'
    `)
    .get() as { total: number; allowCount: number; reviewCount: number; blockCount: number };

  const demoExecStats = db
    .prepare(`
      SELECT
        COUNT(*) as total,
        COALESCE(SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END), 0) as allowCount,
        COALESCE(SUM(CASE WHEN decision = 'REVIEW' THEN 1 ELSE 0 END), 0) as reviewCount,
        COALESCE(SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END), 0) as blockCount
      FROM tool_executions
      WHERE source = 'demo_simulator'
    `)
    .get() as { total: number; allowCount: number; reviewCount: number; blockCount: number };

  const livePostHookRow = db
    .prepare(`
      SELECT COUNT(*) as c
      FROM integration_logs
      WHERE source_mode = 'live' AND hook_type = 'PostMCPHook'
    `)
    .get() as { c: number };

  const livePreHookRow = db
    .prepare(`
      SELECT COUNT(*) as c
      FROM integration_logs
      WHERE source_mode = 'live' AND hook_type IN ('PreMCPHook', 'PostMCPHook')
    `)
    .get() as { c: number };

  const rejectedAuthRow = db
    .prepare(`
      SELECT COUNT(*) as c
      FROM integration_logs
      WHERE source_mode = 'live' AND hook_type = 'AdapterEvent' AND status_code IN (401, 503)
    `)
    .get() as { c: number };

  const recentLiveHookLogs = db
    .prepare(`
      SELECT payload_json
      FROM integration_logs
      WHERE source_mode = 'live' AND hook_type IN ('PreMCPHook', 'PostMCPHook')
      ORDER BY created_at DESC
      LIMIT 10
    `)
    .all() as Array<{ payload_json: string }>;

  let pluginVersion: string | null = null;
  for (const row of recentLiveHookLogs) {
    try {
      const parsed = JSON.parse(row.payload_json) as { plugin_version?: unknown };
      if (typeof parsed.plugin_version === 'string' && parsed.plugin_version.trim()) {
        pluginVersion = parsed.plugin_version.trim();
        break;
      }
    } catch {
      // Ignore malformed payload JSON
    }
  }

  const lastRealExecution =
    (db
      .prepare(`
        SELECT id, execution_uid, tool_name, decision, risk_score, execution_status, duration_ms, created_at
        FROM tool_executions
        WHERE source = 'bifrost'
        ORDER BY created_at DESC
        LIMIT 1
      `)
      .get() as BifrostTelemetry['lastRealExecution']) ?? null;

  const gatewayReachable = cfg.last_test_status === 'connected';
  const hmacAuthStatus = cfg.webhook_auth_status ?? 'secret_missing';

  let pluginLoadingStatus: BifrostTelemetry['pluginLoadingStatus'] = 'not_detected';
  if (livePreHookRow.c > 0) {
    pluginLoadingStatus = 'active_live';
  } else if (gatewayReachable) {
    pluginLoadingStatus = 'gateway_reachable_no_hook';
  } else if (cfg.mode === 'live' && hmacAuthStatus === 'hmac_configured') {
    pluginLoadingStatus = 'configured_awaiting_traffic';
  }

  return {
    gatewayReachable,
    gatewayStatus: cfg.last_test_status,
    endpointUrl: cfg.endpoint_url,
    lastTestedAt: cfg.last_tested_at,
    pluginLoadingStatus,
    pluginVersion,
    pinnedSpecVersion: '1.0.0 (bifrost transports/v2.5.1 · core v1.15.2)',
    hmacAuthStatus,
    signatureTtlSeconds: cfg.signature_ttl_seconds ?? 300,
    lastRealExecution,
    liveCounts: {
      total: liveExecStats.total,
      allow: liveExecStats.allowCount,
      review: liveExecStats.reviewCount,
      block: liveExecStats.blockCount,
      postHookCompleted: livePostHookRow.c,
      rejectedAuthCalls: rejectedAuthRow.c,
    },
    demoCounts: {
      total: demoExecStats.total,
      allow: demoExecStats.allowCount,
      review: demoExecStats.reviewCount,
      block: demoExecStats.blockCount,
    },
  };
}

/**
 * Tests real HTTP reachability of the configured Bifrost Gateway endpoint.
 * NEVER fabricates a successful connection.
 */
export async function testBifrostConnection(endpointUrl: string): Promise<{
  reachable: boolean;
  status: string;
  statusCode: number;
  message: string;
  latencyMs: number;
}> {
  const started = Date.now();
  let parsed: URL;
  try {
    parsed = new URL(endpointUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      throw new Error('Only HTTP/HTTPS endpoints are supported.');
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid Bifrost URL.';
    db.prepare(`
      UPDATE integration_configs
      SET last_test_status = 'invalid_url', last_test_message = ?, last_tested_at = datetime('now'), updated_at = datetime('now')
      WHERE provider = 'bifrost'
    `).run(message);
    return { reachable: false, status: 'invalid_url', statusCode: 400, message, latencyMs: 0 };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3500);

  try {
    const target = `${parsed.origin}/health`;
    const res = await fetch(target, { method: 'GET', signal: controller.signal });
    clearTimeout(timer);
    const latencyMs = Date.now() - started;

    const ok = res.ok;
    const status = ok ? 'connected' : 'http_error';
    const message = ok
      ? `Bifrost Gateway responded HTTP ${res.status} at ${target} (${latencyMs}ms).`
      : `Endpoint ${target} responded with HTTP ${res.status}; verify Bifrost health route.`;

    db.prepare(`
      UPDATE integration_configs
      SET endpoint_url = ?, last_test_status = ?, last_test_message = ?, last_tested_at = datetime('now'), updated_at = datetime('now')
      WHERE provider = 'bifrost'
    `).run(parsed.origin, status, message);

    logBifrostEvent({
      hookType: 'ConnectionTest',
      sourceMode: 'live',
      statusCode: res.status,
      message,
      payload: { target, latencyMs, ok },
    });

    return { reachable: ok, status, statusCode: res.status, message, latencyMs };
  } catch (err) {
    clearTimeout(timer);
    const latencyMs = Date.now() - started;
    const errMsg = err instanceof Error ? err.message : 'Connection failed';
    const message = `No active Bifrost Gateway reachable at ${parsed.origin} (${errMsg}). Use DEMO MODE for standalone evaluation.`;

    db.prepare(`
      UPDATE integration_configs
      SET endpoint_url = ?, last_test_status = 'unreachable', last_test_message = ?, last_tested_at = datetime('now'), updated_at = datetime('now')
      WHERE provider = 'bifrost'
    `).run(parsed.origin, message);

    logBifrostEvent({
      hookType: 'ConnectionTest',
      sourceMode: 'live',
      statusCode: 503,
      message,
      payload: { target: parsed.origin, error: errMsg, latencyMs },
    });

    return { reachable: false, status: 'unreachable', statusCode: 503, message, latencyMs };
  }
}

/**
 * Runs an honest end-to-end live integration audit across HMAC config, plugin artifact presence,
 * live HTTP /health gateway probe, and observed signed live PreMCPHook/PostMCPHook telemetry.
 */
export async function verifyBifrostLiveIntegration(): Promise<BifrostLiveVerificationResult> {
  const cfg = getBifrostConfig();
  const pluginDir = path.resolve(process.cwd(), 'bifrost-plugin');
  const goSourceExists = fs.existsSync(path.join(pluginDir, 'toolseal_plugin.go'));
  const goModExists = fs.existsSync(path.join(pluginDir, 'go.mod'));
  const soExists = fs.existsSync(path.join(pluginDir, 'build', 'toolseal_plugin.so'));

  const hmacReady = cfg.webhook_auth_status === 'hmac_configured';
  const gatewayProbe = await testBifrostConnection(cfg.endpoint_url);

  const liveHookCountRow = db
    .prepare(`
      SELECT COUNT(*) as c
      FROM integration_logs
      WHERE source_mode = 'live' AND hook_type IN ('PreMCPHook', 'PostMCPHook')
    `)
    .get() as { c: number };

  const checks: BifrostLiveVerificationResult['checks'] = [
    {
      id: 'hmac_secret',
      label: 'HMAC-SHA256 Shared Secret',
      status: hmacReady ? 'PASS' : 'FAIL',
      detail: hmacReady
        ? `BIFROST_SHARED_SECRET is configured (${cfg.signature_ttl_seconds ?? 300}s TTL + SQLite replay cache).`
        : 'BIFROST_SHARED_SECRET is unset; /api/bifrost/pre-mcp-hook fails closed with HTTP 503.',
    },
    {
      id: 'plugin_artifacts',
      label: 'Native Go Plugin Artifacts',
      status: goSourceExists && goModExists && soExists ? 'PASS' : goSourceExists && goModExists ? 'WARN' : 'FAIL',
      detail: soExists
        ? 'Native plugin sources and compiled bifrost-plugin/build/toolseal_plugin.so are present.'
        : goSourceExists && goModExists
          ? 'Pinned Go plugin source & go.mod (core v1.15.2) present, but compiled .so binary is not built on this host (build via ./bifrost-plugin/build.sh on Linux/macOS with Go 1.27.3).'
          : 'Missing bifrost-plugin/toolseal_plugin.go or go.mod.',
    },
    {
      id: 'gateway_health',
      label: 'Bifrost Gateway HTTP Probe',
      status: gatewayProbe.reachable ? 'PASS' : 'FAIL',
      detail: gatewayProbe.message,
    },
    {
      id: 'live_hook_traffic',
      label: 'Signed Live Hook Telemetry',
      status: liveHookCountRow.c > 0 ? 'PASS' : 'FAIL',
      detail:
        liveHookCountRow.c > 0
          ? `${liveHookCountRow.c} HMAC-authenticated live PreMCPHook/PostMCPHook events recorded in SQLite.`
          : 'Zero HMAC-authenticated live PreMCPHook/PostMCPHook calls observed yet from a running Bifrost gateway.',
    },
  ];

  const allPassed = checks.every((c) => c.status === 'PASS');
  const anyPassed = checks.some((c) => c.status === 'PASS');

  const overallStatus: BifrostLiveVerificationResult['overallStatus'] = allPassed
    ? 'verified'
    : anyPassed
      ? 'partial'
      : 'not_connected';

  const summary = allPassed
    ? 'Live Bifrost Gateway, compiled .so plugin, HMAC webhook signing, and signed MCP hook telemetry verified.'
    : gatewayProbe.reachable && liveHookCountRow.c === 0
      ? 'Bifrost Gateway responded on /health, but no signed live MCP hook calls have reached TOOLSEAL yet.'
      : 'Live Bifrost Gateway runtime is not currently reachable or missing live plugin telemetry. Local/Demo hooks remain operational.';

  return {
    overallStatus,
    verifiedAt: new Date().toISOString(),
    summary,
    checks,
  };
}
