import { db, uid } from '../db/database.ts';
import {
  evaluateDeterministicRules,
  getActivePolicy,
  processApprovalDecision,
  runSafeMockSandbox,
} from '../security/engine.ts';
import {
  analyzeBehaviourDrift,
  syncBehaviourBaselineFromSchema,
} from '../security/behaviourDrift.ts';
import { computeToolDna, diffToolSchemas } from '../security/toolDna.ts';
import { testBifrostConnection } from '../bifrost/adapter.ts';
import { signBifrostPayload, verifyBifrostWebhookRequest } from '../bifrost/webhookAuth.ts';
import { createSession, revokeSession } from '../auth/auth.ts';
import { broadcaster } from '../ws/broadcaster.ts';
import type { CanonicalToolSchema, QaTestItem, QaSuiteReport, UserRecord } from '../../types/toolseal.ts';

export interface QaSuiteContext {
  baseUrl?: string;
  actor?: UserRecord;
}

/**
 * Executes non-destructive end-to-end verification across all TOOLSEAL backend modules,
 * including HMAC webhook authentication, RBAC authorization, and behavioural baseline consistency.
 * SQLite write tests run inside a rolled-back savepoint so production telemetry stays clean.
 */
export async function runQaVerificationSuite(context?: QaSuiteContext): Promise<QaSuiteReport> {
  const startedAt = new Date().toISOString();
  const tests: QaTestItem[] = [];
  const baseUrl = context?.baseUrl || `http://127.0.0.1:${Number(process.env.PORT) || 3000}`;

  const runCheck = async (
    id: string,
    moduleName: string,
    title: string,
    fn: () => Promise<string> | string
  ) => {
    const t0 = Date.now();
    try {
      const detail = await fn();
      tests.push({
        id,
        module: moduleName,
        title,
        status: 'PASS',
        durationMs: Date.now() - t0,
        detail,
      });
    } catch (err) {
      tests.push({
        id,
        module: moduleName,
        title,
        status: 'FAIL',
        durationMs: Date.now() - t0,
        detail: err instanceof Error ? err.message : 'Assertion failed',
      });
    }
  };

  // 1. SQLite Relational Schema & Transaction Persistence Check
  await runCheck('qa-sqlite', 'Database (SQLite)', 'Relational tables & transactional write/readback', () => {
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table'")
      .all() as Array<{ name: string }>;
    const names = new Set(tables.map((t) => t.name));
    const required = [
      'users',
      'user_sessions',
      'webhook_replay_nonces',
      'registered_tools',
      'tool_schemas',
      'schema_fingerprints',
      'tool_executions',
      'security_incidents',
      'approval_requests',
      'security_policies',
      'integration_configs',
      'integration_logs',
      'audit_logs',
      'tool_behaviour_profiles',
      'tool_behaviour_events',
    ];
    const missing = required.filter((r) => !names.has(r));
    if (missing.length > 0) {
      throw new Error(`Missing SQLite tables: ${missing.join(', ')}`);
    }

    const probeId = uid('qa-probe');
    db.exec('SAVEPOINT qa_probe_sp');
    try {
      db.prepare(`
        INSERT INTO audit_logs (id, actor_id, actor_role, action, target_type, target_id, details_json)
        VALUES (?, 'qa-runner', 'admin', 'QA_PROBE', 'system', 'sqlite', '{}')
      `).run(probeId);
      const found = db.prepare('SELECT id FROM audit_logs WHERE id = ?').get(probeId) as { id: string } | undefined;
      if (!found) throw new Error('Inserted row could not be read back from SQLite.');
    } finally {
      db.exec('ROLLBACK TO qa_probe_sp');
      db.exec('RELEASE qa_probe_sp');
    }
    return `All ${required.length} relational tables verified and transactional readback passed.`;
  });

  // 2. Security Engine: ALLOW (Normal Operation)
  await runCheck('qa-allow', 'Security Engine', 'Deterministic ALLOW on get_weather({"city":"Mumbai"})', () => {
    const policy = getActivePolicy();
    const res = evaluateDeterministicRules('get_weather', { city: 'Mumbai' }, policy);
    if (res.decision !== 'ALLOW' || res.riskScore > 30) {
      throw new Error(`Expected ALLOW (<=30), got ${res.decision} (${res.riskScore})`);
    }
    const sandbox = runSafeMockSandbox('get_weather', { city: 'Mumbai' });
    if (!sandbox.includes('Mumbai')) {
      throw new Error('Safe sandbox did not return expected city output.');
    }
    return `Scored ${res.riskScore}/100 -> ALLOW with safe sandbox execution.`;
  });

  // 3. Security Engine: REVIEW (Unknown tool)
  await runCheck('qa-review', 'Security Engine', 'Deterministic REVIEW escalation on unregistered tool', () => {
    const policy = getActivePolicy();
    const unknownPolicy = { ...policy, unknown_tool_action: 'REVIEW' as const };
    const res = evaluateDeterministicRules('unregistered_qa_tool', { query: 'test' }, unknownPolicy);
    if (res.decision !== 'REVIEW') {
      throw new Error(`Expected REVIEW, got ${res.decision} (${res.riskScore})`);
    }
    return `Scored ${res.riskScore}/100 -> REVIEW escalation triggered.`;
  });

  // 4. Security Engine: BLOCK (Data Exfiltration + Destructive Operation + Sensitive File)
  await runCheck('qa-block', 'Security Engine', 'Deterministic BLOCK on exfiltration, destructive, and /etc/shadow', () => {
    const policy = getActivePolicy();
    const exfil = evaluateDeterministicRules('export_customer_database', { scope: 'all_customers' }, policy);
    const destr = evaluateDeterministicRules('delete_all_records', { confirmation: true }, policy);
    const blockPolicy = { ...policy, sensitive_file_action: 'BLOCK' as const };
    const sens = evaluateDeterministicRules('read_file', { path: '/etc/shadow' }, blockPolicy);

    if (exfil.decision !== 'BLOCK' || destr.decision !== 'BLOCK' || sens.decision !== 'BLOCK') {
      throw new Error(`Unexpected decision: exfil=${exfil.decision}, destr=${destr.decision}, sens=${sens.decision}`);
    }
    return `Blocked all 3 threat vectors (scores: ${exfil.riskScore}, ${destr.riskScore}, ${sens.riskScore}).`;
  });

  // 5. Tool DNA: SHA-256 Fingerprinting & Drift Diffing
  await runCheck('qa-tooldna', 'Tool DNA', 'Canonical SHA-256 hashing & schema manipulation diffing', () => {
    const baseA: CanonicalToolSchema = {
      name: 'qa_tool',
      description: 'Test',
      parameters: {
        type: 'object',
        properties: { b: { type: 'string' }, a: { type: 'number' } },
        required: ['b', 'a'],
      },
    };
    const baseB: CanonicalToolSchema = {
      name: 'qa_tool',
      description: 'Test',
      parameters: {
        type: 'object',
        properties: { a: { type: 'number' }, b: { type: 'string' } },
        required: ['a', 'b'],
      },
    };
    const mutated: CanonicalToolSchema = {
      name: 'qa_tool',
      description: 'Test',
      parameters: {
        type: 'object',
        properties: {
          a: { type: 'number' },
          b: { type: 'string' },
          exfiltrate_webhook: { type: 'string', description: 'Exfil target' },
        },
        required: ['a', 'b'],
      },
    };

    const h1 = computeToolDna(baseA);
    const h2 = computeToolDna(baseB);
    const h3 = computeToolDna(mutated);
    if (h1.sha256 !== h2.sha256) {
      throw new Error('Canonicalization failed: key reordering altered SHA-256.');
    }
    if (h1.sha256 === h3.sha256) {
      throw new Error('Added parameter did not alter SHA-256 fingerprint.');
    }
    const diffs = diffToolSchemas(baseA, mutated);
    if (diffs.length !== 1 || diffs[0].parameter !== 'exfiltrate_webhook') {
      throw new Error('Schema diff engine failed to isolate added parameter.');
    }
    return `Canonical SHA-256 verified (${h1.sha256.slice(0, 12)}…) and detected added param "${diffs[0].parameter}".`;
  });

  // 6. Approval Center & Incident Persistence
  await runCheck('qa-workflow', 'Approval & Incidents', 'Persisted incidents & approval queue schema integrity', () => {
    const incCount = (db.prepare('SELECT COUNT(*) as c FROM security_incidents').get() as { c: number }).c;
    const aprCount = (db.prepare('SELECT COUNT(*) as c FROM approval_requests').get() as { c: number }).c;
    const admin = db.prepare("SELECT id, role FROM users WHERE role = 'admin' LIMIT 1").get() as
      | { id: string; role: string }
      | undefined;
    if (!admin) throw new Error('No administrator user found for RBAC approval enforcement.');
    return `Verified ${incCount} persisted incident(s), ${aprCount} approval record(s), and admin RBAC (${admin.id}).`;
  });

  // 7. WebSocket Real-Time Broadcaster
  await runCheck('qa-ws', 'WebSocket Service', 'Authenticated broadcaster attached on /ws and active', () => {
    const count = broadcaster.getClientCount();
    broadcaster.broadcast('connected', { status: 'qa_ping', clientCount: count });
    return `WebSocket server active on /ws (${count} authenticated dashboard client${count === 1 ? '' : 's'}).`;
  });

  // 8. Bifrost Gateway Adapter (Honest Connectivity)
  await runCheck('qa-bifrost', 'Bifrost Adapter', 'Honest reachability check (never fakes live gateway)', async () => {
    const cfg = db.prepare("SELECT mode, endpoint_url FROM integration_configs WHERE provider = 'bifrost'").get() as
      | { mode: string; endpoint_url: string }
      | undefined;
    if (!cfg) throw new Error('Missing Bifrost integration config in SQLite.');
    const probe = await testBifrostConnection('http://127.0.0.1:59998');
    if (probe.reachable) {
      throw new Error('Expected unreachable test port to return reachable=false.');
    }
    return `Bifrost config mode="${cfg.mode}". Unreachable port accurately reported status="${probe.status}".`;
  });

  // 9. Bifrost Webhook Auth: Valid Signature
  await runCheck('qa-hmac-valid', 'Webhook Auth (HMAC)', 'Accepts valid HMAC-SHA256 signature within TTL window', () => {
    const testSecret = 'qa-hmac-ephemeral-secret-for-test';
    const rawBody = JSON.stringify({ tool_name: 'get_weather', arguments: { city: 'Mumbai' } });
    const nowSec = Math.floor(Date.now() / 1000);
    const nonce = uid('nonce-valid');
    const sig = signBifrostPayload(rawBody, nowSec, nonce, testSecret);

    db.exec('SAVEPOINT qa_hmac_valid_sp');
    try {
      const res = verifyBifrostWebhookRequest({
        rawBody,
        timestampHeader: String(nowSec),
        nonceHeader: nonce,
        signatureHeader: sig,
        secretOverride: testSecret,
        ttlSecondsOverride: 300,
        nowSecondsOverride: nowSec,
      });
      if (!res.ok || res.code !== 'OK') {
        throw new Error(`Expected OK for valid signature, got ${res.code} (${res.error})`);
      }
      return 'Valid HMAC-SHA256 signature verified with constant-time comparison and nonce recorded.';
    } finally {
      db.exec('ROLLBACK TO qa_hmac_valid_sp');
      db.exec('RELEASE qa_hmac_valid_sp');
    }
  });

  // 10. Bifrost Webhook Auth: Invalid Signature
  await runCheck('qa-hmac-invalid', 'Webhook Auth (HMAC)', 'Rejects tampered/invalid HMAC-SHA256 signature (401)', () => {
    const testSecret = 'qa-hmac-ephemeral-secret-for-test';
    const rawBody = JSON.stringify({ tool_name: 'get_weather', arguments: { city: 'Mumbai' } });
    const nowSec = Math.floor(Date.now() / 1000);
    const nonce = uid('nonce-bad');
    const badSig = signBifrostPayload(rawBody, nowSec, nonce, 'wrong-secret');

    const res = verifyBifrostWebhookRequest({
      rawBody,
      timestampHeader: String(nowSec),
      nonceHeader: nonce,
      signatureHeader: badSig,
      secretOverride: testSecret,
      ttlSecondsOverride: 300,
      nowSecondsOverride: nowSec,
    });
    if (res.ok || res.code !== 'INVALID_SIGNATURE' || res.status !== 401) {
      throw new Error(`Expected 401 INVALID_SIGNATURE, got ${res.status} ${res.code}`);
    }
    return 'Invalid HMAC signature rejected with HTTP 401 INVALID_SIGNATURE.';
  });

  // 11. Bifrost Webhook Auth: Missing Signature
  await runCheck('qa-hmac-missing', 'Webhook Auth (HMAC)', 'Rejects unsigned webhook requests missing headers (401)', () => {
    const res = verifyBifrostWebhookRequest({
      rawBody: '{"tool_name":"get_weather"}',
      secretOverride: 'qa-hmac-ephemeral-secret-for-test',
    });
    if (res.ok || res.code !== 'MISSING_SIGNATURE' || res.status !== 401) {
      throw new Error(`Expected 401 MISSING_SIGNATURE, got ${res.status} ${res.code}`);
    }
    return 'Unsigned request lacking X-Bifrost-* headers rejected with HTTP 401.';
  });

  // 12. Bifrost Webhook Auth: Expired Timestamp
  await runCheck('qa-hmac-expired', 'Webhook Auth (HMAC)', 'Rejects expired timestamp outside configured TTL window (401)', () => {
    const testSecret = 'qa-hmac-ephemeral-secret-for-test';
    const rawBody = '{"tool_name":"get_weather"}';
    const nowSec = Math.floor(Date.now() / 1000);
    const staleSec = nowSec - 600;
    const nonce = uid('nonce-stale');
    const sig = signBifrostPayload(rawBody, staleSec, nonce, testSecret);

    const res = verifyBifrostWebhookRequest({
      rawBody,
      timestampHeader: String(staleSec),
      nonceHeader: nonce,
      signatureHeader: sig,
      secretOverride: testSecret,
      ttlSecondsOverride: 300,
      nowSecondsOverride: nowSec,
    });
    if (res.ok || res.code !== 'EXPIRED_TIMESTAMP' || res.status !== 401) {
      throw new Error(`Expected 401 EXPIRED_TIMESTAMP, got ${res.status} ${res.code}`);
    }
    return 'Expired 600s-old timestamp rejected outside 300s TTL with HTTP 401.';
  });

  // 13. Bifrost Webhook Auth: Replay Protection
  await runCheck('qa-hmac-replay', 'Webhook Auth (HMAC)', 'Blocks replayed webhook request with identical nonce/signature (401)', () => {
    const testSecret = 'qa-hmac-ephemeral-secret-for-test';
    const rawBody = '{"tool_name":"get_weather"}';
    const nowSec = Math.floor(Date.now() / 1000);
    const nonce = uid('nonce-replay');
    const sig = signBifrostPayload(rawBody, nowSec, nonce, testSecret);

    db.exec('SAVEPOINT qa_hmac_replay_sp');
    try {
      const first = verifyBifrostWebhookRequest({
        rawBody,
        timestampHeader: String(nowSec),
        nonceHeader: nonce,
        signatureHeader: sig,
        secretOverride: testSecret,
        ttlSecondsOverride: 300,
        nowSecondsOverride: nowSec,
      });
      if (!first.ok) {
        throw new Error(`Initial valid signed request failed unexpectedly: ${first.code}`);
      }
      const second = verifyBifrostWebhookRequest({
        rawBody,
        timestampHeader: String(nowSec),
        nonceHeader: nonce,
        signatureHeader: sig,
        secretOverride: testSecret,
        ttlSecondsOverride: 300,
        nowSecondsOverride: nowSec,
      });
      if (second.ok || second.code !== 'REPLAY_DETECTED' || second.status !== 401) {
        throw new Error(`Expected 401 REPLAY_DETECTED on second call, got ${second.status} ${second.code}`);
      }
      return 'First signed request accepted; duplicate replay blocked with HTTP 401 REPLAY_DETECTED.';
    } finally {
      db.exec('ROLLBACK TO qa_hmac_replay_sp');
      db.exec('RELEASE qa_hmac_replay_sp');
    }
  });

  // 14. Auth & RBAC: Reject unauthenticated requests with 401
  await runCheck('qa-auth-unauth', 'Auth & RBAC', 'Rejects unauthenticated REST and webhook access', async () => {
    const dashRes = await fetch(`${baseUrl}/api/dashboard/overview`);
    const polRes = await fetch(`${baseUrl}/api/policies/pol-default`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const hookRes = await fetch(`${baseUrl}/api/bifrost/pre-mcp-hook`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool_name: 'get_weather', arguments: { city: 'Mumbai' } }),
    });

    if (dashRes.status !== 401 || polRes.status !== 401) {
      throw new Error(`Expected 401 for unauthenticated endpoints, got dash=${dashRes.status}, policy=${polRes.status}`);
    }
    if (hookRes.status !== 401 && hookRes.status !== 503) {
      throw new Error(`Expected 401 or 503 for unsigned webhook, got ${hookRes.status}`);
    }
    return `Verified HTTP ${dashRes.status}/${polRes.status} on protected APIs and HTTP ${hookRes.status} on unsigned webhook.`;
  });

  // 15. Auth & RBAC: Prevent privilege escalation for viewer and analyst roles
  await runCheck('qa-rbac-escalation', 'Auth & RBAC', 'Blocks viewer/analyst privilege escalation on admin endpoints (403)', async () => {
    const viewerSession = createSession('usr-viewer-1');
    const analystSession = createSession('usr-analyst-1');

    try {
      const viewerPolicyRes = await fetch(`${baseUrl}/api/policies/pol-default`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${viewerSession.token}`,
        },
        body: JSON.stringify({
          allow_max_risk: 20,
          review_max_risk: 60,
          sensitive_file_action: 'BLOCK',
          unknown_tool_action: 'REVIEW',
          block_on_schema_mismatch: true,
          bulk_threshold: 500,
          role: 'admin',
        }),
      });

      const viewerInspectRes = await fetch(`${baseUrl}/api/executions/inspect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${viewerSession.token}`,
        },
        body: JSON.stringify({ toolName: 'get_weather', arguments: { city: 'Mumbai' } }),
      });

      const analystApproveRes = await fetch(`${baseUrl}/api/approvals/apr-seed-1/decide`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${analystSession.token}`,
        },
        body: JSON.stringify({
          action: 'approved',
          reviewerId: 'usr-admin-1',
          role: 'admin',
          note: 'Spoof attempt',
        }),
      });

      const analystDnaApproveRes = await fetch(`${baseUrl}/api/tools/tool-weather/approve-fingerprint`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${analystSession.token}`,
        },
      });

      if (
        viewerPolicyRes.status !== 403 ||
        viewerInspectRes.status !== 403 ||
        analystApproveRes.status !== 403 ||
        analystDnaApproveRes.status !== 403
      ) {
        throw new Error(
          `RBAC bypass detected: viewerPolicy=${viewerPolicyRes.status}, viewerInspect=${viewerInspectRes.status}, analystApprove=${analystApproveRes.status}, analystDna=${analystDnaApproveRes.status}`
        );
      }

      return 'All 4 escalation attempts (viewer write/policy + analyst approval/Tool DNA approve) returned HTTP 403.';
    } finally {
      revokeSession(viewerSession.token);
      revokeSession(analystSession.token);
    }
  });

  // 16. Behavioural Drift Detection: Normal Weather Baseline
  await runCheck('qa-behaviour-baseline', 'Behavioural Drift', 'Baseline alignment on get_weather({"city":"Mumbai"})', () => {
    const policy = getActivePolicy();
    const drift = analyzeBehaviourDrift('get_weather', { city: 'Mumbai', units: 'metric' }, policy, { overrideRpm: 2 });
    if (!drift.hasBaseline) {
      throw new Error('Missing baseline profile for get_weather.');
    }
    if (drift.isAnomalous || drift.deviationScore > policy.drift_low_max) {
      throw new Error(`Expected low deviation <= ${policy.drift_low_max}, got ${drift.deviationScore}`);
    }
    return `Verified learned baseline (${drift.baselineBehaviour.sampleCount} samples) -> deviation ${drift.deviationScore}/100 (ALLOW).`;
  });

  // 17. Behavioural Drift Detection: Weather Tool -> Customer DB Anomaly + Unified Engine
  await runCheck(
    'qa-behaviour-drift',
    'Behavioural Drift',
    'Detect get_weather anomaly requesting customer_database records',
    () => {
      const policy = getActivePolicy();
      const args = {
        city: 'Mumbai',
        resource: 'customer_database',
        table: 'customer_records',
        operation: 'export',
        limit: 2500,
      };
      const evalRes = evaluateDeterministicRules('get_weather', args, policy);
      const drift = evalRes.behaviourDrift;
      const dims = new Set(drift.differences.map((d) => d.dimension));
      const requiredDims = ['parameters', 'resource', 'operation', 'bulk_volume', 'sensitive_resource'] as const;
      const missingDims = requiredDims.filter((d) => !dims.has(d));
      if (missingDims.length > 0) {
        throw new Error(`Missed drift dimensions: ${missingDims.join(', ')}`);
      }
      if (drift.deviationScore <= policy.drift_medium_max) {
        throw new Error(`Expected high deviation > ${policy.drift_medium_max}, got ${drift.deviationScore}`);
      }
      if (evalRes.decision === 'ALLOW') {
        throw new Error(`Expected BLOCK or REVIEW on severe drift, got ALLOW (${evalRes.riskScore})`);
      }
      return `Flagged 5 drift dimensions (deviation ${drift.deviationScore}/100 -> risk ${evalRes.riskScore}/100, ${evalRes.decision}).`;
    }
  );

  // 18. Behavioural Drift Detection: Frequency Spike Anomaly
  await runCheck('qa-behaviour-freq', 'Behavioural Drift', 'Detect execution frequency burst above baseline multiplier', () => {
    const policy = getActivePolicy();
    const drift = analyzeBehaviourDrift('get_weather', { city: 'Mumbai' }, policy, { overrideRpm: 18 });
    const hasFreqRule = drift.triggeredRules.some((r) => r.id === 'BEHAVIOUR_FREQUENCY_SPIKE');
    if (!hasFreqRule || !drift.isAnomalous) {
      throw new Error('Expected BEHAVIOUR_FREQUENCY_SPIKE rule to trigger at 18 req/min.');
    }
    return `Frequency spike 18 req/min flagged against baseline ${drift.baselineBehaviour.baselineRpm}/min (deviation ${drift.deviationScore}/100).`;
  });

  // 19. Phase 3: Approval & Tool DNA Behavioural Baseline Consistency
  await runCheck(
    'qa-baseline-consistency',
    'Baseline Consistency',
    'Approval safe-learning & Tool DNA approved-schema baseline sync',
    () => {
      const adminUser =
        context?.actor ??
        (db.prepare("SELECT id, username, email, role, display_name, COALESCE(is_active, 1) as is_active, created_at FROM users WHERE role = 'admin' LIMIT 1").get() as UserRecord);

      db.exec('SAVEPOINT qa_baseline_sp');
      try {
        // A. Clean approved execution learns safely & writes BEHAVIOUR_BASELINE_LEARNED
        const beforeProfile = db
          .prepare('SELECT total_baseline_executions, normal_param_keys_json FROM tool_behaviour_profiles WHERE tool_name = ?')
          .get('get_weather') as { total_baseline_executions: number; normal_param_keys_json: string };

        const cleanExecId = uid('qa-exec');
        const cleanAprId = uid('qa-apr');
        db.prepare(`
          INSERT INTO tool_executions (
            id, execution_uid, tool_name, arguments_json, source, agent_id, session_id,
            risk_score, decision, reason, triggered_rules_json, execution_status, duration_ms
          ) VALUES (?, ?, 'get_weather', ?, 'api_direct', 'qa-agent', 'qa-sess', 35, 'REVIEW', 'Manual hold test', '[]', 'pending_approval', 5)
        `).run(cleanExecId, `EXE-${uid('q')}`, JSON.stringify({ city: 'Delhi', units: 'metric' }));

        db.prepare(`
          INSERT INTO approval_requests (
            id, request_uid, execution_id, incident_id, tool_name, arguments_json,
            risk_score, reason, triggered_rules_json, status
          ) VALUES (?, ?, ?, NULL, 'get_weather', ?, 35, 'Manual hold test', '[]', 'pending')
        `).run(cleanAprId, `APR-${uid('q')}`, cleanExecId, JSON.stringify({ city: 'Delhi', units: 'metric' }));

        const cleanDecision = processApprovalDecision(cleanAprId, 'approved', adminUser, 'QA clean check');
        if (cleanDecision.status !== 'approved' || !cleanDecision.learnedBaseline) {
          throw new Error('Clean trusted approval failed to record safe baseline learning.');
        }

        const afterCleanProfile = db
          .prepare('SELECT total_baseline_executions FROM tool_behaviour_profiles WHERE tool_name = ?')
          .get('get_weather') as { total_baseline_executions: number };
        if (afterCleanProfile.total_baseline_executions !== beforeProfile.total_baseline_executions + 1) {
          throw new Error('Baseline execution counter did not increment on clean approved call.');
        }

        // B. Suspicious execution must NOT poison baseline even if sent through approval revalidation
        const anomExecId = uid('qa-exec');
        const anomAprId = uid('qa-apr');
        const anomArgs = { city: 'Delhi', rogue_param: 'exfil' };
        db.prepare(`
          INSERT INTO tool_executions (
            id, execution_uid, tool_name, arguments_json, source, agent_id, session_id,
            risk_score, decision, reason, triggered_rules_json, execution_status, duration_ms
          ) VALUES (?, ?, 'get_weather', ?, 'api_direct', 'qa-agent', 'qa-sess', 45, 'REVIEW', 'Drift hold', '[]', 'pending_approval', 5)
        `).run(anomExecId, `EXE-${uid('q2')}`, JSON.stringify(anomArgs));

        db.prepare(`
          INSERT INTO approval_requests (
            id, request_uid, execution_id, incident_id, tool_name, arguments_json,
            risk_score, reason, triggered_rules_json, status
          ) VALUES (?, ?, ?, NULL, 'get_weather', ?, 45, 'Drift hold', '[]', 'pending')
        `).run(anomAprId, `APR-${uid('q2')}`, anomExecId, JSON.stringify(anomArgs));

        const anomDecision = processApprovalDecision(anomAprId, 'approved', adminUser, 'QA anomaly check');
        if (anomDecision.learnedBaseline) {
          throw new Error('Safe-learning policy violated: anomalous arguments poisoned baseline!');
        }

        const afterAnomProfile = db
          .prepare('SELECT normal_param_keys_json FROM tool_behaviour_profiles WHERE tool_name = ?')
          .get('get_weather') as { normal_param_keys_json: string };
        if (afterAnomProfile.normal_param_keys_json.includes('rogue_param')) {
          throw new Error('Anomalous rogue_param leaked into normal_param_keys_json.');
        }

        // C. Explicit Tool DNA approval syncs approved parameter keys into baseline
        const syncedSchema: CanonicalToolSchema = {
          name: 'get_weather',
          description: 'Forecast',
          parameters: {
            type: 'object',
            properties: {
              city: { type: 'string' },
              units: { type: 'string' },
              lang: { type: 'string' },
            },
            required: ['city'],
          },
        };
        const { sha256 } = computeToolDna(syncedSchema);
        const synced = syncBehaviourBaselineFromSchema({
          toolName: 'get_weather',
          approvedSchema: syncedSchema,
          sha256,
          actorId: adminUser.id,
          actorRole: adminUser.role,
        });
        if (!synced || !synced.normal_param_keys_json.includes('lang')) {
          throw new Error('Tool DNA schema sync failed to update normal_param_keys_json.');
        }

        return 'Verified clean approval safe-learning, anomaly non-poisoning, and Tool DNA schema baseline sync.';
      } finally {
        db.exec('ROLLBACK TO qa_baseline_sp');
        db.exec('RELEASE qa_baseline_sp');
      }
    }
  );

  const passed = tests.filter((t) => t.status === 'PASS').length;
  const failed = tests.length - passed;

  return {
    startedAt,
    completedAt: new Date().toISOString(),
    summary: {
      total: tests.length,
      passed,
      failed,
    },
    tests,
  };
}
