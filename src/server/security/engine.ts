import { db, uid, writeAuditLog } from '../db/database.ts';
import { computeToolDna, diffToolSchemas } from './toolDna.ts';
import {
  analyzeBehaviourDrift,
  recordApprovedBehaviourExecution,
  recordBehaviourEventAndLearn,
} from './behaviourDrift.ts';
import { broadcaster } from '../ws/broadcaster.ts';
import type {
  BehaviourDriftAnalysis,
  CanonicalToolSchema,
  EventSource,
  ExecutionStatus,
  IncidentSeverity,
  RegisteredTool,
  SecurityDecision,
  SecurityPolicy,
  TriggeredRule,
  UserRecord,
} from '../../types/toolseal.ts';

export interface InspectionInput {
  toolName: string;
  arguments: Record<string, unknown>;
  source?: EventSource;
  agentId?: string;
  sessionId?: string;
  incomingSchema?: CanonicalToolSchema;
  overrideRpm?: number;
}

export interface InspectionOutput {
  executionId: string;
  executionUid: string;
  toolName: string;
  riskScore: number;
  decision: SecurityDecision;
  executionStatus: ExecutionStatus;
  reason: string;
  triggeredRules: TriggeredRule[];
  behaviourDrift: BehaviourDriftAnalysis;
  incidentId: string | null;
  incidentUid: string | null;
  approvalRequestId: string | null;
  approvalRequestUid: string | null;
  mockExecutionOutput: string | null;
}

export function getActivePolicy(): SecurityPolicy {
  const row = db.prepare('SELECT * FROM security_policies WHERE is_active = 1 LIMIT 1').get() as SecurityPolicy | undefined;
  if (row) {
    return {
      ...row,
      drift_low_max: row.drift_low_max ?? 25,
      drift_medium_max: row.drift_medium_max ?? 60,
      drift_high_action: row.drift_high_action ?? 'BLOCK',
      drift_frequency_multiplier: row.drift_frequency_multiplier ?? 3,
    };
  }
  return {
    id: 'pol-default',
    name: 'Zero-Trust Production Baseline',
    description: 'Fallback baseline policy',
    allow_max_risk: 30,
    review_max_risk: 70,
    sensitive_file_action: 'BLOCK',
    unknown_tool_action: 'REVIEW',
    block_on_schema_mismatch: 1,
    bulk_threshold: 500,
    drift_low_max: 25,
    drift_medium_max: 60,
    drift_high_action: 'BLOCK',
    drift_frequency_multiplier: 3,
    is_active: 1,
    updated_at: new Date().toISOString(),
  };
}

export function getToolWithFingerprints(toolName: string) {
  const tool = db.prepare('SELECT * FROM registered_tools WHERE name = ?').get(toolName) as RegisteredTool | undefined;
  if (!tool) return null;

  const approvedRow = db.prepare(`
    SELECT ts.schema_json, sf.sha256_hash
    FROM schema_fingerprints sf
    JOIN tool_schemas ts ON ts.id = sf.schema_id
    WHERE sf.tool_id = ? AND sf.status = 'approved'
    ORDER BY ts.version DESC LIMIT 1
  `).get(tool.id) as { schema_json: string; sha256_hash: string } | undefined;

  const latestRow = db.prepare(`
    SELECT ts.schema_json, sf.sha256_hash, sf.status
    FROM schema_fingerprints sf
    JOIN tool_schemas ts ON ts.id = sf.schema_id
    WHERE sf.tool_id = ?
    ORDER BY ts.version DESC, sf.created_at DESC LIMIT 1
  `).get(tool.id) as { schema_json: string; sha256_hash: string; status: string } | undefined;

  return {
    tool,
    approvedSchema: approvedRow ? (JSON.parse(approvedRow.schema_json) as CanonicalToolSchema) : null,
    approvedHash: approvedRow?.sha256_hash ?? null,
    latestSchema: latestRow ? (JSON.parse(latestRow.schema_json) as CanonicalToolSchema) : null,
    latestHash: latestRow?.sha256_hash ?? null,
    fingerprintStatus: latestRow?.status ?? null,
  };
}

/**
 * Safe mock execution sandbox — NEVER executes shell commands or real filesystem/DB writes.
 */
export function runSafeMockSandbox(toolName: string, args: Record<string, unknown>): string {
  if (toolName === 'get_weather') {
    const city = String(args.city || 'Mumbai');
    const units = String(args.units || 'metric');
    return JSON.stringify({
      sandbox: true,
      city,
      temperature: units === 'imperial' ? '84°F' : '29°C',
      condition: 'Clear Sky',
      humidity: '64%',
      verifiedBy: 'TOOLSEAL Safe Sandbox',
    });
  }
  if (toolName === 'search_knowledge_base') {
    return JSON.stringify({
      sandbox: true,
      query: String(args.query || ''),
      matches: 3,
      snippet: 'Bifrost PreMCPHook intercepts MCP tool calls prior to downstream execution.',
    });
  }
  if (toolName === 'read_file') {
    return JSON.stringify({
      sandbox: true,
      path: String(args.path || ''),
      bytesRead: 412,
      contentPreview: '[Safe workspace file read simulated inside isolated sandbox]',
    });
  }
  return JSON.stringify({
    sandbox: true,
    toolName,
    status: 'simulated_success',
    timestamp: new Date().toISOString(),
  });
}

function severityFromScore(score: number): IncidentSeverity {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 31) return 'medium';
  return 'low';
}

/**
 * Deterministic rule evaluation for an incoming tool call (used both on initial inspect and approval revalidation).
 */
export function evaluateDeterministicRules(
  toolName: string,
  args: Record<string, unknown>,
  policy: SecurityPolicy,
  incomingSchema?: CanonicalToolSchema,
  options?: { overrideRpm?: number }
): {
  riskScore: number;
  decision: SecurityDecision;
  triggeredRules: TriggeredRule[];
  primaryCategory: string;
  explanation: string;
  behaviourDrift: BehaviourDriftAnalysis;
} {
  const triggeredRules: TriggeredRule[] = [];
  const lowerTool = toolName.toLowerCase();
  const serializedArgs = JSON.stringify(args).toLowerCase();

  const dnaRecord = getToolWithFingerprints(toolName);

  // 1. Tool DNA Integrity Check
  if (!dnaRecord) {
    const weight = policy.unknown_tool_action === 'BLOCK' ? 78 : 52;
    triggeredRules.push({
      id: 'UNKNOWN_UNREGISTERED_TOOL',
      name: 'Unregistered MCP Tool',
      category: 'Unknown Tool',
      weight,
      severity: policy.unknown_tool_action === 'BLOCK' ? 'high' : 'medium',
      detail: `Tool "${toolName}" is not present in the approved Tool DNA Registry.`,
    });
  } else {
    if (dnaRecord.tool.trust_status === 'modified' || dnaRecord.tool.trust_status === 'untrusted') {
      const weight = policy.block_on_schema_mismatch ? 90 : 60;
      triggeredRules.push({
        id: 'TOOL_DNA_TAMPER',
        name: 'Tool DNA Fingerprint Mismatch',
        category: 'Schema Manipulation',
        weight,
        severity: 'critical',
        detail: `Tool "${toolName}" is flagged as "${dnaRecord.tool.trust_status}" because its schema diverged from approved SHA-256 fingerprint (${dnaRecord.approvedHash?.slice(0, 12)}...).`,
      });
    } else if (incomingSchema && dnaRecord.approvedHash) {
      const incoming = computeToolDna(incomingSchema);
      if (incoming.sha256 !== dnaRecord.approvedHash) {
        const diffs = dnaRecord.approvedSchema ? diffToolSchemas(dnaRecord.approvedSchema, incomingSchema) : [];
        const diffParams = diffs.map((d) => `${d.changeType}:${d.parameter}`).join(', ') || 'schema structure';
        triggeredRules.push({
          id: 'RUNTIME_SCHEMA_DRIFT',
          name: 'Runtime Schema Drift Detected',
          category: 'Schema Manipulation',
          weight: policy.block_on_schema_mismatch ? 92 : 62,
          severity: 'critical',
          detail: `Incoming schema SHA-256 (${incoming.sha256.slice(0, 12)}...) mismatches approved DNA (${dnaRecord.approvedHash.slice(0, 12)}...). Changed: ${diffParams}.`,
        });
      }
    }
  }

  // 2. Destructive Operation Check
  const destructiveNamePattern = /(delete_all|drop_table|truncate|wipe|purge|destroy|format_disk|rm_rf|nuke|reset_prod)/;
  const destructiveArgPattern = /(drop\s+table|truncate\s+table|rm\s+-rf|--no-preserve-root|delete\s+from\s+\w+\s*;)/;
  if (destructiveNamePattern.test(lowerTool) || destructiveArgPattern.test(serializedArgs)) {
    const hasConfirm = args.confirmation === true;
    triggeredRules.push({
      id: 'DESTRUCTIVE_COMMAND',
      name: 'Destructive Operation Guard',
      category: 'Destructive Operation',
      weight: hasConfirm ? 95 : 88,
      severity: 'critical',
      detail: `Tool "${toolName}" attempts an irreversible mass-deletion or destructive command${hasConfirm ? ' with confirmation=true' : ''}.`,
    });
  }

  // 3. Bulk Data Exfiltration Check
  const exfilNamePattern = /(export_.*database|dump_|exfiltrate|backup_all|scrape_all)/;
  const scopeVal = String(args.scope ?? '').toLowerCase();
  const limitVal = Number(args.limit ?? 0);
  const webhookVal = String(args.webhook ?? args.callback_url ?? args.destination ?? '');

  if (
    exfilNamePattern.test(lowerTool) ||
    /(all_customers|all_users|entire_db|full_dump|\*)/.test(scopeVal) ||
    (!Number.isNaN(limitVal) && limitVal > policy.bulk_threshold) ||
    /^https?:\/\//.test(webhookVal)
  ) {
    const isUnbounded = /(all_customers|all_users|entire_db|full_dump|\*)/.test(scopeVal) || exfilNamePattern.test(lowerTool);
    triggeredRules.push({
      id: 'DATA_EXFILTRATION',
      name: 'Bulk Data Exfiltration Detection',
      category: 'Data Exfiltration',
      weight: isUnbounded ? 92 : 64,
      severity: isUnbounded ? 'critical' : 'high',
      detail: `Bulk extraction pattern detected (scope="${scopeVal || 'unspecified'}", threshold=${policy.bulk_threshold}).`,
    });
  }

  // 4. Sensitive File Access Check
  const filePath = String(args.path ?? args.file ?? args.filepath ?? args.target ?? '');
  const sensitiveFilePattern =
    /(\/etc\/shadow|\/etc\/passwd|\/etc\/sudoers|\.env|\.ssh\/|id_rsa|id_ed25519|\/proc\/self|aws\/credentials|secret|\.pem$|\.key$|\.\.\/)/i;
  if (filePath && sensitiveFilePattern.test(filePath)) {
    const weight = policy.sensitive_file_action === 'BLOCK' ? 86 : 58;
    triggeredRules.push({
      id: 'SENSITIVE_FILE_ACCESS',
      name: 'Sensitive System File Access',
      category: 'Sensitive File Access',
      weight,
      severity: policy.sensitive_file_action === 'BLOCK' ? 'critical' : 'medium',
      detail: `Requested path "${filePath}" targets a restricted system credential, secret, or traversal target.`,
    });
  }

  // 5. Command / SQL Injection Pattern Check
  const injectionPattern = /(;\s*rm\s|&&\s*curl|\|\s*bash|\$\(|`.*`|union\s+select|or\s+1\s*=\s*1)/i;
  if (injectionPattern.test(serializedArgs)) {
    triggeredRules.push({
      id: 'INJECTION_PATTERN',
      name: 'Command or SQL Injection Payload',
      category: 'Injection Attack',
      weight: 90,
      severity: 'critical',
      detail: 'Arguments contain shell chaining metacharacters or SQL injection syntax.',
    });
  }

  // 6. Behavioural Drift Detection (integrated into unified risk scoring)
  const behaviourDrift = analyzeBehaviourDrift(toolName, args, policy, options);
  const nonBehaviourRules = [...triggeredRules];

  if (behaviourDrift.isAnomalous && behaviourDrift.triggeredRules.length > 0) {
    // Only add individual drift rules when tool has an established baseline (avoid duplicate weight on unregistered unknown tool)
    if (behaviourDrift.hasBaseline) {
      for (const driftRule of behaviourDrift.triggeredRules) {
        triggeredRules.push(driftRule);
      }
    }
  }

  // 7. Compute Deterministic Risk Score
  let riskScore = 0;
  if (triggeredRules.length === 0) {
    // Verified safe baseline score (4 - 16)
    const argComplexity = Math.min(8, Object.keys(args).length * 3);
    riskScore = 6 + argComplexity;
    triggeredRules.push({
      id: 'SAFE_READONLY_BASELINE',
      name: 'Verified Tool DNA & Clean Arguments',
      category: 'Baseline Trust',
      weight: riskScore,
      severity: 'low',
      detail: `Tool "${toolName}" matched approved Tool DNA SHA-256 fingerprint, aligned with behavioural baseline (deviation ${behaviourDrift.deviationScore}/100), and passed all argument safety rules.`,
    });
  } else {
    // Combine max triggered weight + secondary rule contributions (capped at 100)
    const sorted = [...triggeredRules].sort((a, b) => b.weight - a.weight);
    const maxW = sorted[0].weight;
    const secondary = sorted.slice(1).reduce((acc, r) => acc + Math.round(r.weight * 0.2), 0);
    riskScore = Math.min(100, maxW + secondary);

    // Ensure behavioural drift threshold policies are honoured in unified risk score
    if (behaviourDrift.hasBaseline && behaviourDrift.isAnomalous) {
      if (behaviourDrift.deviationLevel === 'high') {
        if (policy.drift_high_action === 'BLOCK') {
          riskScore = Math.max(riskScore, Math.max(policy.review_max_risk + 10, behaviourDrift.deviationScore));
        } else if (nonBehaviourRules.length === 0) {
          riskScore = Math.min(policy.review_max_risk, Math.max(policy.allow_max_risk + 15, behaviourDrift.deviationScore));
        }
      } else if (behaviourDrift.deviationLevel === 'medium' && nonBehaviourRules.length === 0) {
        riskScore = Math.max(riskScore, policy.allow_max_risk + 10);
      }
    }
  }

  // 8. Determine Decision from Policy Thresholds
  let decision: SecurityDecision = 'ALLOW';
  if (riskScore > policy.review_max_risk) {
    decision = 'BLOCK';
  } else if (riskScore > policy.allow_max_risk) {
    decision = 'REVIEW';
  } else {
    decision = 'ALLOW';
  }

  // Explicit policy override for sensitive files if configured as REVIEW and no other static critical rule fired
  const onlySensitiveFile =
    nonBehaviourRules.length === 1 && nonBehaviourRules[0].id === 'SENSITIVE_FILE_ACCESS';
  if (onlySensitiveFile && policy.sensitive_file_action === 'REVIEW') {
    decision = 'REVIEW';
    riskScore = Math.min(policy.review_max_risk, Math.max(policy.allow_max_risk + 1, riskScore));
  }

  // If high drift action is explicitly configured as REVIEW and no non-behaviour rule demands BLOCK
  const maxNonBehaviourWeight = nonBehaviourRules.reduce((m, r) => Math.max(m, r.weight), 0);
  if (
    behaviourDrift.hasBaseline &&
    behaviourDrift.deviationLevel === 'high' &&
    policy.drift_high_action === 'REVIEW' &&
    maxNonBehaviourWeight <= policy.review_max_risk &&
    !onlySensitiveFile
  ) {
    decision = 'REVIEW';
    riskScore = Math.min(policy.review_max_risk, Math.max(policy.allow_max_risk + 15, riskScore));
  }

  const primaryRule =
    nonBehaviourRules.length > 0
      ? [...nonBehaviourRules].sort((a, b) => b.weight - a.weight)[0]
      : [...triggeredRules].sort((a, b) => b.weight - a.weight)[0];
  const primaryCategory = primaryRule?.category ?? 'Baseline Trust';

  const explanation =
    decision === 'ALLOW'
      ? `Allowed (${riskScore}/100): ${primaryRule.detail}`
      : decision === 'REVIEW'
      ? `Flagged for human review (${riskScore}/100): ${triggeredRules.map((r) => r.detail).join(' ')}`
      : `Blocked (${riskScore}/100): ${triggeredRules.map((r) => r.detail).join(' ')}`;

  return {
    riskScore,
    decision,
    triggeredRules,
    primaryCategory,
    explanation,
    behaviourDrift,
  };
}

/**
 * Full runtime inspection pipeline: evaluates rules, persists execution, incidents, approvals, and broadcasts WS events.
 */
export function inspectAndProcessToolCall(input: InspectionInput): InspectionOutput {
  const start = Date.now();
  const source: EventSource = input.source ?? 'api_direct';
  const agentId = input.agentId ?? 'agent-default';
  const sessionId = input.sessionId ?? uid('sess');
  const policy = getActivePolicy();

  const evalResult = evaluateDeterministicRules(
    input.toolName,
    input.arguments ?? {},
    policy,
    input.incomingSchema,
    { overrideRpm: input.overrideRpm }
  );

  const executionId = uid('exec');
  const executionUid = `EXE-${Math.floor(1000 + Math.random() * 9000)}`;

  let executionStatus: ExecutionStatus = 'executed';
  let mockExecutionOutput: string | null = null;

  if (evalResult.decision === 'ALLOW') {
    executionStatus = 'executed';
    mockExecutionOutput = runSafeMockSandbox(input.toolName, input.arguments ?? {});
  } else if (evalResult.decision === 'REVIEW') {
    executionStatus = 'pending_approval';
  } else {
    executionStatus = 'blocked';
  }

  const durationMs = Math.max(2, Date.now() - start);

  db.prepare(`
    INSERT INTO tool_executions (
      id, execution_uid, tool_name, arguments_json, source, agent_id, session_id,
      risk_score, decision, reason, triggered_rules_json, execution_status, duration_ms
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    executionId,
    executionUid,
    input.toolName,
    JSON.stringify(input.arguments ?? {}),
    source,
    agentId,
    sessionId,
    evalResult.riskScore,
    evalResult.decision,
    evalResult.explanation,
    JSON.stringify(evalResult.triggeredRules),
    executionStatus,
    durationMs
  );

  const createdExecution = db.prepare('SELECT * FROM tool_executions WHERE id = ?').get(executionId);
  broadcaster.broadcast('execution:created', createdExecution);

  // Persist Behavioural Drift Event & update baseline learning (only learns on ALLOW)
  const behaviourEvent = recordBehaviourEventAndLearn(
    executionId,
    source,
    input.arguments ?? {},
    evalResult.decision,
    evalResult.behaviourDrift
  );
  broadcaster.broadcast('behaviour:drift', behaviourEvent);

  let incidentId: string | null = null;
  let incidentUid: string | null = null;
  let approvalRequestId: string | null = null;
  let approvalRequestUid: string | null = null;

  if (evalResult.decision === 'REVIEW' || evalResult.decision === 'BLOCK') {
    incidentId = uid('inc');
    incidentUid = `INC-${Math.floor(1000 + Math.random() * 9000)}`;
    const severity = severityFromScore(evalResult.riskScore);

    db.prepare(`
      INSERT INTO security_incidents (
        id, incident_uid, execution_id, tool_name, risk_score, threat_category,
        arguments_json, decision, explanation, severity, status, source
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
    `).run(
      incidentId,
      incidentUid,
      executionId,
      input.toolName,
      evalResult.riskScore,
      evalResult.primaryCategory,
      JSON.stringify(input.arguments ?? {}),
      evalResult.decision,
      evalResult.explanation,
      severity,
      source
    );

    const createdIncident = db.prepare('SELECT * FROM security_incidents WHERE id = ?').get(incidentId);
    broadcaster.broadcast('incident:created', createdIncident);
  }

  if (evalResult.decision === 'REVIEW') {
    approvalRequestId = uid('apr');
    approvalRequestUid = `APR-${Math.floor(1000 + Math.random() * 9000)}`;

    db.prepare(`
      INSERT INTO approval_requests (
        id, request_uid, execution_id, incident_id, tool_name, arguments_json,
        risk_score, reason, triggered_rules_json, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
    `).run(
      approvalRequestId,
      approvalRequestUid,
      executionId,
      incidentId,
      input.toolName,
      JSON.stringify(input.arguments ?? {}),
      evalResult.riskScore,
      evalResult.explanation,
      JSON.stringify(evalResult.triggeredRules)
    );

    const createdApproval = db.prepare('SELECT * FROM approval_requests WHERE id = ?').get(approvalRequestId);
    broadcaster.broadcast('approval:created', createdApproval);
  }

  writeAuditLog(agentId, 'agent', `TOOL_INSPECT_${evalResult.decision}`, 'tool_execution', executionId, {
    toolName: input.toolName,
    riskScore: evalResult.riskScore,
    deviationScore: evalResult.behaviourDrift.deviationScore,
    source,
  });

  return {
    executionId,
    executionUid,
    toolName: input.toolName,
    riskScore: evalResult.riskScore,
    decision: evalResult.decision,
    executionStatus,
    reason: evalResult.explanation,
    triggeredRules: evalResult.triggeredRules,
    behaviourDrift: evalResult.behaviourDrift,
    incidentId,
    incidentUid,
    approvalRequestId,
    approvalRequestUid,
    mockExecutionOutput,
  };
}

/**
 * Revalidates an approval request before execution when an administrator approves it.
 * Reviewer identity is strictly derived from the authenticated session user.
 */
export function processApprovalDecision(
  approvalId: string,
  action: 'approved' | 'rejected',
  reviewer: UserRecord,
  reviewerNote: string
) {
  const approval = db.prepare('SELECT * FROM approval_requests WHERE id = ?').get(approvalId) as
    | {
        id: string;
        request_uid: string;
        execution_id: string;
        incident_id: string | null;
        tool_name: string;
        arguments_json: string;
        risk_score: number;
        status: string;
      }
    | undefined;

  if (!approval) {
    throw new Error('Approval request not found');
  }
  if (approval.status !== 'pending') {
    throw new Error(`Approval request already finalized as ${approval.status}`);
  }
  if (!reviewer || reviewer.role !== 'admin') {
    throw new Error('Administrator privileges required to approve or reject requests.');
  }

  const execRow = db
    .prepare('SELECT source FROM tool_executions WHERE id = ?')
    .get(approval.execution_id) as { source: EventSource } | undefined;
  const execSource: EventSource = execRow?.source ?? 'api_direct';

  if (action === 'rejected') {
    db.prepare(`
      UPDATE approval_requests
      SET status = 'rejected', reviewed_by = ?, reviewer_note = ?, revalidated = 1, reviewed_at = datetime('now')
      WHERE id = ?
    `).run(reviewer.id, reviewerNote || 'Rejected by security administrator.', approvalId);

    db.prepare(`UPDATE tool_executions SET execution_status = 'rejected' WHERE id = ?`).run(approval.execution_id);

    if (approval.incident_id) {
      db.prepare(`UPDATE security_incidents SET status = 'resolved', resolved_at = datetime('now') WHERE id = ?`).run(
        approval.incident_id
      );
      const updatedInc = db.prepare('SELECT * FROM security_incidents WHERE id = ?').get(approval.incident_id);
      if (updatedInc) broadcaster.broadcast('incident:updated', updatedInc);
    }

    writeAuditLog(reviewer.id, reviewer.role, 'APPROVAL_REJECTED', 'approval_request', approvalId, {
      toolName: approval.tool_name,
      note: reviewerNote,
    });

    const updated = db.prepare('SELECT * FROM approval_requests WHERE id = ?').get(approvalId);
    broadcaster.broadcast('approval:updated', updated);
    return {
      status: 'rejected',
      revalidated: true,
      blockedOnRevalidation: false,
      mockOutput: null,
      message: 'Request rejected and execution prevented.',
    };
  }

  // Mandatory Revalidation before execution!
  const policy = getActivePolicy();
  const parsedArgs = JSON.parse(approval.arguments_json) as Record<string, unknown>;
  const reval = evaluateDeterministicRules(approval.tool_name, parsedArgs, policy);
  const dnaRecord = getToolWithFingerprints(approval.tool_name);

  const tampered = dnaRecord && (dnaRecord.tool.trust_status === 'modified' || dnaRecord.tool.trust_status === 'untrusted');

  if (reval.decision === 'BLOCK' || tampered) {
    // Revalidation failed: tool became untrusted or policy tightened to BLOCK
    db.prepare(`
      UPDATE approval_requests
      SET status = 'rejected', reviewed_by = ?, reviewer_note = ?, revalidated = 1, reviewed_at = datetime('now')
      WHERE id = ?
    `).run(
      reviewer.id,
      `Revalidation failed before execution: ${reval.explanation}`,
      approvalId
    );

    db.prepare(`UPDATE tool_executions SET execution_status = 'blocked', decision = 'BLOCK', reason = ? WHERE id = ?`).run(
      `Blocked on revalidation: ${reval.explanation}`,
      approval.execution_id
    );

    const { event: blockedBehavEvent } = recordApprovedBehaviourExecution({
      executionId: approval.execution_id,
      approvalId,
      source: execSource,
      args: parsedArgs,
      finalDecision: 'BLOCK',
      analysis: reval.behaviourDrift,
      reviewerId: reviewer.id,
      reviewerRole: reviewer.role,
    });
    broadcaster.broadcast('behaviour:drift', blockedBehavEvent);

    writeAuditLog(reviewer.id, reviewer.role, 'APPROVAL_REVALIDATION_BLOCKED', 'approval_request', approvalId, {
      toolName: approval.tool_name,
      revalDecision: reval.decision,
      tampered: Boolean(tampered),
    });

    const updated = db.prepare('SELECT * FROM approval_requests WHERE id = ?').get(approvalId);
    broadcaster.broadcast('approval:updated', updated);
    return {
      status: 'rejected',
      revalidated: true,
      blockedOnRevalidation: true,
      mockOutput: null,
      message: `Revalidation denied execution: ${reval.explanation}`,
    };
  }

  // Revalidation passed -> execute safely in sandbox
  const mockOutput = runSafeMockSandbox(approval.tool_name, parsedArgs);

  db.prepare(`
    UPDATE approval_requests
    SET status = 'approved', reviewed_by = ?, reviewer_note = ?, revalidated = 1, reviewed_at = datetime('now')
    WHERE id = ?
  `).run(reviewer.id, reviewerNote || 'Approved and revalidated by security administrator.', approvalId);

  db.prepare(`UPDATE tool_executions SET execution_status = 'approved_executed' WHERE id = ?`).run(approval.execution_id);

  if (approval.incident_id) {
    db.prepare(`UPDATE security_incidents SET status = 'resolved', resolved_at = datetime('now') WHERE id = ?`).run(
      approval.incident_id
    );
    const updatedInc = db.prepare('SELECT * FROM security_incidents WHERE id = ?').get(approval.incident_id);
    if (updatedInc) broadcaster.broadcast('incident:updated', updatedInc);
  }

  const { event: approvedBehavEvent, learnedBaseline } = recordApprovedBehaviourExecution({
    executionId: approval.execution_id,
    approvalId,
    source: execSource,
    args: parsedArgs,
    finalDecision: reval.decision,
    analysis: reval.behaviourDrift,
    reviewerId: reviewer.id,
    reviewerRole: reviewer.role,
  });
  broadcaster.broadcast('behaviour:drift', approvedBehavEvent);

  writeAuditLog(reviewer.id, reviewer.role, 'APPROVAL_APPROVED_EXECUTED', 'approval_request', approvalId, {
    toolName: approval.tool_name,
    revalidatedRiskScore: reval.riskScore,
    revalidatedDecision: reval.decision,
    learnedBaseline,
  });

  const updated = db.prepare('SELECT * FROM approval_requests WHERE id = ?').get(approvalId);
  broadcaster.broadcast('approval:updated', updated);

  return {
    status: 'approved',
    revalidated: true,
    blockedOnRevalidation: false,
    learnedBaseline,
    mockOutput,
    message: 'Request revalidated against current Tool DNA & policy, then executed safely.',
  };
}
