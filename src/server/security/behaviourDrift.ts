import { db, uid, writeAuditLog } from '../db/database.ts';
import type {
  BehaviourBaselineSummary,
  BehaviourCurrentSummary,
  BehaviourDifference,
  BehaviourDriftAnalysis,
  BehaviourOverview,
  CanonicalToolSchema,
  EventSource,
  SecurityDecision,
  SecurityPolicy,
  ToolBehaviourEvent,
  ToolBehaviourProfile,
  TriggeredRule,
} from '../../types/toolseal.ts';

const SENSITIVE_RESOURCE_REGEX =
  /(customer_?db|customer_?database|customer_?records|customers|pii|credit_?card|ssn|social_security|password|shadow|passwd|sudoers|\.env|\.ssh|id_rsa|id_ed25519|credentials|secret|billing_records|payment_methods|admin_db|users_table|salary|payroll)/i;

const RESOURCE_ARG_KEYS = [
  'resource',
  'table',
  'database',
  'db',
  'dataset',
  'collection',
  'scope',
  'path',
  'file',
  'filepath',
  'target',
  'endpoint',
  'url',
  'bucket',
  'schema',
];

function safeJsonArray(raw: string | null | undefined, fallback: string[] = []): string[] {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(String) : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Ensures every registered tool has a persistent behavioural profile row in SQLite.
 */
export function ensureBehaviourProfileForTool(
  toolName: string,
  schema?: CanonicalToolSchema | null,
  category?: string
): ToolBehaviourProfile | null {
  const existing = db
    .prepare('SELECT * FROM tool_behaviour_profiles WHERE tool_name = ?')
    .get(toolName) as ToolBehaviourProfile | undefined;
  if (existing) return existing;

  const reg = db
    .prepare('SELECT id, name, category FROM registered_tools WHERE name = ?')
    .get(toolName) as { id: string; name: string; category: string } | undefined;

  // Only create persistent baseline profiles for registered tools (or when explicit schema provided)
  if (!reg && !schema) return null;

  let paramKeys: string[] = [];
  if (schema?.parameters?.properties) {
    paramKeys = Object.keys(schema.parameters.properties);
  } else if (reg) {
    const schemaRow = db
      .prepare('SELECT schema_json FROM tool_schemas WHERE tool_id = ? AND is_active = 1 LIMIT 1')
      .get(reg.id) as { schema_json: string } | undefined;
    if (schemaRow) {
      try {
        const parsed = JSON.parse(schemaRow.schema_json) as CanonicalToolSchema;
        paramKeys = Object.keys(parsed.parameters?.properties ?? {});
      } catch {
        paramKeys = [];
      }
    }
  }

  const effectiveCat = (category ?? reg?.category ?? 'utility').toLowerCase();
  const defaultOps = effectiveCat.includes('export')
    ? ['export']
    : effectiveCat.includes('destructive')
    ? ['delete']
    : ['read'];

  const defaultRes = [`${toolName}:standard`];
  const id = uid('bprof');

  db.prepare(`
    INSERT INTO tool_behaviour_profiles (
      id, tool_name, normal_param_keys_json, normal_resources_json, normal_operations_json,
      baseline_rpm, normal_max_records, total_baseline_executions, anomaly_count, last_deviation_score
    ) VALUES (?, ?, ?, ?, ?, 3.0, 25, 1, 0, 0)
  `).run(id, toolName, JSON.stringify(paramKeys), JSON.stringify(defaultRes), JSON.stringify(defaultOps));

  return db
    .prepare('SELECT * FROM tool_behaviour_profiles WHERE id = ?')
    .get(id) as ToolBehaviourProfile;
}

/**
 * Deterministic feature extraction from incoming tool call arguments.
 */
export function extractBehaviourFeatures(
  toolName: string,
  args: Record<string, unknown>,
  profile: ToolBehaviourProfile | null
): {
  observedParams: string[];
  observedResources: string[];
  observedOperation: string;
  requestedRecords: number;
  touchesSensitiveResource: boolean;
  sensitiveMatches: string[];
} {
  const observedParams = Object.keys(args).sort();
  const lowerTool = toolName.toLowerCase();
  const serialized = JSON.stringify(args);

  // 1. Extract accessed resources
  const resources = new Set<string>();
  for (const key of RESOURCE_ARG_KEYS) {
    const val = args[key];
    if (typeof val === 'string' && val.trim().length > 0) {
      const normalized = val.trim().toLowerCase();
      if (key === 'path' || key === 'file' || key === 'filepath') {
        if (normalized.startsWith('./docs') || normalized.startsWith('docs/')) {
          resources.add('workspace:docs');
        } else if (normalized.startsWith('./') && !normalized.includes('..')) {
          resources.add('workspace:project_files');
        } else {
          resources.add(`filesystem:${val.trim()}`);
        }
      } else if (key === 'scope') {
        if (normalized === 'all_customers' || normalized === 'all_users' || normalized === '*') {
          resources.add(`customer_database:${normalized}`);
        } else {
          resources.add(`crm_db:${normalized}`);
        }
      } else {
        resources.add(`${key}:${val.trim()}`);
      }
    }
  }

  // Fallback canonical resource mapping for baseline utility calls
  if (resources.size === 0) {
    if (toolName === 'get_weather') {
      resources.add('weather_api:forecast');
    } else if (toolName === 'search_knowledge_base') {
      resources.add('knowledge_base:internal_docs');
    } else if (profile) {
      const baseRes = safeJsonArray(profile.normal_resources_json);
      if (baseRes.length > 0) resources.add(baseRes[0]);
    } else {
      resources.add(`${toolName}:default`);
    }
  }

  // 2. Infer operation type
  let observedOperation = 'read';
  const explicitOp = typeof args.operation === 'string' ? args.operation.toLowerCase().trim() : '';
  const explicitAction = typeof args.action === 'string' ? args.action.toLowerCase().trim() : '';
  const opHint = explicitOp || explicitAction;

  if (opHint) {
    if (/(export|dump|extract|download|backup|exfil)/.test(opHint)) observedOperation = 'export';
    else if (/(delete|drop|purge|wipe|truncate|remove)/.test(opHint)) observedOperation = 'delete';
    else if (/(write|update|insert|modify|patch|create)/.test(opHint)) observedOperation = 'write';
    else if (/(query|select|sql|scan)/.test(opHint)) observedOperation = 'query_db';
    else observedOperation = opHint;
  } else if (/(delete_all|drop_|wipe|purge)/.test(lowerTool) || args.confirmation === true) {
    observedOperation = 'delete';
  } else if (/(export_|dump_)/.test(lowerTool) || typeof args.webhook === 'string' || typeof args.destination === 'string') {
    observedOperation = 'export';
  } else if (typeof args.sql === 'string' || (typeof args.table === 'string' && toolName !== 'delete_all_records')) {
    observedOperation = 'query_db';
  } else if (typeof args.write_content === 'string' || typeof args.payload === 'string') {
    observedOperation = 'write';
  }

  // 3. Estimate requested record volume
  let requestedRecords = 1;
  const numericCandidates = [args.limit, args.count, args.rows, args.top_k, args.batch_size, args.max_rows];
  for (const cand of numericCandidates) {
    if (typeof cand === 'number' && !Number.isNaN(cand) && cand > requestedRecords) {
      requestedRecords = cand;
    }
  }
  const scopeStr = String(args.scope ?? args.filter ?? '').toLowerCase();
  if (/(all_customers|all_users|entire_db|full_dump|\*)/.test(scopeStr)) {
    requestedRecords = Math.max(requestedRecords, 10000);
  }

  // 4. Sensitive resource scan across keys and values
  const sensitiveMatches: string[] = [];
  const matchSet = new Set<string>();
  const tokens = [
    ...observedParams,
    ...Array.from(resources),
    serialized,
  ];
  for (const token of tokens) {
    const m = token.match(SENSITIVE_RESOURCE_REGEX);
    if (m && m[0]) {
      matchSet.add(m[0].toLowerCase());
    }
  }
  sensitiveMatches.push(...Array.from(matchSet));

  return {
    observedParams,
    observedResources: Array.from(resources),
    observedOperation,
    requestedRecords,
    touchesSensitiveResource: sensitiveMatches.length > 0,
    sensitiveMatches,
  };
}

function getRecentCallsPerMinute(toolName: string): number {
  const row = db
    .prepare(
      `SELECT COUNT(*) as c FROM tool_executions WHERE tool_name = ? AND created_at >= datetime('now', '-60 seconds')`
    )
    .get(toolName) as { c: number };
  return (row?.c ?? 0) + 1; // include current in-flight call
}

/**
 * Deterministic Behavioural Drift Analysis: compares current call against learned baseline profile.
 */
export function analyzeBehaviourDrift(
  toolName: string,
  args: Record<string, unknown>,
  policy: SecurityPolicy,
  options?: { overrideRpm?: number }
): BehaviourDriftAnalysis {
  const profile = ensureBehaviourProfileForTool(toolName);
  const features = extractBehaviourFeatures(toolName, args, profile);
  const recentRpm = options?.overrideRpm ?? getRecentCallsPerMinute(toolName);

  const expectedParams = profile ? safeJsonArray(profile.normal_param_keys_json) : [];
  const expectedResources = profile ? safeJsonArray(profile.normal_resources_json) : [`${toolName}:unknown`];
  const expectedOperations = profile ? safeJsonArray(profile.normal_operations_json, ['read']) : ['read'];
  const baselineRpm = profile ? Number(profile.baseline_rpm) : 2.0;
  const normalMaxRecords = profile ? Number(profile.normal_max_records) : 25;
  const sampleCount = profile ? Number(profile.total_baseline_executions) : 0;

  const baselineBehaviour: BehaviourBaselineSummary = {
    expectedParams,
    expectedResources,
    expectedOperations,
    baselineRpm,
    normalMaxRecords,
    sampleCount,
  };

  const currentBehaviour: BehaviourCurrentSummary = {
    observedParams: features.observedParams,
    observedResources: features.observedResources,
    observedOperation: features.observedOperation,
    currentRpm: recentRpm,
    requestedRecords: features.requestedRecords,
  };

  const differences: BehaviourDifference[] = [];
  const triggeredRules: TriggeredRule[] = [];

  if (!profile) {
    // Unregistered tool has no learned baseline
    const weight = 35;
    differences.push({
      dimension: 'parameters',
      label: 'No Established Baseline',
      expected: 'Registered tool behaviour profile',
      observed: `${toolName} (${features.observedParams.join(', ') || 'no args'})`,
      weight,
      severity: 'medium',
      detail: `No behavioural baseline exists for unregistered tool "${toolName}".`,
    });
    triggeredRules.push({
      id: 'BEHAVIOUR_NO_BASELINE',
      name: 'Unprofiled Tool Behaviour',
      category: 'Behavioural Drift',
      weight,
      severity: 'medium',
      detail: `Tool "${toolName}" lacks a historical behavioural baseline profile.`,
    });
  } else {
    // 1. Unexpected parameters check
    const expectedParamSet = new Set(expectedParams);
    const unexpectedParams = features.observedParams.filter((p) => !expectedParamSet.has(p));
    if (unexpectedParams.length > 0) {
      const weight = Math.min(40, 22 + unexpectedParams.length * 6);
      const detail = `Unexpected parameter(s) [${unexpectedParams.join(', ')}] not seen in ${sampleCount} baseline execution(s) (normal: ${expectedParams.join(', ') || 'none'}).`;
      differences.push({
        dimension: 'parameters',
        label: 'Unexpected Parameters',
        expected: expectedParams.join(', ') || 'none',
        observed: features.observedParams.join(', '),
        weight,
        severity: unexpectedParams.length >= 2 ? 'high' : 'medium',
        detail,
      });
      triggeredRules.push({
        id: 'BEHAVIOUR_UNEXPECTED_PARAM',
        name: 'Unexpected Parameter Drift',
        category: 'Behavioural Drift',
        weight,
        severity: unexpectedParams.length >= 2 ? 'high' : 'medium',
        detail,
      });
    }

    // 2. Unusual resource access check
    const expectedResSet = new Set(expectedResources);
    const unusualResources = features.observedResources.filter((r) => !expectedResSet.has(r));
    if (unusualResources.length > 0) {
      const weight = 34;
      const detail = `Tool "${toolName}" accessed unusual resource [${unusualResources.join(', ')}] outside baseline [${expectedResources.join(', ')}].`;
      differences.push({
        dimension: 'resource',
        label: 'Unusual Resource Access',
        expected: expectedResources.join(', '),
        observed: unusualResources.join(', '),
        weight,
        severity: 'high',
        detail,
      });
      triggeredRules.push({
        id: 'BEHAVIOUR_UNUSUAL_RESOURCE',
        name: 'Unusual Resource Target',
        category: 'Behavioural Drift',
        weight,
        severity: 'high',
        detail,
      });
    }

    // 3. Unexpected operation type check
    if (!expectedOperations.includes(features.observedOperation)) {
      const isHighRiskOp = ['export', 'delete', 'query_db'].includes(features.observedOperation);
      const weight = isHighRiskOp ? 32 : 20;
      const detail = `Operation type "${features.observedOperation}" deviates from baseline operation(s) [${expectedOperations.join(', ')}].`;
      differences.push({
        dimension: 'operation',
        label: 'Unexpected Operation Type',
        expected: expectedOperations.join(', '),
        observed: features.observedOperation,
        weight,
        severity: isHighRiskOp ? 'high' : 'medium',
        detail,
      });
      triggeredRules.push({
        id: 'BEHAVIOUR_OPERATION_DRIFT',
        name: 'Operation Type Drift',
        category: 'Behavioural Drift',
        weight,
        severity: isHighRiskOp ? 'high' : 'medium',
        detail,
      });
    }

    // 4. Unusual execution frequency spike check
    const multiplier = Math.max(2, policy.drift_frequency_multiplier || 3);
    const freqLimit = Math.max(8, Math.ceil(baselineRpm * multiplier));
    if (recentRpm >= freqLimit) {
      const weight = recentRpm >= freqLimit * 2 ? 36 : 26;
      const detail = `Execution burst of ${recentRpm} req/min exceeds baseline ${baselineRpm} req/min × ${multiplier}x threshold (${freqLimit} req/min).`;
      differences.push({
        dimension: 'frequency',
        label: 'Execution Frequency Spike',
        expected: `<= ${freqLimit} req/min (baseline ${baselineRpm}/min)`,
        observed: `${recentRpm} req/min`,
        weight,
        severity: recentRpm >= freqLimit * 2 ? 'high' : 'medium',
        detail,
      });
      triggeredRules.push({
        id: 'BEHAVIOUR_FREQUENCY_SPIKE',
        name: 'Execution Frequency Anomaly',
        category: 'Behavioural Drift',
        weight,
        severity: recentRpm >= freqLimit * 2 ? 'high' : 'medium',
        detail,
      });
    }

    // 5. Unusual bulk data request check
    const bulkCeiling = Math.max(normalMaxRecords * 5, 50);
    if (features.requestedRecords > bulkCeiling || features.requestedRecords > policy.bulk_threshold) {
      const weight = features.requestedRecords >= 1000 ? 34 : 24;
      const detail = `Requested volume (${features.requestedRecords} records) sharply exceeds baseline ceiling of ${normalMaxRecords} record(s).`;
      differences.push({
        dimension: 'bulk_volume',
        label: 'Unusual Bulk Data Request',
        expected: `<= ${normalMaxRecords} records`,
        observed: `${features.requestedRecords} records`,
        weight,
        severity: features.requestedRecords >= 1000 ? 'critical' : 'high',
        detail,
      });
      triggeredRules.push({
        id: 'BEHAVIOUR_BULK_DRIFT',
        name: 'Behavioural Bulk Data Anomaly',
        category: 'Behavioural Drift',
        weight,
        severity: features.requestedRecords >= 1000 ? 'critical' : 'high',
        detail,
      });
    }
  }

  // 6. Sensitive resource access outside expected safe utility baseline
  const baselineAlreadySensitive = expectedResources.some((r) => SENSITIVE_RESOURCE_REGEX.test(r));
  if (features.touchesSensitiveResource && (!baselineAlreadySensitive || differences.length > 0)) {
    const weight = 38;
    const matched = features.sensitiveMatches.join(', ');
    const detail = `Call targets sensitive resource identifier (${matched}) inconsistent with normal tool usage.`;
    differences.push({
      dimension: 'sensitive_resource',
      label: 'Sensitive Resource Access',
      expected: expectedResources.join(', ') || 'Non-sensitive scope',
      observed: matched,
      weight,
      severity: 'critical',
      detail,
    });
    triggeredRules.push({
      id: 'BEHAVIOUR_SENSITIVE_RESOURCE',
      name: 'Sensitive Resource Behavioural Drift',
      category: 'Behavioural Drift',
      weight,
      severity: 'critical',
      detail,
    });
  }

  // Deterministic Deviation Score calculation (0 - 100)
  let deviationScore = 0;
  if (differences.length === 0) {
    // Small deterministic baseline score (3 - 10) proportional to parameter count
    deviationScore = Math.min(12, 3 + features.observedParams.length * 2);
  } else {
    const sorted = [...differences].sort((a, b) => b.weight - a.weight);
    const primary = sorted[0].weight;
    const secondary = sorted.slice(1).reduce((acc, d) => acc + Math.round(d.weight * 0.55), 0);
    deviationScore = Math.min(100, primary + secondary);
  }

  let deviationLevel: 'low' | 'medium' | 'high' = 'low';
  let driftResponse: SecurityDecision = 'ALLOW';

  if (deviationScore > policy.drift_medium_max) {
    deviationLevel = 'high';
    driftResponse = policy.drift_high_action === 'REVIEW' ? 'REVIEW' : 'BLOCK';
  } else if (deviationScore > policy.drift_low_max) {
    deviationLevel = 'medium';
    driftResponse = 'REVIEW';
  }

  return {
    toolName,
    hasBaseline: Boolean(profile),
    deviationScore,
    deviationLevel,
    driftResponse,
    isAnomalous: deviationScore > policy.drift_low_max,
    baselineBehaviour,
    currentBehaviour,
    differences,
    triggeredRules,
  };
}

/**
 * Persists a behavioural event in SQLite and updates the tool's learned profile.
 * Baseline patterns ONLY learn from verified ALLOW calls on trusted registered tools so attacks never poison baselines.
 */
export function recordBehaviourEventAndLearn(
  executionId: string,
  source: EventSource,
  args: Record<string, unknown>,
  finalDecision: SecurityDecision,
  analysis: BehaviourDriftAnalysis
): ToolBehaviourEvent {
  const id = uid('bev');
  const eventUid = `DRF-${Math.floor(1000 + Math.random() * 9000)}`;

  db.prepare(`
    INSERT INTO tool_behaviour_events (
      id, event_uid, execution_id, tool_name, source, deviation_score, deviation_level,
      is_anomalous, decision, baseline_snapshot_json, current_snapshot_json,
      differences_json, triggered_rules_json, arguments_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    eventUid,
    executionId,
    analysis.toolName,
    source,
    analysis.deviationScore,
    analysis.deviationLevel,
    analysis.isAnomalous ? 1 : 0,
    finalDecision,
    JSON.stringify(analysis.baselineBehaviour),
    JSON.stringify(analysis.currentBehaviour),
    JSON.stringify(analysis.differences),
    JSON.stringify(analysis.triggeredRules),
    JSON.stringify(args)
  );

  // Update profile metrics in SQLite
  const profile = db
    .prepare('SELECT * FROM tool_behaviour_profiles WHERE tool_name = ?')
    .get(analysis.toolName) as ToolBehaviourProfile | undefined;

  const regTool = db
    .prepare('SELECT trust_status FROM registered_tools WHERE name = ?')
    .get(analysis.toolName) as { trust_status: string } | undefined;
  const isTrustedTool = regTool?.trust_status === 'trusted';

  if (profile) {
    if (finalDecision === 'ALLOW' && !analysis.isAnomalous && isTrustedTool) {
      // Safe learning: increment verified baseline executions & gently smooth RPM
      const nextCount = profile.total_baseline_executions + 1;
      const mergedParams = Array.from(
        new Set([...safeJsonArray(profile.normal_param_keys_json), ...analysis.currentBehaviour.observedParams])
      ).sort();
      const smoothedRpm = Number(
        Math.max(1.0, profile.baseline_rpm * 0.9 + analysis.currentBehaviour.currentRpm * 0.1).toFixed(2)
      );

      db.prepare(`
        UPDATE tool_behaviour_profiles
        SET normal_param_keys_json = ?,
            baseline_rpm = ?,
            total_baseline_executions = ?,
            last_deviation_score = ?,
            last_analyzed_at = datetime('now'),
            updated_at = datetime('now')
        WHERE id = ?
      `).run(JSON.stringify(mergedParams), smoothedRpm, nextCount, analysis.deviationScore, profile.id);
    } else if (analysis.isAnomalous) {
      db.prepare(`
        UPDATE tool_behaviour_profiles
        SET anomaly_count = anomaly_count + 1,
            last_deviation_score = ?,
            last_analyzed_at = datetime('now'),
            updated_at = datetime('now')
        WHERE id = ?
      `).run(analysis.deviationScore, profile.id);
    }
  }

  return db.prepare('SELECT * FROM tool_behaviour_events WHERE id = ?').get(id) as ToolBehaviourEvent;
}

/**
 * Records an administrator-approved execution into behavioural telemetry and enforces
 * the safe-learning policy with explicit audit logging.
 */
export function recordApprovedBehaviourExecution(params: {
  executionId: string;
  approvalId: string;
  source: EventSource;
  args: Record<string, unknown>;
  finalDecision: SecurityDecision;
  analysis: BehaviourDriftAnalysis;
  reviewerId: string;
  reviewerRole: string;
}): { event: ToolBehaviourEvent; learnedBaseline: boolean } {
  const regTool = db
    .prepare('SELECT trust_status FROM registered_tools WHERE name = ?')
    .get(params.analysis.toolName) as { trust_status: string } | undefined;
  const isTrustedTool = regTool?.trust_status === 'trusted';

  const event = recordBehaviourEventAndLearn(
    params.executionId,
    params.source,
    params.args,
    params.finalDecision,
    params.analysis
  );

  const profile = db
    .prepare('SELECT id FROM tool_behaviour_profiles WHERE tool_name = ?')
    .get(params.analysis.toolName) as { id: string } | undefined;

  const learnedBaseline =
    Boolean(profile) &&
    params.finalDecision === 'ALLOW' &&
    !params.analysis.isAnomalous &&
    isTrustedTool;

  writeAuditLog(
    params.reviewerId,
    params.reviewerRole,
    learnedBaseline ? 'BEHAVIOUR_BASELINE_LEARNED' : 'BEHAVIOUR_BASELINE_SKIPPED_SAFE_POLICY',
    'tool_behaviour_profile',
    profile?.id ?? params.analysis.toolName,
    {
      toolName: params.analysis.toolName,
      approvalId: params.approvalId,
      executionId: params.executionId,
      revalidatedDecision: params.finalDecision,
      deviationScore: params.analysis.deviationScore,
      isAnomalous: params.analysis.isAnomalous,
      toolTrustStatus: regTool?.trust_status ?? 'unregistered',
      learnedBaseline,
    }
  );

  return { event, learnedBaseline };
}

/**
 * Synchronizes an admin-approved Tool DNA schema fingerprint's parameter keys into
 * tool_behaviour_profiles. Unapproved/malicious schema changes never call this function.
 */
export function syncBehaviourBaselineFromSchema(params: {
  toolName: string;
  approvedSchema: CanonicalToolSchema;
  category?: string;
  sha256: string;
  actorId: string;
  actorRole: string;
}): ToolBehaviourProfile | null {
  const profile = ensureBehaviourProfileForTool(params.toolName, params.approvedSchema, params.category);
  if (!profile) return null;

  const previousKeys = safeJsonArray(profile.normal_param_keys_json).sort();
  const approvedKeys = Object.keys(params.approvedSchema.parameters?.properties ?? {}).sort();

  db.prepare(`
    UPDATE tool_behaviour_profiles
    SET normal_param_keys_json = ?,
        updated_at = datetime('now')
    WHERE id = ?
  `).run(JSON.stringify(approvedKeys), profile.id);

  writeAuditLog(
    params.actorId,
    params.actorRole,
    'BEHAVIOUR_BASELINE_SYNCED_FROM_TOOL_DNA',
    'tool_behaviour_profile',
    profile.id,
    {
      toolName: params.toolName,
      sha256: params.sha256,
      previousParamKeys: previousKeys,
      syncedParamKeys: approvedKeys,
    }
  );

  return db
    .prepare('SELECT * FROM tool_behaviour_profiles WHERE id = ?')
    .get(profile.id) as ToolBehaviourProfile;
}

/**
 * Queries SQLite to build the Behavioural Intelligence overview payload.
 */
export function getBehaviourIntelligenceOverview(policy: SecurityPolicy, toolFilter?: string): BehaviourOverview {
  const profiles = db
    .prepare('SELECT * FROM tool_behaviour_profiles ORDER BY anomaly_count DESC, total_baseline_executions DESC')
    .all() as ToolBehaviourProfile[];

  let eventsQuery = 'SELECT * FROM tool_behaviour_events WHERE 1=1';
  const params: unknown[] = [];
  if (toolFilter) {
    eventsQuery += ' AND tool_name = ?';
    params.push(toolFilter);
  }
  eventsQuery += ' ORDER BY created_at DESC LIMIT 60';
  const recentEvents = db.prepare(eventsQuery).all(...params) as ToolBehaviourEvent[];

  const stats = db.prepare(`
    SELECT
      COUNT(*) as totalEventsAnalyzed,
      SUM(CASE WHEN is_anomalous = 1 THEN 1 ELSE 0 END) as anomaliesDetected,
      SUM(CASE WHEN is_anomalous = 0 THEN 1 ELSE 0 END) as normalEventsCount,
      COALESCE(ROUND(AVG(deviation_score), 1), 0) as avgDeviationScore,
      SUM(CASE WHEN deviation_level = 'high' THEN 1 ELSE 0 END) as highDriftAlerts
    FROM tool_behaviour_events
  `).get() as {
    totalEventsAnalyzed: number;
    anomaliesDetected: number;
    normalEventsCount: number;
    avgDeviationScore: number;
    highDriftAlerts: number;
  };

  const timeline = db.prepare(`
    SELECT
      strftime('%H:%M', created_at) as bucket,
      ROUND(AVG(deviation_score), 1) as avgDeviation,
      MAX(deviation_score) as maxDeviation,
      SUM(CASE WHEN is_anomalous = 0 THEN 1 ELSE 0 END) as normalCalls,
      SUM(CASE WHEN is_anomalous = 1 THEN 1 ELSE 0 END) as anomalousCalls
    FROM tool_behaviour_events
    GROUP BY strftime('%Y-%m-%d %H:%M', created_at)
    ORDER BY MIN(created_at) ASC
    LIMIT 18
  `).all() as BehaviourOverview['timeline'];

  const toolComparison = db.prepare(`
    SELECT
      tool_name as toolName,
      SUM(CASE WHEN is_anomalous = 0 THEN 1 ELSE 0 END) as normalCount,
      SUM(CASE WHEN is_anomalous = 1 THEN 1 ELSE 0 END) as unusualCount,
      ROUND(AVG(deviation_score), 1) as avgDeviation,
      MAX(deviation_score) as maxDeviation
    FROM tool_behaviour_events
    GROUP BY tool_name
    ORDER BY unusualCount DESC, normalCount DESC
    LIMIT 10
  `).all() as BehaviourOverview['toolComparison'];

  return {
    summary: {
      monitoredTools: profiles.length,
      establishedBaselines: profiles.filter((p) => p.total_baseline_executions >= 1).length,
      totalEventsAnalyzed: stats.totalEventsAnalyzed || 0,
      anomaliesDetected: stats.anomaliesDetected || 0,
      normalEventsCount: stats.normalEventsCount || 0,
      avgDeviationScore: stats.avgDeviationScore || 0,
      highDriftAlerts: stats.highDriftAlerts || 0,
    },
    profiles,
    recentEvents,
    timeline,
    toolComparison,
    thresholds: {
      drift_low_max: policy.drift_low_max,
      drift_medium_max: policy.drift_medium_max,
      drift_high_action: policy.drift_high_action,
      drift_frequency_multiplier: policy.drift_frequency_multiplier,
    },
  };
}
