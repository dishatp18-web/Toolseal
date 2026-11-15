export type SecurityDecision = 'ALLOW' | 'REVIEW' | 'BLOCK';
export type TrustStatus = 'trusted' | 'modified' | 'untrusted' | 'pending';
export type EventSource = 'bifrost' | 'demo_simulator' | 'api_direct';
export type ExecutionStatus =
  | 'executed'
  | 'blocked'
  | 'pending_approval'
  | 'approved_executed'
  | 'rejected';

export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'dismissed';
export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

export interface UserRecord {
  id: string;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
  display_name: string;
  is_active?: number;
  created_at: string;
}

export interface AuthSessionResponse {
  authenticated: boolean;
  user: UserRecord | null;
  sessionToken?: string;
  expiresAt?: string;
}

export interface TriggeredRule {
  id: string;
  name: string;
  category: string;
  weight: number;
  severity: IncidentSeverity;
  detail: string;
}

export interface ToolSchemaProperty {
  type?: string;
  description?: string;
  enum?: string[];
  default?: unknown;
  [key: string]: unknown;
}

export interface CanonicalToolSchema {
  name: string;
  description?: string;
  parameters: {
    type: 'object';
    properties: Record<string, ToolSchemaProperty>;
    required?: string[];
    additionalProperties?: boolean;
  };
}

export interface SchemaParameterDiff {
  parameter: string;
  changeType: 'added' | 'removed' | 'modified';
  before?: ToolSchemaProperty | null;
  after?: ToolSchemaProperty | null;
  riskNote: string;
}

export interface RegisteredTool {
  id: string;
  name: string;
  description: string;
  server_name: string;
  category: string;
  trust_status: TrustStatus;
  current_version: number;
  approved_fingerprint: string | null;
  latest_fingerprint: string | null;
  latest_schema_json: string | null;
  approved_schema_json: string | null;
  fingerprint_status: string | null;
  created_at: string;
  updated_at: string;
}

export interface ToolSchemaVersion {
  id: string;
  tool_id: string;
  version: number;
  schema_json: string;
  canonical_json: string;
  sha256_hash: string;
  fingerprint_status: string;
  is_active: number;
  created_at: string;
}

export interface ToolExecution {
  id: string;
  execution_uid: string;
  tool_name: string;
  arguments_json: string;
  source: EventSource;
  agent_id: string;
  session_id: string;
  risk_score: number;
  decision: SecurityDecision;
  reason: string;
  triggered_rules_json: string;
  execution_status: ExecutionStatus;
  duration_ms: number;
  created_at: string;
}

export interface SecurityIncident {
  id: string;
  incident_uid: string;
  execution_id: string | null;
  tool_name: string;
  risk_score: number;
  threat_category: string;
  arguments_json: string;
  decision: SecurityDecision;
  explanation: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  source: EventSource;
  created_at: string;
  resolved_at: string | null;
}

export interface ApprovalRequest {
  id: string;
  request_uid: string;
  execution_id: string;
  incident_id: string | null;
  tool_name: string;
  arguments_json: string;
  risk_score: number;
  reason: string;
  triggered_rules_json: string;
  status: ApprovalStatus;
  reviewed_by: string | null;
  reviewer_name?: string | null;
  reviewer_note: string | null;
  revalidated: number;
  created_at: string;
  reviewed_at: string | null;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  allow_max_risk: number;
  review_max_risk: number;
  sensitive_file_action: 'BLOCK' | 'REVIEW';
  unknown_tool_action: 'REVIEW' | 'BLOCK';
  block_on_schema_mismatch: number;
  bulk_threshold: number;
  drift_low_max: number;
  drift_medium_max: number;
  drift_high_action: 'BLOCK' | 'REVIEW';
  drift_frequency_multiplier: number;
  is_active: number;
  updated_at: string;
}

export interface BehaviourDifference {
  dimension: 'parameters' | 'resource' | 'frequency' | 'operation' | 'bulk_volume' | 'sensitive_resource';
  label: string;
  expected: string;
  observed: string;
  weight: number;
  severity: IncidentSeverity;
  detail: string;
}

export interface BehaviourBaselineSummary {
  expectedParams: string[];
  expectedResources: string[];
  expectedOperations: string[];
  baselineRpm: number;
  normalMaxRecords: number;
  sampleCount: number;
}

export interface BehaviourCurrentSummary {
  observedParams: string[];
  observedResources: string[];
  observedOperation: string;
  currentRpm: number;
  requestedRecords: number;
}

export interface BehaviourDriftAnalysis {
  toolName: string;
  hasBaseline: boolean;
  deviationScore: number;
  deviationLevel: 'low' | 'medium' | 'high';
  driftResponse: SecurityDecision;
  isAnomalous: boolean;
  baselineBehaviour: BehaviourBaselineSummary;
  currentBehaviour: BehaviourCurrentSummary;
  differences: BehaviourDifference[];
  triggeredRules: TriggeredRule[];
}

export interface ToolBehaviourProfile {
  id: string;
  tool_name: string;
  normal_param_keys_json: string;
  normal_resources_json: string;
  normal_operations_json: string;
  baseline_rpm: number;
  normal_max_records: number;
  total_baseline_executions: number;
  anomaly_count: number;
  last_deviation_score: number;
  last_analyzed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ToolBehaviourEvent {
  id: string;
  event_uid: string;
  execution_id: string | null;
  tool_name: string;
  source: EventSource;
  deviation_score: number;
  deviation_level: 'low' | 'medium' | 'high';
  is_anomalous: number;
  decision: SecurityDecision;
  baseline_snapshot_json: string;
  current_snapshot_json: string;
  differences_json: string;
  triggered_rules_json: string;
  arguments_json: string;
  created_at: string;
}

export interface BehaviourOverview {
  summary: {
    monitoredTools: number;
    establishedBaselines: number;
    totalEventsAnalyzed: number;
    anomaliesDetected: number;
    normalEventsCount: number;
    avgDeviationScore: number;
    highDriftAlerts: number;
  };
  profiles: ToolBehaviourProfile[];
  recentEvents: ToolBehaviourEvent[];
  timeline: Array<{
    bucket: string;
    avgDeviation: number;
    maxDeviation: number;
    normalCalls: number;
    anomalousCalls: number;
  }>;
  toolComparison: Array<{
    toolName: string;
    normalCount: number;
    unusualCount: number;
    avgDeviation: number;
    maxDeviation: number;
  }>;
  thresholds: {
    drift_low_max: number;
    drift_medium_max: number;
    drift_high_action: 'BLOCK' | 'REVIEW';
    drift_frequency_multiplier: number;
  };
}

export interface BifrostConfig {
  id: string;
  provider: string;
  mode: 'demo' | 'live';
  endpoint_url: string;
  shared_secret_configured: number;
  signature_ttl_seconds?: number;
  webhook_auth_status?: 'hmac_configured' | 'secret_missing';
  enabled: number;
  last_test_status: string;
  last_test_message: string;
  last_tested_at: string | null;
  updated_at: string;
}

export interface BifrostTelemetry {
  gatewayReachable: boolean;
  gatewayStatus: string;
  endpointUrl: string;
  lastTestedAt: string | null;
  pluginLoadingStatus:
    | 'active_live'
    | 'gateway_reachable_no_hook'
    | 'configured_awaiting_traffic'
    | 'not_detected';
  pluginVersion: string | null;
  pinnedSpecVersion: string;
  hmacAuthStatus: 'hmac_configured' | 'secret_missing';
  signatureTtlSeconds: number;
  lastRealExecution: {
    id: string;
    execution_uid: string;
    tool_name: string;
    decision: SecurityDecision;
    risk_score: number;
    execution_status: ExecutionStatus;
    duration_ms: number;
    created_at: string;
  } | null;
  liveCounts: {
    total: number;
    allow: number;
    review: number;
    block: number;
    postHookCompleted: number;
    rejectedAuthCalls: number;
  };
  demoCounts: {
    total: number;
    allow: number;
    review: number;
    block: number;
  };
}

export interface BifrostLiveVerificationResult {
  overallStatus: 'verified' | 'partial' | 'not_connected';
  verifiedAt: string;
  summary: string;
  checks: Array<{
    id: string;
    label: string;
    status: 'PASS' | 'WARN' | 'FAIL';
    detail: string;
  }>;
}

export interface IntegrationLog {
  id: string;
  provider: string;
  hook_type: 'PreMCPHook' | 'PostMCPHook' | 'ConnectionTest' | 'AdapterEvent';
  source_mode: 'demo' | 'live';
  tool_name: string | null;
  decision: string | null;
  status_code: number;
  message: string;
  payload_json: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  actor_id: string;
  actor_role: string;
  action: string;
  target_type: string;
  target_id: string;
  details_json: string;
  created_at: string;
}

export interface DashboardOverview {
  metrics: {
    totalExecutions: number;
    allowedOperations: number;
    blockedOperations: number;
    reviewOperations: number;
    pendingApprovals: number;
    activeIncidents: number;
    averageRiskScore: number;
    trustedToolsCount: number;
    modifiedToolsCount: number;
  };
  behaviourSummary: {
    monitoredTools: number;
    anomaliesDetected: number;
    avgDeviationScore: number;
    highDriftAlerts: number;
  };
  threatDistribution: Array<{ category: string; count: number; avgRisk: number }>;
  riskTrend: Array<{ bucket: string; avgRisk: number; blocked: number; allowed: number; review: number }>;
  toolUsage: Array<{ toolName: string; total: number; blocked: number; allowed: number; avgRisk: number }>;
  recentIncidents: SecurityIncident[];
  liveFeed: ToolExecution[];
  activePolicy: SecurityPolicy;
  bifrostStatus: {
    mode: 'demo' | 'live';
    enabled: boolean;
    lastTestStatus: string;
  };
}

export interface SimulationStep {
  step: number;
  stage: string;
  status: 'passed' | 'warning' | 'blocked';
  detail: string;
  timestamp: string;
}

export interface SimulationResult {
  scenarioId: string;
  scenarioName: string;
  toolName: string;
  arguments: Record<string, unknown>;
  riskScore: number;
  decision: SecurityDecision;
  executionStatus: ExecutionStatus;
  triggeredRules: TriggeredRule[];
  explanation: string;
  executionId: string;
  incidentId: string | null;
  approvalRequestId: string | null;
  mockExecutionOutput: string | null;
  steps: SimulationStep[];
  behaviourDrift?: BehaviourDriftAnalysis;
  schemaComparison?: {
    originalHash: string;
    modifiedHash: string;
    originalSchema: CanonicalToolSchema;
    modifiedSchema: CanonicalToolSchema;
    diffs: SchemaParameterDiff[];
  };
}

export type WsEventType =
  | 'connected'
  | 'execution:created'
  | 'incident:created'
  | 'incident:updated'
  | 'approval:created'
  | 'approval:updated'
  | 'tool:updated'
  | 'behaviour:drift'
  | 'bifrost:log'
  | 'policy:updated';

export interface WsBroadcastMessage<T = unknown> {
  type: WsEventType;
  payload: T;
  timestamp: string;
}

export interface QaTestItem {
  id: string;
  module: string;
  title: string;
  status: 'PASS' | 'FAIL';
  durationMs: number;
  detail: string;
}

export interface QaSuiteReport {
  startedAt: string;
  completedAt: string;
  summary: {
    total: number;
    passed: number;
    failed: number;
  };
  tests: QaTestItem[];
}


