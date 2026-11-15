import Database from 'better-sqlite3';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { computeToolDna } from '../security/toolDna.ts';
import { hashPassword } from '../auth/password.ts';
import type { CanonicalToolSchema } from '../../types/toolseal.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = process.env.TOOLSEAL_DB_PATH || path.join(DATA_DIR, 'toolseal.db');
export const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

export function initializeDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
      display_name TEXT NOT NULL,
      password_hash TEXT,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS user_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      expires_at TEXT NOT NULL,
      revoked_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS webhook_replay_nonces (
      nonce_hash TEXT PRIMARY KEY,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS registered_tools (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL,
      server_name TEXT NOT NULL,
      category TEXT NOT NULL,
      trust_status TEXT NOT NULL CHECK(trust_status IN ('trusted', 'modified', 'untrusted', 'pending')),
      current_version INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS tool_schemas (
      id TEXT PRIMARY KEY,
      tool_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      schema_json TEXT NOT NULL,
      canonical_json TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (tool_id) REFERENCES registered_tools(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS schema_fingerprints (
      id TEXT PRIMARY KEY,
      tool_id TEXT NOT NULL,
      schema_id TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('approved', 'mismatched', 'pending_review', 'revoked')),
      approved_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (tool_id) REFERENCES registered_tools(id) ON DELETE CASCADE,
      FOREIGN KEY (schema_id) REFERENCES tool_schemas(id) ON DELETE CASCADE,
      FOREIGN KEY (approved_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS security_policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL,
      allow_max_risk INTEGER NOT NULL DEFAULT 30,
      review_max_risk INTEGER NOT NULL DEFAULT 70,
      sensitive_file_action TEXT NOT NULL CHECK(sensitive_file_action IN ('BLOCK', 'REVIEW')) DEFAULT 'BLOCK',
      unknown_tool_action TEXT NOT NULL CHECK(unknown_tool_action IN ('REVIEW', 'BLOCK')) DEFAULT 'REVIEW',
      block_on_schema_mismatch INTEGER NOT NULL DEFAULT 1,
      bulk_threshold INTEGER NOT NULL DEFAULT 500,
      drift_low_max INTEGER NOT NULL DEFAULT 25,
      drift_medium_max INTEGER NOT NULL DEFAULT 60,
      drift_high_action TEXT NOT NULL CHECK(drift_high_action IN ('BLOCK', 'REVIEW')) DEFAULT 'BLOCK',
      drift_frequency_multiplier INTEGER NOT NULL DEFAULT 3,
      is_active INTEGER NOT NULL DEFAULT 1,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS tool_executions (
      id TEXT PRIMARY KEY,
      execution_uid TEXT NOT NULL UNIQUE,
      tool_name TEXT NOT NULL,
      arguments_json TEXT NOT NULL,
      source TEXT NOT NULL CHECK(source IN ('bifrost', 'demo_simulator', 'api_direct')),
      agent_id TEXT NOT NULL,
      session_id TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
      reason TEXT NOT NULL,
      triggered_rules_json TEXT NOT NULL,
      execution_status TEXT NOT NULL CHECK(execution_status IN ('executed', 'blocked', 'pending_approval', 'approved_executed', 'rejected')),
      duration_ms INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS security_incidents (
      id TEXT PRIMARY KEY,
      incident_uid TEXT NOT NULL UNIQUE,
      execution_id TEXT,
      tool_name TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      threat_category TEXT NOT NULL,
      arguments_json TEXT NOT NULL,
      decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
      explanation TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
      status TEXT NOT NULL CHECK(status IN ('open', 'investigating', 'resolved', 'dismissed')) DEFAULT 'open',
      source TEXT NOT NULL CHECK(source IN ('bifrost', 'demo_simulator', 'api_direct')),
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      resolved_at TEXT,
      FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS approval_requests (
      id TEXT PRIMARY KEY,
      request_uid TEXT NOT NULL UNIQUE,
      execution_id TEXT NOT NULL,
      incident_id TEXT,
      tool_name TEXT NOT NULL,
      arguments_json TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      reason TEXT NOT NULL,
      triggered_rules_json TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
      reviewed_by TEXT,
      reviewer_note TEXT,
      revalidated INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      reviewed_at TEXT,
      FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE CASCADE,
      FOREIGN KEY (incident_id) REFERENCES security_incidents(id) ON DELETE SET NULL,
      FOREIGN KEY (reviewed_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS integration_configs (
      id TEXT PRIMARY KEY,
      provider TEXT NOT NULL UNIQUE,
      mode TEXT NOT NULL CHECK(mode IN ('demo', 'live')) DEFAULT 'demo',
      endpoint_url TEXT NOT NULL,
      shared_secret_configured INTEGER NOT NULL DEFAULT 0,
      enabled INTEGER NOT NULL DEFAULT 1,
      last_test_status TEXT NOT NULL DEFAULT 'untested',
      last_test_message TEXT NOT NULL DEFAULT 'Not yet tested against an external Bifrost endpoint.',
      last_tested_at TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS integration_logs (
      id TEXT PRIMARY KEY,
      provider TEXT NOT NULL,
      hook_type TEXT NOT NULL CHECK(hook_type IN ('PreMCPHook', 'PostMCPHook', 'ConnectionTest', 'AdapterEvent')),
      source_mode TEXT NOT NULL CHECK(source_mode IN ('demo', 'live')),
      tool_name TEXT,
      decision TEXT,
      status_code INTEGER NOT NULL,
      message TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      actor_id TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      target_type TEXT NOT NULL,
      target_id TEXT NOT NULL,
      details_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS tool_behaviour_profiles (
      id TEXT PRIMARY KEY,
      tool_name TEXT NOT NULL UNIQUE,
      normal_param_keys_json TEXT NOT NULL,
      normal_resources_json TEXT NOT NULL,
      normal_operations_json TEXT NOT NULL,
      baseline_rpm REAL NOT NULL DEFAULT 2.0,
      normal_max_records INTEGER NOT NULL DEFAULT 25,
      total_baseline_executions INTEGER NOT NULL DEFAULT 0,
      anomaly_count INTEGER NOT NULL DEFAULT 0,
      last_deviation_score INTEGER NOT NULL DEFAULT 0,
      last_analyzed_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS tool_behaviour_events (
      id TEXT PRIMARY KEY,
      event_uid TEXT NOT NULL UNIQUE,
      execution_id TEXT,
      tool_name TEXT NOT NULL,
      source TEXT NOT NULL CHECK(source IN ('bifrost', 'demo_simulator', 'api_direct')),
      deviation_score INTEGER NOT NULL,
      deviation_level TEXT NOT NULL CHECK(deviation_level IN ('low', 'medium', 'high')),
      is_anomalous INTEGER NOT NULL DEFAULT 0,
      decision TEXT NOT NULL CHECK(decision IN ('ALLOW', 'REVIEW', 'BLOCK')),
      baseline_snapshot_json TEXT NOT NULL,
      current_snapshot_json TEXT NOT NULL,
      differences_json TEXT NOT NULL,
      triggered_rules_json TEXT NOT NULL,
      arguments_json TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (execution_id) REFERENCES tool_executions(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_executions_created ON tool_executions(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_incidents_created ON security_incidents(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON security_incidents(severity);
    CREATE INDEX IF NOT EXISTS idx_approvals_status ON approval_requests(status);
    CREATE INDEX IF NOT EXISTS idx_tools_name ON registered_tools(name);
    CREATE INDEX IF NOT EXISTS idx_behaviour_profiles_tool ON tool_behaviour_profiles(tool_name);
    CREATE INDEX IF NOT EXISTS idx_behaviour_events_tool ON tool_behaviour_events(tool_name, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_behaviour_events_created ON tool_behaviour_events(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_replay_nonces_expires ON webhook_replay_nonces(expires_at);
  `);

  migratePolicyBehaviourColumns();
  migrateUsersAuthColumns();
  seedInitialData();
  seedUserPasswords();
  seedBehaviourBaselines();
}

function migrateUsersAuthColumns() {
  const cols = db.prepare('PRAGMA table_info(users)').all() as Array<{ name: string }>;
  const existing = new Set(cols.map((c) => c.name));

  if (!existing.has('password_hash')) {
    db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT');
  }
  if (!existing.has('is_active')) {
    db.exec('ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1');
  }
}

function seedUserPasswords() {
  const defaults: Array<{ username: string; password: string }> = [
    {
      username: 'evance',
      password: (process.env.TOOLSEAL_ADMIN_PASSWORD || '').trim() || 'toolseal-admin-2026',
    },
    {
      username: 'mchen',
      password: (process.env.TOOLSEAL_ANALYST_PASSWORD || '').trim() || 'toolseal-analyst-2026',
    },
    {
      username: 'audit',
      password: (process.env.TOOLSEAL_VIEWER_PASSWORD || '').trim() || 'toolseal-viewer-2026',
    },
  ];

  const findUser = db.prepare('SELECT id, password_hash FROM users WHERE username = ?');
  const setHash = db.prepare('UPDATE users SET password_hash = ?, is_active = COALESCE(is_active, 1) WHERE id = ?');

  for (const item of defaults) {
    const row = findUser.get(item.username) as { id: string; password_hash: string | null } | undefined;
    if (row && !row.password_hash) {
      setHash.run(hashPassword(item.password), row.id);
    }
  }
}

function migratePolicyBehaviourColumns() {
  const cols = db.prepare('PRAGMA table_info(security_policies)').all() as Array<{ name: string }>;
  const existing = new Set(cols.map((c) => c.name));

  if (!existing.has('drift_low_max')) {
    db.exec('ALTER TABLE security_policies ADD COLUMN drift_low_max INTEGER NOT NULL DEFAULT 25');
  }
  if (!existing.has('drift_medium_max')) {
    db.exec('ALTER TABLE security_policies ADD COLUMN drift_medium_max INTEGER NOT NULL DEFAULT 60');
  }
  if (!existing.has('drift_high_action')) {
    db.exec(
      "ALTER TABLE security_policies ADD COLUMN drift_high_action TEXT NOT NULL DEFAULT 'BLOCK'"
    );
  }
  if (!existing.has('drift_frequency_multiplier')) {
    db.exec('ALTER TABLE security_policies ADD COLUMN drift_frequency_multiplier INTEGER NOT NULL DEFAULT 3');
  }
}

export function uid(prefix: string): string {
  return `${prefix}-${crypto.randomUUID().slice(0, 8)}`;
}

function seedInitialData() {
  const userCount = (db.prepare('SELECT COUNT(*) as c FROM users').get() as { c: number }).c;
  if (userCount > 0) return;

  const insertUser = db.prepare(
    'INSERT INTO users (id, username, email, role, display_name) VALUES (?, ?, ?, ?, ?)'
  );
  insertUser.run('usr-admin-1', 'evance', 'elena.vance@toolseal.sec', 'admin', 'Elena Vance (Security Admin)');
  insertUser.run('usr-analyst-1', 'mchen', 'marcus.chen@toolseal.sec', 'analyst', 'Marcus Chen (SOC Analyst)');
  insertUser.run('usr-viewer-1', 'audit', 'auditor@toolseal.sec', 'viewer', 'Compliance Auditor');

  // Seed default security policy
  db.prepare(`
    INSERT INTO security_policies (
      id, name, description, allow_max_risk, review_max_risk,
      sensitive_file_action, unknown_tool_action, block_on_schema_mismatch, bulk_threshold, is_active
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'pol-default',
    'Zero-Trust Production Baseline',
    'Strict runtime policy: blocks destructive actions, bulk exfiltration, sensitive system file access, and Tool DNA schema drift.',
    30,
    70,
    'BLOCK',
    'REVIEW',
    1,
    500,
    1
  );

  // Seed Bifrost integration config in honest Demo Mode
  db.prepare(`
    INSERT INTO integration_configs (
      id, provider, mode, endpoint_url, shared_secret_configured, enabled, last_test_status, last_test_message
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    'int-bifrost',
    'bifrost',
    'demo',
    'http://localhost:8080',
    0,
    1,
    'demo_mode',
    'Running in standalone DEMO MODE. Configure a live Bifrost gateway URL and test connectivity to switch to live inspection.'
  );

  // Seed baseline registered MCP tools with real SHA-256 Tool DNA fingerprints
  const baselineTools: Array<{
    id: string;
    name: string;
    description: string;
    serverName: string;
    category: string;
    schema: CanonicalToolSchema;
  }> = [
    {
      id: 'tool-weather',
      name: 'get_weather',
      description: 'Retrieves current meteorological forecast for a given city.',
      serverName: 'mcp-utilities-server',
      category: 'Read-Only Utility',
      schema: {
        name: 'get_weather',
        description: 'Retrieves current meteorological forecast for a given city.',
        parameters: {
          type: 'object',
          properties: {
            city: { type: 'string', description: 'Target city name (e.g. Mumbai)' },
            units: { type: 'string', enum: ['metric', 'imperial'], description: 'Temperature unit system' },
          },
          required: ['city'],
          additionalProperties: false,
        },
      },
    },
    {
      id: 'tool-kb',
      name: 'search_knowledge_base',
      description: 'Performs read-only semantic lookup across approved internal documentation.',
      serverName: 'mcp-docs-server',
      category: 'Knowledge Retrieval',
      schema: {
        name: 'search_knowledge_base',
        description: 'Performs read-only semantic lookup across approved internal documentation.',
        parameters: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Search query string' },
            top_k: { type: 'number', description: 'Maximum results (1-20)' },
          },
          required: ['query'],
          additionalProperties: false,
        },
      },
    },
    {
      id: 'tool-read-file',
      name: 'read_file',
      description: 'Reads workspace text files within authorized project directories.',
      serverName: 'mcp-filesystem-server',
      category: 'Filesystem Access',
      schema: {
        name: 'read_file',
        description: 'Reads workspace text files within authorized project directories.',
        parameters: {
          type: 'object',
          properties: {
            path: { type: 'string', description: 'Relative workspace file path' },
          },
          required: ['path'],
          additionalProperties: false,
        },
      },
    },
    {
      id: 'tool-export-db',
      name: 'export_customer_database',
      description: 'Exports filtered customer account records for authorized compliance audits.',
      serverName: 'mcp-crm-postgres',
      category: 'Data Export',
      schema: {
        name: 'export_customer_database',
        description: 'Exports filtered customer account records for authorized compliance audits.',
        parameters: {
          type: 'object',
          properties: {
            scope: { type: 'string', description: 'Export scope identifier' },
            limit: { type: 'number', description: 'Maximum number of rows' },
          },
          required: ['scope'],
          additionalProperties: false,
        },
      },
    },
    {
      id: 'tool-delete-all',
      name: 'delete_all_records',
      description: 'Purges records from a target datastore table.',
      serverName: 'mcp-crm-postgres',
      category: 'Destructive Admin',
      schema: {
        name: 'delete_all_records',
        description: 'Purges records from a target datastore table.',
        parameters: {
          type: 'object',
          properties: {
            table: { type: 'string', description: 'Target table name' },
            confirmation: { type: 'boolean', description: 'Explicit purge confirmation flag' },
          },
          required: ['confirmation'],
          additionalProperties: false,
        },
      },
    },
  ];

  const insertTool = db.prepare(`
    INSERT INTO registered_tools (id, name, description, server_name, category, trust_status, current_version)
    VALUES (?, ?, ?, ?, ?, 'trusted', 1)
  `);
  const insertSchema = db.prepare(`
    INSERT INTO tool_schemas (id, tool_id, version, schema_json, canonical_json, is_active)
    VALUES (?, ?, 1, ?, ?, 1)
  `);
  const insertFp = db.prepare(`
    INSERT INTO schema_fingerprints (id, tool_id, schema_id, sha256_hash, status, approved_by)
    VALUES (?, ?, ?, ?, 'approved', 'usr-admin-1')
  `);

  for (const t of baselineTools) {
    const { canonicalJson, sha256 } = computeToolDna(t.schema);
    const schemaId = uid('sch');
    const fpId = uid('fp');
    insertTool.run(t.id, t.name, t.description, t.serverName, t.category);
    insertSchema.run(schemaId, t.id, JSON.stringify(t.schema, null, 2), canonicalJson);
    insertFp.run(fpId, t.id, schemaId, sha256);
  }

  // Seed initial verifiable demonstration events backed in SQLite (labeled demo_simulator)
  const seedExecs = [
    {
      id: 'exec-seed-1',
      uid: 'EXE-9041',
      tool: 'get_weather',
      args: { city: 'Bengaluru', units: 'metric' },
      risk: 8,
      decision: 'ALLOW',
      reason: 'Known read-only utility tool with verified Tool DNA fingerprint and benign parameters.',
      rules: [{ id: 'SAFE_READONLY_BASELINE', name: 'Verified Safe Baseline', category: 'Baseline Trust', weight: 8, severity: 'low', detail: 'Read-only weather lookup verified.' }],
      status: 'executed',
      hoursAgo: 5,
    },
    {
      id: 'exec-seed-2',
      uid: 'EXE-9042',
      tool: 'search_knowledge_base',
      args: { query: 'Bifrost MCP plugin lifecycle hooks', top_k: 5 },
      risk: 10,
      decision: 'ALLOW',
      reason: 'Approved read-only knowledge retrieval within safe top_k bounds.',
      rules: [{ id: 'SAFE_READONLY_BASELINE', name: 'Verified Safe Baseline', category: 'Baseline Trust', weight: 10, severity: 'low', detail: 'Scoped search query passed inspection.' }],
      status: 'executed',
      hoursAgo: 4,
    },
    {
      id: 'exec-seed-3',
      uid: 'EXE-9043',
      tool: 'read_file',
      args: { path: './docs/architecture.md' },
      risk: 14,
      decision: 'ALLOW',
      reason: 'Workspace relative path inside authorized project directory.',
      rules: [{ id: 'SAFE_READONLY_BASELINE', name: 'Authorized Workspace Path', category: 'Filesystem', weight: 14, severity: 'low', detail: 'No sensitive system path or traversal detected.' }],
      status: 'executed',
      hoursAgo: 3,
    },
    {
      id: 'exec-seed-4',
      uid: 'EXE-9044',
      tool: 'sync_external_crm',
      args: { region: 'apac', dry_run: true },
      risk: 52,
      decision: 'REVIEW',
      reason: 'Unregistered tool "sync_external_crm" lacks an approved Tool DNA SHA-256 fingerprint.',
      rules: [{ id: 'UNKNOWN_UNREGISTERED_TOOL', name: 'Unregistered MCP Tool', category: 'Unknown Tool', weight: 52, severity: 'medium', detail: 'Tool is not registered in Tool DNA Registry.' }],
      status: 'pending_approval',
      hoursAgo: 2,
    },
    {
      id: 'exec-seed-5',
      uid: 'EXE-9045',
      tool: 'export_customer_database',
      args: { scope: 'all_customers' },
      risk: 92,
      decision: 'BLOCK',
      reason: 'Bulk data exfiltration attempt targeting scope "all_customers" blocked before execution.',
      rules: [{ id: 'DATA_EXFILTRATION', name: 'Bulk Data Exfiltration Pattern', category: 'Data Exfiltration', weight: 92, severity: 'critical', detail: 'Unbounded scope "all_customers" violates data boundary policy.' }],
      status: 'blocked',
      hoursAgo: 1,
    },
  ];

  const insertExec = db.prepare(`
    INSERT INTO tool_executions (
      id, execution_uid, tool_name, arguments_json, source, agent_id, session_id,
      risk_score, decision, reason, triggered_rules_json, execution_status, duration_ms, created_at
    ) VALUES (?, ?, ?, ?, 'demo_simulator', 'agent-demo-orchestrator', 'sess-bootstrap-01', ?, ?, ?, ?, ?, ?, datetime('now', ?))
  `);

  for (const s of seedExecs) {
    insertExec.run(
      s.id,
      s.uid,
      s.tool,
      JSON.stringify(s.args),
      s.risk,
      s.decision,
      s.reason,
      JSON.stringify(s.rules),
      s.status,
      s.decision === 'ALLOW' ? 14 : 4,
      `-${s.hoursAgo} hours`
    );
  }

  // Create incident + pending approval for seeded REVIEW and incident for seeded BLOCK
  db.prepare(`
    INSERT INTO security_incidents (
      id, incident_uid, execution_id, tool_name, risk_score, threat_category,
      arguments_json, decision, explanation, severity, status, source, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 'demo_simulator', datetime('now', '-2 hours'))
  `).run(
    'inc-seed-1',
    'INC-4101',
    'exec-seed-4',
    'sync_external_crm',
    52,
    'Unknown Tool',
    JSON.stringify({ region: 'apac', dry_run: true }),
    'REVIEW',
    'Unregistered tool "sync_external_crm" lacks an approved Tool DNA SHA-256 fingerprint.',
    'medium'
  );

  db.prepare(`
    INSERT INTO approval_requests (
      id, request_uid, execution_id, incident_id, tool_name, arguments_json,
      risk_score, reason, triggered_rules_json, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now', '-2 hours'))
  `).run(
    'apr-seed-1',
    'APR-3001',
    'exec-seed-4',
    'inc-seed-1',
    'sync_external_crm',
    JSON.stringify({ region: 'apac', dry_run: true }),
    52,
    'Unregistered tool "sync_external_crm" lacks an approved Tool DNA SHA-256 fingerprint.',
    JSON.stringify([{ id: 'UNKNOWN_UNREGISTERED_TOOL', name: 'Unregistered MCP Tool', category: 'Unknown Tool', weight: 52, severity: 'medium', detail: 'Tool is not registered in Tool DNA Registry.' }])
  );

  db.prepare(`
    INSERT INTO security_incidents (
      id, incident_uid, execution_id, tool_name, risk_score, threat_category,
      arguments_json, decision, explanation, severity, status, source, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 'demo_simulator', datetime('now', '-1 hours'))
  `).run(
    'inc-seed-2',
    'INC-4102',
    'exec-seed-5',
    'export_customer_database',
    92,
    'Data Exfiltration',
    JSON.stringify({ scope: 'all_customers' }),
    'BLOCK',
    'Bulk data exfiltration attempt targeting scope "all_customers" blocked before execution.',
    'critical'
  );

  db.prepare(`
    INSERT INTO audit_logs (id, actor_id, actor_role, action, target_type, target_id, details_json)
    VALUES (?, 'system', 'system', 'DATABASE_INITIALIZED', 'system', 'toolseal', ?)
  `).run(uid('aud'), JSON.stringify({ message: 'TOOLSEAL SQLite database initialized with 5 Tool DNA baselines.' }));
}

function seedBehaviourBaselines() {
  const count = (db.prepare('SELECT COUNT(*) as c FROM tool_behaviour_profiles').get() as { c: number }).c;
  if (count > 0) return;

  const profiles = [
    {
      id: 'bprof-weather',
      toolName: 'get_weather',
      params: ['city', 'units'],
      resources: ['weather_api:forecast'],
      operations: ['read'],
      rpm: 3.0,
      maxRecords: 1,
      samples: 42,
      anomalies: 0,
      lastDeviation: 4,
    },
    {
      id: 'bprof-kb',
      toolName: 'search_knowledge_base',
      params: ['query', 'top_k'],
      resources: ['knowledge_base:internal_docs'],
      operations: ['read'],
      rpm: 4.0,
      maxRecords: 20,
      samples: 28,
      anomalies: 0,
      lastDeviation: 6,
    },
    {
      id: 'bprof-read-file',
      toolName: 'read_file',
      params: ['path'],
      resources: ['workspace:docs'],
      operations: ['read'],
      rpm: 3.0,
      maxRecords: 1,
      samples: 19,
      anomalies: 0,
      lastDeviation: 5,
    },
    {
      id: 'bprof-export-db',
      toolName: 'export_customer_database',
      params: ['scope', 'limit'],
      resources: ['crm_db:scoped_audit'],
      operations: ['export'],
      rpm: 0.5,
      maxRecords: 100,
      samples: 4,
      anomalies: 1,
      lastDeviation: 84,
    },
    {
      id: 'bprof-delete-all',
      toolName: 'delete_all_records',
      params: ['table', 'confirmation'],
      resources: ['crm_db:staging_cleanup'],
      operations: ['delete'],
      rpm: 0.2,
      maxRecords: 10,
      samples: 1,
      anomalies: 0,
      lastDeviation: 12,
    },
  ];

  const insertProfile = db.prepare(`
    INSERT INTO tool_behaviour_profiles (
      id, tool_name, normal_param_keys_json, normal_resources_json, normal_operations_json,
      baseline_rpm, normal_max_records, total_baseline_executions, anomaly_count, last_deviation_score, last_analyzed_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '-30 minutes'))
  `);

  for (const p of profiles) {
    insertProfile.run(
      p.id,
      p.toolName,
      JSON.stringify(p.params),
      JSON.stringify(p.resources),
      JSON.stringify(p.operations),
      p.rpm,
      p.maxRecords,
      p.samples,
      p.anomalies,
      p.lastDeviation
    );
  }

  // Seed historical behavioural baseline telemetry events (explicitly marked demo_simulator)
  const seedEvents = [
    {
      id: 'bev-seed-1',
      uid: 'DRF-1001',
      execId: 'exec-seed-1',
      tool: 'get_weather',
      score: 4,
      level: 'low',
      anomalous: 0,
      decision: 'ALLOW',
      args: { city: 'Bengaluru', units: 'metric' },
      baseline: {
        expectedParams: ['city', 'units'],
        expectedResources: ['weather_api:forecast'],
        expectedOperations: ['read'],
        baselineRpm: 3.0,
        normalMaxRecords: 1,
        sampleCount: 41,
      },
      current: {
        observedParams: ['city', 'units'],
        observedResources: ['weather_api:forecast'],
        observedOperation: 'read',
        currentRpm: 1,
        requestedRecords: 1,
      },
      diffs: [],
      rules: [],
      hoursAgo: 5,
    },
    {
      id: 'bev-seed-2',
      uid: 'DRF-1002',
      execId: 'exec-seed-2',
      tool: 'search_knowledge_base',
      score: 6,
      level: 'low',
      anomalous: 0,
      decision: 'ALLOW',
      args: { query: 'Bifrost MCP plugin lifecycle hooks', top_k: 5 },
      baseline: {
        expectedParams: ['query', 'top_k'],
        expectedResources: ['knowledge_base:internal_docs'],
        expectedOperations: ['read'],
        baselineRpm: 4.0,
        normalMaxRecords: 20,
        sampleCount: 27,
      },
      current: {
        observedParams: ['query', 'top_k'],
        observedResources: ['knowledge_base:internal_docs'],
        observedOperation: 'read',
        currentRpm: 1,
        requestedRecords: 5,
      },
      diffs: [],
      rules: [],
      hoursAgo: 4,
    },
    {
      id: 'bev-seed-3',
      uid: 'DRF-1003',
      execId: 'exec-seed-3',
      tool: 'read_file',
      score: 5,
      level: 'low',
      anomalous: 0,
      decision: 'ALLOW',
      args: { path: './docs/architecture.md' },
      baseline: {
        expectedParams: ['path'],
        expectedResources: ['workspace:docs'],
        expectedOperations: ['read'],
        baselineRpm: 3.0,
        normalMaxRecords: 1,
        sampleCount: 18,
      },
      current: {
        observedParams: ['path'],
        observedResources: ['workspace:docs'],
        observedOperation: 'read',
        currentRpm: 1,
        requestedRecords: 1,
      },
      diffs: [],
      rules: [],
      hoursAgo: 3,
    },
    {
      id: 'bev-seed-4',
      uid: 'DRF-1004',
      execId: 'exec-seed-5',
      tool: 'export_customer_database',
      score: 84,
      level: 'high',
      anomalous: 1,
      decision: 'BLOCK',
      args: { scope: 'all_customers' },
      baseline: {
        expectedParams: ['scope', 'limit'],
        expectedResources: ['crm_db:scoped_audit'],
        expectedOperations: ['export'],
        baselineRpm: 0.5,
        normalMaxRecords: 100,
        sampleCount: 4,
      },
      current: {
        observedParams: ['scope'],
        observedResources: ['customer_database:all_customers'],
        observedOperation: 'export',
        currentRpm: 1,
        requestedRecords: 10000,
      },
      diffs: [
        {
          dimension: 'bulk_volume',
          label: 'Unusual Bulk Request',
          expected: '<= 100 records',
          observed: 'Unbounded (all_customers)',
          weight: 42,
          severity: 'critical',
          detail: 'Requested unbounded export scope "all_customers" exceeding normal baseline limit of 100.',
        },
        {
          dimension: 'sensitive_resource',
          label: 'Sensitive Resource Access',
          expected: 'crm_db:scoped_audit',
          observed: 'customer_database:all_customers',
          weight: 42,
          severity: 'critical',
          detail: 'Call attempts unrestricted extraction from sensitive customer records.',
        },
      ],
      rules: [
        {
          id: 'BEHAVIOUR_BULK_DRIFT',
          name: 'Behavioural Bulk Extraction Anomaly',
          category: 'Behavioural Drift',
          weight: 42,
          severity: 'critical',
          detail: 'Bulk request exceeds learned baseline record volume.',
        },
      ],
      hoursAgo: 1,
    },
  ];

  const insertEvent = db.prepare(`
    INSERT INTO tool_behaviour_events (
      id, event_uid, execution_id, tool_name, source, deviation_score, deviation_level,
      is_anomalous, decision, baseline_snapshot_json, current_snapshot_json,
      differences_json, triggered_rules_json, arguments_json, created_at
    ) VALUES (?, ?, ?, ?, 'demo_simulator', ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))
  `);

  for (const ev of seedEvents) {
    insertEvent.run(
      ev.id,
      ev.uid,
      ev.execId,
      ev.tool,
      ev.score,
      ev.level,
      ev.anomalous,
      ev.decision,
      JSON.stringify(ev.baseline),
      JSON.stringify(ev.current),
      JSON.stringify(ev.diffs),
      JSON.stringify(ev.rules),
      JSON.stringify(ev.args),
      `-${ev.hoursAgo} hours`
    );
  }
}

export function writeAuditLog(
  actorId: string,
  actorRole: string,
  action: string,
  targetType: string,
  targetId: string,
  details: Record<string, unknown>
) {
  db.prepare(`
    INSERT INTO audit_logs (id, actor_id, actor_role, action, target_type, target_id, details_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(uid('aud'), actorId, actorRole, action, targetType, targetId, JSON.stringify(details));
}
