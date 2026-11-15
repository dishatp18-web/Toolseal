import { useState } from 'react';
import { AlertTriangle, CheckCircle2, Play, ShieldAlert, ShieldCheck, ShieldOff } from 'lucide-react';
import { DecisionIndicator, RiskScoreValue } from '../components/DecisionLabel';
import { api } from '../lib/api';
import type { SimulationResult, UserRecord } from '../types/toolseal';

interface ScenarioDef {
  id:
    | 'normal_operation'
    | 'sensitive_file_access'
    | 'data_exfiltration'
    | 'destructive_operation'
    | 'schema_manipulation'
    | 'behaviour_drift_weather';
  number: string;
  title: string;
  tool: string;
  argsPreview: string;
  expected: string;
  summary: string;
}

const SCENARIOS: ScenarioDef[] = [
  {
    id: 'normal_operation',
    number: '01',
    title: 'Normal Operation',
    tool: 'get_weather',
    argsPreview: '{"city":"Mumbai"}',
    expected: 'ALLOW',
    summary: 'Verifies baseline Tool DNA SHA-256 fingerprint and executes benign read-only lookup inside safe sandbox.',
  },
  {
    id: 'sensitive_file_access',
    number: '02',
    title: 'Sensitive File Access',
    tool: 'read_file',
    argsPreview: '{"path":"/etc/shadow"}',
    expected: 'BLOCK or REVIEW',
    summary: 'Detects access to privileged Linux shadow password database; enforces BLOCK or REVIEW per Settings policy.',
  },
  {
    id: 'data_exfiltration',
    number: '03',
    title: 'Data Exfiltration',
    tool: 'export_customer_database',
    argsPreview: '{"scope":"all_customers"}',
    expected: 'BLOCK',
    summary: 'Detects unbounded bulk customer dump attempt and short-circuits before datastore query execution.',
  },
  {
    id: 'destructive_operation',
    number: '04',
    title: 'Destructive Operation',
    tool: 'delete_all_records',
    argsPreview: '{"confirmation":true}',
    expected: 'BLOCK',
    summary: 'Intercepts irreversible mass-deletion call with confirmation=true and logs a critical security incident.',
  },
  {
    id: 'schema_manipulation',
    number: '05',
    title: 'Tool Schema Manipulation (Tool DNA)',
    tool: 'invoice_lookup_mcp',
    argsPreview: '{"invoice_id":"INV-88412","exfiltrate_webhook":"..."}',
    expected: 'BLOCK + Alert',
    summary: 'Registers approved tool, injects hidden webhook & bypass_auth params, detects SHA-256 mismatch, and blocks call.',
  },
  {
    id: 'behaviour_drift_weather',
    number: '06',
    title: 'Behavioural Drift (Weather -> Customer DB)',
    tool: 'get_weather',
    argsPreview: '{"city":"Mumbai","resource":"customer_database","operation":"export","limit":2500}',
    expected: 'BLOCK or REVIEW',
    summary: 'Baselined weather tool suddenly requests customer database export; detects parameter, resource, operation & volume drift.',
  },
];

interface SimulatorPageProps {
  userRole: UserRecord['role'];
  onSimulated: () => void;
}

export function SimulatorPage({ userRole, onSimulated }: SimulatorPageProps) {
  const [runningId, setRunningId] = useState<string | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const canSimulate = userRole === 'admin' || userRole === 'analyst';

  const runScenario = async (scenarioId: ScenarioDef['id']) => {
    setRunningId(scenarioId);
    setError(null);
    try {
      const res = await api.post<SimulationResult>('/api/simulator/run', { scenarioId });
      setResult(res);
      onSimulated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Simulation failed');
    } finally {
      setRunningId(null);
    }
  };

  return (
    <div className="space-y-8">
      <div className="border-b border-[#D9D5CE] pb-5">
        <p className="text-xs font-mono text-[#8C2635] font-medium">Controlled Verification Harness</p>
        <h2 className="text-2xl font-semibold text-[#191919] mt-1">Technical Testing Console</h2>
        <p className="text-xs text-[#5E5A55] mt-1">
          Every scenario executes real backend deterministic rules, Tool DNA SHA-256 verification, SQLite persistence, and WebSocket broadcasts in an isolated safe sandbox.
        </p>
      </div>

      {!canSimulate && (
        <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] text-xs font-mono text-[#5E5A55]">
          Signed in as <span className="uppercase font-semibold text-[#191919]">{userRole}</span>. Running attack simulator scenarios requires Analyst or Administrator privileges.
        </div>
      )}

      {/* 5 Scenario Matrix */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {SCENARIOS.map((sc) => {
          const isRunning = runningId === sc.id;
          const isSelected = result?.scenarioId === sc.id;

          return (
            <div
              key={sc.id}
              className={`p-5 rounded-[2px] border bg-[#FCFBF8] flex flex-col justify-between gap-4 transition-colors ${
                isSelected ? 'border-[#8C2635]' : 'border-[#D9D5CE]'
              }`}
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between text-xs font-mono text-[#5E5A55]">
                  <span className="text-[#8C2635] font-semibold">Case {sc.number}</span>
                  <span>Expected: {sc.expected}</span>
                </div>
                <h3 className="text-base font-semibold text-[#191919]">{sc.title}</h3>
                <p className="text-xs text-[#5E5A55] leading-relaxed">{sc.summary}</p>
                <div className="p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] break-all">
                  {sc.tool}({sc.argsPreview})
                </div>
              </div>

              <button
                type="button"
                disabled={!canSimulate || Boolean(runningId)}
                onClick={() => runScenario(sc.id)}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-[2px] bg-[#191919] hover:bg-[#8C2635] disabled:opacity-50 text-xs font-semibold text-[#FCFBF8] transition-colors"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{isRunning ? 'Executing Pipeline...' : canSimulate ? 'Execute Test Case' : 'Analyst / Admin Only'}</span>
              </button>
            </div>
          );
        })}
      </div>

      {error && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {error}
        </div>
      )}

      {/* Technical Execution Output */}
      {result && (
        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[#D9D5CE] pb-4">
            <div>
              <div className="text-xs text-[#5E5A55] font-mono">
                {result.executionId}
                {result.incidentId ? ` · Incident ${result.incidentId}` : ''}
                {result.approvalRequestId ? ` · Approval ${result.approvalRequestId}` : ''}
              </div>
              <h3 className="text-lg font-semibold text-[#191919] mt-1">{result.scenarioName}</h3>
            </div>

            <div className="flex items-center gap-8">
              <div>
                <span className="text-[11px] text-[#5E5A55] block">Risk Score</span>
                <RiskScoreValue score={result.riskScore} />
              </div>
              <div>
                <span className="text-[11px] text-[#5E5A55] block">Security Decision</span>
                <DecisionIndicator decision={result.decision} />
              </div>
            </div>
          </div>

          {/* Risk Threshold Scale */}
          <div className="space-y-1.5">
            <div className="flex justify-between text-[11px] font-mono text-[#5E5A55]">
              <span>0 (Safe)</span>
              <span>30 (Allow Max)</span>
              <span>70 (Review Max)</span>
              <span>100 (Critical)</span>
            </div>
            <div className="h-2 rounded-[2px] bg-[#EFECE5] border border-[#D9D5CE] overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${
                  result.riskScore > 70
                    ? 'bg-[#B91C1C]'
                    : result.riskScore > 30
                    ? 'bg-[#A16207]'
                    : 'bg-[#1B6B44]'
                }`}
                style={{ width: `${result.riskScore}%` }}
              />
            </div>
          </div>

          {/* Step-by-Step Pipeline Trace */}
          <div>
            <h4 className="text-xs font-semibold text-[#191919] mb-3">Runtime Execution Pipeline Trace</h4>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              {result.steps.map((st) => (
                <div key={st.step} className="p-3.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[11px] text-[#5E5A55]">Step 0{st.step}</span>
                    {st.status === 'passed' ? (
                      <CheckCircle2 className="w-4 h-4 text-[#1B6B44]" />
                    ) : st.status === 'warning' ? (
                      <AlertTriangle className="w-4 h-4 text-[#A16207]" />
                    ) : (
                      <ShieldOff className="w-4 h-4 text-[#B91C1C]" />
                    )}
                  </div>
                  <div className="text-xs font-semibold text-[#191919]">{st.stage}</div>
                  <p className="text-[11px] text-[#5E5A55] leading-relaxed">{st.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Explanation & Triggered Rules */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-2.5">
              <h4 className="text-xs font-semibold text-[#191919]">Security Engine Explanation</h4>
              <p className="p-3.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919] leading-relaxed">
                {result.explanation}
              </p>

              <h4 className="text-xs font-semibold text-[#191919] pt-2">Triggered Deterministic Rules</h4>
              <div className="space-y-2">
                {result.triggeredRules.map((rule) => (
                  <div
                    key={rule.id}
                    className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs flex items-start gap-2.5"
                  >
                    {result.decision === 'ALLOW' ? (
                      <ShieldCheck className="w-4 h-4 text-[#1B6B44] shrink-0 mt-0.5" />
                    ) : (
                      <ShieldAlert
                        className={`w-4 h-4 shrink-0 mt-0.5 ${
                          result.decision === 'BLOCK' ? 'text-[#B91C1C]' : 'text-[#A16207]'
                        }`}
                      />
                    )}
                    <div>
                      <div className="font-mono font-semibold text-[#191919]">
                        {rule.name} (+{rule.weight}) · {rule.category}
                      </div>
                      <p className="text-[#5E5A55] mt-0.5">{rule.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <h4 className="text-xs font-semibold text-[#191919]">Inspected Payload &amp; Sandbox Output</h4>
              <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto">
                {JSON.stringify({ tool: result.toolName, arguments: result.arguments }, null, 2)}
              </pre>
              {result.mockExecutionOutput && (
                <div>
                  <div className="text-xs font-mono font-medium text-[#1B6B44] mb-1">
                    Safe Sandbox Execution Output
                  </div>
                  <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#1B6B44]/40 text-[11px] font-mono text-[#1B6B44] overflow-x-auto">
                    {JSON.stringify(JSON.parse(result.mockExecutionOutput), null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* Behavioural Drift Analysis Breakdown (when available) */}
          {result.behaviourDrift && (
            <div className="pt-5 border-t border-[#D9D5CE] space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h4 className="text-sm font-semibold text-[#191919]">
                    Behavioural Drift Comparison (Baseline vs Current Execution)
                  </h4>
                  <p className="text-xs text-[#5E5A55] mt-0.5">
                    Learned profile ({result.behaviourDrift.baselineBehaviour.sampleCount} samples) compared against runtime arguments
                  </p>
                </div>
                <span
                  className={`font-mono text-xs font-semibold ${
                    result.behaviourDrift.deviationScore > 60
                      ? 'text-[#B91C1C]'
                      : result.behaviourDrift.deviationScore > 25
                      ? 'text-[#A16207]'
                      : 'text-[#1B6B44]'
                  }`}
                >
                  Deviation Score: {result.behaviourDrift.deviationScore}/100 (
                  {result.behaviourDrift.deviationLevel.toUpperCase()})
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="p-3.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] space-y-1 font-mono">
                  <div className="font-semibold text-[#1B6B44]">Expected Baseline Behaviour</div>
                  <div className="text-[#191919]">
                    Params: {result.behaviourDrift.baselineBehaviour.expectedParams.join(', ') || 'none'}
                  </div>
                  <div className="text-[#191919]">
                    Resources: {result.behaviourDrift.baselineBehaviour.expectedResources.join(', ')}
                  </div>
                  <div className="text-[#191919]">
                    Operations: {result.behaviourDrift.baselineBehaviour.expectedOperations.join(', ')}
                  </div>
                </div>
                <div className="p-3.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] space-y-1 font-mono">
                  <div className="font-semibold text-[#8C2635]">Observed Runtime Behaviour</div>
                  <div className="text-[#191919]">
                    Params: {result.behaviourDrift.currentBehaviour.observedParams.join(', ') || 'none'}
                  </div>
                  <div className="text-[#191919]">
                    Resources: {result.behaviourDrift.currentBehaviour.observedResources.join(', ')}
                  </div>
                  <div className="text-[#191919]">
                    Operation: {result.behaviourDrift.currentBehaviour.observedOperation} · Records:{' '}
                    {result.behaviourDrift.currentBehaviour.requestedRecords}
                  </div>
                </div>
              </div>

              {result.behaviourDrift.differences.length > 0 && (
                <div className="space-y-2">
                  {result.behaviourDrift.differences.map((d, idx) => (
                    <div
                      key={`${d.dimension}-${idx}`}
                      className="p-3 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    >
                      <div>
                        <span className="font-mono font-semibold text-[#191919]">{d.label}</span>{' '}
                        <span className="text-[#5E5A55]">· {d.detail}</span>
                      </div>
                      <span className="font-mono font-semibold text-[#B91C1C] shrink-0">+{d.weight}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Scenario 5: Visual Original vs Modified Schema Comparison */}
          {result.schemaComparison && (
            <div className="pt-5 border-t border-[#D9D5CE] space-y-4">
              <div>
                <h4 className="text-sm font-semibold text-[#191919]">
                  Tool DNA Integrity Diff: Original vs Manipulated Schema
                </h4>
                <p className="text-xs text-[#5E5A55] mt-1 font-mono">
                  Approved SHA-256:{' '}
                  <span className="text-[#1B6B44] font-medium">{result.schemaComparison.originalHash}</span>
                  <br />
                  Observed SHA-256:{' '}
                  <span className="text-[#B91C1C] font-medium">{result.schemaComparison.modifiedHash}</span>
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-xs font-mono font-medium text-[#1B6B44] mb-1.5">Original Approved Schema</div>
                  <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#1B6B44]/40 text-[11px] font-mono text-[#191919] overflow-x-auto">
                    {JSON.stringify(result.schemaComparison.originalSchema, null, 2)}
                  </pre>
                </div>
                <div>
                  <div className="text-xs font-mono font-medium text-[#B91C1C] mb-1.5">
                    Manipulated Schema (Untrusted)
                  </div>
                  <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#B91C1C]/40 text-[11px] font-mono text-[#191919] overflow-x-auto">
                    {JSON.stringify(result.schemaComparison.modifiedSchema, null, 2)}
                  </pre>
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-xs font-semibold text-[#A16207]">Detected Parameter Drift</div>
                {result.schemaComparison.diffs.map((d) => (
                  <div
                    key={d.parameter}
                    className="p-3 rounded-[2px] border border-[#A16207]/40 bg-[#A16207]/5 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                  >
                    <div>
                      <span className="font-mono font-semibold text-[#191919]">{d.parameter}</span>{' '}
                      <span className="font-mono text-[#A16207] uppercase font-medium">({d.changeType})</span>
                    </div>
                    <span className="text-[#5E5A55]">{d.riskNote}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
