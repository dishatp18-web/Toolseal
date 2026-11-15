import { useCallback, useEffect, useState } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Eye,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldOff,
} from 'lucide-react';
import { DecisionIndicator } from '../components/DecisionLabel';
import { api, formatUtcTime } from '../lib/api';
import type {
  BehaviourBaselineSummary,
  BehaviourCurrentSummary,
  BehaviourDifference,
  BehaviourDriftAnalysis,
  BehaviourOverview,
  SecurityDecision,
  ToolBehaviourEvent,
  TriggeredRule,
  UserRecord,
} from '../types/toolseal';

interface BehaviourPageProps {
  refreshSignal: number;
  userRole: UserRecord['role'];
  onDataChanged: () => void;
}

interface DemoExecutionResponse {
  mode: string;
  label: string;
  result: {
    executionUid: string;
    riskScore: number;
    decision: SecurityDecision;
    reason: string;
    incidentUid: string | null;
    approvalRequestUid: string | null;
    behaviourDrift: BehaviourDriftAnalysis;
    triggeredRules: TriggeredRule[];
  };
}

function safeParseJson<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function DeviationScoreMeter({ score }: { score: number }) {
  const color =
    score > 60 ? 'text-[#B91C1C]' : score > 25 ? 'text-[#A16207]' : 'text-[#1B6B44]';
  return (
    <span className={`font-mono text-xs font-semibold tabular-nums whitespace-nowrap ${color}`}>
      {score}/100
    </span>
  );
}

function DeviationLevelLabel({ level }: { level: 'low' | 'medium' | 'high' }) {
  if (level === 'high') {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-[#B91C1C] uppercase">
        <ShieldOff className="w-3.5 h-3.5 shrink-0" />
        <span>High Drift</span>
      </span>
    );
  }
  if (level === 'medium') {
    return (
      <span className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-[#A16207] uppercase">
        <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
        <span>Medium Drift</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 font-mono text-xs font-medium text-[#1B6B44] uppercase">
      <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
      <span>Baseline</span>
    </span>
  );
}

export function BehaviourPage({ refreshSignal, userRole, onDataChanged }: BehaviourPageProps) {
  const [overview, setOverview] = useState<BehaviourOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTool, setSelectedTool] = useState<string>('');
  const [eventFilter, setEventFilter] = useState<'all' | 'anomalies' | 'normal'>('all');
  const [runningDemo, setRunningDemo] = useState<string | null>(null);
  const [demoResult, setDemoResult] = useState<DemoExecutionResponse | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<ToolBehaviourEvent | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const isAdmin = userRole === 'admin';
  const canRunDemo = userRole === 'admin' || userRole === 'analyst';

  const loadData = useCallback(async () => {
    try {
      const qs = selectedTool ? `?toolName=${encodeURIComponent(selectedTool)}` : '';
      const res = await api.get<BehaviourOverview>(`/api/behaviour/overview${qs}`);
      setOverview(res);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to load behavioural intelligence data.');
    } finally {
      setLoading(false);
    }
  }, [selectedTool]);

  useEffect(() => {
    loadData();
  }, [loadData, refreshSignal]);

  const runDemo = async (
    mode: 'weather_baseline' | 'weather_customer_db_drift' | 'weather_frequency_spike'
  ) => {
    setRunningDemo(mode);
    setActionError(null);
    try {
      const res = await api.post<DemoExecutionResponse>('/api/behaviour/demo', { mode });
      setDemoResult(res);
      onDataChanged();
      await loadData();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to run behavioural drift demonstration.');
    } finally {
      setRunningDemo(null);
    }
  };

  const resetBaselineCounters = async (toolName: string) => {
    setActionError(null);
    try {
      await api.post(`/api/behaviour/profiles/${encodeURIComponent(toolName)}/reset-baseline`, {});
      onDataChanged();
      await loadData();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to reset baseline counters.');
    }
  };

  if (loading && !overview) {
    return (
      <div className="space-y-6">
        <div className="h-24 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] animate-pulse" />
        <div className="h-80 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] animate-pulse" />
      </div>
    );
  }

  if (!overview) {
    return (
      <div className="p-8 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] text-center text-xs text-[#B91C1C]">
        {actionError || 'Unable to load Behavioural Intelligence data.'}
      </div>
    );
  }

  const { summary, profiles, recentEvents, timeline, toolComparison, thresholds } = overview;

  const filteredEvents = recentEvents.filter((ev) => {
    if (eventFilter === 'anomalies') return ev.is_anomalous === 1;
    if (eventFilter === 'normal') return ev.is_anomalous === 0;
    return true;
  });

  const statLedger = [
    { label: 'Monitored Tools', value: summary.monitoredTools, tone: 'text-[#191919]' },
    { label: 'Normal Activity', value: summary.normalEventsCount, tone: 'text-[#1B6B44]' },
    { label: 'Unusual / Drift Events', value: summary.anomaliesDetected, tone: 'text-[#B91C1C]' },
    { label: 'High-Drift Alerts', value: summary.highDriftAlerts, tone: 'text-[#B91C1C]' },
    { label: 'Avg Deviation Score', value: `${summary.avgDeviationScore}`, suffix: '/100', tone: 'text-[#8C2635]' },
  ];

  // Parse inspected event details
  const inspectedBaseline = selectedEvent
    ? safeParseJson<BehaviourBaselineSummary | null>(selectedEvent.baseline_snapshot_json, null)
    : null;
  const inspectedCurrent = selectedEvent
    ? safeParseJson<BehaviourCurrentSummary | null>(selectedEvent.current_snapshot_json, null)
    : null;
  const inspectedDiffs = selectedEvent
    ? safeParseJson<BehaviourDifference[]>(selectedEvent.differences_json, [])
    : [];
  const inspectedRules = selectedEvent
    ? safeParseJson<TriggeredRule[]>(selectedEvent.triggered_rules_json, [])
    : [];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-[#D9D5CE] pb-5">
        <div>
          <p className="text-xs font-mono text-[#8C2635] font-medium">
            Baseline Learning &amp; Runtime Anomaly Detection
          </p>
          <h2 className="text-2xl font-semibold text-[#191919] mt-1">Behavioural Intelligence</h2>
          <p className="text-xs text-[#5E5A55] mt-1.5 font-mono">
            Low ≤ {thresholds.drift_low_max} (Allow) · Medium ≤ {thresholds.drift_medium_max} (Review) · High &gt;{' '}
            {thresholds.drift_medium_max} ({thresholds.drift_high_action}) · Frequency Limit:{' '}
            {thresholds.drift_frequency_multiplier}x Baseline RPM
          </p>
        </div>
        {selectedTool && (
          <button
            type="button"
            onClick={() => setSelectedTool('')}
            className="px-3.5 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] hover:border-[#191919] text-xs font-medium text-[#191919] whitespace-nowrap shrink-0"
          >
            Clear Filter ({selectedTool})
          </button>
        )}
      </div>

      {actionError && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {actionError}
        </div>
      )}

      {/* Swiss 5-Column Behavioural Ledger */}
      <div className="grid grid-cols-2 md:grid-cols-5 border border-[#D9D5CE] bg-[#FCFBF8] rounded-[2px] divide-y md:divide-y-0 md:divide-x divide-[#D9D5CE]">
        {statLedger.map((item) => (
          <div key={item.label} className="p-5 flex flex-col justify-between">
            <span className="text-xs text-[#5E5A55]">{item.label}</span>
            <div className={`mt-3 text-2xl font-semibold font-mono tabular-nums ${item.tone}`}>
              {item.value}
              {item.suffix && <span className="text-xs text-[#77736D] ml-0.5">{item.suffix}</span>}
            </div>
          </div>
        ))}
      </div>

      {/* Working Demonstration: Weather Tool Behavioural Drift */}
      <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#D9D5CE] pb-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono text-[#8C2635] font-semibold">
              <span>Interactive Demonstration · Source: Simulation</span>
            </div>
            <h3 className="text-base font-semibold text-[#191919] mt-1">
              Weather Tool Behavioural Drift (get_weather → Customer Database Access)
            </h3>
            <p className="text-xs text-[#5E5A55] mt-1">
              The weather tool is baselined to read meteorological forecasts using only <span className="font-mono text-[#191919]">city</span> and{' '}
              <span className="font-mono text-[#191919]">units</span>. Trigger a baseline call or simulate the compromised tool suddenly requesting{' '}
              <span className="font-mono text-[#B91C1C]">customer_database</span> records.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              disabled={!canRunDemo || Boolean(runningDemo)}
              onClick={() => runDemo('weather_baseline')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#1B6B44] text-xs font-medium text-[#191919] disabled:opacity-50 whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5 text-[#1B6B44]" />
              <span>{runningDemo === 'weather_baseline' ? 'Running...' : '1. Normal Weather Call'}</span>
            </button>
            <button
              type="button"
              disabled={!canRunDemo || Boolean(runningDemo)}
              onClick={() => runDemo('weather_customer_db_drift')}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] text-xs font-semibold text-[#FCFBF8] disabled:opacity-50 whitespace-nowrap"
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>
                {runningDemo === 'weather_customer_db_drift'
                  ? 'Analyzing Drift...'
                  : '2. Simulate Customer DB Drift'}
              </span>
            </button>
            <button
              type="button"
              disabled={!canRunDemo || Boolean(runningDemo)}
              onClick={() => runDemo('weather_frequency_spike')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#A16207] text-xs font-medium text-[#191919] disabled:opacity-50 whitespace-nowrap"
            >
              <Activity className="w-3.5 h-3.5 text-[#A16207]" />
              <span>
                {runningDemo === 'weather_frequency_spike' ? 'Bursting...' : '3. Simulate Frequency Burst'}
              </span>
            </button>
          </div>
        </div>

        {/* Live Explainable Demo Output */}
        {demoResult && (
          <div className="space-y-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-4 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE]">
              <div>
                <div className="text-[11px] font-mono text-[#5E5A55]">
                  {demoResult.label} · Execution {demoResult.result.executionUid}
                  {demoResult.result.incidentUid ? ` · Incident ${demoResult.result.incidentUid}` : ''}
                </div>
                <p className="text-xs text-[#191919] mt-1 font-medium">{demoResult.result.reason}</p>
              </div>
              <div className="flex items-center gap-6 shrink-0">
                <div>
                  <span className="text-[11px] text-[#5E5A55] block">Deviation Score</span>
                  <DeviationScoreMeter score={demoResult.result.behaviourDrift.deviationScore} />
                </div>
                <div>
                  <span className="text-[11px] text-[#5E5A55] block">Unified Risk</span>
                  <DeviationScoreMeter score={demoResult.result.riskScore} />
                </div>
                <div>
                  <span className="text-[11px] text-[#5E5A55] block">Decision</span>
                  <DecisionIndicator decision={demoResult.result.decision} />
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Baseline Behaviour */}
              <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] space-y-2">
                <div className="text-xs font-semibold text-[#1B6B44] font-mono">
                  Established Baseline Behaviour ({demoResult.result.behaviourDrift.baselineBehaviour.sampleCount} samples)
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Expected Params</span>
                    <span className="font-mono text-[#191919]">
                      {demoResult.result.behaviourDrift.baselineBehaviour.expectedParams.join(', ')}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Normal Resources</span>
                    <span className="font-mono text-[#191919]">
                      {demoResult.result.behaviourDrift.baselineBehaviour.expectedResources.join(', ')}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Normal Operations</span>
                    <span className="font-mono text-[#191919]">
                      {demoResult.result.behaviourDrift.baselineBehaviour.expectedOperations.join(', ')}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Baseline Frequency / Volume</span>
                    <span className="font-mono text-[#191919]">
                      {demoResult.result.behaviourDrift.baselineBehaviour.baselineRpm}/min · max{' '}
                      {demoResult.result.behaviourDrift.baselineBehaviour.normalMaxRecords} rec
                    </span>
                  </div>
                </div>
              </div>

              {/* Current Observed Behaviour */}
              <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] space-y-2">
                <div
                  className={`text-xs font-semibold font-mono ${
                    demoResult.result.behaviourDrift.isAnomalous ? 'text-[#B91C1C]' : 'text-[#1B6B44]'
                  }`}
                >
                  Current Observed Behaviour ({demoResult.result.behaviourDrift.deviationLevel.toUpperCase()} DEVIATION)
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Observed Params</span>
                    <span className="font-mono text-[#191919] break-all">
                      {demoResult.result.behaviourDrift.currentBehaviour.observedParams.join(', ')}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Accessed Resources</span>
                    <span className="font-mono text-[#191919] break-all">
                      {demoResult.result.behaviourDrift.currentBehaviour.observedResources.join(', ')}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Observed Operation</span>
                    <span className="font-mono text-[#191919]">
                      {demoResult.result.behaviourDrift.currentBehaviour.observedOperation}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#5E5A55] block text-[11px]">Current Rate / Volume</span>
                    <span className="font-mono text-[#191919]">
                      {demoResult.result.behaviourDrift.currentBehaviour.currentRpm}/min ·{' '}
                      {demoResult.result.behaviourDrift.currentBehaviour.requestedRecords} rec
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Detected Differences */}
            {demoResult.result.behaviourDrift.differences.length > 0 && (
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-[#191919]">
                  Detected Behavioural Differences ({demoResult.result.behaviourDrift.differences.length})
                </h4>
                <div className="overflow-x-auto border border-[#D9D5CE] rounded-[2px]">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-[#F7F5F0] border-b border-[#D9D5CE] text-[#5E5A55]">
                      <tr>
                        <th className="py-2 px-3 font-medium">Dimension</th>
                        <th className="py-2 px-3 font-medium">Baseline Expected</th>
                        <th className="py-2 px-3 font-medium">Observed Runtime</th>
                        <th className="py-2 px-3 font-medium text-right">Drift Weight</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#D9D5CE]/70 bg-[#FCFBF8]">
                      {demoResult.result.behaviourDrift.differences.map((diff, idx) => (
                        <tr key={`${diff.dimension}-${idx}`}>
                          <td className="py-2 px-3 font-semibold text-[#191919] whitespace-nowrap">
                            {diff.label}
                          </td>
                          <td className="py-2 px-3 font-mono text-[#1B6B44]">{diff.expected}</td>
                          <td className="py-2 px-3 font-mono text-[#B91C1C]">{diff.observed}</td>
                          <td className="py-2 px-3 font-mono text-right font-semibold text-[#8C2635]">
                            +{diff.weight}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Charts: Deviation Timeline & Normal vs Unusual Activity */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
          <div className="mb-5 border-b border-[#D9D5CE]/70 pb-3">
            <h3 className="text-sm font-semibold text-[#191919]">Behavioural Deviation Score Timeline</h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">
              Average and peak behavioural drift scores across runtime intervals
            </p>
          </div>
          <div className="h-64 w-full">
            {timeline.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#77736D] font-mono">
                No behavioural events recorded yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="driftBurgundyGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#8C2635" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#8C2635" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#D9D5CE" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="bucket" stroke="#77736D" fontSize={11} tickLine={false} />
                  <YAxis stroke="#77736D" fontSize={11} tickLine={false} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FCFBF8',
                      borderColor: '#D9D5CE',
                      borderRadius: '2px',
                      fontSize: '12px',
                      color: '#191919',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="maxDeviation"
                    name="Peak Deviation"
                    stroke="#B91C1C"
                    strokeWidth={1.5}
                    strokeDasharray="4 4"
                    fill="none"
                  />
                  <Area
                    type="monotone"
                    dataKey="avgDeviation"
                    name="Avg Deviation"
                    stroke="#8C2635"
                    strokeWidth={2}
                    fill="url(#driftBurgundyGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
          <div className="mb-5 border-b border-[#D9D5CE]/70 pb-3">
            <h3 className="text-sm font-semibold text-[#191919]">Normal vs Unusual Activity</h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">Baseline calls vs detected anomalies per tool</p>
          </div>
          <div className="h-64 w-full">
            {toolComparison.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#77736D] font-mono">
                No comparative tool telemetry recorded yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={toolComparison} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
                  <CartesianGrid stroke="#D9D5CE" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="toolName" stroke="#5E5A55" fontSize={10} tickLine={false} />
                  <YAxis stroke="#77736D" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FCFBF8',
                      borderColor: '#D9D5CE',
                      borderRadius: '2px',
                      fontSize: '12px',
                      color: '#191919',
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: '11px' }} />
                  <Bar dataKey="normalCount" name="Normal Baseline" fill="#1B6B44" radius={[2, 2, 0, 0]} barSize={14} />
                  <Bar dataKey="unusualCount" name="Unusual Drift" fill="#B91C1C" radius={[2, 2, 0, 0]} barSize={14} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Learned Tool Behaviour Profiles */}
      <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 border-b border-[#D9D5CE]/70 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#191919]">Tool Behaviour Profiles (SQLite Learned Baselines)</h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">
              Click any tool row to filter its activity timeline and inspect baseline parameters
            </p>
          </div>
          <span className="text-xs font-mono text-[#5E5A55]">{profiles.length} profiled tools</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#D9D5CE] text-[#5E5A55]">
                <th className="py-2.5 pr-3 font-medium">Tool Name</th>
                <th className="py-2.5 px-3 font-medium">Normal Parameters</th>
                <th className="py-2.5 px-3 font-medium">Normal Resources</th>
                <th className="py-2.5 px-3 font-medium">Operations</th>
                <th className="py-2.5 px-3 font-medium text-right">Baseline RPM</th>
                <th className="py-2.5 px-3 font-medium text-right">Samples</th>
                <th className="py-2.5 px-3 font-medium text-right">Anomalies</th>
                <th className="py-2.5 px-3 font-medium text-right">Last Drift</th>
                <th className="py-2.5 pl-3 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#D9D5CE]/70">
              {profiles.map((p) => {
                const params = safeParseJson<string[]>(p.normal_param_keys_json, []);
                const resources = safeParseJson<string[]>(p.normal_resources_json, []);
                const ops = safeParseJson<string[]>(p.normal_operations_json, []);
                const isSelected = selectedTool === p.tool_name;

                return (
                  <tr
                    key={p.id}
                    onClick={() => setSelectedTool(isSelected ? '' : p.tool_name)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? 'bg-[#8C2635]/5' : 'hover:bg-[#F7F5F0]'
                    }`}
                  >
                    <td className="py-2.5 pr-3 font-mono font-semibold text-[#191919] whitespace-nowrap">
                      {p.tool_name}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#5E5A55]">{params.join(', ') || 'none'}</td>
                    <td className="py-2.5 px-3 font-mono text-[#5E5A55]">{resources.join(', ')}</td>
                    <td className="py-2.5 px-3 font-mono text-[#191919]">{ops.join(', ')}</td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-right text-[#5E5A55]">
                      {p.baseline_rpm}/m
                    </td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-right text-[#1B6B44] font-medium">
                      {p.total_baseline_executions}
                    </td>
                    <td
                      className={`py-2.5 px-3 font-mono tabular-nums text-right font-semibold ${
                        p.anomaly_count > 0 ? 'text-[#B91C1C]' : 'text-[#5E5A55]'
                      }`}
                    >
                      {p.anomaly_count}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <DeviationScoreMeter score={p.last_deviation_score} />
                    </td>
                    <td className="py-2.5 pl-3 text-right">
                      <button
                        type="button"
                        disabled={!isAdmin}
                        onClick={(e) => {
                          e.stopPropagation();
                          resetBaselineCounters(p.tool_name);
                        }}
                        title={isAdmin ? 'Reset anomaly counters for this tool' : 'Administrator privileges required'}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#191919] disabled:opacity-50 text-[11px] font-medium text-[#191919]"
                      >
                        <RotateCcw className="w-3 h-3" />
                        <span>Clear Alerts</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Anomaly History & Activity Log */}
      <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#D9D5CE]/70 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#191919]">
              Behavioural Anomaly History &amp; Activity Stream
              {selectedTool ? ` (${selectedTool})` : ''}
            </h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">
              Select any record to inspect baseline vs observed behaviour and triggered drift rules
            </p>
          </div>
          <div className="inline-flex border border-[#D9D5CE] rounded-[2px] bg-[#F7F5F0] p-0.5 shrink-0">
            {[
              { id: 'all', label: 'All Events' },
              { id: 'anomalies', label: 'Anomalies Only' },
              { id: 'normal', label: 'Baseline Normal' },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setEventFilter(tab.id as 'all' | 'anomalies' | 'normal')}
                className={`px-3 py-1 text-xs font-medium rounded-[2px] transition-colors whitespace-nowrap ${
                  eventFilter === tab.id
                    ? 'bg-[#FCFBF8] text-[#191919] border border-[#D9D5CE]'
                    : 'text-[#5E5A55] hover:text-[#191919]'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#D9D5CE] text-[#5E5A55]">
                <th className="py-2.5 pr-3 font-medium">Event ID</th>
                <th className="py-2.5 px-3 font-medium">Tool</th>
                <th className="py-2.5 px-3 font-medium">Origin</th>
                <th className="py-2.5 px-3 font-medium">Drift Status</th>
                <th className="py-2.5 px-3 font-medium text-right">Deviation</th>
                <th className="py-2.5 px-3 font-medium">Response</th>
                <th className="py-2.5 px-3 font-medium">Summary</th>
                <th className="py-2.5 pl-3 font-medium text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#D9D5CE]/70">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#77736D]">
                    No behavioural drift events match the selected filter.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => {
                  const diffs = safeParseJson<BehaviourDifference[]>(ev.differences_json, []);
                  return (
                    <tr
                      key={ev.id}
                      onClick={() => setSelectedEvent(ev)}
                      className={`cursor-pointer transition-colors ${
                        selectedEvent?.id === ev.id ? 'bg-[#8C2635]/5' : 'hover:bg-[#F7F5F0]'
                      }`}
                    >
                      <td className="py-2.5 pr-3 font-mono text-[#5E5A55] whitespace-nowrap">{ev.event_uid}</td>
                      <td className="py-2.5 px-3 font-mono font-semibold text-[#191919] whitespace-nowrap">
                        {ev.tool_name}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[#5E5A55] whitespace-nowrap">
                        {ev.source === 'demo_simulator'
                          ? 'Simulation'
                          : ev.source === 'bifrost'
                          ? 'Bifrost Live'
                          : 'API Direct'}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <DeviationLevelLabel level={ev.deviation_level} />
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <DeviationScoreMeter score={ev.deviation_score} />
                      </td>
                      <td className="py-2.5 px-3">
                        <DecisionIndicator decision={ev.decision} />
                      </td>
                      <td className="py-2.5 px-3 text-[#5E5A55] max-w-xs truncate">
                        {diffs.length > 0
                          ? diffs.map((d) => d.label).join(' · ')
                          : 'Aligned with learned tool baseline'}
                      </td>
                      <td className="py-2.5 pl-3 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(ev);
                          }}
                          className="inline-flex items-center gap-1 text-xs font-medium text-[#8C2635] hover:underline"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Inspect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Explainable Selected Event Comparison Drawer / Panel */}
      {selectedEvent && inspectedBaseline && inspectedCurrent && (
        <div className="p-6 rounded-[2px] border border-[#8C2635] bg-[#FCFBF8] space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#D9D5CE] pb-4">
            <div>
              <div className="text-xs font-mono text-[#5E5A55]">
                {selectedEvent.event_uid} ·{' '}
                {selectedEvent.source === 'demo_simulator' ? 'SIMULATION EVENT' : 'RUNTIME EVENT'} ·{' '}
                {formatUtcTime(selectedEvent.created_at)}
              </div>
              <h3 className="text-base font-semibold text-[#191919] mt-1">
                Explainable Drift Report: <span className="font-mono">{selectedEvent.tool_name}</span>
              </h3>
            </div>
            <div className="flex items-center gap-6">
              <div>
                <span className="text-[11px] text-[#5E5A55] block">Deviation Score</span>
                <DeviationScoreMeter score={selectedEvent.deviation_score} />
              </div>
              <div>
                <span className="text-[11px] text-[#5E5A55] block">Decision</span>
                <DecisionIndicator decision={selectedEvent.decision} />
              </div>
              <button
                type="button"
                onClick={() => setSelectedEvent(null)}
                className="px-3 py-1.5 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] text-xs font-medium text-[#191919]"
              >
                Close
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] space-y-1.5 text-xs">
              <div className="font-mono font-semibold text-[#1B6B44]">Baseline Behaviour Snapshot</div>
              <p className="font-mono text-[#191919]">
                Params: {inspectedBaseline.expectedParams.join(', ') || 'none'}
              </p>
              <p className="font-mono text-[#191919]">
                Resources: {inspectedBaseline.expectedResources.join(', ')}
              </p>
              <p className="font-mono text-[#191919]">
                Operations: {inspectedBaseline.expectedOperations.join(', ')} · Rate: {inspectedBaseline.baselineRpm}/min
              </p>
            </div>

            <div className="p-4 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] space-y-1.5 text-xs">
              <div className="font-mono font-semibold text-[#8C2635]">Current Execution Snapshot</div>
              <p className="font-mono text-[#191919]">
                Params: {inspectedCurrent.observedParams.join(', ') || 'none'}
              </p>
              <p className="font-mono text-[#191919]">
                Resources: {inspectedCurrent.observedResources.join(', ')}
              </p>
              <p className="font-mono text-[#191919]">
                Operation: {inspectedCurrent.observedOperation} · Rate: {inspectedCurrent.currentRpm}/min · Records:{' '}
                {inspectedCurrent.requestedRecords}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-[#191919]">Detected Differences &amp; Triggered Rules</h4>
              {inspectedDiffs.length === 0 ? (
                <p className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#1B6B44]">
                  No behavioural deviations detected. Execution matched learned baseline profile.
                </p>
              ) : (
                <div className="space-y-2">
                  {inspectedDiffs.map((d, idx) => (
                    <div
                      key={`${d.dimension}-${idx}`}
                      className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs space-y-1"
                    >
                      <div className="flex items-center justify-between font-mono font-semibold">
                        <span className="text-[#191919]">{d.label}</span>
                        <span className="text-[#B91C1C]">+{d.weight}</span>
                      </div>
                      <p className="text-[#5E5A55]">{d.detail}</p>
                    </div>
                  ))}
                  {inspectedRules.map((r) => (
                    <div key={r.id} className="text-[11px] font-mono text-[#8C2635]">
                      Rule Triggered: {r.id} ({r.name})
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-[#191919]">Inspected Execution Arguments</h4>
              <pre className="p-3.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto">
                {JSON.stringify(safeParseJson(selectedEvent.arguments_json, {}), null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
