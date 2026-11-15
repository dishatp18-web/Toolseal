import { useEffect, useState, type FormEvent } from 'react';
import { Play, Search } from 'lucide-react';
import { DecisionIndicator, RiskScoreValue } from '../components/DecisionLabel';
import { api, formatUtcTime } from '../lib/api';
import type { ToolExecution, UserRecord } from '../types/toolseal';

interface LiveMonitorPageProps {
  refreshSignal: number;
  userRole: UserRecord['role'];
}

export function LiveMonitorPage({ refreshSignal, userRole }: LiveMonitorPageProps) {
  const [executions, setExecutions] = useState<ToolExecution[]>([]);
  const [decisionFilter, setDecisionFilter] = useState<'ALL' | 'ALLOW' | 'REVIEW' | 'BLOCK'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const canInspect = userRole === 'admin' || userRole === 'analyst';

  const [toolName, setToolName] = useState('read_file');
  const [argsInput, setArgsInput] = useState('{\n  "path": "./docs/README.md"\n}');
  const [inspecting, setInspecting] = useState(false);
  const [inspectFeedback, setInspectFeedback] = useState<string | null>(null);
  const [inspectError, setInspectError] = useState<string | null>(null);

  const loadExecutions = async () => {
    setLoadError(null);
    try {
      const qs = decisionFilter !== 'ALL' ? `?decision=${decisionFilter}&limit=100` : '?limit=100';
      const data = await api.get<{ executions: ToolExecution[] }>(`/api/executions${qs}`);
      setExecutions(data.executions);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load live execution stream.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadExecutions();
  }, [decisionFilter, refreshSignal]);

  const handleInspectSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setInspectError(null);
    setInspectFeedback(null);

    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(argsInput);
    } catch {
      setInspectError('Arguments must be valid JSON.');
      return;
    }

    setInspecting(true);
    try {
      const res = await api.post<{
        executionUid: string;
        decision: string;
        riskScore: number;
        reason: string;
      }>('/api/executions/inspect', {
        toolName: toolName.trim(),
        arguments: parsedArgs,
        source: 'api_direct',
        agentId: 'live-console-tester',
      });
      setInspectFeedback(`${res.executionUid}: ${res.decision} (${res.riskScore}/100) — ${res.reason}`);
      await loadExecutions();
    } catch (err) {
      setInspectError(err instanceof Error ? err.message : 'Inspection failed');
    } finally {
      setInspecting(false);
    }
  };

  const filtered = executions.filter((ex) => {
    if (!searchTerm.trim()) return true;
    const q = searchTerm.toLowerCase();
    return (
      ex.tool_name.toLowerCase().includes(q) ||
      ex.execution_uid.toLowerCase().includes(q) ||
      ex.reason.toLowerCase().includes(q) ||
      ex.arguments_json.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-8">
      {/* Structured Tool Inspection Console */}
      <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5">
        <div className="border-b border-[#D9D5CE] pb-3">
          <h2 className="text-lg font-semibold text-[#191919]">Runtime Tool Inspection Console</h2>
          <p className="text-xs text-[#5E5A55] mt-1">
            Submit any MCP tool invocation directly to the deterministic Security Engine and observe live stream persistence.
          </p>
        </div>

        <form onSubmit={handleInspectSubmit} className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          <div className="lg:col-span-4 space-y-1.5">
            <label htmlFor="tool-name-input" className="block text-xs font-medium text-[#191919]">
              Tool Identifier
            </label>
            <input
              id="tool-name-input"
              type="text"
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              placeholder="e.g. get_weather, read_file, custom_tool"
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-sm font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              required
            />
          </div>

          <div className="lg:col-span-6 space-y-1.5">
            <label htmlFor="tool-args-input" className="block text-xs font-medium text-[#191919]">
              Payload Arguments (JSON)
            </label>
            <textarea
              id="tool-args-input"
              rows={2}
              value={argsInput}
              onChange={(e) => setArgsInput(e.target.value)}
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
            />
          </div>

          <div className="lg:col-span-2 lg:pt-6">
            <button
              type="submit"
              disabled={!canInspect || inspecting}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] disabled:opacity-50 text-xs font-semibold text-[#FCFBF8] transition-colors whitespace-nowrap"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{inspecting ? 'Inspecting...' : canInspect ? 'Inspect Call' : 'Read-Only'}</span>
            </button>
          </div>
        </form>

        {!canInspect && (
          <p className="text-xs font-mono text-[#5E5A55]">
            Viewer role has read-only access to the execution stream. Sign in as analyst or admin to dispatch live inspection probes.
          </p>
        )}
        {inspectError && <p className="text-xs font-mono text-[#B91C1C]">{inspectError}</p>}
        {inspectFeedback && <p className="text-xs font-mono text-[#1B6B44]">{inspectFeedback}</p>}
      </div>

      {loadError && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {loadError}
        </div>
      )}

      {/* Structured Technical Event Stream */}
      <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#D9D5CE] pb-4">
          <div className="flex items-center gap-1 p-1 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] w-fit">
            {(['ALL', 'ALLOW', 'REVIEW', 'BLOCK'] as const).map((tab) => (
              <button
                key={tab}
                type="button"
                onClick={() => setDecisionFilter(tab)}
                className={`px-3 py-1.5 rounded-[2px] text-xs font-mono font-medium transition-colors whitespace-nowrap ${
                  decisionFilter === tab
                    ? 'bg-[#FCFBF8] text-[#8C2635] border border-[#D9D5CE] font-semibold'
                    : 'text-[#5E5A55] hover:text-[#191919] border border-transparent'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>

          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 text-[#77736D] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Filter by tool, UID, or argument..."
              className="w-full pl-8 pr-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#D9D5CE] text-[#5E5A55]">
                <th className="py-2.5 pr-3 font-medium">Execution ID</th>
                <th className="py-2.5 px-3 font-medium">Tool</th>
                <th className="py-2.5 px-3 font-medium">Arguments</th>
                <th className="py-2.5 px-3 font-medium">Decision</th>
                <th className="py-2.5 px-3 font-medium text-right">Risk</th>
                <th className="py-2.5 px-3 font-medium">Status</th>
                <th className="py-2.5 px-3 font-medium">Source</th>
                <th className="py-2.5 pl-3 font-medium text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#D9D5CE]/70">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#77736D] font-mono">
                    Loading live execution stream...
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-[#77736D] font-mono">
                    No matching tool executions found.
                  </td>
                </tr>
              ) : (
                filtered.map((ex) => (
                  <tr key={ex.id} className="hover:bg-[#F7F5F0] align-top">
                    <td className="py-3 pr-3 font-mono text-[#5E5A55] whitespace-nowrap">{ex.execution_uid}</td>
                    <td className="py-3 px-3 font-mono font-medium text-[#191919] whitespace-nowrap">
                      {ex.tool_name}
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] text-[#5E5A55] max-w-xs truncate">
                      {ex.arguments_json}
                    </td>
                    <td className="py-3 px-3">
                      <DecisionIndicator decision={ex.decision} />
                    </td>
                    <td className="py-3 px-3 text-right">
                      <RiskScoreValue score={ex.risk_score} />
                    </td>
                    <td className="py-3 px-3 font-mono text-[#191919] whitespace-nowrap">{ex.execution_status}</td>
                    <td className="py-3 px-3 font-mono text-[#5E5A55] whitespace-nowrap">
                      {ex.source === 'bifrost' ? 'Bifrost Live' : ex.source === 'demo_simulator' ? 'Demo' : 'API'}
                    </td>
                    <td className="py-3 pl-3 font-mono text-[#5E5A55] text-right whitespace-nowrap">
                      {formatUtcTime(ex.created_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
