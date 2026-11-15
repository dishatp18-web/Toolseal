import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ArrowRight, RefreshCw, ShieldAlert, ShieldCheck } from 'lucide-react';
import { DecisionIndicator, RiskScoreValue, SeverityText } from '../components/DecisionLabel';
import { QaVerificationPanel } from '../components/QaVerificationPanel';
import { formatUtcTime } from '../lib/api';
import type { DashboardOverview, UserRecord } from '../types/toolseal';
import type { NavPage } from '../components/Layout';

interface DashboardPageProps {
  data: DashboardOverview | null;
  loading: boolean;
  error: string | null;
  userRole: UserRecord['role'];
  onRefresh: () => void;
  onNavigate: (page: NavPage) => void;
}

export function DashboardPage({ data, loading, error, userRole, onRefresh, onNavigate }: DashboardPageProps) {
  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 lg:grid-cols-6 border border-[#D9D5CE] bg-[#FCFBF8]">
          {Array.from({ length: 6 }).map((_, idx) => (
            <div key={idx} className="h-24 border-r border-[#D9D5CE] last:border-r-0 animate-pulse bg-[#EFECE5]/50" />
          ))}
        </div>
        <div className="h-80 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] animate-pulse" />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-8 rounded-[2px] border border-[#B91C1C]/40 bg-[#FCFBF8] text-center space-y-3">
        <p className="text-sm font-medium text-[#B91C1C]">
          {error || 'Unable to load security telemetry from SQLite backend.'}
        </p>
        <button
          type="button"
          onClick={onRefresh}
          className="px-4 py-2 rounded-[2px] bg-[#191919] text-xs font-medium text-[#FCFBF8]"
        >
          Retry Sync
        </button>
      </div>
    );
  }

  const {
    metrics,
    behaviourSummary,
    threatDistribution,
    riskTrend,
    toolUsage,
    recentIncidents,
    liveFeed,
    activePolicy,
    bifrostStatus,
  } = data;

  const statCards = [
    { label: 'Total Executions', value: metrics.totalExecutions, tone: 'text-[#191919]' },
    { label: 'Allowed Operations', value: metrics.allowedOperations, tone: 'text-[#1B6B44]' },
    { label: 'Blocked Threats', value: metrics.blockedOperations, tone: 'text-[#B91C1C]' },
    { label: 'Pending Approvals', value: metrics.pendingApprovals, tone: 'text-[#A16207]' },
    { label: 'Active Incidents', value: metrics.activeIncidents, tone: 'text-[#B91C1C]' },
    { label: 'Average Risk Score', value: `${metrics.averageRiskScore}`, suffix: '/100', tone: 'text-[#8C2635]' },
  ];

  return (
    <div className="space-y-8">
      {/* Editorial Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-[#D9D5CE] pb-5">
        <div>
          <p className="text-xs font-mono text-[#8C2635] font-medium">Continuous Trust Verification</p>
          <h2 className="text-2xl font-semibold text-[#191919] mt-1">Runtime Security Posture</h2>
          <p className="text-xs text-[#5E5A55] mt-1.5 font-mono">
            Policy: {activePolicy.name} · Trusted Tools: {metrics.trustedToolsCount} · Flagged Tools:{' '}
            {metrics.modifiedToolsCount} · Drift Anomalies: {behaviourSummary?.anomaliesDetected ?? 0} · Bifrost:{' '}
            {bifrostStatus.mode === 'live' ? 'Live Hook' : 'Demo Mode'}
          </p>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] hover:border-[#191919] text-xs font-medium text-[#191919] transition-colors whitespace-nowrap shrink-0"
        >
          <RefreshCw className="w-3.5 h-3.5 text-[#8C2635]" />
          <span>Refresh Telemetry</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {error}
        </div>
      )}

      {/* Swiss 6-Column Metric Ledger */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 border border-[#D9D5CE] bg-[#FCFBF8] rounded-[2px] divide-y md:divide-y-0 md:divide-x divide-[#D9D5CE]">
        {statCards.map((card) => (
          <div key={card.label} className="p-5 flex flex-col justify-between">
            <span className="text-xs text-[#5E5A55]">{card.label}</span>
            <div className={`mt-3 text-2xl font-semibold font-mono tabular-nums ${card.tone}`}>
              {card.value}
              {card.suffix && <span className="text-xs text-[#77736D] ml-0.5">{card.suffix}</span>}
            </div>
          </div>
        ))}
      </div>

      {/* System Security Posture Bar */}
      <div className="p-5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start sm:items-center gap-3">
          {metrics.modifiedToolsCount > 0 || metrics.activeIncidents > 0 ? (
            <ShieldAlert className="w-5 h-5 text-[#A16207] shrink-0 mt-0.5 sm:mt-0" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-[#1B6B44] shrink-0 mt-0.5 sm:mt-0" />
          )}
          <div>
            <p className="text-sm font-semibold text-[#191919]">
              {metrics.modifiedToolsCount > 0
                ? `${metrics.modifiedToolsCount} tool(s) flagged for Tool DNA drift · ${metrics.activeIncidents} open security incident(s)`
                : `All registered MCP tools verified · ${metrics.activeIncidents} open incident(s) under monitoring`}
            </p>
            <p className="text-xs text-[#5E5A55] mt-0.5 font-mono">
              Risk Thresholds: Allow ≤ {activePolicy.allow_max_risk} · Review ≤ {activePolicy.review_max_risk} · Drift
              Profiles: {behaviourSummary?.monitoredTools ?? 0} tools (avg deviation{' '}
              {behaviourSummary?.avgDeviationScore ?? 0}/100, {behaviourSummary?.highDriftAlerts ?? 0} high-drift)
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 shrink-0">
          {metrics.pendingApprovals > 0 && (
            <button
              type="button"
              onClick={() => onNavigate('approvals')}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] text-xs font-medium text-[#FCFBF8] whitespace-nowrap"
            >
              <span>Review {metrics.pendingApprovals} Pending</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
          <button
            type="button"
            onClick={() => onNavigate('behaviour')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#8C2635] text-xs font-medium text-[#191919] whitespace-nowrap"
          >
            <span>Behavioural Drift</span>
          </button>
          <button
            type="button"
            onClick={() => onNavigate('tooldna')}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#191919] text-xs font-medium text-[#191919] whitespace-nowrap"
          >
            <span>Inspect Tool DNA</span>
          </button>
        </div>
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
          <div className="mb-5 border-b border-[#D9D5CE]/70 pb-3">
            <h3 className="text-sm font-semibold text-[#191919]">Risk Score &amp; Enforcement Trend</h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">Average risk score across persisted runtime intervals</p>
          </div>
          <div className="h-64 w-full">
            {riskTrend.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#77736D] font-mono">
                No execution trend buckets recorded yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={riskTrend} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="swissRiskGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#8C2635" stopOpacity={0.18} />
                      <stop offset="95%" stopColor="#8C2635" stopOpacity={0.01} />
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
                    dataKey="avgRisk"
                    name="Avg Risk Score"
                    stroke="#8C2635"
                    strokeWidth={2}
                    fill="url(#swissRiskGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
          <div className="mb-5 border-b border-[#D9D5CE]/70 pb-3">
            <h3 className="text-sm font-semibold text-[#191919]">Threat Category Distribution</h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">Persisted security incident classification</p>
          </div>
          <div className="h-64 w-full">
            {threatDistribution.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-[#77736D] font-mono">
                No security incidents logged yet.
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={threatDistribution}
                  layout="vertical"
                  margin={{ top: 4, right: 16, left: 10, bottom: 0 }}
                >
                  <CartesianGrid stroke="#D9D5CE" strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" stroke="#77736D" fontSize={11} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="category"
                    stroke="#191919"
                    fontSize={11}
                    width={120}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#FCFBF8',
                      borderColor: '#D9D5CE',
                      borderRadius: '2px',
                      fontSize: '12px',
                      color: '#191919',
                    }}
                  />
                  <Bar dataKey="count" name="Incidents" fill="#B91C1C" radius={[0, 2, 2, 0]} barSize={14} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Tool Usage Analytics + Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
          <div className="flex items-center justify-between mb-4 border-b border-[#D9D5CE]/70 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-[#191919]">Tool Usage Analytics</h3>
              <p className="text-xs text-[#5E5A55] mt-0.5">Invocation volume and block ratio per MCP tool</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('tooldna')}
              className="text-xs text-[#8C2635] hover:underline font-medium"
            >
              Open Registry
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#D9D5CE] text-[#5E5A55]">
                  <th className="py-2.5 pr-3 font-medium">Tool</th>
                  <th className="py-2.5 px-3 font-medium text-right">Calls</th>
                  <th className="py-2.5 px-3 font-medium text-right">Allowed</th>
                  <th className="py-2.5 px-3 font-medium text-right">Blocked</th>
                  <th className="py-2.5 pl-3 font-medium text-right">Avg Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#D9D5CE]/70">
                {toolUsage.map((row) => (
                  <tr key={row.toolName} className="hover:bg-[#F7F5F0]">
                    <td className="py-2.5 pr-3 font-mono text-[#191919]">{row.toolName}</td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-right text-[#191919]">{row.total}</td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-right text-[#1B6B44]">
                      {row.allowed}
                    </td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-right text-[#B91C1C]">{row.blocked}</td>
                    <td className="py-2.5 pl-3 text-right">
                      <RiskScoreValue score={Math.round(row.avgRisk)} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
          <div className="flex items-center justify-between mb-4 border-b border-[#D9D5CE]/70 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-[#191919]">Recent Security Incidents</h3>
              <p className="text-xs text-[#5E5A55] mt-0.5">Latest flagged or blocked tool invocations</p>
            </div>
            <button
              type="button"
              onClick={() => onNavigate('incidents')}
              className="text-xs text-[#8C2635] hover:underline font-medium"
            >
              All Incidents
            </button>
          </div>
          <div className="divide-y divide-[#D9D5CE]/70">
            {recentIncidents.length === 0 ? (
              <p className="py-8 text-center text-xs text-[#77736D]">No security incidents recorded.</p>
            ) : (
              recentIncidents.map((inc) => (
                <div key={inc.id} className="py-3 flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 text-xs">
                      <span className="font-mono text-[#191919] font-semibold">{inc.incident_uid}</span>
                      <span className="text-[#D9D5CE]">·</span>
                      <span className="font-mono text-[#191919] truncate">{inc.tool_name}</span>
                      <span className="text-[#D9D5CE]">·</span>
                      <SeverityText severity={inc.severity} />
                    </div>
                    <p className="text-xs text-[#5E5A55] mt-1 line-clamp-1">{inc.explanation}</p>
                    <div className="text-[11px] font-mono text-[#77736D] mt-1">
                      {inc.threat_category} · {inc.source === 'bifrost' ? 'Bifrost Live' : 'Demo / Simulator'} ·{' '}
                      {formatUtcTime(inc.created_at)}
                    </div>
                  </div>
                  <div className="shrink-0 text-right">
                    <DecisionIndicator decision={inc.decision} />
                    <div className="mt-1">
                      <RiskScoreValue score={inc.risk_score} />
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Live Activity Feed */}
      <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
        <div className="flex items-center justify-between mb-4 border-b border-[#D9D5CE]/70 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-[#191919]">Live Tool Execution Stream</h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">Real-time WebSocket feed backed by SQLite</p>
          </div>
          <button
            type="button"
            onClick={() => onNavigate('monitor')}
            className="text-xs text-[#8C2635] hover:underline font-medium"
          >
            Open Live Console
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#D9D5CE] text-[#5E5A55]">
                <th className="py-2.5 pr-3 font-medium">Execution ID</th>
                <th className="py-2.5 px-3 font-medium">Tool</th>
                <th className="py-2.5 px-3 font-medium">Source</th>
                <th className="py-2.5 px-3 font-medium">Decision</th>
                <th className="py-2.5 px-3 font-medium text-right">Risk</th>
                <th className="py-2.5 px-3 font-medium">Reason</th>
                <th className="py-2.5 pl-3 font-medium text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#D9D5CE]/70">
              {liveFeed.slice(0, 8).map((item) => (
                <tr key={item.id} className="hover:bg-[#F7F5F0]">
                  <td className="py-2.5 pr-3 font-mono text-[#5E5A55] whitespace-nowrap">{item.execution_uid}</td>
                  <td className="py-2.5 px-3 font-mono font-medium text-[#191919] whitespace-nowrap">
                    {item.tool_name}
                  </td>
                  <td className="py-2.5 px-3 font-mono text-[#5E5A55] whitespace-nowrap">
                    {item.source === 'bifrost' ? 'Bifrost' : item.source === 'demo_simulator' ? 'Simulator' : 'API'}
                  </td>
                  <td className="py-2.5 px-3">
                    <DecisionIndicator decision={item.decision} />
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <RiskScoreValue score={item.risk_score} />
                  </td>
                  <td className="py-2.5 px-3 text-[#191919] max-w-md truncate">{item.reason}</td>
                  <td className="py-2.5 pl-3 font-mono text-[#5E5A55] text-right whitespace-nowrap">
                    {formatUtcTime(item.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Runtime QA & Module Verification Matrix */}
      <QaVerificationPanel userRole={userRole} />
    </div>
  );
}
