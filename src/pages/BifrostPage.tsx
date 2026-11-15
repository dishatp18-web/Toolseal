import { useEffect, useState, type FormEvent } from 'react';
import {
  Activity,
  Check,
  Copy,
  Lock,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Terminal,
} from 'lucide-react';
import { api, formatUtcTime, getClientSessionToken } from '../lib/api';
import type {
  BifrostConfig,
  BifrostLiveVerificationResult,
  BifrostTelemetry,
  IntegrationLog,
  UserRecord,
} from '../types/toolseal';

interface BifrostPageProps {
  refreshSignal: number;
  userRole: UserRecord['role'];
  onConfigChanged: () => void;
}

const PLUGIN_STATUS_LABELS: Record<BifrostTelemetry['pluginLoadingStatus'], string> = {
  active_live: 'ACTIVE (LIVE HOOKS OBSERVED)',
  gateway_reachable_no_hook: 'GATEWAY UP · NO HOOK TRAFFIC',
  configured_awaiting_traffic: 'STANDBY · AWAITING PLUGIN',
  not_detected: 'NOT DETECTED',
};

export function BifrostPage({ refreshSignal, userRole, onConfigChanged }: BifrostPageProps) {
  const [config, setConfig] = useState<BifrostConfig | null>(null);
  const [telemetry, setTelemetry] = useState<BifrostTelemetry | null>(null);
  const [logs, setLogs] = useState<IntegrationLog[]>([]);
  const [logFilter, setLogFilter] = useState<'all' | 'live' | 'demo'>('all');
  const [goSource, setGoSource] = useState<string>('');
  const [endpointUrl, setEndpointUrl] = useState('http://localhost:8080');
  const [mode, setMode] = useState<'demo' | 'live'>('demo');
  const [enabled, setEnabled] = useState(true);
  const [testing, setTesting] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<{ reachable: boolean; message: string; latencyMs: number } | null>(null);
  const [liveVerification, setLiveVerification] = useState<BifrostLiveVerificationResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const [hookTool, setHookTool] = useState('export_customer_database');
  const [hookServer, setHookServer] = useState('crm-postgres-mcp');
  const [hookArgs, setHookArgs] = useState('{\n  "scope": "all_customers"\n}');
  const [hookOutput, setHookOutput] = useState<string | null>(null);

  const isAdmin = userRole === 'admin';
  const canRunDemo = userRole === 'admin' || userRole === 'analyst';

  const loadAll = async () => {
    setLoadError(null);
    try {
      const [cfgRes, telemetryRes, logsRes, goRes] = await Promise.all([
        api.get<{ config: BifrostConfig }>('/api/bifrost/config'),
        api.get<{ telemetry: BifrostTelemetry }>('/api/bifrost/telemetry'),
        api.get<{ logs: IntegrationLog[] }>('/api/bifrost/logs'),
        api.get<{ source: string }>('/api/bifrost/go-plugin').catch(() => ({ source: '' })),
      ]);
      setConfig(cfgRes.config);
      setTelemetry(telemetryRes.telemetry);
      setEndpointUrl(cfgRes.config.endpoint_url);
      setMode(cfgRes.config.mode);
      setEnabled(Boolean(cfgRes.config.enabled));
      setLogs(logsRes.logs);
      setGoSource(goRes.source);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load Bifrost gateway status and logs.');
    }
  };

  useEffect(() => {
    loadAll();
  }, [refreshSignal]);

  const handleSaveConfig = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await api.put<{ config: BifrostConfig }>('/api/bifrost/config', {
        mode,
        endpoint_url: endpointUrl.trim(),
        enabled,
      });
      setConfig(res.config);
      setActionSuccess('Bifrost gateway configuration saved.');
      await loadAll();
      onConfigChanged();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to save Bifrost configuration.');
    } finally {
      setSaving(false);
    }
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await api.post<{
        reachable: boolean;
        message: string;
        latencyMs: number;
        config: BifrostConfig;
      }>('/api/bifrost/test', { endpoint_url: endpointUrl.trim() });
      setTestResult({ reachable: res.reachable, message: res.message, latencyMs: res.latencyMs });
      setConfig(res.config);
      await loadAll();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Connectivity test failed.');
    } finally {
      setTesting(false);
    }
  };

  const handleVerifyLiveIntegration = async () => {
    setVerifying(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const res = await api.post<{
        verification: BifrostLiveVerificationResult;
        config: BifrostConfig;
        telemetry: BifrostTelemetry;
      }>('/api/bifrost/verify-live-integration');
      setLiveVerification(res.verification);
      setConfig(res.config);
      setTelemetry(res.telemetry);
      await loadAll();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Live integration verification failed.');
    } finally {
      setVerifying(false);
    }
  };

  const handleDispatchHook = async () => {
    setHookOutput(null);
    setActionError(null);
    try {
      const parsedArgs = JSON.parse(hookArgs);
      const token = getClientSessionToken();
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
      const res = await fetch('/api/bifrost/demo-dispatch', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({
          tool_name: hookTool.trim(),
          arguments: parsedArgs,
          mcp_server: hookServer.trim(),
        }),
      });
      const data = await res.json();
      setHookOutput(JSON.stringify(data, null, 2));
      await loadAll();
      onConfigChanged();
    } catch (err) {
      setHookOutput(err instanceof Error ? err.message : 'Demo hook dispatch failed');
    }
  };

  const handleCopyGo = () => {
    navigator.clipboard.writeText(goSource);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const hmacConfigured = config?.webhook_auth_status === 'hmac_configured';
  const filteredLogs = logs.filter((log) => (logFilter === 'all' ? true : log.source_mode === logFilter));

  return (
    <div className="space-y-8">
      <div className="border-b border-[#D9D5CE] pb-5 flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div>
          <p className="text-xs font-mono text-[#8C2635] font-medium">
            Native MCP Plugin (transports/v2.5.1 · core v1.15.2) &amp; HMAC Security
          </p>
          <h2 className="text-2xl font-semibold text-[#191919] mt-1">Bifrost Gateway Integration</h2>
          <p className="text-xs text-[#5E5A55] mt-1">
            Live PreMCPHook &amp; PostMCPHook webhooks enforce HMAC-SHA256 signatures, TTL replay protection, and constant-time verification via backend environment secrets.
          </p>
        </div>
        {config && (
          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex items-center gap-2 text-xs font-mono text-[#191919] px-3 py-1.5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
              <Network className="w-3.5 h-3.5 text-[#8C2635]" />
              <span>{config.mode === 'live' ? 'LIVE BIFROST' : 'DEMO MODE'}</span>
            </div>
            <div
              className={`inline-flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-[2px] border ${
                hmacConfigured
                  ? 'border-[#1B6B44]/40 bg-[#1B6B44]/5 text-[#1B6B44]'
                  : 'border-[#B91C1C]/40 bg-[#B91C1C]/5 text-[#B91C1C]'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{hmacConfigured ? 'HMAC-SHA256 Ready' : 'HMAC Secret Unset'}</span>
            </div>
          </div>
        )}
      </div>

      {loadError && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {loadError}
        </div>
      )}
      {actionError && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {actionError}
        </div>
      )}
      {actionSuccess && (
        <div className="p-4 rounded-[2px] border border-[#1B6B44]/40 bg-[#1B6B44]/5 text-xs font-mono text-[#1B6B44]">
          {actionSuccess}
        </div>
      )}

      {/* Phase 4: Real Telemetry vs. Demo Separation */}
      {telemetry && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-1">
              <p className="text-[11px] font-mono uppercase tracking-wider text-[#77736D]">
                Gateway Reachability
              </p>
              <p
                className={`text-sm font-mono font-semibold ${
                  telemetry.gatewayReachable ? 'text-[#1B6B44]' : 'text-[#A16207]'
                }`}
              >
                {telemetry.gatewayReachable ? 'REACHABLE (HTTP 200)' : telemetry.gatewayStatus.toUpperCase()}
              </p>
              <p className="text-[11px] font-mono text-[#5E5A55] truncate">{telemetry.endpointUrl}</p>
            </div>

            <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-1">
              <p className="text-[11px] font-mono uppercase tracking-wider text-[#77736D]">
                Plugin Loading Status
              </p>
              <p
                className={`text-sm font-mono font-semibold ${
                  telemetry.pluginLoadingStatus === 'active_live'
                    ? 'text-[#1B6B44]'
                    : telemetry.pluginLoadingStatus === 'gateway_reachable_no_hook'
                      ? 'text-[#A16207]'
                      : 'text-[#5E5A55]'
                }`}
              >
                {PLUGIN_STATUS_LABELS[telemetry.pluginLoadingStatus]}
              </p>
              <p className="text-[11px] font-mono text-[#5E5A55]">
                {telemetry.pluginVersion
                  ? `Observed Plugin v${telemetry.pluginVersion}`
                  : `Pinned Spec v${telemetry.pinnedSpecVersion}`}
              </p>
            </div>

            <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-1">
              <p className="text-[11px] font-mono uppercase tracking-wider text-[#77736D]">
                Webhook Auth &amp; Rejections
              </p>
              <p
                className={`text-sm font-mono font-semibold ${
                  telemetry.hmacAuthStatus === 'hmac_configured' ? 'text-[#1B6B44]' : 'text-[#B91C1C]'
                }`}
              >
                {telemetry.hmacAuthStatus === 'hmac_configured'
                  ? `HMAC Active (${telemetry.signatureTtlSeconds}s TTL)`
                  : 'Secret Unconfigured (503)'}
              </p>
              <p className="text-[11px] font-mono text-[#5E5A55]">
                {telemetry.liveCounts.rejectedAuthCalls} rejected unsigned/expired calls
              </p>
            </div>

            <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-1">
              <p className="text-[11px] font-mono uppercase tracking-wider text-[#77736D]">
                Last Real MCP Execution
              </p>
              {telemetry.lastRealExecution ? (
                <>
                  <p className="text-sm font-mono font-semibold text-[#191919] truncate">
                    {telemetry.lastRealExecution.tool_name} ({telemetry.lastRealExecution.decision})
                  </p>
                  <p className="text-[11px] font-mono text-[#5E5A55]">
                    {telemetry.lastRealExecution.execution_uid} · {formatUtcTime(telemetry.lastRealExecution.created_at)}
                  </p>
                </>
              ) : (
                <>
                  <p className="text-sm font-mono font-semibold text-[#77736D]">None Recorded</p>
                  <p className="text-[11px] font-mono text-[#5E5A55]">Awaiting signed live PreMCPHook</p>
                </>
              )}
            </div>
          </div>

          {/* Strictly Separated LIVE vs. DEMO Counts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="p-5 rounded-[2px] border border-[#191919]/20 bg-[#FCFBF8]">
              <div className="flex items-center justify-between border-b border-[#D9D5CE] pb-2.5 mb-3">
                <div className="flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-[#1B6B44]" />
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-[#191919]">
                    Live Bifrost Traffic (source = bifrost)
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-[#5E5A55]">
                  {telemetry.liveCounts.total} Total · {telemetry.liveCounts.postHookCompleted} PostHooks
                </span>
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE]">
                  <p className="text-[10px] font-mono text-[#5E5A55]">ALLOW</p>
                  <p className="text-lg font-mono font-semibold text-[#1B6B44] tabular-nums">
                    {telemetry.liveCounts.allow}
                  </p>
                </div>
                <div className="p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE]">
                  <p className="text-[10px] font-mono text-[#5E5A55]">REVIEW</p>
                  <p className="text-lg font-mono font-semibold text-[#A16207] tabular-nums">
                    {telemetry.liveCounts.review}
                  </p>
                </div>
                <div className="p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE]">
                  <p className="text-[10px] font-mono text-[#5E5A55]">BLOCK</p>
                  <p className="text-lg font-mono font-semibold text-[#B91C1C] tabular-nums">
                    {telemetry.liveCounts.block}
                  </p>
                </div>
              </div>
            </div>

            <div className="p-5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8]">
              <div className="flex items-center justify-between border-b border-[#D9D5CE] pb-2.5 mb-3">
                <div className="flex items-center gap-2">
                  <Terminal className="w-3.5 h-3.5 text-[#8C2635]" />
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-[#191919]">
                    Demo / Simulator Traffic (source = demo_simulator)
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-[#5E5A55]">
                  {telemetry.demoCounts.total} Total
                </span>
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE]">
                  <p className="text-[10px] font-mono text-[#5E5A55]">ALLOW</p>
                  <p className="text-lg font-mono font-semibold text-[#1B6B44] tabular-nums">
                    {telemetry.demoCounts.allow}
                  </p>
                </div>
                <div className="p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE]">
                  <p className="text-[10px] font-mono text-[#5E5A55]">REVIEW</p>
                  <p className="text-lg font-mono font-semibold text-[#A16207] tabular-nums">
                    {telemetry.demoCounts.review}
                  </p>
                </div>
                <div className="p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE]">
                  <p className="text-[10px] font-mono text-[#5E5A55]">BLOCK</p>
                  <p className="text-lg font-mono font-semibold text-[#B91C1C] tabular-nums">
                    {telemetry.demoCounts.block}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Minimal Configuration & PreMCPHook Tester */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <form onSubmit={handleSaveConfig} className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-4">
          <div className="border-b border-[#D9D5CE] pb-3 flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-[#191919]">Gateway Connection &amp; Webhook Auth</h3>
              <p className="text-xs text-[#5E5A55] mt-0.5">
                Connectivity probes perform genuine HTTP checks; HMAC secrets stay strictly in backend env.
              </p>
            </div>
            {!isAdmin && (
              <span className="text-[11px] font-mono text-[#8C2635] shrink-0">Admin Only</span>
            )}
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-[#191919]">Operating Mode</label>
            <div className="grid grid-cols-2 gap-2">
              {(['demo', 'live'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  disabled={!isAdmin}
                  onClick={() => setMode(m)}
                  className={`px-3 py-2 rounded-[2px] text-xs font-mono font-medium border text-left transition-colors disabled:opacity-60 ${
                    mode === m
                      ? 'bg-[#8C2635] border-[#8C2635] text-[#FCFBF8]'
                      : 'bg-[#F7F5F0] border-[#D9D5CE] text-[#5E5A55] hover:text-[#191919]'
                  }`}
                >
                  {m === 'demo' ? 'DEMO MODE (Standalone)' : 'LIVE BIFROST GATEWAY'}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="bf-url" className="block text-xs font-medium text-[#191919]">
              Bifrost Gateway Endpoint URL
            </label>
            <input
              id="bf-url"
              type="url"
              required
              disabled={!isAdmin}
              value={endpointUrl}
              onChange={(e) => setEndpointUrl(e.target.value)}
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] disabled:opacity-60 focus:outline-none focus:border-[#8C2635]"
            />
          </div>

          <label className="flex items-center gap-2 text-xs text-[#191919] cursor-pointer">
            <input
              type="checkbox"
              disabled={!isAdmin}
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="accent-[#8C2635]"
            />
            <span>Enable PreMCPHook / PostMCPHook Adapter Endpoints</span>
          </label>

          {config && (
            <div className="p-3.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[#5E5A55]">Connection Status</span>
                <span
                  className={`font-mono font-semibold ${
                    config.last_test_status === 'connected' ? 'text-[#1B6B44]' : 'text-[#A16207]'
                  }`}
                >
                  {config.last_test_status}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#5E5A55]">Webhook HMAC-SHA256 Auth</span>
                <span className={`font-mono font-semibold ${hmacConfigured ? 'text-[#1B6B44]' : 'text-[#B91C1C]'}`}>
                  {hmacConfigured
                    ? `Active (${config.signature_ttl_seconds ?? 300}s TTL · Replay Cache)`
                    : 'BIFROST_SHARED_SECRET Missing (Fail-Closed 503)'}
                </span>
              </div>
              <p className="text-[#191919] font-mono text-[11px] pt-1 border-t border-[#D9D5CE]/70">
                {testResult ? testResult.message : config.last_test_message}
              </p>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              type="submit"
              disabled={!isAdmin || saving}
              className="px-4 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] disabled:opacity-50 text-xs font-semibold text-[#FCFBF8]"
            >
              {saving ? 'Saving...' : 'Save Settings'}
            </button>
            <button
              type="button"
              disabled={!isAdmin || testing}
              onClick={handleTestConnection}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#191919] disabled:opacity-50 text-xs font-medium text-[#191919]"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${testing ? 'animate-spin' : ''}`} />
              <span>{testing ? 'Testing...' : 'Test Connection'}</span>
            </button>
            <button
              type="button"
              disabled={!isAdmin || verifying}
              onClick={handleVerifyLiveIntegration}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[2px] border border-[#191919] bg-[#191919] hover:bg-[#8C2635] hover:border-[#8C2635] disabled:opacity-50 text-xs font-medium text-[#FCFBF8] transition-colors"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>{verifying ? 'Verifying...' : 'Verify Live Integration'}</span>
            </button>
          </div>

          {liveVerification && (
            <div className="p-3.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] space-y-2">
              <div className="flex items-center justify-between border-b border-[#D9D5CE] pb-2">
                <span className="text-[11px] font-mono font-semibold text-[#191919]">
                  LIVE INTEGRATION AUDIT
                </span>
                <span
                  className={`text-[11px] font-mono font-semibold ${
                    liveVerification.overallStatus === 'verified'
                      ? 'text-[#1B6B44]'
                      : liveVerification.overallStatus === 'partial'
                        ? 'text-[#A16207]'
                        : 'text-[#B91C1C]'
                  }`}
                >
                  {liveVerification.overallStatus.toUpperCase()}
                </span>
              </div>
              <p className="text-[11px] text-[#5E5A55]">{liveVerification.summary}</p>
              <div className="space-y-1.5 pt-1">
                {liveVerification.checks.map((chk) => (
                  <div
                    key={chk.id}
                    className="flex items-start justify-between gap-3 text-[11px] font-mono border-t border-[#D9D5CE]/50 pt-1.5"
                  >
                    <div>
                      <span className="text-[#191919] font-medium">{chk.label}: </span>
                      <span className="text-[#5E5A55]">{chk.detail}</span>
                    </div>
                    <span
                      className={`shrink-0 font-semibold ${
                        chk.status === 'PASS'
                          ? 'text-[#1B6B44]'
                          : chk.status === 'WARN'
                            ? 'text-[#A16207]'
                            : 'text-[#B91C1C]'
                      }`}
                    >
                      [{chk.status}]
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </form>

        {/* PreMCPHook Ingestion Tester */}
        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-4">
          <div className="border-b border-[#D9D5CE] pb-3">
            <h3 className="text-sm font-semibold text-[#191919]">PreMCPHook Demo Event Dispatcher</h3>
            <p className="text-xs text-[#5E5A55] mt-0.5">
              Live webhooks at <code className="text-[#8C2635] font-medium">/api/bifrost/pre-mcp-hook</code> require server-side HMAC-SHA256 signing. In Demo Mode, dispatch simulated payloads via <code className="text-[#191919]">/api/bifrost/demo-dispatch</code>.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-[#191919] mb-1">MCP Tool Name</label>
              <input
                type="text"
                value={hookTool}
                onChange={(e) => setHookTool(e.target.value)}
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-[#191919] mb-1">Upstream MCP Server</label>
              <input
                type="text"
                value={hookServer}
                onChange={(e) => setHookServer(e.target.value)}
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#191919] mb-1">MCP Tool Arguments (JSON)</label>
            <textarea
              rows={3}
              value={hookArgs}
              onChange={(e) => setHookArgs(e.target.value)}
              className="w-full p-2.5 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
            />
          </div>

          {config?.mode === 'live' ? (
            <div className="p-3 rounded-[2px] border border-[#A16207]/40 bg-[#A16207]/5 text-xs font-mono text-[#A16207]">
              Gateway is in LIVE mode. Browser demo dispatch is disabled because live PreMCPHook requests must be HMAC-SHA256 signed by your Bifrost Go plugin using BIFROST_SHARED_SECRET.
            </div>
          ) : (
            <button
              type="button"
              disabled={!canRunDemo}
              onClick={handleDispatchHook}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[2px] bg-[#191919] hover:bg-[#8C2635] disabled:opacity-50 text-xs font-semibold text-[#FCFBF8] transition-colors"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Dispatch Demo PreMCPHook</span>
            </button>
          )}

          {hookOutput && (
            <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto max-h-48">
              {hookOutput}
            </pre>
          )}
        </div>
      </div>

      {/* Integration Logs */}
      <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h3 className="text-sm font-semibold text-[#191919]">Bifrost Adapter Integration Logs</h3>
          <div className="inline-flex border border-[#D9D5CE] rounded-[2px] overflow-hidden">
            {(
              [
                { key: 'all', label: 'All Events' },
                { key: 'live', label: 'Live Bifrost' },
                { key: 'demo', label: 'Demo Events' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.key}
                type="button"
                onClick={() => setLogFilter(tab.key)}
                className={`px-3 py-1 text-[11px] font-mono transition-colors ${
                  logFilter === tab.key
                    ? 'bg-[#191919] text-[#FCFBF8]'
                    : 'bg-[#F7F5F0] text-[#5E5A55] hover:text-[#191919]'
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
                <th className="py-2.5 pr-3 font-medium">Hook</th>
                <th className="py-2.5 px-3 font-medium">Origin Mode</th>
                <th className="py-2.5 px-3 font-medium">Tool</th>
                <th className="py-2.5 px-3 font-medium">Decision</th>
                <th className="py-2.5 px-3 font-medium">HTTP</th>
                <th className="py-2.5 px-3 font-medium">Message</th>
                <th className="py-2.5 pl-3 font-medium text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#D9D5CE]/70">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-[#77736D] font-mono">
                    No matching Bifrost adapter events recorded yet.
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#F7F5F0]">
                    <td className="py-2.5 pr-3 font-mono font-medium text-[#191919] whitespace-nowrap">
                      {log.hook_type}
                    </td>
                    <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                      <span className={log.source_mode === 'live' ? 'text-[#1B6B44] font-semibold' : 'text-[#A16207]'}>
                        {log.source_mode === 'live' ? 'LIVE BIFROST' : 'DEMO EVENT'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[#5E5A55] whitespace-nowrap">{log.tool_name || '—'}</td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {log.decision === 'ALLOW' || log.decision === 'COMPLETED' ? (
                        <span className="inline-flex items-center gap-1 font-mono font-semibold text-[#1B6B44]">
                          <ShieldCheck className="w-3.5 h-3.5" /> {log.decision}
                        </span>
                      ) : log.decision === 'BLOCK' ||
                        log.decision === 'ERROR' ||
                        log.status_code === 401 ||
                        log.status_code === 503 ? (
                        <span className="inline-flex items-center gap-1 font-mono font-semibold text-[#B91C1C]">
                          <ShieldOff className="w-3.5 h-3.5" /> {log.decision || 'REJECTED'}
                        </span>
                      ) : (
                        <span className="text-[#5E5A55] font-mono">{log.decision || '—'}</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono tabular-nums text-[#191919]">{log.status_code}</td>
                    <td className="py-2.5 px-3 text-[#5E5A55] max-w-md truncate">{log.message}</td>
                    <td className="py-2.5 pl-3 font-mono text-[#5E5A55] text-right whitespace-nowrap">
                      {formatUtcTime(log.created_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Native Go Plugin Template */}
      {goSource && (
        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-3">
          <div className="flex items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-[#191919]">
                Native Go Bifrost Plugin (bifrost-plugin/toolseal_plugin.go)
              </h3>
              <p className="text-xs text-[#5E5A55] mt-0.5">
                Implements pinned <code className="font-mono">github.com/maximhq/bifrost/core v1.15.2</code> dynamic hooks and signs every request with HMAC-SHA256 (<code className="font-mono">X-Bifrost-Timestamp</code>, <code className="font-mono">X-Bifrost-Nonce</code>, <code className="font-mono">X-Bifrost-Signature</code>).
              </p>
            </div>
            <button
              type="button"
              onClick={handleCopyGo}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#191919] text-xs font-medium text-[#191919] shrink-0"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-[#1B6B44]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Go Source'}</span>
            </button>
          </div>
          <pre className="p-4 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto max-h-72">
            {goSource}
          </pre>
        </div>
      )}
    </div>
  );
}
