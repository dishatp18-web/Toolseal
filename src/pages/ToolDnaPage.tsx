import { useEffect, useState, type FormEvent } from 'react';
import { Check, Copy, Fingerprint, Plus, ShieldAlert, ShieldCheck, Wrench } from 'lucide-react';
import { TrustIndicator } from '../components/DecisionLabel';
import { api, formatUtcTime } from '../lib/api';
import type { CanonicalToolSchema, RegisteredTool, SchemaParameterDiff, UserRecord } from '../types/toolseal';

interface ToolDnaPageProps {
  refreshSignal: number;
  userRole: UserRecord['role'];
}

interface DiffResponse {
  tool: RegisteredTool;
  approvedHash: string | null;
  latestHash: string | null;
  approvedSchema: CanonicalToolSchema | null;
  latestSchema: CanonicalToolSchema | null;
  diffs: SchemaParameterDiff[];
}

export function ToolDnaPage({ refreshSignal, userRole }: ToolDnaPageProps) {
  const [tools, setTools] = useState<RegisteredTool[]>([]);
  const [selectedToolId, setSelectedToolId] = useState<string | null>(null);
  const [diffData, setDiffData] = useState<DiffResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const isAdmin = userRole === 'admin';
  const canSimulateDrift = userRole === 'admin' || userRole === 'analyst';

  const [showRegister, setShowRegister] = useState(false);
  const [newName, setNewName] = useState('');
  const [newServer, setNewServer] = useState('mcp-custom-server');
  const [newCategory, setNewCategory] = useState('Custom MCP');
  const [newDesc, setNewDesc] = useState('');
  const [newPropsJson, setNewPropsJson] = useState(
    '{\n  "record_id": { "type": "string", "description": "Unique resource identifier" }\n}'
  );

  const [mutateJson, setMutateJson] = useState('');

  const loadTools = async () => {
    setLoadError(null);
    try {
      const res = await api.get<{ tools: RegisteredTool[] }>('/api/tools');
      setTools(res.tools);
      if (!selectedToolId && res.tools.length > 0) {
        setSelectedToolId(res.tools[0].id);
      }
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load Tool DNA registry.');
    } finally {
      setLoading(false);
    }
  };

  const loadDiff = async (toolId: string) => {
    try {
      const res = await api.get<DiffResponse>(`/api/tools/${toolId}/diff`);
      setDiffData(res);
      if (res.latestSchema) {
        setMutateJson(JSON.stringify(res.latestSchema, null, 2));
      }
    } catch (err) {
      setDiffData(null);
      setLoadError(err instanceof Error ? err.message : 'Failed to inspect Tool DNA diff.');
    }
  };

  useEffect(() => {
    loadTools();
  }, [refreshSignal]);

  useEffect(() => {
    if (selectedToolId) {
      loadDiff(selectedToolId);
    }
  }, [selectedToolId, refreshSignal]);

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedHash(val);
    setTimeout(() => setCopiedHash(null), 1500);
  };

  const handleRegister = async (e: FormEvent) => {
    e.preventDefault();
    setActionMsg(null);
    try {
      const properties = JSON.parse(newPropsJson);
      const schema: CanonicalToolSchema = {
        name: newName.trim(),
        description: newDesc.trim(),
        parameters: {
          type: 'object',
          properties,
          required: Object.keys(properties),
          additionalProperties: false,
        },
      };
      await api.post('/api/tools', {
        name: newName.trim(),
        description: newDesc.trim(),
        serverName: newServer.trim(),
        category: newCategory.trim(),
        schema,
      });
      setShowRegister(false);
      setNewName('');
      setNewDesc('');
      setActionMsg({ type: 'ok', text: 'Registered new tool and computed SHA-256 Tool DNA fingerprint.' });
      await loadTools();
    } catch (err) {
      setActionMsg({ type: 'err', text: err instanceof Error ? err.message : 'Failed to register tool' });
    }
  };

  const handleInjectSchemaChange = async () => {
    if (!selectedToolId) return;
    setActionMsg(null);
    try {
      const parsed = JSON.parse(mutateJson) as CanonicalToolSchema;
      const res = await api.put<{ changed: boolean; incidentUid?: string; message?: string }>(
        `/api/tools/${selectedToolId}/schema`,
        { schema: parsed }
      );
      if (res.changed) {
        setActionMsg({
          type: 'ok',
          text: `Fingerprint mismatch detected! Tool flagged as modified and incident ${res.incidentUid} created.`,
        });
      } else {
        setActionMsg({ type: 'ok', text: res.message || 'No schema change detected.' });
      }
      await loadTools();
      await loadDiff(selectedToolId);
    } catch (err) {
      setActionMsg({ type: 'err', text: err instanceof Error ? err.message : 'Schema update failed' });
    }
  };

  const handleApproveFingerprint = async () => {
    if (!selectedToolId) return;
    setActionMsg(null);
    try {
      const res = await api.post<{ behaviourBaselineSynced?: boolean }>(`/api/tools/${selectedToolId}/approve-fingerprint`);
      setActionMsg({
        type: 'ok',
        text: res.behaviourBaselineSynced
          ? 'Latest schema fingerprint approved as trusted Tool DNA baseline and synchronized to Behavioural Intelligence.'
          : 'Latest schema fingerprint approved and set as trusted Tool DNA baseline.',
      });
      await loadTools();
      await loadDiff(selectedToolId);
    } catch (err) {
      setActionMsg({ type: 'err', text: err instanceof Error ? err.message : 'Failed to approve fingerprint' });
    }
  };

  const handleRevokeTrust = async () => {
    if (!selectedToolId) return;
    setActionMsg(null);
    try {
      await api.post(`/api/tools/${selectedToolId}/revoke`);
      setActionMsg({ type: 'ok', text: 'Tool trust revoked. Subsequent calls will be blocked until re-verified.' });
      await loadTools();
      await loadDiff(selectedToolId);
    } catch (err) {
      setActionMsg({ type: 'err', text: err instanceof Error ? err.message : 'Failed to revoke tool trust' });
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-[#D9D5CE] pb-5">
        <div>
          <p className="text-xs font-mono text-[#8C2635] font-medium">Cryptographic Schema Verification</p>
          <h2 className="text-2xl font-semibold text-[#191919] mt-1">Tool DNA Registry</h2>
          <p className="text-xs text-[#5E5A55] mt-1">
            Canonical SHA-256 schema fingerprints detect silent MCP tool poisoning and unauthorized parameter drift.
          </p>
        </div>
        {isAdmin && (
          <button
            type="button"
            onClick={() => setShowRegister((v) => !v)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] text-xs font-semibold text-[#FCFBF8] whitespace-nowrap shrink-0"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{showRegister ? 'Close Form' : 'Register MCP Tool'}</span>
          </button>
        )}
      </div>

      {loadError && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {loadError}
        </div>
      )}

      {actionMsg && (
        <div
          className={`p-3.5 rounded-[2px] border text-xs font-mono ${
            actionMsg.type === 'err'
              ? 'border-[#B91C1C]/40 bg-[#B91C1C]/5 text-[#B91C1C]'
              : 'border-[#1B6B44]/40 bg-[#1B6B44]/5 text-[#1B6B44]'
          }`}
        >
          {actionMsg.text}
        </div>
      )}

      {showRegister && (
        <form
          onSubmit={handleRegister}
          className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          <div>
            <label className="block text-xs font-medium text-[#191919] mb-1">Tool Name</label>
            <input
              type="text"
              required
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="e.g. fetch_order_status"
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919]"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#191919] mb-1">MCP Server</label>
            <input
              type="text"
              required
              value={newServer}
              onChange={(e) => setNewServer(e.target.value)}
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919]"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#191919] mb-1">Category</label>
            <input
              type="text"
              required
              value={newCategory}
              onChange={(e) => setNewCategory(e.target.value)}
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919]"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-[#191919] mb-1">Description</label>
            <input
              type="text"
              required
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              placeholder="Read-only order lookup"
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919]"
            />
          </div>
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-[#191919] mb-1">
              Parameters JSON Schema (properties object)
            </label>
            <textarea
              rows={4}
              value={newPropsJson}
              onChange={(e) => setNewPropsJson(e.target.value)}
              className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919]"
            />
          </div>
          <div className="md:col-span-2 flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] text-xs font-semibold text-[#FCFBF8]"
            >
              Generate SHA-256 DNA &amp; Register
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Minimal Schema Registry List */}
        <div className="lg:col-span-5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] divide-y divide-[#D9D5CE]">
          <div className="px-4 py-3 text-xs font-semibold text-[#191919] flex items-center justify-between bg-[#F7F5F0]">
            <span>Registered MCP Tools ({tools.length})</span>
            <Fingerprint className="w-4 h-4 text-[#8C2635]" />
          </div>
          {loading ? (
            <div className="p-6 text-xs text-[#77736D] font-mono text-center">Loading Tool DNA registry...</div>
          ) : (
            tools.map((tool) => {
              const selected = tool.id === selectedToolId;
              return (
                <button
                  key={tool.id}
                  type="button"
                  onClick={() => setSelectedToolId(tool.id)}
                  className={`w-full text-left p-4 transition-colors ${
                    selected ? 'bg-[#EFECE5]' : 'hover:bg-[#F7F5F0]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-sm font-semibold text-[#191919] truncate">{tool.name}</span>
                    <TrustIndicator status={tool.trust_status} />
                  </div>
                  <p className="text-xs text-[#5E5A55] mt-1 line-clamp-1">{tool.description}</p>
                  <div className="mt-2 flex items-center gap-2 text-[11px] text-[#77736D] font-mono">
                    <span>{tool.server_name}</span>
                    <span>·</span>
                    <span>v{tool.current_version}</span>
                    <span>·</span>
                    <span className="truncate">
                      {tool.latest_fingerprint ? tool.latest_fingerprint.slice(0, 14) + '…' : 'no-hash'}
                    </span>
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Schema Inspector & Comparison */}
        <div className="lg:col-span-7 space-y-6">
          {diffData ? (
            <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 border-b border-[#D9D5CE] pb-4">
                <div>
                  <div className="flex items-center gap-3">
                    <h3 className="text-base font-mono font-semibold text-[#191919]">{diffData.tool.name}</h3>
                    <TrustIndicator status={diffData.tool.trust_status} />
                  </div>
                  <p className="text-xs text-[#5E5A55] mt-1 font-mono">
                    {diffData.tool.server_name} · {diffData.tool.category} · Updated{' '}
                    {formatUtcTime(diffData.tool.updated_at)}
                  </p>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    disabled={!isAdmin}
                    onClick={handleApproveFingerprint}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[2px] bg-[#191919] hover:bg-[#2E2E2E] disabled:opacity-50 text-xs font-medium text-[#FCFBF8] whitespace-nowrap"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>Approve Baseline</span>
                  </button>
                  <button
                    type="button"
                    disabled={!isAdmin}
                    onClick={handleRevokeTrust}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[2px] border border-[#B91C1C] text-xs font-medium text-[#B91C1C] hover:bg-[#B91C1C]/10 disabled:opacity-50 whitespace-nowrap"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    <span>Revoke</span>
                  </button>
                </div>
              </div>

              {/* SHA-256 Fingerprints */}
              <div className="grid grid-cols-1 gap-3 text-xs">
                <div className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <span className="text-[#5E5A55] block text-[11px]">Approved Baseline SHA-256</span>
                    <span className="font-mono text-[#1B6B44] font-medium break-all">
                      {diffData.approvedHash || 'None'}
                    </span>
                  </div>
                  {diffData.approvedHash && (
                    <button
                      type="button"
                      onClick={() => handleCopy(diffData.approvedHash!)}
                      className="p-1.5 text-[#5E5A55] hover:text-[#191919] shrink-0"
                      aria-label="Copy approved SHA-256"
                    >
                      {copiedHash === diffData.approvedHash ? (
                        <Check className="w-3.5 h-3.5 text-[#1B6B44]" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  )}
                </div>

                <div className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <span className="text-[#5E5A55] block text-[11px]">Current Observed SHA-256</span>
                    <span
                      className={`font-mono font-medium break-all ${
                        diffData.approvedHash === diffData.latestHash ? 'text-[#1B6B44]' : 'text-[#B91C1C]'
                      }`}
                    >
                      {diffData.latestHash || 'None'}
                    </span>
                  </div>
                  {diffData.latestHash && (
                    <button
                      type="button"
                      onClick={() => handleCopy(diffData.latestHash!)}
                      className="p-1.5 text-[#5E5A55] hover:text-[#191919] shrink-0"
                      aria-label="Copy current SHA-256"
                    >
                      {copiedHash === diffData.latestHash ? (
                        <Check className="w-3.5 h-3.5 text-[#1B6B44]" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  )}
                </div>
              </div>

              {/* Parameter Diff Alerts */}
              {diffData.diffs.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold text-[#A16207]">
                    Detected Schema Parameter Changes ({diffData.diffs.length})
                  </h4>
                  <div className="space-y-2">
                    {diffData.diffs.map((d) => (
                      <div
                        key={d.parameter}
                        className="p-3 rounded-[2px] border border-[#A16207]/40 bg-[#A16207]/5 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-semibold text-[#191919]">{d.parameter}</span>
                          <span className="font-mono uppercase text-[11px] font-semibold text-[#A16207]">
                            {d.changeType}
                          </span>
                        </div>
                        <p className="text-[#5E5A55]">{d.riskNote}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Visual Side-by-Side Schema Comparison */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <div className="text-xs font-mono font-medium text-[#1B6B44] mb-1.5">Original Approved Schema</div>
                  <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto max-h-60">
                    {diffData.approvedSchema ? JSON.stringify(diffData.approvedSchema, null, 2) : 'No approved schema'}
                  </pre>
                </div>
                <div>
                  <div
                    className={`text-xs font-mono font-medium mb-1.5 ${
                      diffData.diffs.length > 0 ? 'text-[#B91C1C]' : 'text-[#5E5A55]'
                    }`}
                  >
                    Latest Observed Schema
                  </div>
                  <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto max-h-60">
                    {diffData.latestSchema ? JSON.stringify(diffData.latestSchema, null, 2) : 'No schema'}
                  </pre>
                </div>
              </div>

              {/* Schema Drift Tester */}
              <div className="pt-4 border-t border-[#D9D5CE] space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-[#191919]">
                    Test Schema Update / Drift Detection
                  </span>
                  <button
                    type="button"
                    disabled={!canSimulateDrift}
                    onClick={handleInjectSchemaChange}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[2px] border border-[#8C2635] text-xs font-medium text-[#8C2635] hover:bg-[#8C2635] hover:text-[#FCFBF8] disabled:opacity-50 transition-colors"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    <span>Submit Schema Update</span>
                  </button>
                </div>
                <textarea
                  rows={5}
                  disabled={!canSimulateDrift}
                  value={mutateJson}
                  onChange={(e) => setMutateJson(e.target.value)}
                  className="w-full p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] disabled:opacity-60 focus:outline-none focus:border-[#8C2635]"
                />
              </div>
            </div>
          ) : (
            <div className="p-8 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] text-center text-xs text-[#77736D] font-mono">
              Select a registered tool to inspect its Tool DNA SHA-256 fingerprint and schema history.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
