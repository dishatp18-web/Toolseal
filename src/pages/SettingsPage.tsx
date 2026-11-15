import { useEffect, useState, type FormEvent } from 'react';
import { Lock, Save } from 'lucide-react';
import { api, formatUtcTime } from '../lib/api';
import type { AuditLog, SecurityPolicy, UserRecord } from '../types/toolseal';

interface SettingsPageProps {
  refreshSignal: number;
  userRole: UserRecord['role'];
  onPolicySaved: () => void;
}

export function SettingsPage({ refreshSignal, userRole, onPolicySaved }: SettingsPageProps) {
  const [policy, setPolicy] = useState<SecurityPolicy | null>(null);
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [saving, setSaving] = useState(false);
  const [savedMsg, setSavedMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const isAdmin = userRole === 'admin';

  const loadData = async () => {
    setLoadError(null);
    try {
      const [polRes, usrRes, audRes] = await Promise.all([
        api.get<{ policies: SecurityPolicy[] }>('/api/policies'),
        api.get<{ users: UserRecord[] }>('/api/users'),
        api.get<{ logs: AuditLog[] }>('/api/audit-logs'),
      ]);
      const active = polRes.policies.find((p) => p.is_active === 1) || polRes.policies[0] || null;
      setPolicy(active);
      setUsers(usrRes.users);
      setAuditLogs(audRes.logs);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load policy settings and audit trail.');
    }
  };

  useEffect(() => {
    loadData();
  }, [refreshSignal]);

  const handleSavePolicy = async (e: FormEvent) => {
    e.preventDefault();
    if (!policy) return;
    setSaving(true);
    setSavedMsg(null);
    setErrorMsg(null);

    try {
      const res = await api.put<{ policy: SecurityPolicy }>(`/api/policies/${policy.id}`, {
        allow_max_risk: Number(policy.allow_max_risk),
        review_max_risk: Number(policy.review_max_risk),
        sensitive_file_action: policy.sensitive_file_action,
        unknown_tool_action: policy.unknown_tool_action,
        block_on_schema_mismatch: Boolean(policy.block_on_schema_mismatch),
        bulk_threshold: Number(policy.bulk_threshold),
        drift_low_max: Number(policy.drift_low_max),
        drift_medium_max: Number(policy.drift_medium_max),
        drift_high_action: policy.drift_high_action,
        drift_frequency_multiplier: Number(policy.drift_frequency_multiplier),
      });
      setPolicy(res.policy);
      setSavedMsg('Security policy persisted to SQLite and applied immediately to all runtime inspections.');
      onPolicySaved();
      await loadData();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Failed to update policy');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="border-b border-[#D9D5CE] pb-5">
        <p className="text-xs font-mono text-[#8C2635] font-medium">Policy &amp; Access Control</p>
        <h2 className="text-2xl font-semibold text-[#191919] mt-1">Security Policy &amp; Governance</h2>
        <p className="text-xs text-[#5E5A55] mt-1">
          Configure deterministic risk thresholds, sensitive file actions, administrator roles, and inspect the audit trail.
        </p>
      </div>

      {loadError && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {loadError}
        </div>
      )}

      {!isAdmin && (
        <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] flex items-center gap-2.5 text-xs font-mono text-[#5E5A55]">
          <Lock className="w-3.5 h-3.5 text-[#8C2635] shrink-0" />
          <span>
            Signed in as <span className="uppercase font-semibold text-[#191919]">{userRole}</span>. Policy threshold changes are strictly restricted to Security Administrators.
          </span>
        </div>
      )}

      {/* Deterministic Policy Form */}
      {policy && (
        <form onSubmit={handleSavePolicy} className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[#D9D5CE] pb-3">
            <div>
              <h3 className="text-sm font-semibold text-[#191919]">{policy.name}</h3>
              <p className="text-xs text-[#5E5A55] mt-0.5">{policy.description}</p>
            </div>
            <span className="text-xs font-mono font-semibold text-[#8C2635]">Active Policy</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-medium text-[#191919] mb-1">ALLOW Max Risk Score (0–60)</label>
              <input
                type="number"
                min={5}
                max={60}
                value={policy.allow_max_risk}
                onChange={(e) => setPolicy({ ...policy, allow_max_risk: Number(e.target.value) })}
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#191919] mb-1">REVIEW Max Risk Score (20–95)</label>
              <input
                type="number"
                min={20}
                max={95}
                value={policy.review_max_risk}
                onChange={(e) => setPolicy({ ...policy, review_max_risk: Number(e.target.value) })}
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#191919] mb-1">Bulk Extraction Row Threshold</label>
              <input
                type="number"
                min={10}
                max={100000}
                value={policy.bulk_threshold}
                onChange={(e) => setPolicy({ ...policy, bulk_threshold: Number(e.target.value) })}
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-[#191919] mb-1">Sensitive File Access Action</label>
              <select
                value={policy.sensitive_file_action}
                onChange={(e) =>
                  setPolicy({ ...policy, sensitive_file_action: e.target.value as 'BLOCK' | 'REVIEW' })
                }
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919] focus:outline-none focus:border-[#8C2635]"
              >
                <option value="BLOCK">BLOCK (Short-Circuit Immediately)</option>
                <option value="REVIEW">REVIEW (Route to Approval Centre)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-[#191919] mb-1">Unknown Unregistered Tool Action</label>
              <select
                value={policy.unknown_tool_action}
                onChange={(e) =>
                  setPolicy({ ...policy, unknown_tool_action: e.target.value as 'REVIEW' | 'BLOCK' })
                }
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919] focus:outline-none focus:border-[#8C2635]"
              >
                <option value="REVIEW">REVIEW (Require Human Approval)</option>
                <option value="BLOCK">BLOCK (Strict Allowlist Only)</option>
              </select>
            </div>

            <div className="flex items-end pb-2">
              <label className="flex items-center gap-2 text-xs text-[#191919] cursor-pointer">
                <input
                  type="checkbox"
                  checked={Boolean(policy.block_on_schema_mismatch)}
                  onChange={(e) => setPolicy({ ...policy, block_on_schema_mismatch: e.target.checked ? 1 : 0 })}
                  className="accent-[#8C2635]"
                />
                <span>Block immediately on Tool DNA SHA-256 mismatch</span>
              </label>
            </div>
          </div>

          <div className="pt-4 border-t border-[#D9D5CE]">
            <h4 className="text-xs font-semibold text-[#191919] mb-3">
              Behavioural Drift Detection Thresholds
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs font-medium text-[#191919] mb-1">
                  Low Deviation Max (Allow, 5–50)
                </label>
                <input
                  type="number"
                  min={5}
                  max={50}
                  value={policy.drift_low_max}
                  onChange={(e) => setPolicy({ ...policy, drift_low_max: Number(e.target.value) })}
                  className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#191919] mb-1">
                  Medium Deviation Max (Review, 20–90)
                </label>
                <input
                  type="number"
                  min={20}
                  max={90}
                  value={policy.drift_medium_max}
                  onChange={(e) => setPolicy({ ...policy, drift_medium_max: Number(e.target.value) })}
                  className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#191919] mb-1">
                  High Deviation Response
                </label>
                <select
                  value={policy.drift_high_action}
                  onChange={(e) =>
                    setPolicy({ ...policy, drift_high_action: e.target.value as 'BLOCK' | 'REVIEW' })
                  }
                  className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919] focus:outline-none focus:border-[#8C2635]"
                >
                  <option value="BLOCK">BLOCK (Short-Circuit High Drift)</option>
                  <option value="REVIEW">REVIEW (Require Admin Approval)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-[#191919] mb-1">
                  Frequency Spike Multiplier (2x–20x)
                </label>
                <input
                  type="number"
                  min={2}
                  max={20}
                  value={policy.drift_frequency_multiplier}
                  onChange={(e) => setPolicy({ ...policy, drift_frequency_multiplier: Number(e.target.value) })}
                  className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
                />
              </div>
            </div>
          </div>

          {errorMsg && <p className="text-xs font-mono text-[#B91C1C]">{errorMsg}</p>}
          {savedMsg && <p className="text-xs font-mono text-[#1B6B44]">{savedMsg}</p>}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={!isAdmin || saving}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] disabled:opacity-50 text-xs font-semibold text-[#FCFBF8]"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{saving ? 'Saving Policy...' : isAdmin ? 'Save Security Policy' : 'Admin Required to Save'}</span>
            </button>
          </div>
        </form>
      )}

      {/* Governance Roles & Audit Trail */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-3">
          <h3 className="text-sm font-semibold text-[#191919]">Authorized Governance Roles</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-[#D9D5CE] text-[#5E5A55]">
                  <th className="py-2 pr-3 font-medium">Name</th>
                  <th className="py-2 px-3 font-medium">Email</th>
                  <th className="py-2 pl-3 font-medium text-right">Role</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#D9D5CE]/70">
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="py-2.5 pr-3 text-[#191919] font-medium">{u.display_name}</td>
                    <td className="py-2.5 px-3 font-mono text-[#5E5A55]">{u.email}</td>
                    <td className="py-2.5 pl-3 font-mono uppercase text-right text-[#8C2635] font-semibold">
                      {u.role}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-3">
          <h3 className="text-sm font-semibold text-[#191919]">Security Audit Log</h3>
          <div className="max-h-72 overflow-y-auto divide-y divide-[#D9D5CE]/70">
            {auditLogs.slice(0, 25).map((log) => (
              <div key={log.id} className="py-2.5 text-xs flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="font-mono font-medium text-[#191919]">{log.action}</div>
                  <div className="text-[11px] font-mono text-[#5E5A55] truncate">
                    Actor: {log.actor_id} ({log.actor_role}) · Target: {log.target_type}
                  </div>
                </div>
                <span className="font-mono text-[11px] text-[#77736D] shrink-0">
                  {formatUtcTime(log.created_at)}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
