import { useEffect, useState } from 'react';
import { CheckCircle2, Lock, ShieldAlert, XCircle } from 'lucide-react';
import { RiskScoreValue } from '../components/DecisionLabel';
import { api, formatUtcTime } from '../lib/api';
import type { ApprovalRequest, TriggeredRule, UserRecord } from '../types/toolseal';

interface ApprovalsPageProps {
  refreshSignal: number;
  userRole: UserRecord['role'];
}

export function ApprovalsPage({ refreshSignal, userRole }: ApprovalsPageProps) {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [statusFilter, setStatusFilter] = useState<'pending' | 'approved' | 'rejected' | 'all'>('pending');
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [outcomeMsg, setOutcomeMsg] = useState<{ type: 'ok' | 'warn'; text: string } | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const isAdmin = userRole === 'admin';

  const loadApprovals = async () => {
    setLoadError(null);
    try {
      const qs = statusFilter === 'all' ? '' : `?status=${statusFilter}`;
      const res = await api.get<{ approvals: ApprovalRequest[] }>(`/api/approvals${qs}`);
      setApprovals(res.approvals);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load approval queue.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadApprovals();
  }, [statusFilter, refreshSignal]);

  const handleDecision = async (id: string, action: 'approved' | 'rejected') => {
    setProcessingId(id);
    setOutcomeMsg(null);
    try {
      // Reviewer identity and role are strictly verified from the server session cookie
      const res = await api.post<{
        status: string;
        revalidated: boolean;
        blockedOnRevalidation: boolean;
        mockOutput: string | null;
        message: string;
      }>(`/api/approvals/${id}/decide`, {
        action,
        note: notes[id] || '',
      });

      setOutcomeMsg({
        type: res.blockedOnRevalidation ? 'warn' : 'ok',
        text: res.mockOutput ? `${res.message} Sandbox output: ${res.mockOutput}` : res.message,
      });
      await loadApprovals();
    } catch (err) {
      setOutcomeMsg({
        type: 'warn',
        text: err instanceof Error ? err.message : 'Decision failed',
      });
    } finally {
      setProcessingId(null);
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 border-b border-[#D9D5CE] pb-5">
        <div>
          <p className="text-xs font-mono text-[#8C2635] font-medium">Human-in-the-Loop Governance</p>
          <h2 className="text-2xl font-semibold text-[#191919] mt-1">Approval Centre</h2>
          <p className="text-xs text-[#5E5A55] mt-1">
            Review medium-risk tool invocations. Approved requests undergo mandatory Tool DNA and policy revalidation prior to execution.
          </p>
        </div>

        <div className="flex items-center gap-1 p-1 rounded-[2px] bg-[#EFECE5] border border-[#D9D5CE] w-fit">
          {(['pending', 'approved', 'rejected', 'all'] as const).map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setStatusFilter(tab)}
              className={`px-3 py-1.5 rounded-[2px] text-xs font-mono font-medium capitalize transition-colors whitespace-nowrap ${
                statusFilter === tab
                  ? 'bg-[#FCFBF8] text-[#8C2635] border border-[#D9D5CE] font-semibold'
                  : 'text-[#5E5A55] hover:text-[#191919] border border-transparent'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {!isAdmin && (
        <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] flex items-center gap-2.5 text-xs font-mono text-[#5E5A55]">
          <Lock className="w-3.5 h-3.5 text-[#8C2635] shrink-0" />
          <span>
            Signed in as <span className="uppercase font-semibold text-[#191919]">{userRole}</span>. Approving or rejecting pending executions requires Security Administrator privileges.
          </span>
        </div>
      )}

      {loadError && (
        <div className="p-4 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
          {loadError}
        </div>
      )}

      {outcomeMsg && (
        <div
          className={`p-4 rounded-[2px] border text-xs font-mono ${
            outcomeMsg.type === 'warn'
              ? 'border-[#B91C1C]/40 bg-[#B91C1C]/5 text-[#B91C1C]'
              : 'border-[#1B6B44]/40 bg-[#1B6B44]/5 text-[#1B6B44]'
          }`}
        >
          {outcomeMsg.text}
        </div>
      )}

      {loading ? (
        <div className="p-8 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] text-center text-xs font-mono text-[#77736D]">
          Loading approval queue...
        </div>
      ) : approvals.length === 0 ? (
        <div className="p-10 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] text-center space-y-2">
          <p className="text-sm font-medium text-[#191919]">
            No {statusFilter === 'all' ? '' : statusFilter} approval requests
          </p>
          <p className="text-xs text-[#5E5A55]">
            Tool calls scoring inside the REVIEW threshold (31–70) appear here for administrator authorization.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {approvals.map((req) => {
            const rules: TriggeredRule[] = (() => {
              try {
                return JSON.parse(req.triggered_rules_json);
              } catch {
                return [];
              }
            })();

            return (
              <div key={req.id} className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#D9D5CE]/70 pb-3">
                  <div>
                    <div className="flex items-center gap-2.5 text-sm">
                      <span className="font-mono font-semibold text-[#191919]">{req.request_uid}</span>
                      <span className="text-[#D9D5CE]">·</span>
                      <span className="font-mono text-[#8C2635] font-medium">{req.tool_name}</span>
                      <span className="text-[#D9D5CE]">·</span>
                      <RiskScoreValue score={req.risk_score} />
                    </div>
                    <p className="text-xs font-mono text-[#5E5A55] mt-1">
                      Submitted {formatUtcTime(req.created_at)} · Status:{' '}
                      <span className="uppercase font-semibold text-[#191919]">{req.status}</span>
                      {req.revalidated ? ' · Revalidated' : ''}
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-[#191919]">Flagged Reason &amp; Triggered Rules</div>
                    <p className="text-xs text-[#A16207] font-medium">{req.reason}</p>
                    <ul className="space-y-1.5 text-xs text-[#5E5A55] pt-1">
                      {rules.map((r) => (
                        <li key={r.id} className="flex items-start gap-2">
                          <ShieldAlert className="w-3.5 h-3.5 text-[#A16207] shrink-0 mt-0.5" />
                          <span>
                            <span className="font-mono text-[#191919] font-medium">{r.name}</span> (+{r.weight}):{' '}
                            {r.detail}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div>
                    <div className="text-xs font-semibold text-[#191919] mb-1.5">Execution Arguments</div>
                    <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto">
                      {(() => {
                        try {
                          return JSON.stringify(JSON.parse(req.arguments_json), null, 2);
                        } catch {
                          return req.arguments_json;
                        }
                      })()}
                    </pre>
                  </div>
                </div>

                {req.status === 'pending' ? (
                  <div className="pt-4 border-t border-[#D9D5CE] flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
                    <input
                      type="text"
                      disabled={!isAdmin}
                      value={notes[req.id] || ''}
                      onChange={(e) => setNotes((prev) => ({ ...prev, [req.id]: e.target.value }))}
                      placeholder={isAdmin ? 'Administrator review note...' : 'Administrator privileges required to review'}
                      className="flex-1 px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919] disabled:opacity-60 focus:outline-none focus:border-[#8C2635]"
                    />
                    <div className="flex items-center gap-2.5 shrink-0">
                      <button
                        type="button"
                        disabled={!isAdmin || processingId === req.id}
                        onClick={() => handleDecision(req.id, 'rejected')}
                        className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[2px] border border-[#B91C1C] text-xs font-medium text-[#B91C1C] hover:bg-[#B91C1C]/10 disabled:opacity-50 whitespace-nowrap"
                      >
                        <XCircle className="w-3.5 h-3.5" />
                        <span>Reject</span>
                      </button>
                      <button
                        type="button"
                        disabled={!isAdmin || processingId === req.id}
                        onClick={() => handleDecision(req.id, 'approved')}
                        className="inline-flex items-center gap-1.5 px-4 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] text-xs font-semibold text-[#FCFBF8] disabled:opacity-50 whitespace-nowrap"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{processingId === req.id ? 'Revalidating...' : 'Revalidate & Approve'}</span>
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="pt-3 border-t border-[#D9D5CE] text-xs font-mono text-[#5E5A55]">
                    Reviewed by {req.reviewer_name || 'Administrator'} on {formatUtcTime(req.reviewed_at)} · Note:{' '}
                    {req.reviewer_note || '—'}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
