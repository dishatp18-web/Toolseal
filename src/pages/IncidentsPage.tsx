import { useEffect, useState } from 'react';
import { Search } from 'lucide-react';
import { DecisionIndicator, RiskScoreValue, SeverityText } from '../components/DecisionLabel';
import { api, formatUtcTime } from '../lib/api';
import type { IncidentSeverity, IncidentStatus, SecurityIncident, UserRecord } from '../types/toolseal';

interface IncidentsPageProps {
  refreshSignal: number;
  userRole: UserRecord['role'];
}

export function IncidentsPage({ refreshSignal, userRole }: IncidentsPageProps) {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<SecurityIncident | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const canModifyIncident = userRole === 'admin' || userRole === 'analyst';

  const loadIncidents = async () => {
    setLoadError(null);
    try {
      const params = new URLSearchParams();
      if (severityFilter !== 'all') params.set('severity', severityFilter);
      if (statusFilter !== 'all') params.set('status', statusFilter);
      if (fromDate) params.set('fromDate', fromDate);
      if (toDate) params.set('toDate', toDate);
      if (search.trim()) params.set('search', search.trim());

      const res = await api.get<{ incidents: SecurityIncident[] }>(`/api/incidents?${params.toString()}`);
      setIncidents(res.incidents);
      if (selected) {
        const refreshed = res.incidents.find((i) => i.id === selected.id) || null;
        setSelected(refreshed);
      } else if (res.incidents.length > 0) {
        setSelected(res.incidents[0]);
      }
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : 'Failed to load security incidents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [severityFilter, statusFilter, fromDate, toDate, search, refreshSignal]);

  const handleStatusChange = async (id: string, nextStatus: IncidentStatus) => {
    setActionError(null);
    try {
      await api.patch(`/api/incidents/${id}`, { status: nextStatus });
      await loadIncidents();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Failed to update incident status');
    }
  };

  return (
    <div className="space-y-8">
      <div className="border-b border-[#D9D5CE] pb-5">
        <p className="text-xs font-mono text-[#8C2635] font-medium">Forensic Audit Trail</p>
        <h2 className="text-2xl font-semibold text-[#191919] mt-1">Security Incident Reports</h2>
        <p className="text-xs text-[#5E5A55] mt-1">
          Persistent forensic ledger capturing blocked threats, schema tampering alerts, and human review escalations.
        </p>
      </div>

      {/* Filters Toolbar */}
      <div className="p-5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <div>
          <label className="block text-[11px] font-medium text-[#5E5A55] mb-1">Severity</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919] focus:outline-none focus:border-[#8C2635]"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] font-medium text-[#5E5A55] mb-1">Incident Status</label>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs text-[#191919] focus:outline-none focus:border-[#8C2635]"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="dismissed">Dismissed</option>
          </select>
        </div>

        <div>
          <label className="block text-[11px] font-medium text-[#5E5A55] mb-1">From Date</label>
          <input
            type="date"
            value={fromDate}
            onChange={(e) => setFromDate(e.target.value)}
            className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
          />
        </div>

        <div>
          <label className="block text-[11px] font-medium text-[#5E5A55] mb-1">To Date</label>
          <input
            type="date"
            value={toDate}
            onChange={(e) => setToDate(e.target.value)}
            className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
          />
        </div>

        <div>
          <label className="block text-[11px] font-medium text-[#5E5A55] mb-1">Search</label>
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-[#77736D] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Tool, category, ID..."
              className="w-full pl-8 pr-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-xs font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
            />
          </div>
        </div>
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

      {/* Forensic Ledger + Report Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        <div className="lg:col-span-7 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#D9D5CE] bg-[#F7F5F0] text-[#5E5A55]">
                <th className="py-2.5 px-4 font-medium">Incident</th>
                <th className="py-2.5 px-3 font-medium">Tool</th>
                <th className="py-2.5 px-3 font-medium">Severity</th>
                <th className="py-2.5 px-3 font-medium text-right">Risk</th>
                <th className="py-2.5 px-3 font-medium">Status</th>
                <th className="py-2.5 px-4 font-medium text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#D9D5CE]/70">
              {loading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[#77736D] font-mono">
                    Loading incidents...
                  </td>
                </tr>
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-[#77736D] font-mono">
                    No security incidents match your filters.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => setSelected(inc)}
                    className={`cursor-pointer transition-colors ${
                      selected?.id === inc.id ? 'bg-[#EFECE5]' : 'hover:bg-[#F7F5F0]'
                    }`}
                  >
                    <td className="py-3 px-4 font-mono font-semibold text-[#191919] whitespace-nowrap">
                      {inc.incident_uid}
                    </td>
                    <td className="py-3 px-3 font-mono text-[#191919] whitespace-nowrap">{inc.tool_name}</td>
                    <td className="py-3 px-3">
                      <SeverityText severity={inc.severity as IncidentSeverity} />
                    </td>
                    <td className="py-3 px-3 text-right">
                      <RiskScoreValue score={inc.risk_score} />
                    </td>
                    <td className="py-3 px-3 font-mono text-[#5E5A55] capitalize whitespace-nowrap">{inc.status}</td>
                    <td className="py-3 px-4 font-mono text-[#5E5A55] text-right whitespace-nowrap">
                      {formatUtcTime(inc.created_at)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Forensic Report Document */}
        <div className="lg:col-span-5 p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5">
          {selected ? (
            <>
              <div className="flex items-start justify-between gap-3 border-b border-[#D9D5CE] pb-4">
                <div>
                  <div className="flex items-center gap-2 text-sm">
                    <span className="font-mono font-semibold text-[#191919]">{selected.incident_uid}</span>
                    <span className="text-[#D9D5CE]">·</span>
                    <SeverityText severity={selected.severity} />
                  </div>
                  <p className="text-xs font-mono text-[#5E5A55] mt-1">
                    {selected.threat_category} · {selected.source === 'bifrost' ? 'Bifrost Live' : 'Demo / Simulator'}
                  </p>
                </div>
                <DecisionIndicator decision={selected.decision} />
              </div>

              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-[#191919]">Forensic Summary</div>
                <p className="text-xs text-[#5E5A55] leading-relaxed">{selected.explanation}</p>
              </div>

              <div className="space-y-1.5">
                <div className="text-xs font-semibold text-[#191919]">Captured Execution Arguments</div>
                <pre className="p-3 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-[11px] font-mono text-[#191919] overflow-x-auto">
                  {(() => {
                    try {
                      return JSON.stringify(JSON.parse(selected.arguments_json), null, 2);
                    } catch {
                      return selected.arguments_json;
                    }
                  })()}
                </pre>
              </div>

              <div className="pt-4 border-t border-[#D9D5CE] space-y-2.5">
                <div className="text-xs font-semibold text-[#191919]">Incident Resolution State</div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  {(['open', 'investigating', 'resolved', 'dismissed'] as const).map((st) => (
                    <button
                      key={st}
                      type="button"
                      disabled={!canModifyIncident}
                      onClick={() => handleStatusChange(selected.id, st)}
                      className={`px-3 py-2 rounded-[2px] text-xs font-mono font-medium capitalize border transition-colors disabled:opacity-50 ${
                        selected.status === st
                          ? 'bg-[#8C2635] text-[#FCFBF8] border-[#8C2635] font-semibold'
                          : 'bg-[#F7F5F0] border-[#D9D5CE] text-[#191919] hover:border-[#191919]'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="py-10 text-center text-xs font-mono text-[#77736D]">
              Select an incident row to inspect the forensic report and update resolution status.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
