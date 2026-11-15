import { useEffect, useState } from 'react';
import { CheckCircle2, Lock, Play, XCircle } from 'lucide-react';
import { api } from '../lib/api';
import type { QaSuiteReport, UserRecord } from '../types/toolseal';

interface QaVerificationPanelProps {
  userRole: UserRecord['role'];
}

export function QaVerificationPanel({ userRole }: QaVerificationPanelProps) {
  const [report, setReport] = useState<QaSuiteReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isAdmin = userRole === 'admin';

  const runSuite = async () => {
    if (!isAdmin) return;
    setRunning(true);
    setError(null);
    try {
      const res = await api.post<QaSuiteReport>('/api/qa/run-suite');
      setReport(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'QA verification suite failed to execute');
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    if (isAdmin) {
      runSuite();
    }
  }, [isAdmin]);

  return (
    <section className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#D9D5CE] pb-4">
        <div>
          <h3 className="text-sm font-semibold text-[#191919]">Runtime Verification Matrix</h3>
          <p className="text-xs text-[#5E5A55] mt-0.5 font-mono">
            {!isAdmin
              ? 'Administrator role required to execute backend security & RBAC verification suite'
              : report
              ? `${report.summary.passed}/${report.summary.total} checks passed · ${report.summary.failed} failed`
              : 'Executing assertions across SQLite, Security Engine, Tool DNA, HMAC Auth, RBAC, and Behavioural Drift'}
          </p>
        </div>

        <button
          type="button"
          disabled={!isAdmin || running}
          onClick={runSuite}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-[2px] border border-[#191919] bg-[#191919] hover:bg-[#2E2E2E] disabled:opacity-50 text-xs font-medium text-[#FCFBF8] transition-colors whitespace-nowrap shrink-0"
        >
          <Play className="w-3 h-3" />
          <span>{running ? 'Running Checks...' : 'Re-run Suite'}</span>
        </button>
      </div>

      {!isAdmin ? (
        <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] flex items-center gap-2.5 text-xs font-mono text-[#5E5A55]">
          <Lock className="w-3.5 h-3.5 text-[#8C2635] shrink-0" />
          <span>
            Signed in as <span className="uppercase font-semibold text-[#191919]">{userRole}</span>. Security self-tests run live RBAC and HMAC probes and are restricted to Security Administrators.
          </span>
        </div>
      ) : (
        <>
          {error && <p className="text-xs text-[#B91C1C] font-mono">{error}</p>}

          {report ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-[#D9D5CE] text-[#5E5A55]">
                    <th className="py-2.5 pr-4 font-medium">Result</th>
                    <th className="py-2.5 px-4 font-medium">Module</th>
                    <th className="py-2.5 px-4 font-medium">Verification Check</th>
                    <th className="py-2.5 px-4 font-medium">Diagnostic Output</th>
                    <th className="py-2.5 pl-4 font-medium text-right">Time</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#D9D5CE]/70">
                  {report.tests.map((test) => (
                    <tr key={test.id} className="hover:bg-[#F7F5F0]">
                      <td className="py-2.5 pr-4 whitespace-nowrap">
                        {test.status === 'PASS' ? (
                          <span className="inline-flex items-center gap-1.5 font-mono font-semibold text-[#1B6B44]">
                            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                            <span>PASS</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 font-mono font-semibold text-[#B91C1C]">
                            <XCircle className="w-3.5 h-3.5 shrink-0" />
                            <span>FAIL</span>
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 font-medium text-[#191919] whitespace-nowrap">{test.module}</td>
                      <td className="py-2.5 px-4 text-[#191919] whitespace-nowrap">{test.title}</td>
                      <td className="py-2.5 px-4 font-mono text-[11px] text-[#5E5A55] max-w-md truncate">
                        {test.detail}
                      </td>
                      <td className="py-2.5 pl-4 font-mono tabular-nums text-[#5E5A55] text-right whitespace-nowrap">
                        {test.durationMs}ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-[#77736D] font-mono">Running verification suite...</div>
          )}
        </>
      )}
    </section>
  );
}
