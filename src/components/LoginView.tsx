import { useState, type FormEvent } from 'react';
import { Lock, Shield, UserCheck } from 'lucide-react';
import { api, setClientSessionToken } from '../lib/api';
import type { AuthSessionResponse, UserRecord } from '../types/toolseal';

interface LoginViewProps {
  onAuthenticated: (user: UserRecord) => void;
  notice?: string | null;
}

const STARTER_ACCOUNTS = [
  { username: 'evance', role: 'admin', label: 'Security Admin' },
  { username: 'mchen', role: 'analyst', label: 'SOC Analyst' },
  { username: 'audit', role: 'viewer', label: 'Compliance Viewer' },
] as const;

export function LoginView({ onAuthenticated, notice }: LoginViewProps) {
  const [username, setUsername] = useState('evance');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    try {
      const res = await api.post<AuthSessionResponse>('/api/auth/login', {
        username: username.trim(),
        password,
      });
      if (res.authenticated && res.user) {
        if (res.sessionToken) {
          setClientSessionToken(res.sessionToken);
        }
        onAuthenticated(res.user);
      } else {
        setError('Authentication failed.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to sign in to TOOLSEAL.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#F7F5F0] bg-swiss-grid text-[#191919] flex flex-col justify-center items-center p-6">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Masthead */}
        <div className="border-b border-[#D9D5CE] pb-5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-[2px] bg-[#8C2635] flex items-center justify-center text-[#FCFBF8]">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-[#191919]">TOOLSEAL</h1>
              <p className="text-[11px] font-mono text-[#5E5A55]">
                Every AI Tool Call Must Earn Your Trust.
              </p>
            </div>
          </div>
          <span className="text-[11px] font-mono text-[#8C2635] font-semibold">RBAC AUTH</span>
        </div>

        {/* Sign-In Card */}
        <form
          onSubmit={handleSubmit}
          className="p-6 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-5"
        >
          <div className="border-b border-[#D9D5CE]/80 pb-3">
            <h2 className="text-base font-semibold text-[#191919]">Operator Sign In</h2>
            <p className="text-xs text-[#5E5A55] mt-1">
              Sign in with a SQLite-backed TOOLSEAL account. Role permissions (admin, analyst, viewer) are enforced server-side.
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <label htmlFor="login-username" className="block text-xs font-medium text-[#191919] mb-1">
                Username or Email
              </label>
              <input
                id="login-username"
                type="text"
                required
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. evance"
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-sm font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              />
            </div>

            <div>
              <label htmlFor="login-password" className="block text-xs font-medium text-[#191919] mb-1">
                Password
              </label>
              <input
                id="login-password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter account password"
                className="w-full px-3 py-2 rounded-[2px] bg-[#F7F5F0] border border-[#D9D5CE] text-sm font-mono text-[#191919] focus:outline-none focus:border-[#8C2635]"
              />
            </div>
          </div>

          {(error || notice) && (
            <div className="p-3 rounded-[2px] border border-[#B91C1C]/40 bg-[#B91C1C]/5 text-xs font-mono text-[#B91C1C]">
              {error || notice}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] disabled:opacity-50 text-xs font-semibold text-[#FCFBF8] transition-colors"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>{submitting ? 'Verifying Credentials...' : 'Sign In to Security Console'}</span>
          </button>
        </form>

        {/* Local Evaluation Accounts */}
        <div className="p-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-2.5">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-[#191919] inline-flex items-center gap-1.5">
              <UserCheck className="w-3.5 h-3.5 text-[#8C2635]" />
              <span>Seeded Local Role Accounts</span>
            </span>
            <span className="font-mono text-[11px] text-[#77736D]">Click to select username</span>
          </div>
          <div className="grid grid-cols-1 gap-1.5">
            {STARTER_ACCOUNTS.map((acc) => (
              <button
                key={acc.username}
                type="button"
                onClick={() => {
                  setUsername(acc.username);
                  setPassword('');
                  setError(null);
                }}
                className="flex items-center justify-between px-3 py-2 rounded-[2px] border border-[#D9D5CE] bg-[#F7F5F0] hover:border-[#8C2635] text-left transition-colors"
              >
                <div className="text-xs">
                  <span className="font-mono font-semibold text-[#191919]">{acc.username}</span>
                  <span className="text-[#5E5A55] ml-2">{acc.label}</span>
                </div>
                <span className="font-mono text-[11px] uppercase font-semibold text-[#8C2635]">
                  {acc.role}
                </span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
