import { useState, type ReactNode } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckSquare,
  Fingerprint,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Settings,
  Shield,
  Swords,
  X,
} from 'lucide-react';
import type { WsConnectionState } from '../hooks/useWebSocket';
import type { UserRecord } from '../types/toolseal';

export type NavPage =
  | 'dashboard'
  | 'monitor'
  | 'tooldna'
  | 'behaviour'
  | 'approvals'
  | 'incidents'
  | 'simulator'
  | 'bifrost'
  | 'settings';

interface LayoutProps {
  activePage: NavPage;
  onNavigate: (page: NavPage) => void;
  wsStatus: WsConnectionState;
  pendingApprovalsCount: number;
  openIncidentsCount: number;
  bifrostMode: 'demo' | 'live';
  user: UserRecord;
  onLogout: () => void;
  children: ReactNode;
}

const NAV_ITEMS: Array<{ id: NavPage; index: string; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'dashboard', index: '01', label: 'Overview', icon: LayoutDashboard },
  { id: 'monitor', index: '02', label: 'Live Monitoring', icon: Activity },
  { id: 'tooldna', index: '03', label: 'Tool DNA Registry', icon: Fingerprint },
  { id: 'behaviour', index: '04', label: 'Behavioural Intelligence', icon: GitBranch },
  { id: 'approvals', index: '05', label: 'Approval Centre', icon: CheckSquare },
  { id: 'incidents', index: '06', label: 'Incidents', icon: AlertOctagon },
  { id: 'simulator', index: '07', label: 'Attack Simulator', icon: Swords },
  { id: 'bifrost', index: '08', label: 'Bifrost Gateway', icon: Network },
  { id: 'settings', index: '09', label: 'Settings', icon: Settings },
];

export function Layout({
  activePage,
  onNavigate,
  wsStatus,
  pendingApprovalsCount,
  openIncidentsCount,
  bifrostMode,
  user,
  onLogout,
  children,
}: LayoutProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const activeItem = NAV_ITEMS.find((n) => n.id === activePage) ?? NAV_ITEMS[0];

  const handleNav = (id: NavPage) => {
    onNavigate(id);
    setMobileOpen(false);
  };

  return (
    <div className="min-h-screen bg-[#F7F5F0] bg-swiss-grid text-[#191919] flex">
      {/* Mobile Sidebar Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-[#191919]/40 lg:hidden"
          onClick={() => setMobileOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Left Sidebar Navigation — Swiss Editorial Rail */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 bg-[#F7F5F0] border-r border-[#D9D5CE] flex flex-col transition-transform duration-200 lg:static lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="h-16 px-5 border-b border-[#D9D5CE] flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-[2px] bg-[#8C2635] flex items-center justify-center text-[#F7F5F0]">
              <Shield className="w-4 h-4" />
            </div>
            <span className="text-base font-bold tracking-tight text-[#191919] whitespace-nowrap">
              TOOLSEAL
            </span>
          </div>
          <button
            type="button"
            onClick={() => setMobileOpen(false)}
            className="lg:hidden p-2 text-[#5E5A55] hover:text-[#191919] rounded-[2px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#8C2635]"
            aria-label="Close navigation menu"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <nav className="flex-1 px-3 py-5 space-y-0.5 overflow-y-auto" aria-label="Primary navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activePage === item.id;
            const count =
              item.id === 'approvals'
                ? pendingApprovalsCount
                : item.id === 'incidents'
                ? openIncidentsCount
                : 0;

            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleNav(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-[2px] text-[13px] font-medium transition-colors whitespace-nowrap focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#8C2635] ${
                  isActive
                    ? 'bg-[#FCFBF8] text-[#191919] border border-[#D9D5CE]'
                    : 'text-[#5E5A55] hover:text-[#191919] hover:bg-[#EFECE5] border border-transparent'
                }`}
              >
                <span className="flex items-center gap-2.5 truncate">
                  <span
                    className={`font-mono text-[11px] tabular-nums ${
                      isActive ? 'text-[#8C2635] font-semibold' : 'text-[#77736D]'
                    }`}
                  >
                    {item.index}
                  </span>
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-[#8C2635]' : 'text-[#77736D]'}`} />
                  <span className="truncate">{item.label}</span>
                </span>
                {count > 0 && (
                  <span
                    className={`font-mono text-xs font-semibold tabular-nums ${
                      item.id === 'approvals' ? 'text-[#A16207]' : 'text-[#B91C1C]'
                    }`}
                  >
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Authenticated Operator & Runtime Summary */}
        <div className="p-4 border-t border-[#D9D5CE] space-y-3 text-xs text-[#5E5A55]">
          <div className="p-2.5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] space-y-1">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[#191919] font-semibold truncate">{user.username}</span>
              <span className="font-mono text-[10px] uppercase font-semibold text-[#8C2635]">
                {user.role}
              </span>
            </div>
            <div className="text-[11px] text-[#5E5A55] truncate">{user.display_name}</div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span>Telemetry Stream</span>
              <span
                className={`inline-flex items-center gap-1.5 font-mono font-medium ${
                  wsStatus === 'connected'
                    ? 'text-[#1B6B44]'
                    : wsStatus === 'disconnected'
                    ? 'text-[#B91C1C]'
                    : 'text-[#A16207]'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    wsStatus === 'connected'
                      ? 'bg-[#1B6B44]'
                      : wsStatus === 'disconnected'
                      ? 'bg-[#B91C1C]'
                      : 'bg-[#A16207]'
                  }`}
                />
                {wsStatus === 'connected'
                  ? 'Connected'
                  : wsStatus === 'disconnected'
                  ? 'Disconnected'
                  : 'Reconnecting'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Bifrost Hook</span>
              <span className="font-mono text-[#191919]">
                {bifrostMode === 'live' ? 'Live' : 'Demo Mode'}
              </span>
            </div>
          </div>

          <button
            type="button"
            onClick={onLogout}
            className="w-full inline-flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] hover:border-[#191919] text-xs font-medium text-[#191919] transition-colors"
          >
            <LogOut className="w-3.5 h-3.5 text-[#8C2635]" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Workspace */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-16 px-4 sm:px-8 bg-[#F7F5F0] border-b border-[#D9D5CE] flex items-center justify-between gap-4 sticky top-0 z-30">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-2 -ml-1 text-[#5E5A55] hover:text-[#191919] rounded-[2px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#8C2635]"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2.5 text-sm min-w-0">
              <span className="text-[#77736D] font-mono text-xs hidden sm:inline">TOOLSEAL</span>
              <span className="text-[#D9D5CE] hidden sm:inline">/</span>
              <span className="font-mono text-xs text-[#8C2635] font-semibold hidden sm:inline">
                {activeItem.index}
              </span>
              <h1 className="text-sm sm:text-base font-semibold text-[#191919] truncate">
                {activeItem.label}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <span className="hidden md:inline font-mono text-xs text-[#5E5A55]">
              Role: <span className="uppercase font-semibold text-[#191919]">{user.role}</span>
            </span>
            {user.role === 'viewer' ? (
              <span className="px-3 py-1.5 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] text-xs font-mono text-[#5E5A55]">
                Read-Only Audit Mode
              </span>
            ) : (
              <button
                type="button"
                onClick={() => onNavigate('simulator')}
                className="px-4 py-2 rounded-[2px] bg-[#8C2635] hover:bg-[#731E2B] text-xs font-semibold text-[#FCFBF8] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#8C2635] focus-visible:ring-offset-2 focus-visible:ring-offset-[#F7F5F0]"
              >
                Run Attack Simulator
              </button>
            )}
          </div>
        </header>

        {(wsStatus === 'reconnecting' || wsStatus === 'disconnected') && (
          <div className="px-4 sm:px-8 py-2.5 bg-[#A16207]/10 border-b border-[#A16207]/30 flex items-center gap-2 text-xs font-mono text-[#A16207]">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            <span>
              {wsStatus === 'reconnecting'
                ? 'Real-time WebSocket telemetry stream interrupted — attempting automatic reconnect...'
                : 'Real-time WebSocket telemetry stream disconnected. Use manual Refresh or re-authenticate.'}
            </span>
          </div>
        )}

        <main className="flex-1 p-4 sm:p-8 max-w-[1440px] w-full mx-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
