import { useCallback, useEffect, useState } from 'react';
import { Layout, type NavPage } from './components/Layout';
import { LoginView } from './components/LoginView';
import { useWebSocket } from './hooks/useWebSocket';
import { api, clearClientSessionToken, setUnauthorizedHandler } from './lib/api';
import { ApprovalsPage } from './pages/ApprovalsPage';
import { BehaviourPage } from './pages/BehaviourPage';
import { BifrostPage } from './pages/BifrostPage';
import { DashboardPage } from './pages/DashboardPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { LiveMonitorPage } from './pages/LiveMonitorPage';
import { SettingsPage } from './pages/SettingsPage';
import { SimulatorPage } from './pages/SimulatorPage';
import { ToolDnaPage } from './pages/ToolDnaPage';
import type { AuthSessionResponse, DashboardOverview, UserRecord } from './types/toolseal';

export default function App() {
  const [user, setUser] = useState<UserRecord | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);
  const [activePage, setActivePage] = useState<NavPage>('dashboard');
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshSignal, setRefreshSignal] = useState(0);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      clearClientSessionToken();
      setUser(null);
      setOverview(null);
      setSessionNotice('Your session expired or was revoked. Please sign in again.');
    });
    return () => setUnauthorizedHandler(null);
  }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await api.get<AuthSessionResponse>('/api/auth/me');
        if (active) {
          if (res.authenticated && res.user) {
            setUser(res.user);
            setSessionNotice(null);
          } else {
            clearClientSessionToken();
            setUser(null);
          }
        }
      } catch {
        // Keep existing state clear on network/auth bootstrap error without throwing uncaught rejection
        if (active) {
          setUser(null);
        }
      } finally {
        if (active) setAuthChecking(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const loadOverview = useCallback(async () => {
    if (!user) return;
    setOverviewError(null);
    try {
      const res = await api.get<DashboardOverview>('/api/dashboard/overview');
      setOverview(res);
    } catch (err) {
      setOverviewError(err instanceof Error ? err.message : 'Failed to load security telemetry.');
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    if (user) {
      setLoading(true);
      loadOverview();
    }
  }, [user, loadOverview, refreshSignal]);

  const wsStatus = useWebSocket(
    (msg) => {
      if (msg.type !== 'connected') {
        setRefreshSignal((s) => s + 1);
      }
    },
    Boolean(user)
  );

  const triggerRefresh = useCallback(() => {
    setRefreshSignal((s) => s + 1);
  }, []);

  const handleLogout = async () => {
    try {
      await api.post('/api/auth/logout');
    } catch {
      // Clear local session regardless of transport error
    } finally {
      clearClientSessionToken();
      setUser(null);
      setOverview(null);
      setSessionNotice(null);
      setActivePage('dashboard');
    }
  };

  if (authChecking) {
    return (
      <div className="min-h-screen bg-[#F7F5F0] bg-swiss-grid flex items-center justify-center p-6">
        <div className="px-6 py-4 rounded-[2px] border border-[#D9D5CE] bg-[#FCFBF8] text-xs font-mono text-[#5E5A55]">
          Verifying TOOLSEAL security session...
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <LoginView
        notice={sessionNotice}
        onAuthenticated={(authenticatedUser) => {
          setSessionNotice(null);
          setOverviewError(null);
          setLoading(true);
          setUser(authenticatedUser);
          setRefreshSignal((s) => s + 1);
        }}
      />
    );
  }

  return (
    <Layout
      activePage={activePage}
      onNavigate={setActivePage}
      wsStatus={wsStatus}
      pendingApprovalsCount={overview?.metrics.pendingApprovals ?? 0}
      openIncidentsCount={overview?.metrics.activeIncidents ?? 0}
      bifrostMode={overview?.bifrostStatus.mode ?? 'demo'}
      user={user}
      onLogout={handleLogout}
    >
      {activePage === 'dashboard' && (
        <DashboardPage
          data={overview}
          loading={loading}
          error={overviewError}
          userRole={user.role}
          onRefresh={triggerRefresh}
          onNavigate={setActivePage}
        />
      )}
      {activePage === 'monitor' && (
        <LiveMonitorPage refreshSignal={refreshSignal} userRole={user.role} />
      )}
      {activePage === 'tooldna' && (
        <ToolDnaPage refreshSignal={refreshSignal} userRole={user.role} />
      )}
      {activePage === 'behaviour' && (
        <BehaviourPage refreshSignal={refreshSignal} userRole={user.role} onDataChanged={triggerRefresh} />
      )}
      {activePage === 'approvals' && (
        <ApprovalsPage refreshSignal={refreshSignal} userRole={user.role} />
      )}
      {activePage === 'incidents' && (
        <IncidentsPage refreshSignal={refreshSignal} userRole={user.role} />
      )}
      {activePage === 'simulator' && (
        <SimulatorPage userRole={user.role} onSimulated={triggerRefresh} />
      )}
      {activePage === 'bifrost' && (
        <BifrostPage refreshSignal={refreshSignal} userRole={user.role} onConfigChanged={triggerRefresh} />
      )}
      {activePage === 'settings' && (
        <SettingsPage refreshSignal={refreshSignal} userRole={user.role} onPolicySaved={triggerRefresh} />
      )}
    </Layout>
  );
}
