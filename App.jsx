import React, { useState, useEffect } from 'react';
import CyberBackground from './components/CyberBackground';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import TrafficPage from './pages/TrafficPage';
import DetectionPage from './pages/DetectionPage';
import AlertsPage from './pages/AlertsPage';
import ModelPage from './pages/ModelPage';
import ReportsPage from './pages/ReportsPage';
import SettingsPage from './pages/SettingsPage';
import { api, getStoredToken, getStoredUser } from './api/client';

export default function App() {
  const [user, setUser] = useState(getStoredUser());
  const [isAuthenticated, setIsAuthenticated] = useState(!!getStoredToken());
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [isLiveActive, setIsLiveActive] = useState(false);
  const [alertCount, setAlertCount] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  // Check auth session
  useEffect(() => {
    async function verifyAuth() {
      const token = getStoredToken();
      if (!token) {
        setIsAuthenticated(false);
        return;
      }
      try {
        const profile = await api.getCurrentUser();
        setUser(profile);
        setIsAuthenticated(true);
      } catch (err) {
        console.warn('Auth verification failed:', err);
        setIsAuthenticated(false);
      }
    }
    verifyAuth();

    const handleUnauthorized = () => {
      setIsAuthenticated(false);
      setUser(null);
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  // Poll alert count & live status
  useEffect(() => {
    if (!isAuthenticated) return;

    async function checkStatus() {
      try {
        const [liveRes, alertsRes] = await Promise.all([
          api.getLiveStatus().catch(() => ({ is_active: false })),
          api.getAlerts({ status: 'New', limit: 1 }).catch(() => []),
        ]);
        setIsLiveActive(liveRes.is_active);
      } catch (e) {}
    }

    checkStatus();
    const interval = setInterval(checkStatus, 10000);
    return () => clearInterval(interval);
  }, [isAuthenticated, refreshTrigger]);

  const handleLoginSuccess = (userData) => {
    setUser(userData);
    setIsAuthenticated(true);
    setActiveTab('dashboard');
  };

  const handleLogout = () => {
    api.logout();
    setIsAuthenticated(false);
    setUser(null);
  };

  const handleToggleLive = async () => {
    try {
      const nextState = !isLiveActive;
      await api.toggleLive(nextState);
      setIsLiveActive(nextState);
    } catch (e) {
      alert(`Error toggling live monitor: ${e.message}`);
    }
  };

  const handleRefresh = () => {
    setIsRefreshing(true);
    setRefreshTrigger((prev) => prev + 1);
    setTimeout(() => setIsRefreshing(false), 800);
  };

  if (!isAuthenticated) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="min-h-screen bg-[#060911] text-slate-100 relative flex overflow-x-hidden">
      {/* Background Cyber Node Canvas */}
      <CyberBackground />

      {/* Cyber Grid Texture */}
      <div className="fixed inset-0 cyber-grid opacity-30 pointer-events-none z-0" />

      {/* Collapsible Sidebar */}
      <Sidebar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
        alertCount={alertCount}
        user={user}
        onLogout={handleLogout}
      />

      {/* Main Content Area */}
      <div
        className={`flex-1 flex flex-col min-h-screen transition-all duration-300 relative z-10 ${
          sidebarCollapsed ? 'ml-20' : 'ml-72'
        }`}
      >
        <Header
          activeTab={activeTab}
          isLiveActive={isLiveActive}
          onToggleLive={handleToggleLive}
          onRefresh={handleRefresh}
          isRefreshing={isRefreshing}
        />

        <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
          {activeTab === 'dashboard' && <DashboardPage key={refreshTrigger} setActiveTab={setActiveTab} />}
          {activeTab === 'traffic' && (
            <TrafficPage
              key={refreshTrigger}
              isLiveActive={isLiveActive}
              onToggleLive={handleToggleLive}
            />
          )}
          {activeTab === 'detection' && <DetectionPage key={refreshTrigger} />}
          {activeTab === 'alerts' && <AlertsPage key={refreshTrigger} />}
          {activeTab === 'model' && <ModelPage key={refreshTrigger} />}
          {activeTab === 'reports' && <ReportsPage key={refreshTrigger} />}
          {activeTab === 'settings' && (
            <SettingsPage key={refreshTrigger} user={user} onUserUpdated={setUser} />
          )}
        </main>

        {/* Footer */}
        <footer className="px-6 py-4 border-t border-slate-900 bg-slate-950/40 text-center text-xs font-mono text-slate-500">
          AI-Based Intrusion Detection System (AI-IDS) • Project Code: RW-CS-001 • Organization: RW Software Solutions
        </footer>
      </div>
    </div>
  );
}
