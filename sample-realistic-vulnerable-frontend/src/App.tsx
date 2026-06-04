import { useState } from 'react';
import { isAuthenticated, logout } from './auth/authService';
import Header from './components/Header';
import { currentUser } from './data/mockData';
import DashboardPage from './pages/DashboardPage';
import LoginPage from './pages/LoginPage';
import NoticePage from './pages/NoticePage';
import ProfilePage from './pages/ProfilePage';
import SettingsPage from './pages/SettingsPage';
import type { PageKey, UserProfile } from './types';

export default function App() {
  const [user, setUser] = useState<UserProfile | null>(isAuthenticated() ? currentUser : null);
  const [activePage, setActivePage] = useState<PageKey>('dashboard');

  if (!user) {
    return <LoginPage onLoggedIn={setUser} />;
  }

  function handleLogout() {
    logout();
    setUser(null);
    setActivePage('dashboard');
  }

  return (
    <div className="app-shell">
      <Header user={user} activePage={activePage} onNavigate={setActivePage} onLogout={handleLogout} />
      <main className="workspace">
        {activePage === 'dashboard' && <DashboardPage />}
        {activePage === 'profile' && <ProfilePage user={user} />}
        {activePage === 'notices' && <NoticePage />}
        {activePage === 'settings' && <SettingsPage />}
      </main>
    </div>
  );
}
