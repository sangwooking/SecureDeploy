import type { PageKey, UserProfile } from '../types';

interface HeaderProps {
  user: UserProfile;
  activePage: PageKey;
  onNavigate: (page: PageKey) => void;
  onLogout: () => void;
}

const navItems: Array<{ key: PageKey; label: string }> = [
  { key: 'dashboard', label: '대시보드' },
  { key: 'profile', label: '프로필' },
  { key: 'notices', label: '공지' },
  { key: 'settings', label: '설정' },
];

export default function Header({ user, activePage, onNavigate, onLogout }: HeaderProps) {
  return (
    <header className="app-header">
      <div>
        <span className="brand">AdminHub</span>
        <strong>{user.team}</strong>
      </div>
      <nav>
        {navItems.map((item) => (
          <button
            key={item.key}
            className={activePage === item.key ? 'active' : ''}
            type="button"
            onClick={() => onNavigate(item.key)}
          >
            {item.label}
          </button>
        ))}
      </nav>
      <button className="ghost-button" type="button" onClick={onLogout}>로그아웃</button>
    </header>
  );
}
