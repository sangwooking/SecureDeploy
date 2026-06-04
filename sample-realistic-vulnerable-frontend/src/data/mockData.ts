import type { DashboardStats, Notice, UserProfile } from '../types';

export const currentUser: UserProfile = {
  id: 1,
  name: '박상우',
  email: 'admin@adminhub.test',
  role: 'ADMIN',
  team: 'Platform Security',
};

export const dashboardStats: DashboardStats = {
  activeProjects: 12,
  openTickets: 7,
  deploymentReady: 4,
  weeklyVisitors: 18320,
};

export const notices: Notice[] = [
  {
    id: 101,
    title: '배포 점검 안내',
    category: 'Deployment',
    author: 'DevOps Team',
    publishedAt: '2026-06-01',
    bodyHtml: '<p>금요일 18시에 배포 점검이 있습니다.</p><strong>관리자만 확인하세요.</strong>',
  },
  {
    id: 102,
    title: '긴급 공지 HTML 템플릿 테스트',
    category: 'Security',
    author: 'Security Team',
    publishedAt: '2026-06-02',
    bodyHtml: `<img src=x onerror="alert('xss')" /><p>외부 입력 HTML이 그대로 렌더링되는 예시입니다.</p>`,
  },
];
