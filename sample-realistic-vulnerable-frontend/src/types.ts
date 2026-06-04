export type PageKey = 'dashboard' | 'profile' | 'notices' | 'settings';

export interface UserProfile {
  id: number;
  name: string;
  email: string;
  role: string;
  team: string;
}

export interface Notice {
  id: number;
  title: string;
  category: string;
  author: string;
  publishedAt: string;
  bodyHtml: string;
}

export interface DashboardStats {
  activeProjects: number;
  openTickets: number;
  deploymentReady: number;
  weeklyVisitors: number;
}
