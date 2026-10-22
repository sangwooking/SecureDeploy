import type { ResultView } from './reviewPresentation';
import { resultViews } from './reviewPresentation';

export type ProjectTab = 'overview' | 'findings' | 'history' | 'rescan' | 'settings';
export type WorkspaceRoute = { page: 'dashboard' | 'projects' | 'new' | 'account' | 'not-found' }
  | { page: 'project'; projectId: number; tab: ProjectTab; reviewId?: number; view: ResultView };
export const projectTabs: { id: ProjectTab; label: string }[] = [
  { id: 'overview', label: '개요' }, { id: 'findings', label: '발견된 문제' }, { id: 'history', label: '분석 이력' },
  { id: 'rescan', label: '재검사' }, { id: 'settings', label: '프로젝트 설정' },
];

export function parseWorkspaceRoute(hash: string): WorkspaceRoute {
  const [path, query] = hash.replace(/^#/, '').split('?');
  if (!path || path === '/' || path === '/dashboard') return { page: 'dashboard' };
  if (path === '/projects' || path === '/new' || path === '/account') return { page: path.slice(1) as 'projects' | 'new' | 'account' };
  const match = /^\/projects\/(\d+)(?:\/(overview|findings|history|rescan|settings))?$/.exec(path);
  if (!match || !Number.isSafeInteger(Number(match[1])) || Number(match[1]) < 1) return { page: 'not-found' };
  const params = new URLSearchParams(query), review = params.get('review'), view = params.get('view');
  if (review !== null && (!/^\d+$/.test(review) || !Number.isSafeInteger(Number(review)) || Number(review) < 1)) return { page: 'not-found' };
  return { page: 'project', projectId: Number(match[1]), tab: (match[2] ?? 'overview') as ProjectTab,
    reviewId: match[2] === 'findings' && review ? Number(review) : undefined,
    view: resultViews.some(v => v.id === view) ? view as ResultView : 'SUMMARY' };
}

export function projectLink(projectId: number, tab: ProjectTab = 'overview', reviewId?: number, view?: ResultView): string {
  const params = new URLSearchParams();
  if (reviewId != null) params.set('review', String(reviewId));
  if (view) params.set('view', view);
  return `#/projects/${projectId}/${tab}${params.size ? `?${params}` : ''}`;
}
