import type { ResultView } from './reviewPresentation';
import { resultViews } from './reviewPresentation';

export type ProjectTab = 'overview' | 'edit' | 'findings' | 'history' | 'rescan' | 'settings';
export type WorkspaceRoute = { page: 'dashboard' | 'projects' | 'new' | 'account' | 'not-found' }
  | { page: 'project'; projectId: number; tab: ProjectTab; reviewId?: number; view: ResultView };
export const projectTabs: { id: ProjectTab; label: string }[] = [
  { id: 'findings', label: '보안 결과' }, { id: 'edit', label: '수정 작업' }, { id: 'history', label: '검사 기록' },
];

export function parseWorkspaceRoute(hash: string): WorkspaceRoute {
  const [path, query] = hash.replace(/^#/, '').split('?');
  if (!path || path === '/' || path === '/dashboard') return { page: 'dashboard' };
  if (path === '/projects' || path === '/new' || path === '/account') return { page: path.slice(1) as 'projects' | 'new' | 'account' };
  const match = /^\/projects\/(\d+)(?:\/(overview|findings|edit|history|rescan|settings))?$/.exec(path);
  if (!match || !Number.isSafeInteger(Number(match[1])) || Number(match[1]) < 1) return { page: 'not-found' };
  const params = new URLSearchParams(query), review = params.get('review'), view = params.get('view');
  if (review !== null && (!/^\d+$/.test(review) || !Number.isSafeInteger(Number(review)) || Number(review) < 1)) return { page: 'not-found' };
  return { page: 'project', projectId: Number(match[1]), tab: (!match[2]||match[2]==='overview'?'findings':match[2]) as ProjectTab,
    reviewId: ['findings','edit','history'].includes(match[2]) && review ? Number(review) : undefined,
    view: resultViews.some(v => v.id === view) ? view as ResultView : 'SUMMARY' };
}

export function projectLink(projectId: number, tab: ProjectTab = 'findings', reviewId?: number, view?: ResultView): string {
  const params = new URLSearchParams();
  if (reviewId != null) params.set('review', String(reviewId));
  if (view) params.set('view', view);
  return `#/projects/${projectId}/${tab}${params.size ? `?${params}` : ''}`;
}
