import type { ResultView } from './reviewPresentation';
import { resultViews } from './reviewPresentation';

export interface ResultSelection { adviceId?:string; advisory?:number; findingId?: string; kind?: 'ALL'|'CODE'|'AI'|'ANALYSIS' }
export type ProjectTab = 'overview' | 'edit' | 'findings' | 'history' | 'rescan' | 'settings';
export type WorkspaceRoute = { page: 'dashboard' | 'projects' | 'new' | 'account' | 'not-found' }
  | { page: 'project'; projectId: number; tab: ProjectTab; reviewId?: number; view: ResultView; selection?: ResultSelection };
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
  const encoded=params.get('finding'),kind=params.get('kind');
  let finding:string|null=null;
  if(encoded!==null){try{if(!/^[A-Za-z0-9_-]{1,2800}$/.test(encoded))throw Error();finding=new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(atob(encoded.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)));}catch{return {page:'not-found'};}}
  if(finding!==null&&(!finding||finding.length>512||/[\x00-\x1f\x7f]/.test(finding)))return {page:'not-found'};
  const selection:ResultSelection={};
  const advice=params.get('advice');if(advice!==null){if(!/^[A-Za-z0-9_-]{1,80}$/.test(advice))return {page:'not-found'};selection.adviceId=advice;}
  const advisory=params.get('advisory');
  if(advisory!==null){if(!/^\d{1,5}$/.test(advisory))return {page:'not-found'};selection.advisory=Number(advisory);}
  if(finding)selection.findingId=finding;
  if(kind&&['ALL','CODE','AI','ANALYSIS'].includes(kind))selection.kind=kind as ResultSelection['kind'];
  return { ...(Object.keys(selection).length?{selection}:{}), page: 'project', projectId: Number(match[1]), tab: (!match[2]||match[2]==='overview'?'findings':match[2]) as ProjectTab,
    reviewId: ['findings','edit','history'].includes(match[2]) && review ? Number(review) : undefined,
    view: resultViews.some(v => v.id === view) ? view as ResultView : 'SUMMARY' };
}

export function projectLink(projectId: number, tab: ProjectTab = 'findings', reviewId?: number, view?: ResultView, selection?: ResultSelection): string {
  const params = new URLSearchParams();
  if (reviewId != null) params.set('review', String(reviewId));
  if (view) params.set('view', view);
  if(selection?.findingId)params.set('finding',btoa(String.fromCharCode(...new TextEncoder().encode(selection.findingId))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''));
  if(selection?.adviceId)params.set('advice',selection.adviceId);
  if(selection?.advisory!==undefined)params.set('advisory',String(selection.advisory));
  if(selection?.kind&&selection.kind!=='ALL')params.set('kind',selection.kind);
  return `#/projects/${projectId}/${tab}${params.size ? `?${params}` : ''}`;
}
