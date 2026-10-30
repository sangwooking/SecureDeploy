import { useEffect, useRef, useState } from 'react';
import { downloadAiReviewReport, downloadReviewReport, updateVulnerabilityStatus } from '../api/securityReviewApi';
import type { SecurityReviewResponse, Vulnerability, VulnerabilityStatus } from '../types/securityReview';
import { ReviewResultWorkspace } from './ReviewResultWorkspace';
import type { ResultView } from './reviewPresentation';
import { SourceEditingWorkspace } from './SourceEditingWorkspace';

export function ProjectReviewResult({ result, view, onView, onRescan, editing: editingProp, onEditingChange }: {
  result: SecurityReviewResponse; view: ResultView; onView: (view: ResultView) => void; onRescan: () => void; editing?:boolean; onEditingChange?:(value:boolean)=>void;
}) {
  const [current, setCurrent] = useState(result);
  const [comments, setComments] = useState<Record<number, string>>({});
  const [updating, setUpdating] = useState<number | null>(null);
  const [report, setReport] = useState<'basic' | 'ai' | null>(null);
  const [error, setError] = useState('');
  const [dependencyAdviceId,setDependencyAdviceId]=useState<string>();
  const [editingLocal, setEditingLocal] = useState(false);
  const editing=editingProp??editingLocal;const setEditing=(value:boolean)=>{setEditingLocal(value);onEditingChange?.(value);};
  const [editingPath, setEditingPath] = useState<string>();
  useEffect(()=>{if(!editing){setEditingPath(undefined);setDependencyAdviceId(undefined);}},[editing]);
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const update = async (v: Vulnerability, status: VulnerabilityStatus) => {
    if (v.vulnerabilityId == null) return;
    const id = v.vulnerabilityId;
    setUpdating(id); setError('');
    try {
      const changed = await updateVulnerabilityStatus(id, status, comments[id] ?? v.statusComment ?? '');
      if (active.current) setCurrent(previous => ({ ...previous, vulnerabilities: previous.vulnerabilities.map(item => item.vulnerabilityId === id ? { ...item, ...changed } : item) }));
    } catch (e) { if (active.current) setError(e instanceof Error ? e.message : '상태를 변경하지 못했습니다.'); }
    finally { if (active.current) setUpdating(null); }
  };
  const download = async (ai: boolean) => {
    if (!current.reviewId) return;
    if (ai && !window.confirm('이 PDF는 기존 AI 리뷰를 새로 생성합니다. 외부 API 호출과 비용이 발생할 수 있으며 저장된 해결 가이드 내보내기가 아닙니다. 계속할까요?')) return;
    setReport(ai ? 'ai' : 'basic'); setError('');
    try {
      const blob = await (ai ? downloadAiReviewReport(current.reviewId) : downloadReviewReport(current.reviewId));
      if (!active.current) return;
      const url = URL.createObjectURL(blob), link = document.createElement('a');
      link.href = url; link.download = `securedeploy-${ai ? 'ai-' : ''}report-${current.reviewId}.pdf`;
      document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) { if (active.current) setError(e instanceof Error ? e.message : '리포트를 다운로드하지 못했습니다.'); }
    finally { if (active.current) setReport(null); }
  };
  if (editing) return <SourceEditingWorkspace embedded key={current.reviewId} result={current} initialPath={editingPath} initialAdviceId={dependencyAdviceId} onBack={() => setEditing(false)} />;
  return <>
    {error && <p role="alert" className="error-message">{error}</p>}
    <ReviewResultWorkspace result={current} view={view} onViewChange={onView} progress={null}
      onEditDependency={current.sourceType==='WORKSPACE'?undefined:id=>{setDependencyAdviceId(id);setEditingPath(undefined);setEditing(true);}}
      onEditFile={current.sourceType==='WORKSPACE'?undefined:path=>{setDependencyAdviceId(undefined);setEditingPath(path);setEditing(true);}}
      rescanActions={<button className="secondary-button" type="button" onClick={onRescan}>다시 검사하기</button>}
      statusActions={{ updatingId: updating, comments, onComment: (id, comment) => setComments(previous => ({ ...previous, [id]: comment })), onStatus: (v, status) => void update(v, status) }}
      reportActions={<>
        <button type="button" className="secondary-button" disabled={!!report} onClick={() => void download(false)}>{report === 'basic' ? 'PDF 생성 중...' : '기본 리포트 다운로드'}</button>
        <button type="button" className="secondary-button" disabled={!!report} onClick={() => void download(true)}>{report === 'ai' ? 'AI PDF 생성 중...' : 'AI 리뷰 PDF 생성·다운로드'}</button>
      </>} />
  </>;
}
