import { useEffect, useRef, useState } from 'react';
import { deleteProject } from '../api/securityReviewApi';
import { projectLink } from './workspaceRoute';

export function ProjectManagement({ project, onDeleted, variant = 'menu' }: {
  project: { projectId: number; name: string }; onDeleted?: () => void; variant?: 'menu' | 'settings';
}) {
  const menu = useRef<HTMLDetailsElement>(null);
  const trigger = useRef<HTMLElement | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const submitting = useRef(false);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const id = `delete-project-${project.projectId}`;

  useEffect(() => {
    if (!open) return;
    dialog.current?.showModal();
    cancel.current?.focus();
    return () => { dialog.current?.close(); };
  }, [open]);
  useEffect(() => { if (busy) dialog.current?.focus(); }, [busy]);
  useEffect(() => {
    const close = (event: PointerEvent) => {
      if (event.target instanceof Node && !menu.current?.contains(event.target)) menu.current?.removeAttribute('open');
    };
    document.addEventListener('pointerdown', close);
    return () => document.removeEventListener('pointerdown', close);
  }, []);
  const dismiss = () => {
    if (submitting.current) return;
    dialog.current?.close(); setOpen(false); trigger.current?.focus();
  };
  const remove = async () => {
    if (submitting.current || name !== project.name) return;
    submitting.current = true; setBusy(true); setError('');
    try {
      await deleteProject(project.projectId);
      setOpen(false); onDeleted?.();
    } catch (failure) {
      setError(`${failure instanceof Error ? failure.message : '삭제 완료를 확인하지 못했습니다.'} 목록을 새로고침해 현재 상태를 확인할 수 있습니다.`);
    } finally { submitting.current = false; setBusy(false); }
  };
  return <div className="project-management">
    {variant === 'settings' ? <button type="button" className="delete-button" onClick={event => {
      trigger.current = event.currentTarget; setName(''); setError(''); setOpen(true);
    }}>프로젝트 삭제</button> : <details ref={menu} onKeyDown={event => {
      if (event.key === 'Escape') { menu.current?.removeAttribute('open'); menu.current?.querySelector('summary')?.focus(); }
    }}>
      <summary className="project-menu-trigger" aria-label={`${project.name} 관리`} title="프로젝트 관리"><span aria-hidden="true">⋯</span></summary>
      <div className="project-menu">
        <a href={projectLink(project.projectId)}>프로젝트 열기</a>
        <button type="button" className="project-menu-delete" onClick={() => {
          trigger.current = menu.current?.querySelector('summary') ?? null;
          menu.current?.removeAttribute('open'); setName(''); setError(''); setOpen(true);
        }}>프로젝트 삭제</button>
      </div>
    </details>}
    {open && <dialog ref={dialog} tabIndex={-1} className="project-delete-dialog" aria-labelledby={`${id}-title`} aria-describedby={`${id}-description`}
      onKeyDown={event => {
        if (event.key !== 'Tab') return;
        const fields = [...event.currentTarget.querySelectorAll<HTMLElement>('summary, button:not(:disabled), input:not(:disabled), a[href]')];
        const last = fields[fields.length - 1];
        const target = event.shiftKey ? last : fields[0];
        if (!fields.length) { event.preventDefault(); return; }
        if (document.activeElement === (event.shiftKey ? fields[0] : last)) {
          event.preventDefault(); target?.focus();
        }
      }}
      onCancel={event => { event.preventDefault(); dismiss(); }}>
      <form onSubmit={event => { event.preventDefault(); void remove(); }}>
        <h2 id={`${id}-title`}>프로젝트를 삭제하시겠습니까?</h2>
        <p className="delete-project-name">{project.name}</p>
        <p id={`${id}-description`}>SecureDeploy에 저장된 이 프로젝트와 연결된 분석 기록을 삭제합니다. 삭제한 데이터는 화면에서 복구할 수 없습니다.</p>
        <p>GitHub 원본 저장소, 계정과 GitHub 연결, 다른 프로젝트는 유지됩니다. 열려 있는 수정 작업이나 진행 중인 검사가 있으면 삭제할 수 없습니다.</p>
        <details className="delete-scope-limit"><summary>삭제 범위의 한계</summary>
          <p>이미 내려받은 ZIP·Patch, 관리용 백업과 과거의 미확인 임시 파일까지 지우는 보안 삭제는 아닙니다. 종료된 검사의 최소 상태 정보는 잠시 남을 수 있지만 삭제한 분석 결과와 소스에는 접근할 수 없습니다.</p>
        </details>
        <label htmlFor={`${id}-name`}>확인을 위해 프로젝트 이름을 입력해 주세요.</label>
        <input id={`${id}-name`} value={name} onChange={event => setName(event.target.value)} autoComplete="off" disabled={busy} />
        {error && <p className="error-message" role="alert">{error}</p>}
        {busy && <p role="status">프로젝트를 삭제하고 있습니다.</p>}
        <div className="dialog-actions">
          <button ref={cancel} type="button" className="secondary-button" disabled={busy} onClick={dismiss}>취소</button>
          <button type="submit" className="delete-button" disabled={busy || name !== project.name}>{busy ? '삭제 중…' : '프로젝트 삭제'}</button>
        </div>
      </form>
    </dialog>}
  </div>;
}
