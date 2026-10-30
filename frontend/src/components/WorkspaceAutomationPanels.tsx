import { providerOriginLabel } from './EvidenceSupportLayout';
import {useEffect,useRef,useState} from 'react';
import {prepareWorkspaceSemantic,generateWorkspaceSemantic,prepareDependencyFiles,generateDependencyFiles,applyDependencyFiles} from '../api/editingApi';
import type {EditingWorkspace,WorkspaceSemanticReview,DependencyFilesProposal} from '../api/editingApi';
import {SemanticReviewSection} from './SemanticReviewSection';
import {PatchDiff} from './PatchDiff';
const requestState=(s:string)=>({APPROVAL_REQUIRED:'외부 전송 동의 대기',NO_SUPPORTED_CONTEXT:'지원되는 코드 문맥 없음',GENERATING:'검토 중',COMPLETED:'선택한 문맥 검토 완료',PARTIAL:'일부 근거 검증 실패',REJECTED:'근거 검증에서 거부',FAILED:'요청 실패',EXECUTION_APPROVAL_REQUIRED:'npm 실행 동의 대기',PROPOSED:'Diff 검토와 적용 승인 대기',ACCEPTED:'승인한 변경 반영 완료'}[s]??'요청 상태 확인 필요');
export function WorkspaceAutomationPanels({workspace,adviceId,disabled,onApplied}:{workspace:EditingWorkspace;adviceId?:string;disabled:boolean;onApplied:(w:EditingWorkspace)=>Promise<void>}){
 const [semantic,setSemantic]=useState<WorkspaceSemanticReview|null>(null),[proposal,setProposal]=useState<DependencyFilesProposal|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const [codeConsent,setCodeConsent]=useState(false),[execConsent,setExecConsent]=useState(false),[applyConsent,setApplyConsent]=useState(false);const generation=useRef(0);
 useEffect(()=>{generation.current++;setSemantic(null);setProposal(null);setCodeConsent(false);setExecConsent(false);setApplyConsent(false);setError('');return()=>{generation.current++;};},[workspace.id,workspace.revision,adviceId]);
 const run=async(fn:()=>Promise<void>)=>{if(busy)return;setBusy(true);setError('');try{await fn();}catch{setError('준비·생성·원본 검증을 완료하지 못했습니다. 자동 재시도하지 않으며 최신 파일을 확인해 주세요.');}finally{setBusy(false);}};
 return <section aria-label="추가 검토 및 의존성 파일 제안" className="workspace-automation">
  <section aria-label="선별 코드 AI 추가 검토"><h3>선별 코드 AI 추가 검토</h3><p>등록된 Express handler의 미완료 흐름만 대상으로 합니다. 다른 UNKNOWN·전체 프로젝트의 검토를 의미하지 않습니다.</p>
   <button type="button" disabled={disabled||busy} onClick={()=>void run(async()=>{const g=generation.current;const p=await prepareWorkspaceSemantic(workspace);if(g===generation.current)setSemantic(p);})}>추가 검토 전송 범위 확인</button>
   {semantic&&<><p>{requestState(semantic.state)} · 선택 {semantic.selectedContexts}개 · 생략 {semantic.omittedContexts}개 · {providerOriginLabel(semantic.origin)}</p>
    {semantic.state==='NO_SUPPORTED_CONTEXT'?<p>지원되는 파싱·HTTP·미완료 함수 연결 근거가 없습니다. 안전 판정이 아닙니다.</p>:<><pre>{semantic.transmittedData}</pre>{semantic.state==='APPROVAL_REQUIRED'&&<><p>실제 파일 경로와 비식별 코드가 표시됩니다. 민감정보·개인정보가 남아 있으면 동의하지 마세요.</p><label><input type="checkbox" checked={codeConsent} disabled={busy} onChange={e=>setCodeConsent(e.target.checked)}/>이 코드 문맥의 외부 전송과 API 비용 발생 가능성에 동의합니다.</label><button type="button" disabled={disabled||busy||!codeConsent||!semantic.available} onClick={()=>void run(async()=>{setCodeConsent(false);const g=generation.current;const p=await generateWorkspaceSemantic(workspace,semantic);if(g===generation.current)setSemantic(p);})}>동의한 문맥 추가 검토</button>{!semantic.available&&<p>AI Provider 비활성화 · 기존 근거 기반 안내를 사용하세요.</p>}</>}</>}
    {semantic.result&&<><p>{semantic.origin==='MOCK'?'아래 후보는 Mock으로 생성됐으며 실제 취약점 TP 증거가 아닙니다.':'후보의 위치 검증은 보안 해석의 참을 입증하지 않습니다.'}</p><SemanticReviewSection snapshot={semantic.result}/></>}
    <details><summary>원본 상태값·문맥 제한</summary><p>{semantic.state}</p><ul>{semantic.limitations.map((s,i)=><li key={i}>{s}</li>)}</ul></details></>}
  </section>
  {adviceId&&<section aria-label="의존성 수정 파일 자동 생성"><h3>의존성 수정 파일 제안</h3><p>AI는 버전을 제안하고 npm이 파일을 생성합니다. Diff 승인 전 Workspace 원본은 바뀌지 않습니다.</p>
   <button type="button" disabled={disabled||busy} onClick={()=>void run(async()=>{const g=generation.current;const p=await prepareDependencyFiles(workspace,adviceId);if(g===generation.current)setProposal(p);})}>npm 파일 생성 범위 확인</button>
   {proposal&&<><p>{requestState(proposal.state)} · {proposal.packageName} {proposal.fromVersion} → {proposal.toVersion} · {proposal.origin==='MOCK'?'Mock 버전 제안':'버전 제안 출처: '+proposal.origin}</p><p>{proposal.message}</p>
    {proposal.state==='EXECUTION_APPROVAL_REQUIRED'&&<><p>단일 루트 npm v3·leaf 의존성만 지원합니다. 공개 registry 조회와 npm install --package-lock-only --ignore-scripts --no-audit --no-fund를 격리 실행합니다. 설치 스크립트·빌드·실행은 하지 않습니다.</p><label><input type="checkbox" checked={execConsent} disabled={busy} onChange={e=>setExecConsent(e.target.checked)}/>공개 의존성 메타데이터 조회와 격리 npm 잠금 파일 생성에 동의합니다.</label><button type="button" disabled={disabled||busy||!execConsent||!proposal.executionEnabled} onClick={()=>void run(async()=>{setExecConsent(false);const g=generation.current;const p=await generateDependencyFiles(workspace,proposal);if(g===generation.current)setProposal(p);})}>동의한 npm 수정 파일 생성</button>{!proposal.executionEnabled&&<p>서버의 npm 실행기가 비활성화되어 있습니다. 수동 수정은 계속 사용할 수 있습니다.</p>}</>}
    {proposal.differences.map(d=><div key={d.fileId}><h4>{d.path}</h4><details><summary>원본·수정본 해시 검증</summary><p>원본 {d.originalHash} · 제안 {d.proposedHash}</p></details><PatchDiff patch={d.patch}/></div>)}
    {proposal.state==='PROPOSED'&&<><p>호환성 NOT_VERIFIED · 수정 검증 REVIEW_REQUIRED</p><label><input type="checkbox" checked={applyConsent} disabled={busy} onChange={e=>setApplyConsent(e.target.checked)}/>두 파일의 Diff와 해시를 검토했으며 Workspace 적용을 승인합니다.</label><button type="button" disabled={disabled||busy||!applyConsent} onClick={()=>void run(async()=>{setApplyConsent(false);const next=await applyDependencyFiles(workspace,proposal);await onApplied(next);})}>승인한 두 파일 적용</button></>}
   </>}
  </section>}
  {busy&&<p role="status">검증 중입니다. 자동 재시도하지 않습니다.</p>}{error&&<p role="alert">{error}</p>}
 </section>;
}
