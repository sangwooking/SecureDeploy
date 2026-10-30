import {useState} from 'react';
import {useUiCapabilities} from './useUiCapabilities';
import {createEditingWorkspace,type EditingWorkspace} from '../api/editingApi';
import {requestProblem} from '../api/requestProblem';
import {WorkspaceAutomationPanels} from './WorkspaceAutomationPanels';
import type {SecurityReviewResponse} from '../types/securityReview';
export function hasExpressReviewContext(result:Pick<SecurityReviewResponse,'serverAnalysis'>){
 const a=result.serverAnalysis;
 return !!a?.nodeUses?.some(n=>n.ruleId==='JS_SERVER_ENTRY_CONTEXT'&&n.kind==='ENTRY_REGISTERED'&&n.operation==='EXPRESS_ROUTER_MOUNTED'&&n.trace.some(t=>t.kind==='EXPRESS_HANDLER_TARGET'&&a.files?.some(f=>f.filePath===t.filePath&&f.parseStatus==='PARSED'&&f.entrypoints>0&&f.flowStatus==='PARTIAL')&&a.nodeUses?.some(u=>['FLOW_UNRESOLVED','UNKNOWN','PROCESS_CONTRACT_UNKNOWN'].includes(u.kind)&&u.location.filePath===t.filePath)));
}
export function RelatedSemanticReview({result}:{result:SecurityReviewResponse}){
 const cap=useUiCapabilities();const [workspace,setWorkspace]=useState<EditingWorkspace|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState('');
 if(!hasExpressReviewContext(result))return <p>이 검사에는 추가 검토로 연결할 미완료 Express handler 근거가 없어요. 다른 코드의 안전을 확인한 것은 아닙니다.</p>;
 if(cap.loading)return <p role="status">추가 검토 지원 확인 중…</p>;
 if(!cap.value?.workspaceSemanticReview)return <p>{cap.problem?.message??'현재 서버는 선별 코드 추가 검토를 지원하지 않아요.'} 저장된 분석 근거를 직접 검토해 주세요.</p>;
 if(!cap.value.providerAvailable)return <p>추가 검토에는 AI Provider 설정이 필요해요. 기존 코드 근거 확인과 수동 수정은 사용할 수 있습니다.</p>;
 if(result.sourceType!=='GITHUB')return <p>원본 commit과 연결되는 GitHub 검사만 추가 검토할 수 있어요.</p>;
 return <section aria-label="관련 코드 추가 검토"><h3>미완료 Express 코드 추가 검토</h3><p>원본 검증과 전송 문맥 확인 후 별도 동의를 받아요. AI 후보는 확정 Finding이나 점수에 합산하지 않습니다.</p>
  {!workspace&&<button type="button" disabled={busy} onClick={async()=>{setBusy(true);setError('');try{setWorkspace(await createEditingWorkspace(result.reviewId!));}catch(e){setError(requestProblem(e,'추가 검토 원본').message);}finally{setBusy(false);}}}>추가 검토용 원본 확인</button>}
  {error&&<p role="alert">{error}</p>}{workspace&&<WorkspaceAutomationPanels workspace={workspace} showSemantic disabled={busy} onApplied={async()=>{}}/>}
 </section>;
}
