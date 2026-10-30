import {changeOriginLabel} from './EvidenceSupportLayout';
import type {ChangeAttribution} from '../api/editingApi';
export function attributionLabel(e:ChangeAttribution){
 const generated=e.generator==='OPENAI'?'수정 제안: OpenAI':e.generator==='MOCK'?'수정 제안: Mock · 실제 모델 미검증':e.generator==='DETERMINISTIC'?'수정 생성: 결정적 서버 검증':e.generator==='NPM'?`수정 파일 생성: npm · 업데이트 방향: ${e.directionOrigin==='OPENAI'?'OpenAI':e.directionOrigin==='MOCK'?'Mock · 실제 모델 미검증':'출처 확인 불가'}`:e.generator==='MANUAL'?'사용자 직접 편집':'생성 출처 확인 불가';
 return `${generated} · ${e.approved?'사용자 승인 완료':'다운로드 승인 별도'}`;
}
export function ChangeProvenance({origin,events}:{origin?:string;events?:ChangeAttribution[]|null}){
 const known=events??[];return <div className="change-origin"><p>{known.length?attributionLabel(known[known.length-1]):changeOriginLabel(origin)}</p>{!!known.length&&<details><summary>파일 변경 출처 이력 ({known.length})</summary><p>서버가 기록한 파일 단위 변경 이력입니다. 혼합 편집의 행별 기여분을 확정하는 것은 아닙니다.</p><ul>{known.map((e,i)=><li key={i}>r{e.revision} · {attributionLabel(e)}{e.model&&` · ${e.model}`}<details><summary>승인·제안 근거</summary>{e.proposalId&&<p>제안 ID: {e.proposalId}</p>}{e.adviceId&&<p>업데이트 방향 ID: {e.adviceId}</p>}<p>사용자 {e.userId} · {e.at} · 파일 SHA-256: {e.currentHash}</p></details></li>)}</ul></details>}</div>;
}
