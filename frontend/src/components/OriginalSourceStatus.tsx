import {useEffect,useState} from 'react';
import {loadSourceVerification,type SourceVerification} from '../api/editingApi';
import {ApiRequestError} from '../api/requestProblem';
const labels:Record<SourceVerification['status'],string>={VERIFIED:'원본 확인됨',MISMATCH:'원본 불일치',UNAVAILABLE:'원본 확인 불가',PARTIAL:'원본 일부 확인',UNVERIFIED:'원본 동일성 미확인'};
export function OriginalSourceStatus({reviewId,value}:{reviewId?:number|null;value?:SourceVerification}){
 const [loaded,setLoaded]=useState<{id:number;value:SourceVerification}|null>(null);
 useEffect(()=>{let current=true;if(reviewId&&!value)loadSourceVerification(reviewId).then(v=>{if(current)setLoaded({id:reviewId,value:v});}).catch(e=>{if(current)setLoaded({id:reviewId,value:{status:'UNAVAILABLE',recorded:false,fileCount:0,scope:'ORIGINAL_BYTES_ONLY',message:e instanceof ApiRequestError&&e.status===403?'현재 계정으로 원본 기록에 접근할 수 없어요.':e instanceof ApiRequestError&&e.status===404?'원본 검증 기록을 조회할 수 없습니다.':e instanceof ApiRequestError&&e.status===401?'다시 로그인해 원본 기록을 확인하세요.':'원본 기록을 조회하지 못했습니다. 저장된 분석 근거는 그대로 유지됩니다.'}});});return()=>{current=false;};},[reviewId,value]);
 const state=value??(loaded&&loaded.id===reviewId?loaded.value:undefined);
 return <aside className="notice source-verification" aria-label="검사 원본 검증"><strong>{state?labels[state.status]:'원본 기록 확인 중'}</strong>{state&&<><p>{state.message}</p><details><summary>원본 검증 근거</summary><p>파일 해시 기록 {state.fileCount}개 · 원본 동일성 확인과 보안·기능 검증은 별개입니다.</p>{state.commitSha&&<p>Commit <code>{state.commitSha}</code></p>}{state.archiveSha256&&<p>ZIP SHA-256 <code>{state.archiveSha256}</code></p>}</details></>}</aside>;
}
