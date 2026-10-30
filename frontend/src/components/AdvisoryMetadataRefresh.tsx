import {useEffect,useRef,useState} from 'react';
import type {DependencyVulnerability,RiskFinding} from '../types/securityReview';
import {refreshSavedAdvisory} from '../api/securityReviewApi';
import {requestProblem} from '../api/requestProblem';
import {useUiCapabilities} from './useUiCapabilities';
export function AdvisoryMetadataRefresh({reviewId,finding,dependency,onMetadata}:{reviewId?:number|null;finding?:RiskFinding;dependency:DependencyVulnerability;onMetadata:(d:DependencyVulnerability)=>void}){
 const cap=useUiCapabilities(),[busy,setBusy]=useState(false),[message,setMessage]=useState('');const generation=useRef(0);
 useEffect(()=>{generation.current++;setMessage('');setBusy(false);return()=>{generation.current++;};},[reviewId,finding?.findingId,dependency.ecosystem,dependency.packageName,dependency.osvId,dependency.installedVersion]);
 const lookup=async()=>{if(!reviewId||!finding||busy||!cap.value?.advisoryDetails)return;const epoch=generation.current;setBusy(true);setMessage('');try{
  const value=await refreshSavedAdvisory(reviewId,finding.findingId);
  if(epoch!==generation.current)return;
  if(value.status==='DISABLED'){setMessage('현재 Backend의 공식 메타데이터 조회가 비활성화되어 있습니다. 원문 공지와 수동 업데이트 경로를 이용하세요.');return;}
  const ids=new Set([dependency.osvId,...dependency.aliases].map(x=>x.toUpperCase()));const matches=value.findings.filter(d=>d.ecosystem===dependency.ecosystem&&d.packageName===dependency.packageName&&d.installedVersion===dependency.installedVersion&&[d.osvId,...d.aliases].some(id=>ids.has(id.toUpperCase())));
  if(value.provenance!=='OFFICIAL_METADATA_REFRESH'||!['COMPLETE','PARTIAL'].includes(value.status)||matches.length!==1){setMessage('이 공지의 공식 수정 근거를 확인하지 못했습니다. 원본 분석은 유지됩니다.');return;}
  const next=matches[0];onMetadata({...dependency,fixedVersions:next.fixedVersions,affectedRanges:next.affectedRanges,referenceUrls:next.referenceUrls,modified:next.modified});setMessage(`별도 공식 메타데이터 조회 · ${value.checkedAt} · ${value.status}. 원본 Snapshot·Risk/Score는 변경하지 않았습니다.`);
 }catch(error){if(epoch===generation.current)setMessage(requestProblem(error,'공식 공지 보완 조회').message);}finally{if(epoch===generation.current)setBusy(false);}};
 if(!reviewId||!finding)return <p>저장된 항목 ID가 없어 공식 보완 조회를 연결하지 못했습니다. 원문 공지를 확인하세요.</p>;
 return <section className="advisory-refresh" aria-label="공식 공지 메타데이터 보완"><p>저장된 수정 버전 근거가 부족하면 공개 패키지명·버전의 OSV 자료를 별도로 조회합니다. 코드·프로젝트 경로는 보내지 않으며 AI 요청이 아닙니다.</p>{cap.value?.advisoryDetails?<button type="button" disabled={busy} onClick={()=>void lookup()}>{busy?'공식 공지 확인 중…':'공식 수정 버전 다시 확인'}</button>:<p>{cap.loading?'공식 보완 조회 지원 확인 중…':'현재 Backend에서 공식 보완 조회를 지원하지 않거나 지원 정보를 확인하지 못했습니다. 원문 공지로 확인하세요.'}</p>}{message&&<p role="status">{message}</p>}</section>;
}
