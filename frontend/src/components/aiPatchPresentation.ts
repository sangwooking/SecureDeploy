import type {AiPatch} from '../api/editingApi';
import {providerOriginLabel,providerSetupLabel} from './EvidenceSupportLayout';

export function aiPatchChoice(method?:string,structured=false,express=false) {
  return method==='AI_ASSISTED'||(method==='DETERMINISTIC_FIX'&&structured&&express);
}
export function patchProviderLabel(patch:AiPatch) {
  return ['PROPOSED','ACCEPTED'].includes(patch.state)
    ?providerOriginLabel(patch.provider.origin,patch.provider.name)
    :providerSetupLabel(patch.provider.origin,patch.provider.name);
}
export function patchUsageLabel(patch:AiPatch) {
  const usage=patch.usage;
  if(!usage)return '실제 사용량과 비용을 아직 확인하지 못했습니다. 무료 처리됐다는 의미는 아닙니다.';
  if(patch.provider.origin==='MOCK')return 'Mock 통제 사용량 · 실제 OpenAI 호출·비용 없음';
  if(!usage.billable)return '외부 요청 전 중단 · 과금 대상 요청 미실행';
  if(!usage.usageKnown)return '외부 요청 결과·실제 토큰·비용 미확인 · 0토큰 또는 무료로 확정하지 않습니다.';
  return `API 응답 사용량 · 모델 ${usage.model??'미확인'} · 입력 ${usage.promptTokens} / 캐시 ${usage.cachedInputTokens} / 출력 ${usage.completionTokens}토큰 · ${usage.estimatedCostUsd==null?'비용 미확인':`추정 US$${Number(usage.estimatedCostUsd).toFixed(6)}`} · 실제 청구액과 구분`;
}
