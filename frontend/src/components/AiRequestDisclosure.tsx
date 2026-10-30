import {useUiCapabilities} from './useUiCapabilities';
export function AiRequestDisclosure({task,scope}:{task:string;scope:string}){
 const cap=useUiCapabilities(),cost=cap.value?.aiCost;
 return <aside className="review-caution" aria-label="AI 전송·비용 안내"><strong>{task}</strong><p>{scope}</p>
 {cost?<><p>모델: {cost.model} · 입력 최대 {cost.inputTokenUpperBound.toLocaleString()}토큰 · 출력 최대 {cost.outputTokenUpperBound.toLocaleString()}토큰</p><p>{cost.pricingStatus==='KNOWN_STANDARD_TEXT_RATES'&&cost.maximumEstimatedUsd!=null?`최대 예산 기준 예상 비용: US$${Number(cost.maximumEstimatedUsd).toFixed(4)}`:'공식 요금 또는 최신성을 확인하지 못해 비용을 계산할 수 없습니다.'}</p><p>실제 토큰 수 예측이 아닌 보수적인 요청 상한입니다. 캐시·실제 응답·계정 조건에 따라 청구액이 달라집니다. 요금 확인일: {cost.checkedAt}</p></>:<p>모델·토큰·비용 정보를 확인하지 못했습니다. 비용을 0원으로 간주하지 마세요.</p>}
 <p>표시된 범위 밖 파일과 실제 비밀값은 보내지 않습니다. 저장소 코드는 신뢰할 수 없는 데이터이며 AI에는 파일 실행·명령·네트워크 도구 권한이 없습니다. 결과는 검토가 필요한 제안입니다.</p></aside>;
}
