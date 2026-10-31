import {useEffect,useState} from 'react';
import {fetchUiCapabilities} from '../api/securityReviewApi';
import {requestProblem} from '../api/requestProblem';
export interface UiCapabilities {recoveryReadOnly?:boolean;compatibilityMode?:boolean;deterministicFixes?:boolean;durableAiAdmission?:boolean;structuredPatchPlans?:boolean;advisoryDetails?:boolean;schemaVersion:1;legacyAiReport?:boolean;aiCost?:{model:string;inputTokenUpperBound:number;outputTokenUpperBound:number;pricingStatus:string;maximumEstimatedUsd:number|null;checkedAt:string};patchScopes?:string[];dependencyPlans:boolean;dependencyAdvice:boolean;workspaceSemanticReview:boolean;dependencyFiles:boolean;npmGeneration:boolean;providerAvailable:boolean;providerOrigin:string}
export function useUiCapabilities(){
 const [state,setState]=useState<{value:UiCapabilities|null;loading:boolean;problem:ReturnType<typeof requestProblem>|null}>({value:null,loading:true,problem:null});
 useEffect(()=>{let active=true;
 fetchUiCapabilities().then(v=>{if(v.schemaVersion!==1||['dependencyPlans','dependencyAdvice','workspaceSemanticReview','dependencyFiles','npmGeneration','providerAvailable'].some(k=>typeof v[k as keyof UiCapabilities]!=='boolean'))throw Error('지원 계약 미확인');if(active)setState({value:v,loading:false,problem:null});})
 .catch(e=>{if(active)setState({value:null,loading:false,problem:requestProblem(e,'지원 정보')});});
 return()=>{active=false;};},[]);
 return state;
}
