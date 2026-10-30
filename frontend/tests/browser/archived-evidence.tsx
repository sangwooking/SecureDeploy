// Isolated evidence host only. Exact archived records are provided by the local Playwright route.
// No API generation, state-value mutation, model call or backend write exists in this host.
import {useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import type {SecurityReviewResponse} from '../../src/types/securityReview';
import type {DependencyAdviceView} from '../../src/types/dependencyUpdatePlan';
import {EvidenceSupportLayout,AdvisoryItemCount} from '../../src/components/EvidenceSupportLayout';
import {DependencyFindingCard} from '../../src/components/DependencyFindingCard';
import {DependencyAdviceResult} from '../../src/components/DependencyAiAdvicePanel';
import {WorkspaceDiffReview,WorkspaceComparisonOverview,type FileDifferenceView} from '../../src/components/WorkspaceOutcome';
import {CodeFindingCard} from '../../src/components/CodeFindingCard';
import {SemanticReviewSection} from '../../src/components/SemanticReviewSection';
import './archived-evidence.css';
import '../../src/styles.css';import '../../src/renovation.css';import '../../src/product.css';
interface Records {before:SecurityReviewResponse;after:SecurityReviewResponse;advice:DependencyAdviceView;files:FileDifferenceView[];control?:{result:SecurityReviewResponse;semantic:SecurityReviewResponse['semanticReview']}}
function Host(){
 const [data,setData]=useState<Records|null>(null);const mode=new URLSearchParams(location.search).get('mode')??'before';
 useEffect(()=>{let active=true;fetch('/archive-evidence.json',{cache:'no-store'}).then(r=>r.json()).then(v=>{if(active)setData(v);});return()=>{active=false;};},[]);
 if(!data)return <p role="status">로컬 보관 기록 불러오는 중</p>;
 if(mode==='controls'&&data.control){const r=data.control.result;return <main className="workspace-content"><p>합성 UI 경계 테스트 · 전시 증거 아님</p><CodeFindingCard vulnerability={r.vulnerabilities[0]} finding={r.riskAssessment?.codeFindings[0]} remediation={r.remediation} statusActions={{updatingId:null,comments:{},onComment:()=>{},onStatus:()=>{}}}/><DependencyFindingCard dependency={r.sca!.dependencyVulnerabilities[0]}/><SemanticReviewSection snapshot={data.control.semantic}/></main>;}
 const dep=data.before.sca!.dependencyVulnerabilities.find(d=>d.packageName===data.advice.output?.packageName&&d.installedVersion===data.advice.output?.lockedVersion&&d.osvId===data.advice.output?.advisoryId);
 if(!dep||data.advice.provider.origin!=='OPENAI'||data.advice.state!=='GENERATED')return <p role="alert">실제 모델 보관 근거 불일치</p>;
 return <main className="workspace-content evidence-host"><header className="masthead"><h1 className="brand-link">SecureDeploy</h1><p>과거 검증 기록 재표시 · 새 분석·모델 호출 없음</p></header>
 {mode==='before'?<section aria-label="보관된 분석·AI 제안"><header className="result-workspace-header"><div><p className="result-context-label">실제 프로젝트 분석 결과</p><h2>{data.before.projectName}</h2></div><AdvisoryItemCount count={data.before.sca!.dependencyVulnerabilities.length}/></header><EvidenceSupportLayout evidence={<DependencyFindingCard embedded dependency={dep} components={data.before.sca?.components} remediation={data.before.remediation} finding={data.before.riskAssessment?.dependencyFindings.find(f=>f.packageName===dep.packageName&&f.version===dep.installedVersion&&[f.advisoryId,...(f.dependency?.aliases??[])].some(id=>id&&[dep.osvId,...dep.aliases].map(x=>x.toUpperCase()).includes(id.toUpperCase())))}/>} supportTitle="AI 수정 제안" support={<DependencyAdviceResult view={data.advice} archived/>}/></section>
 :<section aria-label="보관된 Diff·수정본 재검사"><h2>수정 내용 확인 · 수정본 재검사</h2><p>OpenAI 수정 방향 제안 → npm 변경 파일 생성 → Workspace 사용자 승인 → 재검사</p><div className="workspace-outcome"><EvidenceSupportLayout evidenceTitle="수정 적용" supportTitle="수정 후 무엇이 달라졌나요?" evidence={<WorkspaceDiffReview files={data.files}/>} support={<WorkspaceComparisonOverview original={data.before} modified={data.after}/>}/></div></section>}
 </main>;
}
createRoot(document.getElementById('root')!).render(<Host/>);
