import { DependencyDetail } from './DependencyDetail';
import {problemItems,groupProblems,groupCounts,itemTitle,itemVulnerability,itemLocation} from './problemGroups';
import {FlowFindingDetail} from './FlowFindingDetail';
import { projectLink, type ResultSelection } from './workspaceRoute';
import { RelatedSemanticReview } from './RelatedSemanticReview';
import { useEffect, useRef, useState, useMemo, type ReactNode } from 'react';
import type { RiskFinding, SecurityReviewResponse, Severity } from '../types/securityReview';
import { CodeFindingCard, type FindingStatusActions } from './CodeFindingCard';
import { DependencyActionGroups } from './DependencyContextDetails';
import { AnalysisCoverageSection, InspectionBoundaryNotice } from './AnalysisCoverageSection';
import { ServerAnalysisSection } from './ServerAnalysisSection';
import { DependencySecuritySection, ScaAssessmentNotice } from './DependencySecuritySection';
import { FindingRemediation, RemediationNotice } from './FindingRemediation';
import { RiskAssessmentSection } from './RiskAssessmentSection';
import { SemanticReviewSection } from './SemanticReviewSection';
import { ReviewProgressPanel } from './ReviewProgressPanel';
import { GitHubSourceInfo } from './GitHubSourceInfo';
import { ReviewSummaryPanel, summaryStateLabel } from './ReviewSummaryPanel';
import { findingGuidance } from './findingGuidance';
import { incompleteDependency, dependencyText } from './dependencyGuidance';
import { severityLabels } from './uiLanguage';
import { IncompleteDependencyCard } from './IncompleteDependencyCard';
import { allRiskFindings, deploymentLabels, findingTitle, priorityLabels, resultViews, reviewCounts,
  semanticStatusText, vulnerabilityForFinding, type ResultView } from './reviewPresentation';

const severityOrder: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

interface Props {
  result: SecurityReviewResponse;
  view: ResultView;
  onViewChange: (view: ResultView,selection?:ResultSelection) => void;
  selection?:ResultSelection;
  statusActions: FindingStatusActions;
  reportActions: ReactNode;
  progress: ReactNode;
  rescanActions?: ReactNode;
  onEditDependency?: (id:string)=>void;
  onEditFile?: (path: string) => void;
}

export function ReviewResultWorkspace({ result, view, onViewChange, statusActions, reportActions, progress, rescanActions, onEditFile, onEditDependency, selection }: Props) {
 const [occurrencePage,setOccurrencePage]=useState(0);
 const [kind,setKind]=useState<'ALL'|'CODE'|'AI'|'ANALYSIS'>(selection?.kind??'ALL');
 const [query,setQuery]=useState(''),[selectedId,setSelectedId]=useState(selection?.findingId??''),[page,setPage]=useState(0);
 const detail=useRef<HTMLDivElement>(null),rows=useRef<HTMLUListElement>(null);
 const findings=allRiskFindings(result),assessment=result.riskAssessment;
 const flowRows=[...(result.serverAnalysis?.validatedFindings??[]),...(result.serverAnalysis?.pythonAnalysis?.validatedFindings??[])].map(flow=>({findingId:'flow:'+flow.findingId,source:'FLOW' as const,priority:flow.priority,sourceFiles:[flow.location.filePath],advisoryId:undefined,flow}));
 const items=useMemo(()=>problemItems(result),[result]);
 const rowTitle=(f:typeof items[number])=>itemTitle(result,f);
 const rowVulnerability=(f:typeof items[number])=>itemVulnerability(result,f);
 const priority=['BLOCKING','REVIEW_REQUIRED','SHOULD_FIX'].includes(view)?view:'ALL';
 const shown=useMemo(()=>items.filter(f=>(kind==='ALL'||f.source===kind||kind==='CODE'&&f.source==='FLOW')&&(priority==='ALL'||f.priority===priority)&&`${rowTitle(f)} ${f.sourceFiles.join(' ')} ${f.advisoryId??''}`.toLowerCase().includes(query.toLowerCase())),[items,kind,priority,query,result]);
 const groups=useMemo(()=>groupProblems(result,shown),[result,shown]);
 const counts=useMemo(()=>groupCounts(result,groups),[result,groups]);
 const selected=shown.find(f=>f.findingId===selectedId);
 const selectedGroup=groups.find(g=>g.items.some(f=>f.findingId===selectedId));
 useEffect(()=>{setSelectedId(selection?.findingId??'');setKind(selection?.kind??'ALL');},[view,result.reviewId,selection?.findingId,selection?.kind]);
 useEffect(()=>{setPage(0);},[view,kind,query,result.reviewId]);
 useEffect(()=>{const index=groups.findIndex(g=>g.items.some(f=>f.findingId===selectedId));if(index>=0)setPage(Math.floor(index/20));},[selectedId,kind,query,view,result.reviewId]);
 useEffect(()=>{const i=selectedGroup?.items.findIndex(f=>f.findingId===selectedId)??-1;setOccurrencePage(Math.max(0,Math.floor(i/50)));},[selectedGroup?.id,selectedId]);
 const choose=(id:string)=>{setSelectedId(id);onViewChange(view,{kind,findingId:id||undefined});};
 useEffect(()=>{if(selectedId){detail.current?.focus({preventScroll:true});detail.current?.scrollIntoView({block:'start'});}},[selectedId]);
 const navigate=(next:ResultView)=>{setKind('ALL');setSelectedId('');onViewChange(next);};
 return <section className="result-area result-workspace" aria-label="프로젝트 분석 결과">
  <header className="result-workspace-header"><div><p className="result-context-label">실제 프로젝트 분석 결과</p><h2>보안 결과</h2><p>{result.projectName} · 검사 #{result.reviewId??'미저장'}{result.createdAt&&<> · <time dateTime={result.createdAt}>{new Date(result.createdAt).toLocaleString('ko-KR')}</time></>}</p></div>
   <details className="report-menu"><summary>리포트·분석 상세</summary><div className="result-actions">{reportActions}<button type="button" onClick={()=>navigate('TECHNICAL')}>기술 정보</button><button type="button" onClick={()=>navigate('GUIDANCE')}>저장된 수정 가이드</button><button type="button" onClick={()=>navigate('PROGRESS')}>검사 변화 보기</button></div></details>
  </header>
  {result.sourceType==='WORKSPACE'&&<p role="note">작업 공간 수정본 검사입니다. 원격 저장소에 반영된 결과는 아닙니다.</p>}
  <div className="result-primary-actions">{rescanActions}</div>
  <p className="result-state-line">{assessment?deploymentLabels[assessment.prioritizedDeploymentAssessment]:'위험 평가 미기록'} · {summaryStateLabel(result.coverage?.status??'NOT_RECORDED')}</p>
  <InspectionBoundaryNotice coverage={result.coverage} compact/>{!assessment&&<p role="note">이전 이력에는 위험 평가가 없습니다. 원본 코드 근거를 표시하며 우선순위를 새로 확정하지 않습니다.</p>}
  <nav className="result-navigation result-list-filters" aria-label="분석 결과 메뉴">
   <button type="button" aria-pressed={['SUMMARY','BLOCKING','REVIEW_REQUIRED','SHOULD_FIX'].includes(view)&&kind==='ALL'} onClick={()=>navigate('SUMMARY')}>문제 목록</button>
   <button type="button" aria-pressed={view==='SUMMARY'&&kind==='CODE'} onClick={()=>{onViewChange('SUMMARY',{kind:'CODE'});setKind('CODE');setSelectedId('');}}>코드</button>
   <button type="button" aria-pressed={view==='LIBRARIES'} onClick={()=>navigate('LIBRARIES')}>외부 라이브러리</button>
   <button type="button" aria-pressed={view==='SUMMARY'&&kind==='AI'} onClick={()=>{onViewChange('SUMMARY',{kind:'AI'});setKind('AI');setSelectedId('');}}>추가 검토</button>
  </nav>
  <div id="result-content" className="result-content">
   {view==='SUMMARY'&&<details className="summary-scope"><summary>검사 요약과 검증 범위</summary><h2 className="visually-hidden">프로젝트 보안 요약</h2><ReviewSummaryPanel result={result} actions={<div className="decision-counts" aria-label="확인할 문제"><span>반드시 처리</span><strong>{reviewCounts(result).blocking??'미평가'}</strong><span>배포 전 직접 확인</span><strong>{reviewCounts(result).review??'미평가'}</strong><p>AI 추가 후보 {reviewCounts(result).candidates}건은 별도 확인</p></div>}><FirstSteps result={result} navigate={navigate} flowCount={(result.serverAnalysis?.validatedFindings?.length??0)+(result.serverAnalysis?.pythonAnalysis?.validatedFindings?.length??0)+(result.serverAnalysis?.javaAnalysis?.findings.length??0)} configCount={(result.serverAnalysis?.deploymentAnalysis?.findings.length??0)+(result.serverAnalysis?.supabaseAnalysis?.findings.length??0)}/></ReviewSummaryPanel><p>{semanticStatusText(result.semanticReview,result.scanMode)}</p><AnalysisCoverageSection coverage={result.coverage} sca={result.sca} semantic={result.semanticReview}/><ServerAnalysisSection snapshot={result.serverAnalysis} compact/></details>}

   {view==='PROGRESS'?<ReviewProgressPanel result={result}/>:view==='TECHNICAL'?<>        <h2>기술 정보</h2>
        {result.sourceType === 'GITHUB' && <GitHubSourceInfo source={result.sourceMetadata} />}
        <dl className="reference-score"><div><dt>보안 점수 · 룰 기반 참고값</dt><dd>{result.securityScore} / 100</dd></div>
          <div><dt>기존 판정 · 참고용</dt><dd>{result.deploymentStatus}</dd></div>
          <div><dt>원본 룰 탐지 수</dt><dd>{result.vulnerabilityCount}</dd></div></dl>
        <p>참고 점수와 기존 정책 판단은 배포 허가가 아닙니다. ‘결과 요약’의 구조 후보와 검사하지 못한 범위를 함께 확인하세요.</p>
        <AnalysisCoverageSection coverage={result.coverage} sca={result.sca} semantic={result.semanticReview} />
        <details><summary>저장된 배포 평가와 분석 범위</summary><RiskAssessmentSection assessment={assessment} /></details>
        <details><summary>코드에서 발견된 문제 · 원본과 판단 근거</summary><LegacyCodeList result={result} statusActions={statusActions} /></details>
        <details><summary>사용 중인 라이브러리 문제 · 보안 공지와 악용 정보</summary><DependencySecuritySection sca={result.sca} riskAssessment={assessment} remediation={result.remediation} reviewId={result.reviewId} onEditDependency={onEditDependency} /></details>
        <details><summary>AI 추가 검토 기록</summary><SemanticReviewSection snapshot={result.semanticReview} /></details>
        <ServerAnalysisSection snapshot={result.serverAnalysis} onEditFile={onEditFile} />
        <RemediationNotice snapshot={result.remediation} /></>:view==='GUIDANCE'?<><Guidance result={result} findings={findings}/>{progress}</>:view==='LIBRARIES'?<DependencySecuritySection initialSelection={selection?.advisory??-1} initialFindingId={selection?.findingId} onSelectionChange={(advisory,findingId)=>onViewChange('LIBRARIES',advisory<0?undefined:findingId?{findingId}:{advisory})} sca={result.sca} riskAssessment={assessment} remediation={result.remediation} reviewId={result.reviewId} onEditDependency={onEditDependency} onEditFile={onEditFile}/>:kind==='AI'?<>
    <p>AI 후보와 미완료 분석 근거는 확정 Finding·위험 점수와 별도로 확인하세요.</p><SemanticReviewSection snapshot={result.semanticReview}/><RelatedSemanticReview result={result}/><details><summary>코드 흐름·설정 및 분석 범위 근거</summary><ServerAnalysisSection snapshot={result.serverAnalysis} onEditFile={onEditFile}/><AnalysisCoverageSection coverage={result.coverage} sca={result.sca} semantic={result.semanticReview}/></details>
   </>:<>
    {!selected&&!selectedId&&<p role="status">목록에서 확인할 문제를 선택하면 근거와 수정 안내가 열립니다.</p>}
    <div className="problem-list-toolbar" hidden={!!selected}><label>문제 검색<input type="search" value={query} onChange={e=>{setQuery(e.target.value);setPage(0);}} placeholder="문제·파일·패키지·공지"/></label><label>검토 우선순위<select value={priority} onChange={e=>onViewChange(e.target.value==='ALL'?'SUMMARY':e.target.value as ResultView)}><option value="ALL">전체</option><option value="BLOCKING">반드시 처리</option><option value="REVIEW_REQUIRED">추가 검토 필요</option><option value="SHOULD_FIX">수정 권장</option></select></label></div>
    {(items.length>0||assessment)?<><p hidden={!!selected}>{counts.groups}개 표시 그룹 · 원본 표시 {counts.originalItems}개 항목 (룰 탐지 {result.vulnerabilityCount}건 / 저장 공지 매칭 {result.sca?.summary.dependencyVulnerabilities??'미기록'}항목) · 확인된 파일·행 위치 {counts.locations}곳 · 상태 기록 {counts.statusRecorded}건. 사용자 완료 표시 {counts.markedResolved}건은 해결 검증이 아닙니다. 항목별 해결 검증 수는 미집계이며 재검사가 필요합니다.</p><ul className="problem-list" aria-label="발견된 문제 목록" hidden={!!selected} ref={rows}>{groups.slice(page*20,page*20+20).map(g=>{const f=g.items[0];return <li key={g.id}><a href={projectLink(result.projectId??0,'findings',result.reviewId??undefined,view,{kind,findingId:f.findingId})} className="problem-row" data-finding-index={items.indexOf(f)} aria-current={selectedId===f.findingId?'true':undefined} onClick={event=>{if(!event.metaKey&&!event.ctrlKey&&!event.shiftKey&&!event.altKey){event.preventDefault();choose(f.findingId);}}}><span className="problem-row-title">{g.title} — {g.items.length}개 원본 항목</span><span>{g.area.label}</span><span>{f.findingId.startsWith('legacy:')?'우선순위 미기록':priorityLabels[f.priority]} · {f.source==='DEPENDENCY'?'외부 라이브러리':f.source==='CODE'?'코드':f.source==='FLOW'?'정적 코드 흐름 · 점수 별도':'분석 확인 필요'}</span><small>{f.advisoryId&&<code>{f.advisoryId} · </code>}{f.sourceFiles.join(', ')||'파일 위치 미기록'}{rowVulnerability(f)&&` · 원본 ${rowVulnerability(f)!.line}행`}</small></a></li>;})}</ul>
     {selectedId&&!selected&&<p role="status">선택한 항목이 이 검사 또는 현재 필터에 없습니다. 목록에서 확인할 문제를 선택해 주세요.</p>}
     {!shown.length&&<p>현재 필터에 표시할 저장된 항목이 없어요. 전체 안전성을 의미하지 않습니다.</p>}
     {!selected&&groups.length>20&&<nav aria-label="문제 목록 페이지"><button disabled={page===0} onClick={()=>setPage(page-1)}>이전</button><span>{page+1} / {Math.ceil(groups.length/20)}</span><button disabled={(page+1)*20>=groups.length} onClick={()=>setPage(page+1)}>다음</button></nav>}
     {selected&&<div className="selected-problem" tabIndex={-1} ref={detail}><button type="button" className="secondary-button" onClick={()=>{const index=items.findIndex(f=>f.findingId===(selectedGroup?.id??selectedId));choose('');requestAnimationFrame(()=>{const button=[...(rows.current?.querySelectorAll<HTMLAnchorElement>('a')??[])].find(b=>b.dataset.findingIndex===String(index));button?.focus();button?.scrollIntoView({block:'center'});});}}>문제 목록으로 돌아가기</button><h3>선택한 문제 상세</h3>{selectedGroup&&selectedGroup.items.length>1&&<section className="problem-occurrences" aria-label="그룹의 원본 발생 위치"><h4>{selectedGroup.title} · 원본 {selectedGroup.items.length}건</h4><p>표시 유형을 묶었습니다. 같은 원인 또는 한 번의 수정으로 해결된다는 의미가 아닙니다. 각 위치의 근거·상태를 확인하세요.</p><ul>{selectedGroup.items.slice(occurrencePage*50,occurrencePage*50+50).map(f=>{const l=itemLocation(result,f),v=rowVulnerability(f);return <li key={f.findingId}><button type="button" aria-pressed={selectedId===f.findingId} onClick={()=>choose(f.findingId)}>{f.source==='DEPENDENCY'&&f.advisoryId?`${f.advisoryId} · `:''}{l.path||'위치 미기록'}{l.line?` · ${l.line}행`:''} · {f.findingId.startsWith('legacy:')?'우선순위 미기록':f.priority} · {v?.status??'상태 미기록'}</button><details><summary>원본 식별자</summary><p>{f.findingId} · {'flow'in f?f.flow.ruleId:f.ruleId??f.advisoryId}</p></details></li>})}</ul>{selectedGroup.items.length>50&&<nav aria-label="발생 위치 페이지"><button disabled={occurrencePage===0} onClick={()=>setOccurrencePage(n=>n-1)}>이전 위치</button><span>{occurrencePage+1} / {Math.ceil(selectedGroup.items.length/50)}</span><button disabled={(occurrencePage+1)*50>=selectedGroup.items.length} onClick={()=>setOccurrencePage(n=>n+1)}>다음 위치</button></nav>}</section>}{'flow' in selected?<FlowFindingDetail finding={selected.flow} onEditFile={onEditFile}/>:<FindingCollection result={result} findings={[selected]} statusActions={statusActions} onEditFile={onEditFile} onEditDependency={onEditDependency} detailOnly/>}</div>}
    </>:<><p>이전 이력에는 위험 평가가 없습니다. 기존 코드 근거와 라이브러리 결과를 확인하세요.</p><LegacyCodeList result={result} statusActions={statusActions}/></>}
   </>}
  </div>
 </section>;
}

function FirstSteps({ result, navigate, flowCount, configCount }: { result: SecurityReviewResponse; navigate: (view: ResultView) => void; flowCount: number; configCount: number }) {
  const assessment = result.riskAssessment, findings = allRiskFindings(result);
  return <section className="next-actions"><h3>가장 먼저 확인할 문제</h3>
    {assessment ? <>
      <ol>{(['BLOCKING', 'REVIEW_REQUIRED', 'SHOULD_FIX'] as const).filter(priority => assessment.prioritySummary[priority] > 0).map(priority => {
        const first = findings.find(f => f.priority === priority);
        return <li key={priority} data-priority={priority}><div><span className="action-priority">{priorityLabels[priority]} · {assessment.prioritySummary[priority]}건</span>
          <p>{first ? findingTitle(result, first) : '저장된 분석 항목을 확인해 주세요.'}</p>
          {first?.sourceFiles[0]&&<code className="next-action-location">{first.sourceFiles[0]}</code>}</div>
          <button className="secondary-button" type="button" onClick={() => navigate(priority)}>수정 방법 확인</button></li>;
      })}</ol>
      {assessment.prioritySummary.BLOCKING === 0 && assessment.prioritySummary.REVIEW_REQUIRED === 0 && assessment.prioritySummary.SHOULD_FIX === 0 && <p>이 분류에서 보고된 문제는 없어요. 검사 범위와 별도 확인 항목도 함께 살펴보세요.</p>}
      {(flowCount + configCount > 0)&&<p className="supplemental-action">점수와 별도로 확인할 코드·설정 항목이 {flowCount + configCount}건 있어요.{' '}
        <button className="text-action" type="button" onClick={() => navigate('REVIEW_REQUIRED')}>근거와 수정 방법 확인</button></p>}
      {assessment.prioritySummary.INFORMATIONAL > 0 && <p>참고 사항 {assessment.prioritySummary.INFORMATIONAL}건은 ‘수정 권장’에서 확인할 수 있어요.</p>}
    </> : <button className="secondary-button" type="button" onClick={() => navigate('REVIEW_REQUIRED')}>저장된 문제 확인</button>}
  </section>;
}

export function FindingCollection({ result, findings, statusActions, onEditFile, onEditDependency, detailOnly=false }: {
  result: SecurityReviewResponse; findings: RiskFinding[]; statusActions: FindingStatusActions;

  onEditFile?: (path: string) => void; onEditDependency?:(id:string)=>void; detailOnly?:boolean;
}) {
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL');
  const [page, setPage] = useState(0);
  const level = (f: RiskFinding) => f.dependency?.severity ?? vulnerabilityForFinding(result, f)?.severity;
  const sorted = findings.filter(f => severity === 'ALL' || level(f) === severity).sort((a, b) =>
    (severityOrder[level(a) as Severity] ?? 4) - (severityOrder[level(b) as Severity] ?? 4));
  const currentPage = Math.min(page, Math.max(0, Math.ceil(sorted.length / 6) - 1));
  return <>
    {!detailOnly&&<label className="finding-filter">심각도 <select value={severity} onChange={event => { setSeverity(event.target.value as Severity | 'ALL'); setPage(0); }}>
      <option value="ALL">전체</option>{Object.keys(severityOrder).map(value => <option key={value} value={value}>{severityLabels[value]}</option>)}
    </select><span>{sorted.length}건</span></label>}
    {findings.filter(f => f.ruleId === 'LOCAL_STORAGE_TOKEN').length > 1 &&
      <p className="review-caution">토큰 사용 위치가 여러 곳입니다. 서로 독립적인 수정 작업이라는 뜻은 아닙니다. 공통 저장 코드와 로그인·갱신 흐름을 함께 확인하세요. 별칭을 통한 저장 위치는 현재 룰에서 확인하지 못할 수 있습니다.</p>}
    {!sorted.length && <p className="result-empty">{findings.length ? '선택한 심각도에 해당하는 문제가 없습니다.' : '이 분류에 저장된 문제가 없습니다.'}</p>}
    <div className="vulnerability-list">{sorted.slice(currentPage * 6, currentPage * 6 + 6).map(finding => {
      if (incompleteDependency(finding)) return <IncompleteDependencyCard key={`${result.reviewId}:${finding.findingId}`}
        finding={finding} reviewId={result.reviewId} />;
      const vulnerability = vulnerabilityForFinding(result, finding);
      if (finding.source === 'CODE' && vulnerability) return <CodeFindingCard key={finding.findingId} vulnerability={vulnerability}
        finding={finding.findingId.startsWith('legacy:')?undefined:finding} remediation={result.remediation} statusActions={statusActions} onEditFile={onEditFile} />;
      if (finding.dependency) return <DependencyDetail reviewId={result.reviewId} key={`${result.reviewId}:${finding.findingId}`} dependency={finding.dependency}
        finding={finding} remediation={result.remediation} intelligence={result.riskAssessment?.threatIntelligence} components={result.sca?.components} onEditDependency={onEditDependency} onEditFile={onEditFile}/>;
      const guide = findingGuidance(finding);
      return <article className="vulnerability-item action-finding" key={finding.findingId}>
        <span className={`risk-badge risk-${finding.priority.toLowerCase()}`}>{priorityLabels[finding.priority]}</span>
        <h3>{guide.summary}</h3><p>{guide.risk}</p>
        <h4>직접 이렇게 확인해 보세요</h4><ol>{guide.steps.map(step => <li key={step}>{step}</li>)}</ol>
        <FindingRemediation finding={finding} snapshot={result.remediation} />
        <details className="technical-details"><summary>기술 정보 보기</summary><p>{dependencyText(finding.findingId)} · {finding.reasonCode}</p>
          <p>{dependencyText(finding.priorityReason)}</p><p className="finding-location">{dependencyText(finding.sourceFiles.join(', '))}</p></details>
      </article>;
    })}</div>
    {sorted.length > 6 && <nav className="finding-pagination" aria-label="문제 목록 페이지">
      <button type="button" className="secondary-button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>이전</button>
      <span>{currentPage + 1} / {Math.ceil(sorted.length / 6)}</span>
      <button type="button" className="secondary-button" disabled={(currentPage + 1) * 6 >= sorted.length} onClick={() => setPage(currentPage + 1)}>다음</button>
    </nav>}
  </>;
}

function LegacyCodeList({ result, statusActions }: { result: SecurityReviewResponse; statusActions: FindingStatusActions }) {
  const [severity, setSeverity] = useState<Severity | 'ALL'>('ALL');
  const list = [...result.vulnerabilities].filter(v => severity === 'ALL' || v.severity === severity)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return <>
    <label className="finding-filter">심각도 <select value={severity} onChange={event => setSeverity(event.target.value as Severity | 'ALL')}>
      <option value="ALL">전체</option>{Object.keys(severityOrder).map(value => <option key={value}>{value}</option>)}
    </select></label>
    <div className="vulnerability-list">{list.map((v, index) => <CodeFindingCard key={v.vulnerabilityId ?? index} vulnerability={v}
      finding={result.riskAssessment?.codeFindings.find(f => v.vulnerabilityId != null && f.vulnerabilityId === v.vulnerabilityId)}
      remediation={result.remediation} statusActions={statusActions} />)}</div>
    {!list.length && <p>표시할 코드 문제가 없습니다.</p>}
  </>;
}

function Guidance({ result, findings }: { result: SecurityReviewResponse; findings: RiskFinding[] }) {
  const [selected, setSelected] = useState('');
  const order = { BLOCKING: 0, REVIEW_REQUIRED: 1, SHOULD_FIX: 2, INFORMATIONAL: 3 };
  const ordered = [...findings].sort((a, b) => order[a.priority] - order[b.priority]);
  const finding = ordered.find(f => f.findingId === selected) ?? ordered[0];
  const vulnerability = finding && vulnerabilityForFinding(result, finding);
  return <section className="guidance-section">
    {finding ? <>
      <label htmlFor="guidance-finding">해결할 문제 선택</label>
      <select id="guidance-finding" value={finding.findingId} onChange={event => setSelected(event.target.value)}>
        {ordered.map(item => <option key={item.findingId} value={item.findingId}>{priorityLabels[item.priority]} · {findingTitle(result, item)}</option>)}
      </select>
      {incompleteDependency(finding)
        ? <IncompleteDependencyCard key={`${result.reviewId}:${finding.findingId}`} finding={finding} reviewId={result.reviewId} />
        : <><h3>{findingTitle(result, finding)}</h3>
          <FindingRemediation key={finding.findingId} finding={finding} snapshot={result.remediation} vulnerability={vulnerability} expanded /></>}
    </> : <p>문제별 해결 방법을 연결할 우선순위 평가가 없습니다. 저장된 원본 결과를 참고하거나 재분석하세요.</p>}
    <RemediationNotice snapshot={result.remediation} />
  </section>;
}
