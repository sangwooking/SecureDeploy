import { Component, type ReactNode } from 'react';
import type { DependencyComponent, DependencyVulnerability, RemediationSnapshot, RiskFinding, ThreatIntelligenceSnapshot } from '../types/securityReview';
import { DependencyFindingCard } from './DependencyFindingCard';
import { DependencyUpdatePlans } from './DependencyUpdatePlans';

class DetailBoundary extends Component<{identity:string;fallback:ReactNode;children:ReactNode},{identity:string;failed:boolean}> {
  state={identity:this.props.identity,failed:false};
  static getDerivedStateFromProps(props:{identity:string},state:{identity:string;failed:boolean}) {
    return props.identity!==state.identity?{identity:props.identity,failed:false}:null;
  }
  static getDerivedStateFromError(){return {failed:true};}
  render(){return this.state.failed?this.props.fallback:this.props.children;}
}

/** Both result paths use the same saved evidence, support controls and failure boundary. */
export function DependencyDetail({dependency,finding,reviewId,components,remediation,intelligence,onEditDependency,onEditFile}:{
  dependency:DependencyVulnerability;finding?:RiskFinding;reviewId?:number|null;
  components?:DependencyComponent[];remediation?:RemediationSnapshot|null;intelligence?:ThreatIntelligenceSnapshot|null;
  onEditDependency?:(id:string)=>void;onEditFile?:(path:string)=>void;
}) {
  const text=(value:unknown)=>typeof value==='string'&&value.trim()?value:'미확인';
  const identity=JSON.stringify([reviewId,finding?.findingId,dependency.ecosystem,dependency.packageName,dependency.installedVersion,dependency.osvId]);
  const fallback=<section role="alert" aria-label="라이브러리 상세 표시 오류">
    <h3>{text(dependency.packageName)} 업데이트 검토</h3>
    <p>저장된 상세 정보의 형식을 표시하지 못했습니다. 기존 분석 근거는 보존되며 안전 여부나 수정 버전을 새로 판단하지 않습니다.</p>
    <dl><dt>현재 버전</dt><dd>{text(dependency.installedVersion)}</dd><dt>보안 공지</dt><dd>{text(dependency.osvId)}</dd>
      <dt>확인할 파일</dt><dd>{Array.isArray(dependency.sourceFiles)?dependency.sourceFiles.filter(p=>typeof p==='string').join(', '):'미확인'}</dd></dl>
    <p>검사 기록에서 같은 항목을 다시 열어 주세요. 계속 실패하면 이 화면과 검사 번호를 관리자에게 전달해 주세요.</p>
  </section>;
  return <DetailBoundary key={identity} identity={identity} fallback={fallback}>
    <DependencyFindingCard dependency={dependency} finding={finding} reviewId={reviewId} components={components}
      remediation={remediation} intelligence={intelligence}
      support={<DependencyUpdatePlans reviewId={reviewId} selectedDependency={dependency} onEditDependency={onEditDependency} onEditFile={onEditFile}/>}/>
  </DetailBoundary>;
}
