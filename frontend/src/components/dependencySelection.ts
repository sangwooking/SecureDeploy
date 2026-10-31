import type { RiskAssessment, ScaResult } from '../types/securityReview';

/** Keep canonical finding identity with its evidence; a display index is not an identity. */
export function dependencyEntries(sca:ScaResult, risk?:RiskAssessment|null) {
  if(risk && risk.schemaVersion>=2) return risk.dependencyFindings.flatMap(f=>
    f.dependency ? [{dependency:f.dependency,finding:f}] : []);
  return sca.dependencyVulnerabilities.map(dependency=>({dependency,finding:risk?.dependencyFindings.find(f=>
    f.ecosystem===dependency.ecosystem && f.packageName===dependency.packageName &&
    f.version===dependency.installedVersion && f.advisoryId===dependency.osvId)}));
}

export function dependencySelectionIndex(entries:ReturnType<typeof dependencyEntries>, findingId:string|undefined, legacyIndex:number) {
  if(findingId!==undefined) {
    const matches=entries.flatMap((entry,i)=>entry.finding?.findingId===findingId?[i]:[]);
    return matches.length===1?matches[0]:-1;
  }
  return Number.isSafeInteger(legacyIndex)&&legacyIndex>=0&&legacyIndex<entries.length?legacyIndex:-1;
}
