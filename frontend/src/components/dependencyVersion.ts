import type {DependencyVulnerability} from '../types/securityReview';
const version=(s:string)=>/^\d+\.\d+\.\d+$/.test(s)?s.split('.').map(Number):null;
export function currentSeriesFix(dep:DependencyVulnerability){const current=version(dep.installedVersion);if(!current)return null;
 const candidates=dep.fixedVersions.flatMap(value=>{const v=version(value);return v&&v[0]===current[0]&&v[1]===current[1]&&v[2]>current[2]?[{value,v}]:[];}).sort((a,b)=>a.v[2]-b.v[2]);return candidates[0]?.value??null;
}
export function versionBasis(files:string[]){return files.some(f=>/(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|uv\.lock)$/.test(f))?'잠금 파일 기록 · 실제 설치/실행은 미검증':'정적 선언 · 실제 설치 버전 미확인';}
