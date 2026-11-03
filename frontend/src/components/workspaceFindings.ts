import type { DependencyVulnerability, SecurityReviewResponse, Vulnerability } from '../types/securityReview';
import type { ServerFlowFinding } from '../types/serverAnalysis';

export const findingPath = (path: string) => path.replace(/\\/g, '/');
export const severityOrder = ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
export type FileFinding = {
  id: string; path: string; title: string; severity: string; line?: number;
  code?: Vulnerability; flow?: ServerFlowFinding; dependency?: DependencyVulnerability;
};

export function indexWorkspaceFindings(result: SecurityReviewResponse, files: ReadonlySet<string>) {
  const byPath = new Map<string, FileFinding[]>();
  const evidence = new Map<string, Set<string>>();
  const inspected = new Set<string>();
  const seen = new Set<string>();
  const add = (item: FileFinding) => {
    if (!files.has(item.path) || seen.has(item.id)) return false;
    seen.add(item.id);
    const entries = byPath.get(item.path) ?? [];
    entries.push(item);
    byPath.set(item.path, entries);
    return true;
  };
  for (const entry of result.coverage?.entries ?? [])
    if (entry.kind === 'FILE' && entry.status === 'SELECTED') inspected.add(findingPath(entry.filePath));
  for (const v of result.vulnerabilities) {
    const path = findingPath(v.filePath);
    add({id: 'code:' + (v.vulnerabilityId ?? JSON.stringify([v.ruleId, path, v.line, v.message])),
      path, title: v.ruleId, severity: v.severity, line: v.line, code: v});
  }
  for (const flow of [...(result.serverAnalysis?.validatedFindings ?? []), ...(result.serverAnalysis?.pythonAnalysis?.validatedFindings ?? [])]) {
    const path = findingPath(flow.location.filePath), id = 'flow:' + flow.findingId;
    if (!add({id, path, title: flow.title, severity: 'UNKNOWN', line: flow.location.line, flow})) continue;
    for (const loc of [...flow.executionLocations, ...flow.evidence.flatMap(e => [e.source, e.sink, ...e.flow])]) {
      const related = findingPath(loc.filePath);
      if (related === path || !files.has(related)) continue;
      const ids = evidence.get(related) ?? new Set<string>();
      ids.add(id);
      evidence.set(related, ids);
    }
  }
  if (result.sca?.status === 'COMPLETE') for (const manifest of result.sca.manifests ?? [])
    if (manifest.status === 'COMPLETE') inspected.add(findingPath(manifest.filePath));
  const risks = result.riskAssessment?.dependencyFindings ?? [];
  for (const dep of result.sca?.dependencyVulnerabilities ?? []) {
    const paths = [...new Set(dep.sourceFiles.map(findingPath))].filter(path => files.has(path)).sort();
    const lock = paths.find(path => /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(path));
    const path = lock ?? paths[0];
    if (!path) continue;
    const risk = risks.find(r => r.ecosystem === dep.ecosystem && r.packageName === dep.packageName
      && r.version === dep.installedVersion && r.advisoryId === dep.osvId);
    const id = 'sca:' + (risk?.findingId ?? JSON.stringify([dep.ecosystem, dep.packageName, dep.installedVersion, dep.osvId]));
    if (!add({id, path, title: `${dep.packageName}@${dep.installedVersion} · ${dep.osvId}`, severity: dep.severity ?? 'UNKNOWN', dependency: dep})) continue;
    for (const related of paths.filter(p => p !== path)) {
      const ids = evidence.get(related) ?? new Set<string>();
      ids.add(id);
      evidence.set(related, ids);
    }
  }
  return {byPath, evidence, inspected};
}
