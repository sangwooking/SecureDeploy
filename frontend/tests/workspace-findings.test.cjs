const {test}=require('node:test');
const assert=require('node:assert/strict');
const {indexWorkspaceFindings}=require('./load-component.cjs')('workspaceFindings');

test('only the representative file counts a repeated Finding ID, even with cross-file evidence',()=>{
  const loc=filePath=>({filePath,line:2});
  const flow={findingId:'f',location:loc('src/sink.ts'),executionLocations:[loc('src/source.ts')],
    evidence:[{source:loc('src/source.ts'),sink:loc('src/sink.ts'),flow:[loc('src/source.ts')]}]};
  const code={vulnerabilityId:42,filePath:'src\\sink.ts',line:0,severity:'HIGH'};
  const index=indexWorkspaceFindings({vulnerabilities:[code,code],serverAnalysis:{validatedFindings:[flow,flow]},
    coverage:{entries:[{kind:'FILE',status:'SELECTED',filePath:'clean.ts'},{kind:'FILE',status:'EXCLUDED',filePath:'ignored.ts'}]}},
    new Set(['src/sink.ts','src/source.ts','clean.ts','ignored.ts']));
  assert.deepEqual(index.byPath.get('src/sink.ts').map(i=>i.id),['code:42','flow:f']);
  assert.equal(index.byPath.get('src/sink.ts')[0].line,0);
  assert.equal(index.byPath.has('src/source.ts'),false);
  assert.deepEqual([...index.evidence.get('src/source.ts')],['flow:f']);
  assert.equal(index.inspected.has('clean.ts'),true);
  assert.equal(index.inspected.has('ignored.ts'),false);
});

test('SCA matches count by advisory, package and version on a real lockfile, not by install path',()=>{
  const dep={ecosystem:'NPM',packageName:'undici',installedVersion:'7.29.1',osvId:'GHSA-1',
    sourceFiles:['package.json','package-lock.json','package-lock.json','not-in-workspace.js']};
  const other={...dep,osvId:'GHSA-2'};
  const index=indexWorkspaceFindings({vulnerabilities:[],sca:{status:'PARTIAL',manifests:[{filePath:'clean.json',status:'COMPLETE'}],
    dependencyVulnerabilities:[dep,dep,other]}},new Set(['package.json','package-lock.json','clean.json','node_modules/undici/index.js']));
  assert.equal(index.byPath.get('package-lock.json').length,2);
  assert.equal(index.byPath.has('package.json'),false);
  assert.equal(index.evidence.get('package.json').size,2);
  assert.equal(index.byPath.has('node_modules/undici/index.js'),false);
  assert.equal(index.inspected.has('clean.json'),false);
});
