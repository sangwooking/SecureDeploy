import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,symlinkSync,rmSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {performance} from 'node:perf_hooks';
import assert from 'node:assert/strict';
import {classify} from '../../analyzers/typescript/url-context.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
const view=value=>`const View=()=> <article dangerouslySetInnerHTML={{__html:${value}}}/>;`;
const provider=`import engine from 'i18next';engine.init({resources:{en:{translation:{notice:'Read <b>notice</b>'}}}});`;
const translated=`import {useTranslation} from 'react-i18next';function View(){const {t}=useTranslation();return <p dangerouslySetInnerHTML={{__html:t('notice')}}/>;}`;
const packet=(content,config)=>[{filePath:'app/page.tsx',content},...(config?[{filePath:'locale.ts',content:config}]:[])];
// Curator-created controls, not CVEs, external independent validation or whole-app labels.
export const cases=[
  ['direct-body','REGRESSION','RISK',packet(view('request.body'))],
  ['external-html','REGRESSION','RISK',packet(view('response.html'))],
  ['active-fixed','REGRESSION','RISK',packet(view(JSON.stringify('<img src=x onerror=alert(1)>')))],
  ['passive-literal','REGRESSION','NORMAL',packet(view('"Read <b>notice</b>"'))],
  ['passive-alias','REGRESSION','NORMAL',packet('const markup="<p>Notice</p>";'+view('markup'))],
  ['passive-concat','REGRESSION','NORMAL',packet('const a="Read ";const b=a+"<b>notice</b>";'+view('b'))],
  ['unknown-transform','REGRESSION','UNKNOWN',packet(view('sanitize(input)'))],
  ['unknown-import','REGRESSION','UNKNOWN',packet('import markup from "./remote";'+view('markup'))],
  ['provider-mutation','REGRESSION','UNKNOWN',packet(translated,provider+'const alias=engine;alias.addResourceBundle(x,y,data);')],
  ['query-alias','VALIDATION','RISK',packet('const html=location.search;'+view('html'))],
  ['active-translation','VALIDATION','RISK',packet(translated,provider.replace('Read <b>notice</b>','<img src=x onerror=alert(1)>'))],
  ['template-constant','VALIDATION','NORMAL',packet('const noun="policy";const html=`<strong>${noun}</strong>`;'+view('html'))],
  ['jsx-escaped','VALIDATION','NORMAL',packet('function View({input}){return <p>{input}</p>;}')],
  ['fixed-translation','VALIDATION','NORMAL',packet(translated,provider)],
  ['dynamic-fallback','VALIDATION','UNKNOWN',packet(view('input||"<b>fallback</b>"'))],
  ['spread-html','VALIDATION','UNKNOWN',packet('const View=()=> <p dangerouslySetInnerHTML={{__html:"ok",...options}}/>;')],
  ['dynamic-interpolation','VALIDATION','UNKNOWN',packet(translated.replace("t('notice')","t('notice',{value:input})"),provider)],
  ['static-link-normal','VALIDATION','NORMAL',packet(view(JSON.stringify('<a href="https://example.invalid">policy</a>')))],
];

export function evaluate(classifier) {
  const results=[],totals={TP:0,FP:0,FN:0,TN:0,UNKNOWN:0,incorrectExclusion:0};
  for(const [id,split,truth,files] of cases) {
    const runs=[];
    for(let repeat=0;repeat<2;repeat++) {
      const start=performance.now(),rows=classifier(files).files;
      const sinkLines=files[0].content.split('\n').flatMap((line,i)=>line.includes('dangerouslySetInnerHTML')?[i+1]:[]);
      const excluded=rows[0].excludedHtmlLines??[];
      const warning=sinkLines.some(line=>!excluded.includes(line));
      runs.push({warning,contexts:rows[0].htmlContexts??[],elapsedMs:Math.round((performance.now()-start)*1000)/1000});
    }
    assert.equal(runs[0].warning,runs[1].warning);
    assert.deepEqual(runs[0].contexts,runs[1].contexts);
    const warning=runs[0].warning;
    const outcome=truth==='UNKNOWN'?'UNKNOWN':truth==='RISK'?(warning?'TP':'FN'):(warning?'FP':'TN');
    totals[outcome]++;
    if(truth==='UNKNOWN'&&!warning)totals.incorrectExclusion++;
    results.push({id,split,truth,outcome,runs});
  }
  return {totals,results};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const [ref,output]=process.argv.slice(2);
  if(!/^[a-f0-9]{40}$/.test(ref??'')||!output)throw Error('BASELINE_SHA_AND_NEW_OUTPUT_REQUIRED');
  const directory=mkdtempSync(join(tmpdir(),'securedeploy-html-baseline-'));
  try {
    for(const name of ['url-context.mjs','static-display-context.mjs']) {
      writeFileSync(join(directory,name),execFileSync('git',['show',`${ref}:analyzers/typescript/${name}`],{cwd:root}));
    }
    symlinkSync(join(root,'analyzers/typescript/node_modules'),join(directory,'node_modules'));
    const before=await import(pathToFileURL(join(directory,'url-context.mjs')).href);
    const baseline=evaluate(before.classify),current=evaluate(classify);
    assert.deepEqual(current.totals,{TP:5,FP:1,FN:0,TN:6,UNKNOWN:6,incorrectExclusion:0});
    const report={schemaVersion:1,baselineRef:ref,
      evaluatorSha256:createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex'),
      currentSourceHashes:Object.fromEntries(['url-context.mjs','static-display-context.mjs'].map(name=>[name,createHash('sha256').update(readFileSync(join(root,'analyzers/typescript',name))).digest('hex')])),
      limitations:['Same-curator synthetic controls; not independently blind','Only React dangerouslySetInnerHTML reconciliation; no browser execution',
        'UNKNOWN retained warnings are not confirmed XSS','No DOM innerHTML/insertAdjacentHTML/srcdoc flow support added','No sanitizer semantics or whole-app safety claim'],
      baseline,current};
    writeFileSync(output,JSON.stringify(report,null,2)+'\n',{flag:'wx'});
    console.log(JSON.stringify({baseline:baseline.totals,current:current.totals,repeats:2}));
  } finally {rmSync(directory,{recursive:true,force:true});}
}
