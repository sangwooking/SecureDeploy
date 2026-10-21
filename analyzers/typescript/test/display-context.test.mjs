import {test} from 'node:test';
import assert from 'node:assert/strict';
import {classify} from '../url-context.mjs';
const config=(text='The Secret Behind A Better Product',extra='')=>`import engine from 'i18next';const dictionaries={en:{translation:{secret:${JSON.stringify(text)},terms:'Read our <b>terms</b>'}}};${extra}engine.init({resources:dictionaries});`;
const page=html=>`import {useTranslation as useText} from 'react-i18next';export function Screen(){const {t:label}=useText();return <p dangerouslySetInnerHTML={{__html:${html}}}/>;}`;
const run=(content,provider=config())=>classify([{filePath:'ui.tsx',content},{filePath:'config.ts',content:provider}]);
test('proven translation labels and fixed translation HTML have separate negative evidence',()=>{
  const r=run(page("label('terms')"));assert.deepEqual(r.files[0].excludedHtmlLines,[1]);assert.deepEqual(r.files[1].excludedSecretLines,[1]);
});
test('a property key sharing the resource binding name is not a variable escape',()=>{
  const provider=config().replaceAll('dictionaries','resources').replace("terms:'", "resources:'Documents',terms:'");
  assert.deepEqual(run(page("label('terms')"),provider).files[0].excludedHtmlLines,[1]);
  assert.deepEqual(run(page("label('terms')"),provider+'export {resources};').files[0].excludedHtmlLines,[]);
});
test('generic objects, opaque credentials and dynamic resource updates retain secret warnings',()=>{
  assert.deepEqual(classify([{filePath:'data.ts',content:'const data={secret:"The Secret Behind A Better Product"};'}]).files[0].excludedSecretLines,[]);
  const fake='ghp_'+'z'.repeat(36);assert.deepEqual(run(page("label('terms')"),config(fake)).files[1].excludedSecretLines,[]);
  assert.deepEqual(run(page("label('terms')"),config(undefined,'dictionaries.en.translation.secret=readValue();')).files[1].excludedSecretLines,[]);
  assert.deepEqual(run(page("label('terms')"),config(undefined,'mutate(dictionaries);')).files[0].excludedHtmlLines,[]);
});
test('interpolation, unknown providers and custom translators do not suppress HTML warnings',()=>{
  for(const html of ["label('terms',{value:request.body})",'request.body','renderUnknown()'])assert.deepEqual(run(page(html)).files[0].excludedHtmlLines,[]);
  assert.deepEqual(run(page("label('terms')"),'const resources={};').files[0].excludedHtmlLines,[]);
  assert.deepEqual(run(page("label('terms')"),config().replace('Read our <b>terms</b>','Hello {{user}}')).files[0].excludedHtmlLines,[]);
});
test('redirect destinations distinguish deployment configuration from request control',()=>{
  const configured='function reply(site,result){const redirectUrl=`${site}/settings?result=${result}`;return `<script>window.location.href="${redirectUrl}"</script>`;}const site=Deno.env.get("SITE_URL")||"http://localhost:5173";reply(site,"ok");';
  assert.deepEqual(classify([{filePath:'server.ts',content:configured}]).files[0].excludedRedirectLines,[1]);
  for(const text of [configured.replace('reply(site,"ok")','reply(request.query.next,"ok")'),
    'const redirectUrl=request.query.next;window.location.href=redirectUrl;',
    'const redirectUrl=validate(request.query.next);window.location.href=redirectUrl;'])assert.deepEqual(classify([{filePath:'x.ts',content:text}]).files[0].excludedRedirectLines,[]);
});
test('oversized or invalid context never supplies new negative proof',()=>{
  const row=run(page("label('terms')"),config()+' '.repeat(250001)).files[0];assert.deepEqual(row.excludedHtmlLines,[]);
  assert.deepEqual(run(page('"<b>ok</b>"')+'???').files[0].excludedHtmlLines??[],[]);
});
test('a safe occurrence cannot suppress a different unsafe sink on the same line',()=>{
  assert.deepEqual(run('const x=<><p dangerouslySetInnerHTML={{__html:"ok"}}/><p dangerouslySetInnerHTML={{__html:input}}/></>;').files[0].excludedHtmlLines,[]);
  assert.deepEqual(classify([{filePath:'x.ts',content:'window.location.href="/ok";window.location.href=input;'}]).files[0].excludedRedirectLines,[]);
});
