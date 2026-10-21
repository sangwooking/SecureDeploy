import {test} from 'node:test';
import assert from 'node:assert/strict';
import {classify} from '../url-context.mjs';

const scan = content => classify([{filePath:'app/page.tsx', content}]).files[0];
const view = value => `const View=()=> <div dangerouslySetInnerHTML={{__html:${value}}}/>;`;
test('fixed active markup is never negative XSS evidence', () => {
  for (const value of ['<img src=x onerror=alert(1)>','<script>alert(1)</script>',
    '<a href="javascript:alert(1)">open</a>','<svg onload=alert(1)>',
    '<iframe srcdoc="active"></iframe>','<b style="color:red">text</b>']) {
    assert.deepEqual(scan(view(JSON.stringify(value))).excludedHtmlLines, []);
  }
});
test('closed lexical constants support passive markup without evaluating code', () => {
  for (const declarations of ['const html="Read <b>terms</b>";',
    'const a="Read ";const html=a+"<b>terms</b>";',
    'const a="terms";const html=`Read <b>${a}</b>`;']) {
    assert.deepEqual(scan(declarations+view('html')).excludedHtmlLines, [1]);
  }
});
test('mutation, scope shadowing and unknown transforms cannot clear warnings', () => {
  for (const text of ['let html="ok";'+view('html'),
    'const html="ok";html=external;'+view('html'),
    'const html="ok";function View(html){return <p dangerouslySetInnerHTML={{__html:html}}/>;}',
    view('sanitize(input)'), view('`<b>${input}</b>`'),
    view('"<b>"+input+"</b>"')]) assert.deepEqual(scan(text).excludedHtmlLines, []);
});
test('unsupported HTML contexts are not mistaken for passive markup', () => {
  for (const value of ['<B>upper</B>','<!-- comment -->','<b title="text">x</b>',
    '<b>unclosed','<b><i>x</b></i>','<math>x</math>']) {
    assert.deepEqual(scan(view(JSON.stringify(value))).excludedHtmlLines, []);
  }
  for(const tag of ['UnknownComponent','script','style','iframe','svg']) {
    assert.deepEqual(scan(`const View=()=> <${tag} dangerouslySetInnerHTML={{__html:"fixed"}}/>;`).excludedHtmlLines, []);
  }
});

test('translation extensions, provider replacement and executable resources retain warnings', () => {
  const page=`import {useTranslation} from 'react-i18next';function View(){const {t}=useTranslation();return <p dangerouslySetInnerHTML={{__html:t('terms')}}/>;}`;
  const provider=`import engine from 'i18next';engine.init({resources:{en:{translation:{terms:'Read <b>terms</b>'}}}});`;
  for(const extra of ['const alias=engine;alias.addResourceBundle(locale,namespace,external);',
    'function replace(engine){return <I18nextProvider i18n={engine}/>;}']) {
    const rows=classify([{filePath:'view.tsx',content:page},{filePath:'provider.tsx',content:provider+extra}]).files;
    assert.deepEqual(rows[0].excludedHtmlLines, []);
  }
  for(const replacement of ['<img src=x onerror=alert(1)>','$t(other)', '{{user}}']) {
    assert.deepEqual(classify([{filePath:'view.tsx',content:page},
      {filePath:'provider.ts',content:provider.replace('Read <b>terms</b>',replacement)}]).files[0].excludedHtmlLines, []);
  }
  for(const config of [provider.replace('resources:', 'resources:external,resources:'),
    provider+'engine.init({resources:external});',provider.replace('engine.init', 'if(enabled)engine.init')]) {
    assert.deepEqual(classify([{filePath:'view.tsx',content:page},
      {filePath:'provider.ts',content:config}]).files[0].excludedHtmlLines, []);
  }
  for(const external of ["const runtime=require('i18next');runtime.addResourceBundle(x,y,data);",
    "import {I18nextProvider as Local} from 'react-i18next';",
    "import * as runtime from 'i18next';runtime.addResourceBundle(x,y,data);"]) {
    assert.deepEqual(classify([{filePath:'view.tsx',content:page},{filePath:'provider.ts',content:provider},
      {filePath:'extension.ts',content:external}]).files[0].excludedHtmlLines, []);
  }
  assert.deepEqual(classify([{filePath:'view.tsx',content:page},
    {filePath:'provider.ts',content:provider}],false).files[0].excludedHtmlLines, []);
  assert.deepEqual(classify([{filePath:'view.tsx',content:view('"<b>fixed</b>"')}],false).files[0].excludedHtmlLines, [1]);
});
