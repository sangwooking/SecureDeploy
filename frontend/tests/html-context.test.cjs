const {test}=require('node:test');
const assert=require('node:assert/strict');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {CodeFindingCard}=require('./load-component.cjs')('CodeFindingCard');
test('HTML findings explain sink-only confidence and escape evidence without inventing a source',()=>{
  const html=renderToStaticMarkup(React.createElement(CodeFindingCard,{
    vulnerability:{vulnerabilityId:99,ruleId:'REACT_DANGEROUS_HTML',category:'CLIENT_XSS',severity:'HIGH',
      filePath:'src/Notice.tsx',line:21,message:'HTML sink',recommendation:'Check source first',
      analysisNote:'HTML_CONTEXT=UNRESOLVED_HTML; SINK_LINE=21; VALUE_LINE=22 · <img src=x onerror=alert(1)>',
      confidence:'HIGH',falsePositiveRisk:'LOW'},
    finding:{findingId:'code:99',priority:'REVIEW_REQUIRED'},
    statusActions:{updatingId:null,comments:{},onComment(){},onStatus(){}}
  }));
  for(const phrase of ['삽입 구문','실제 공격','필요한 경우에만','HTML_CONTEXT=UNRESOLVED_HTML','src/Notice.tsx','&lt;img'])assert.ok(html.includes(phrase),phrase);
  assert.ok(!html.includes('<img'));
});
