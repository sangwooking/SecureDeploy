const {test}=require('node:test');
const assert=require('node:assert/strict');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const load=require('./load-component.cjs');
const {DependencyUpdatePlans}=load('DependencyUpdatePlans');
test('SCA review plan never claims a generated or applicable AI patch before verification',()=>{
 const html=renderToStaticMarkup(React.createElement(DependencyUpdatePlans,{reviewId:1}));
 assert.ok(html.includes('업데이트 계획 지원 확인 중'));assert.ok(!html.includes('AI 전송 범위 확인'));
 assert.ok(html.includes('AI 코드 생성이나 적용 완료를 의미하지 않습니다'));
 assert.ok(!html.includes('AI 생성 완료'));
 const old=renderToStaticMarkup(React.createElement(DependencyUpdatePlans,{}));assert.ok(old.includes('저장된 검사'));
});
test('semantic scope explicitly limits unsupported coverage without changing existing candidate status',()=>{
 const {SemanticReviewSection}=load('SemanticReviewSection');
 const snapshot={semanticReviewStatus:'NOT_REQUESTED',scanMode:'STANDARD',candidates:[],existingFindingEvidence:[],slices:[],notices:[],generatedAt:'2026-10-30T00:00:00Z'};
 const before=JSON.stringify(snapshot);const html=renderToStaticMarkup(React.createElement(SemanticReviewSection,{snapshot}));
 assert.ok(html.includes('PARTIAL·UNKNOWN'));assert.ok(html.includes('Java 중심'));assert.ok(html.includes('기존 위험 기반 배포 판단과 취약점 수에는 합산하지 않습니다'));
 assert.equal(JSON.stringify(snapshot),before);
});

test('re-scan retains a separate review requirement without replacing policy risk',()=>{
 const fs=require('node:fs');const source=fs.readFileSync('src/components/WorkspaceScanPanel.tsx','utf8');
 assert.ok(source.includes('수정 검증: REVIEW_REQUIRED'));assert.ok(source.includes('정상 기능·API 호환성: NOT_VERIFIED'));
 assert.ok(!source.includes('prioritizedDeploymentAssessment ='));
});
