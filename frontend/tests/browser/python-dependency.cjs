// All API responses are synthetic. This test never contacts OSV, GitHub or OpenAI.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const workspace = require('./workspace-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';
(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      const result = require('../result-fixture.cjs')(), errors = [], blocked = [];
      result.sca = require('../python-fixture.cjs')();
      result.scanMode = 'STANDARD'; result.semanticReview = null;
      result.vulnerabilities = []; result.vulnerabilityCount = 0;
      const none = { BLOCKING: 0, REVIEW_REQUIRED: 0, SHOULD_FIX: 0, INFORMATIONAL: 0 };
      result.riskAssessment.prioritySummary = { ...none, SHOULD_FIX: 1 };
      result.riskAssessment.prioritySummaryBySource = { CODE: none, DEPENDENCY: { ...none, SHOULD_FIX: 1 }, ANALYSIS: none };
      result.riskAssessment.codeFindings = []; result.riskAssessment.reviewRequirements = [];
      result.riskAssessment.prioritizedDeploymentAssessment = 'REVIEW_REQUIRED';
      const dep = result.sca.dependencyVulnerabilities[0];
      Object.assign(result.riskAssessment.dependencyFindings[0], {
        ecosystem: 'PYPI', packageName: dep.packageName, version: dep.installedVersion, advisoryId: dep.osvId,
        dependency: dep, sourceFiles: dep.sourceFiles,
      });
      result.coverage = { schemaVersion: 1, policyVersion: 'fixture', status: 'PARTIAL', discoveredFiles: 3, selectedFiles: 2,
        unsupportedFiles: 1, excludedFiles: 0, failedFiles: 0, inventoryComplete: true, omittedEntries: 0,
        entries: [], analyzers: [], inspectionScope: { schemaVersion: 1, assurance: 'NOT_ESTABLISHED', evidenceComplete: true,
          areas: [{ id: 'PYTHON_SOURCE', label: 'Python 코드', status: 'UNSUPPORTED', observedFiles: 1,
            examplePaths: ['server.py'], limitation: 'Python 인증·권한·데이터 흐름은 검사하지 않았습니다.' }], incompleteAnalyzers: [] } };
      page.on('pageerror', e => errors.push(e.message));
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-python-not-authentication');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Python fixture', email: 'python@example.invalid' }));
      });
      await page.route('**/*', route => {
        const target = new URL(route.request().url());
        if (!target.pathname.startsWith('/api/')) {
          if (target.origin === new URL(url).origin) return route.continue();
          blocked.push(target.origin); return route.abort();
        }
        const data = target.pathname === '/api/reviews/101' ? result : workspace(target.pathname, result);
        return route.fulfill({ status: data ? 200 : 404, contentType: 'application/json', body: JSON.stringify(data ?? { message: 'Unmocked request' }) });
      });
      await page.goto(`${url}/#/projects/7/findings`);
      const nav = page.getByRole('navigation', { name: '분석 결과 메뉴' });
      await nav.getByRole('button', { name: '결과 요약', exact: true }).click();
      assert.ok((await page.getByLabel('배포 판단의 검사 범위 한계').innerText()).includes('Python 코드'));
      await nav.getByRole('button', { name: '수정 권장', exact: true }).click();
      const card = page.locator('.dependency-finding').first();
      assert.ok((await card.innerText()).includes('정적 선언에서 확인한'));
      assert.ok((await card.innerText()).includes('실제 설치 여부는 미확인'));
      await card.getByText('Python 선언 근거와 수정 위치 확인', { exact: true }).click();
      assert.ok((await card.innerText()).includes('requirements-dev.txt:3'));
      assert.ok((await card.innerText()).includes('constraints.txt:2'));
      assert.ok((await card.innerText()).includes('설치 환경 조건은 평가하지 않았습니다'));
      await card.getByText('기술 정보 보기', { exact: true }).click();
      await card.getByText('OSV 버전 범위 근거', { exact: true }).click();
      assert.ok((await card.innerText()).includes('영향 시작: 3.0'));
      assert.ok((await card.innerText()).includes('수정: 3.0.2'));
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `overflow ${width}`);
      assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
      console.log(JSON.stringify({ width, pythonDeclarationContext: 'PASS', separateOsvRanges: 'PASS', unsupportedSource: 'PASS', externalRequests: 0 }));
      await page.close();
    }
  } finally { await browser.close(); }
})().catch(error => { console.error('Synthetic Python browser assertion failed:', error.message); process.exitCode = 1; });
