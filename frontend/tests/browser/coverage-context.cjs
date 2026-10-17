// Synthetic responses only; never calls GitHub, OSV, or OpenAI.
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
      result.riskAssessment.prioritizedDeploymentAssessment = 'READY_WITH_WARNINGS';
      result.riskAssessment.assessmentReason = '지원 범위에서 수정 권장 항목이 있습니다.';
      result.riskAssessment.assessmentCoverage = { overall: 'COMPLETE', ruleEngine: 'COMPLETE', sca: 'COMPLETE', ai: 'NOT_INCLUDED' };
      const none = { BLOCKING: 0, REVIEW_REQUIRED: 0, SHOULD_FIX: 0, INFORMATIONAL: 0 };
      result.riskAssessment.prioritySummary = { ...none, SHOULD_FIX: 1 };
      result.riskAssessment.prioritySummaryBySource = { CODE: none, DEPENDENCY: { ...none, SHOULD_FIX: 1 }, ANALYSIS: none };
      result.riskAssessment.codeFindings = [];
      result.riskAssessment.reviewRequirements = [];
      result.vulnerabilities = []; result.vulnerabilityCount = 0;
      result.scanMode = 'STANDARD'; result.semanticReview = null;
      result.sca.status = 'COMPLETE'; result.sca.warnings = []; result.sca.components = [];
      result.sca.summary = { dependenciesDiscovered: 1, dependenciesAnalyzed: 1, unresolvedDependencies: 0,
        vulnerableDependencies: 1, dependencyVulnerabilities: 1, severityCounts: { HIGH: 1 } };
      result.coverage = { schemaVersion: 1, policyVersion: 'coverage-ledger-v1', status: 'PARTIAL', discoveredFiles: 4, selectedFiles: 2,
        unsupportedFiles: 2, excludedFiles: 0, failedFiles: 0, inventoryComplete: true, omittedEntries: 0,
        entries: [{ filePath: 'functions/api/example.ts', kind: 'FILE', fileType: 'TYPESCRIPT', status: 'SELECTED', reason: 'PATTERN_ANALYSIS_INPUT' },
          { filePath: 'scripts/import.py', kind: 'FILE', fileType: null, status: 'UNSUPPORTED', reason: 'NO_SUPPORTED_ANALYZER' }],
        analyzers: [{ analyzer: 'RULE_ENGINE', status: 'COMPLETE', scope: '패턴 검사. 전체 의미 분석 아님', fileStatuses: { SELECTED: 2 } }],
        inspectionScope: { schemaVersion: 1, assurance: 'NOT_ESTABLISHED', evidenceComplete: true,
          areas: [{ id: 'PYTHON_SOURCE', label: 'Python 코드', status: 'UNSUPPORTED', observedFiles: 2,
            examplePaths: ['scripts/import.py'], limitation: 'Python 코드 흐름은 미검증입니다.' }], incompleteAnalyzers: [] } };
      result.sca.components.push({ ecosystem: 'NPM', packageName: 'fixture-library', version: '1.0.0', direct: false,
        sourceFile: 'package-lock.json', line: 20, scope: 'devDependencies', versionResolution: 'EXACT',
        context: { schemaVersion: 1, environment: 'DEVELOPMENT', runtimeReachability: 'NOT_ANALYZED', installedPath: 'node_modules/fixture-library',
          lockLine: 20, lockFlags: ['dev'], pathsComplete: true, limitations: [], paths: [{ declarationFile: 'package.json', declarationLine: 8,
            declarationSection: 'devDependencies', declaredPackage: 'fixture-tool', declaredVersion: '^1.0.0', declarationConfirmed: true,
            optional: false, peer: false, chain: [{ packageName: 'fixture-tool', version: '1.0.0', installedPath: 'node_modules/fixture-tool' },
              { packageName: 'fixture-library', version: '1.0.0', installedPath: 'node_modules/fixture-library' }] }] } });
      page.on('pageerror', e => errors.push(e.message));
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-coverage-not-authentication');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Coverage fixture', email: 'coverage@example.invalid' }));
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
      const boundary = page.getByLabel('배포 판단의 검사 범위 한계');
      assert.ok((await page.getByLabel('지금 배포해도 될까요?').innerText()).includes('배포 가능하지만 수정 권장'));
      assert.ok((await boundary.innerText()).includes('Python 코드'));
      assert.ok((await boundary.innerText()).includes('전체 프로젝트 검사 완료를 뜻하지 않습니다'));
      const coverage = page.getByRole('region', { name: '검사 범위' });
      await coverage.getByText('분석기와 파일별 범위 보기', { exact: true }).click();
      await coverage.getByLabel('파일 상태').selectOption('UNSUPPORTED');
      assert.ok((await coverage.innerText()).includes('scripts/import.py'));
      assert.ok(!(await coverage.innerText()).includes('functions/api/example.ts'));
      await page.getByText('상위 패키지별 묶음 확인', { exact: true }).click();
      assert.ok((await page.getByRole('region', { name: '라이브러리 수정 작업 후보' }).innerText()).includes('fixture-tool'));
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `summary overflow ${width}`);
      await nav.getByRole('button', { name: '수정 권장', exact: true }).click();
      await page.getByText('의존성 경로와 수정 위치 확인', { exact: true }).first().click();
      assert.ok((await page.locator('#result-content').innerText()).includes('package.json:8'));
      assert.ok((await page.locator('#result-content').innerText()).includes('개발·테스트 선언 경로'));
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `context overflow ${width}`);
      assert.deepEqual(errors, []); assert.deepEqual(blocked, []);
      console.log(JSON.stringify({ width, coverageFiltering: 'PASS', unchangedDeploymentWithUnsupportedPython: 'PASS', dependencyContext: 'PASS', overflow: false, externalRequests: 0 }));
      await page.close();
    }
  } finally { await browser.close(); }
})().catch(() => { console.error('Coverage browser assertion failed'); process.exitCode = 1; });
