// Synthetic fixtures and intercepted OSV supplement responses only. No external requests.
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fixture = require('../dependency-guidance-fixture.cjs');
const workspace = require('./workspace-fixture.cjs');
const url = process.env.FRONTEND_URL || 'http://localhost:5173';

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    for (const sourceType of ['ZIP', 'GITHUB']) for (const width of [1440, 390, 320]) {
      const page = await browser.newPage({ viewport: { width, height: 1000 } });
      const result = fixture(sourceType), before = JSON.stringify(result), calls = [], errors = [];
      let outcome = 'COMPLETE';
      page.on('pageerror', e => errors.push(e.message));
      await page.addInitScript(() => {
        localStorage.setItem('securedeploy.accessToken', 'synthetic-guidance-not-authentication');
        localStorage.setItem('securedeploy.authUser', JSON.stringify({ id: 1, name: 'Guidance fixture', email: 'guidance@example.invalid' }));
      });
      await page.route('**/*', async route => {
        const req = route.request(), parsed = new URL(req.url()), path = parsed.pathname;
        if (!path.startsWith('/api/')) return parsed.origin === new URL(url).origin ? route.continue() : route.abort();
        const json = (data, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(data) });
        if (path.endsWith('/supplemental-lookup')) {
          const input = req.postDataJSON(); calls.push(input);
          await new Promise(resolve => setTimeout(resolve, 120));
          if (outcome === 'INVALID') return json({ message: '정확한 버전을 입력해 주세요. 버전 범위는 사용할 수 없습니다.' }, 400);
          return json({ provenance: 'USER_PROVIDED', status: outcome, checkedAt: result.createdAt,
            ecosystem: 'MAVEN', packageName: input.packageName, version: input.version,
            findings: outcome === 'COMPLETE' ? result.sca.dependencyVulnerabilities.map(f => ({ ...f,
              ecosystem: 'MAVEN', packageName: input.packageName, installedVersion: input.version })) : [] });
        }
        if (path === '/api/reviews/101') return json(result);
        if (path === '/api/reviews/upload-policy') return json(require('../upload-policy-fixture.cjs'));
        const data = workspace(path, result);
        return data ? json(data) : json({ message: 'Unexpected route' }, 404);
      });
      const fits = async () => assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `overflow ${sourceType}/${width}`);
      await page.goto(`${url}/#/projects/7/findings`);
      const nav = page.getByRole('navigation', { name: '분석 결과 메뉴' });
      await nav.getByRole('button', { name: '배포 전 직접 확인할 부분', exact: true }).click();
      const cards = page.locator('#result-content > .vulnerability-list .incomplete-dependency');
      await cards.first().waitFor();
      assert.equal(await cards.count(), 2);
      const known = cards.nth(0), unknown = cards.nth(1);
      await unknown.getByText('어디서 확인하는지 알려주세요', { exact: true }).click();
      await unknown.locator('summary').filter({ hasText: '추가 정보로 확인하기' }).click();
      assert.ok((await unknown.innerText()).includes('gradle/libs.versions.toml'));
      assert.ok((await unknown.innerText()).includes('flutter_app/android/app/build.gradle.kts'));
      await unknown.getByLabel('라이브러리 이름', { exact: true }).fill('<script>bad</script>');
      await unknown.getByLabel('현재 사용 버전', { exact: true }).fill('1.0.0');
      await unknown.getByRole('button', { name: '이 정보로 확인', exact: true }).click();
      await unknown.getByRole('alert').waitFor();
      assert.equal(calls.length, 0);
      await unknown.getByLabel('라이브러리 이름', { exact: true }).fill('org.example:library');
      await unknown.getByRole('button', { name: '이 정보로 확인', exact: true }).click();
      await unknown.getByRole('button', { name: '확인 중...' }).waitFor();
      assert.equal(await unknown.getByLabel('현재 사용 버전', { exact: true }).isDisabled(), true);
      await unknown.getByText('사용자가 직접 입력한 정보로 확인한 결과입니다.', { exact: true }).waitFor();
      assert.ok((await unknown.innerText()).includes('기존 분석 결과·점수·배포 판단은 변경되지 않습니다'));
      await fits();
      await page.screenshot({ path: `/private/tmp/securedeploy-dependency-guidance-${sourceType}-${width}.png`, fullPage: true });
      await unknown.screenshot({ path: `/private/tmp/securedeploy-dependency-card-${sourceType}-${width}.png` });
      outcome = 'UNAVAILABLE';
      await unknown.getByLabel('현재 사용 버전', { exact: true }).fill('1.0.1');
      assert.equal(await unknown.locator('.supplemental-result').count(), 0);
      await unknown.getByRole('button', { name: '이 정보로 확인', exact: true }).click();
      await unknown.getByText(/알려진 보안 문제를 끝까지 확인하지 못했습니다/).waitFor();
      assert.ok(!(await unknown.innerText()).includes('보안 문제가 반환되지 않았습니다'));
      outcome = 'INVALID';
      await known.getByText('버전을 알고 있어요', { exact: true }).click();
      assert.equal(await known.getByLabel('라이브러리 이름', { exact: true }).getAttribute('readonly'), '');
      await known.getByLabel('현재 사용 버전', { exact: true }).fill('1.0.0');
      await known.getByRole('button', { name: '이 정보로 확인', exact: true }).click();
      await known.getByRole('alert').waitFor();
      assert.ok((await known.getByRole('alert').innerText()).includes('정확한 버전'));
      await fits();
      await nav.getByRole('button', { name: '해결 방법', exact: true }).click();
      await page.getByLabel('해결할 문제 선택').selectOption(result.riskAssessment.reviewRequirements[1].findingId);
      await page.locator('.guidance-section').getByText('어디서 확인하는지 알려주세요', { exact: true }).click();
      assert.doesNotMatch(await page.locator('#result-content').innerText(), /unresolved-package|\bunknown\b|\bnull\b|N\/A|99\.99\.99|invented-package/);
      await fits();
      await nav.getByRole('button', { name: '결과 요약', exact: true }).click();
      await page.getByRole('heading', { name: '배포 전 수정 필요', exact: true }).waitFor();
      assert.equal(JSON.stringify(result), before);
      assert.equal(calls.length, 3);
      assert.deepEqual(errors, []);
      await page.close();
    }
    console.log(JSON.stringify({ result: 'passed', widths: [1440, 390, 320], sources: ['ZIP', 'GITHUB'],
      form: true, invalid: true, unavailable: true, sourceSnapshotUnchanged: true, externalCalls: 0 }));
  } finally { await browser.close(); }
})().catch(e => { console.error(e.message); process.exitCode = 1; });
