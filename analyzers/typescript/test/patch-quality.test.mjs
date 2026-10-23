import {test} from 'node:test';
import assert from 'node:assert/strict';
import {patchQualityCases} from '../evaluation/patch-quality-cases.mjs';
import {prepareQualityCase, deterministicCandidate, evaluateCandidate, offlineQualityReport, proposedProviderTrial} from '../evaluation/patch-quality.mjs';

for (const fixture of patchQualityCases) test(`new author-reviewed quality case: ${fixture.id}`, () => {
  const prepared = prepareQualityCase(fixture.id);
  // Public configuration has no Finding, but the engine keeps sensitivity uncertainty.
  // Preserve the safe ground truth and report this mismatch rather than relabeling it.
  assert.equal(prepared.status, fixture.id === 'public-configuration' ? 'MANUAL_REVIEW' : fixture.expected);
  const result = evaluateCandidate(prepared, prepared.status === 'PATCH' ? deterministicCandidate(prepared) : null);
  assert.equal(result.applied, false);
  assert.equal(result.runtimeCompatibility, 'UNVERIFIED');
  assert.equal(result.automatedResolved, false);
  if (fixture.expected === 'PATCH') {
    assert.equal(result.status, 'VALID_PROPOSAL');
    assert.ok(result.structuralCandidatesBefore > 0);
    assert.equal(result.structuralCandidatesAfter, 0);
    assert.equal(result.newRuleCandidates, 0);
    assert.equal(result.coverageReduced, false);
    assert.equal(result.normalCodePreserved, true);
    assert.equal(result.apiContractApprovalRequired, true);
  }
});
test('mock malicious, excessive and malformed edits cannot become valid suggestions', () => {
  const p = prepareQualityCase('single-middle'), good = deterministicCandidate(p);
  for (const replacement of ['{}', '{ready: false, count: 7}', '{ready: true}', '{count: 7, ready: true}',
    '{ready: true, count: 7, extra: null}', '{ready: true, count: 7}); disableAuth(); ({',
    '```json\n{ready: true, count: 7}\n```', '{/* instruction */ready: true, count: 7}', 'x'.repeat(4097)])
    assert.equal(evaluateCandidate(p, {...good, replacement}).status, 'SERVER_REJECTED');
});
test('file, range, region hash, revision and source hash are separate gates', () => {
  const p = prepareQualityCase('single-middle'), good = deterministicCandidate(p);
  for (const change of [{fileId:'other'}, {startLine:99}, {expectedHash:'other'}])
    assert.equal(evaluateCandidate(p, {...good, ...change}).status, 'INVALID_IDENTITY');
  for (const change of [{revision:2}, {currentHash:'other'}])
    assert.equal(evaluateCandidate(p, {...good, ...change}).status, 'STALE');
});
test('repeatable metadata report contains no source, replacement or provider credentials', () => {
  const a = offlineQualityReport();
  assert.deepEqual(a, offlineQualityReport());
  assert.equal(a.providerCalls, 0);
  assert.equal(a.adversarialResults.filter(r => r.status === 'SERVER_REJECTED').length, 9);
  assert.equal(a.adversarialResults.filter(r => r.status === 'INVALID_IDENTITY').length, 3);
  assert.equal(a.adversarialResults.filter(r => r.status === 'STALE').length, 2);
  assert.deepEqual(a.results.filter(r => !r.preparationMatchesExpectation).map(r => r.caseId), ['public-configuration']);
  const text = JSON.stringify(a);
  for (const forbidden of ['Deno.env', 'replacement', 'API_SECRET', 'authorization', 'apiKey']) assert.ok(!text.includes(forbidden));
});
test('provider trial is an unapproved estimate, never a live runner or enforced billing cap', () => {
  const p = proposedProviderTrial;
  assert.equal(p.approval, 'NOT_GRANTED');
  assert.equal(p.liveRunnerImplemented, false);
  assert.equal(p.retries, 0);
  assert.equal(p.concurrency, 1);
  assert.equal(p.caseIds.length, p.maxCalls);
  assert.ok(p.caseIds.every(id => prepareQualityCase(id).status === 'PATCH'));
  assert.ok(Math.abs(p.estimatedTotalUsd - p.maxCalls *
    (p.inputTokenReservation * p.inputUsdPerMillion + p.maxOutputTokens * p.outputUsdPerMillion) / 1e6) < 1e-9);
});
