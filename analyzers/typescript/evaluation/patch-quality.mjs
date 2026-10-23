import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {analyze} from '../analyzer.mjs';
import {responsePatch} from '../response-patch.mjs';
import {patchQualityCases} from './patch-quality-cases.mjs';

const filePath = 'supabase/functions/quality/index.ts';
const hash = text => createHash('sha256').update(text).digest('hex');
const run = source => analyze({files:[{filePath, content:source}]});
const exposures = result => result.findings.filter(f => f.ruleId === 'TS_SENSITIVE_DATA_EXPOSURE' && f.sink.kind === 'HTTP_RESPONSE');

export function prepareQualityCase(id) {
  const fixture = patchQualityCases.find(c => c.id === id);
  if (!fixture) throw new Error('UNKNOWN_SYNTHETIC_CASE');
  const analysis = run(fixture.source), findings = exposures(analysis);
  if (!findings.length) return {fixture, analysis,
    status:analysis.exposureUses.some(u => ['FLOW_UNRESOLVED', 'SENSITIVITY_UNVERIFIED'].includes(u.status)) ? 'MANUAL_REVIEW' : 'NO_TARGET'};
  const sink = findings[0].sink;
  const sources = [...new Map(findings.filter(f => f.sink.line === sink.line && f.sink.column === sink.column)
    .flatMap(f => f.flow.filter(s => ['SERVER_SECRET_ENVIRONMENT_VALUE', 'REQUEST_SELECTED_ENVIRONMENT_VALUE'].includes(s.kind)))
    .map(s => [JSON.stringify(s), s])).values()];
  const input = {source:fixture.source, sink, sources};
  try {
    const plan = responsePatch(input);
    return {fixture, analysis, input, plan, status:'PATCH', fileId:hash(id), revision:1, currentHash:hash(fixture.source)};
  } catch { return {fixture, analysis, status:'MANUAL_REVIEW'}; }
}

// Evaluation-only baseline. Never connected to a product endpoint or automatic application.
export function deterministicCandidate(prepared) {
  if (prepared.status !== 'PATCH') throw new Error('MANUAL_REVIEW_REQUIRED');
  const {before, suggestedReplacement:replacement} = prepared.plan;
  responsePatch({...prepared.input, replacement});
  return {fileId:prepared.fileId, revision:prepared.revision, currentHash:prepared.currentHash,
    expectedHash:hash(before), startLine:prepared.plan.line, replacement};
}

export function evaluateCandidate(prepared, candidate) {
  const base = {caseId:prepared.fixture.id, sourceHash:hash(prepared.fixture.source),
    structuralCandidatesBefore:exposures(prepared.analysis).length,
    unresolvedBefore:prepared.analysis.exposureUses.filter(u => ['FLOW_UNRESOLVED', 'SENSITIVITY_UNVERIFIED'].includes(u.status)).length,
    runtimeCompatibility:'UNVERIFIED', automatedResolved:false, applied:false};
  if (prepared.status !== 'PATCH') return {...base, status:prepared.status};
  if (!candidate || candidate.fileId !== prepared.fileId || candidate.startLine !== prepared.plan.line || candidate.expectedHash !== hash(prepared.plan.before))
    return {...base, status:'INVALID_IDENTITY'};
  if (candidate.revision !== prepared.revision || candidate.currentHash !== prepared.currentHash) return {...base, status:'STALE'};
  try { responsePatch({...prepared.input, replacement:candidate.replacement}); }
  catch { return {...base, status:'SERVER_REJECTED', normalCodePreserved:false}; }
  const {source} = prepared.fixture, {offset, before} = prepared.plan;
  const updated = source.slice(0, offset) + candidate.replacement + source.slice(offset + before.length);
  const after = run(updated);
  const priorRules = new Set(prepared.analysis.findings.map(f => f.ruleId));
  const newRuleCandidates = after.findings.filter(f => !priorRules.has(f.ruleId)).length;
  // Rule-family count is observational only, not the product Before/After NEW contract.
  const beforeCoverage = prepared.analysis.files[0], afterCoverage = after.files[0];
  const coverageReduced = afterCoverage.parseStatus !== beforeCoverage.parseStatus
    || afterCoverage.flowStatus !== beforeCoverage.flowStatus
    || afterCoverage.entrypoints < beforeCoverage.entrypoints || afterCoverage.functionsAnalyzed < beforeCoverage.functionsAnalyzed
    || afterCoverage.limitations.some(l => !beforeCoverage.limitations.includes(l));
  return {...base, status:'VALID_PROPOSAL', normalCodePreserved:true, responseFieldsRemoved:prepared.plan.removed.length,
    structuralCandidatesBefore:exposures(prepared.analysis).length, structuralCandidatesAfter:exposures(after).length,
    newRuleCandidates, coverageReduced, updatedHash:hash(updated), apiContractApprovalRequired:true};
}

export function offlineQualityReport() {
  const prepared = prepareQualityCase('single-middle'), good = deterministicCandidate(prepared);
  const mutations = [
    ['UNNECESSARY_FIELD_DELETION', {replacement:'{}'}],
    ['NORMAL_VALUE_CHANGED', {replacement:'{ready: false, count: 7}'}],
    ['UNNECESSARY_FIELD_DELETION', {replacement:'{ready: true}'}],
    ['FIELD_ORDER_CHANGED', {replacement:'{count: 7, ready: true}'}],
    ['EXTRA_FIELD', {replacement:'{ready: true, count: 7, extra: null}'}],
    ['INJECTED_CODE', {replacement:'{ready: true, count: 7}); disableAuth(); ({'}],
    ['MALFORMED_REPLACEMENT', {replacement:'```json\n{ready: true, count: 7}\n```'}],
    ['IN_REGION_INSTRUCTION', {replacement:'{/* instruction */ready: true, count: 7}'}],
    ['OVERSIZED_REPLACEMENT', {replacement:'x'.repeat(4097)}],
    ['WRONG_FILE', {fileId:'other'}], ['WRONG_RANGE', {startLine:99}], ['WRONG_REGION_HASH', {expectedHash:'other'}],
    ['CHANGED_REVISION', {revision:2}], ['CHANGED_SOURCE_HASH', {currentHash:'other'}],
  ];
  return {schemaVersion:1, mode:'OFFLINE_SYNTHETIC', providerCalls:0, externalReview:false,
    adversarialResults:mutations.map(([expectedDefect, change]) => ({expectedDefect, ...evaluateCandidate(prepared, {...good, ...change})})),
    results:patchQualityCases.map(c => { const prepared = prepareQualityCase(c.id);
      return {...evaluateCandidate(prepared, prepared.status === 'PATCH' ? deterministicCandidate(prepared) : null), expected:c.expected,
        preparationMatchesExpectation:prepared.status === c.expected}; })};
}
// A reviewable plan, not a live-call command or spending enforcement mechanism.
export const proposedProviderTrial = Object.freeze({
  approval:'NOT_GRANTED', provider:'OPENAI', model:'gpt-5.4-mini', maxCalls:4, concurrency:1, retries:0,
  caseIds:['single-middle', 'two-exposures', 'selected-name', 'guard-and-envelope'],
  inputTokenReservation:32768, maxOutputTokens:2000, estimatedTotalUsd:0.134304,
  pricingChecked:'2026-10-23', inputUsdPerMillion:0.75, outputUsdPerMillion:4.50,
  prerequisites:['EXPLICIT_SYNTHETIC_ONLY_CONSENT', 'VERIFY_ACTUAL_INPUT_TOKENS_AND_SCHEMA_OVERHEAD',
    'FIX_MODEL_AND_CASE_HASHES', 'RESERVE_FULL_COST_ON_TIMEOUT', 'STOP_ON_FIRST_INVALID_OR_FAILED_RESPONSE'],
  inputScope:'TRUSTED_INSTRUCTIONS_STRICT_SCHEMA_AND_SYNTHETIC_RESPONSE_OBJECT_ONLY',
  logging:'CASE_HASH_STATUS_TOKEN_USAGE_LATENCY_ONLY_NO_RAW_REQUEST_OR_RESPONSE',
  runtimeCompatibility:'UNVERIFIED', liveRunnerImplemented:false,
});
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 2) throw new Error('OFFLINE_ONLY_NO_PROVIDER_ARGUMENTS');
  process.stdout.write(JSON.stringify(offlineQualityReport(), null, 2) + '\n');
}
