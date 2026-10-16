import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyze } from '../analyzer.mjs';
import { qualityCases } from './quality-cases.mjs';

test('fixed independent SQL-flow evaluation set', t => {
  const counts = { truePositive: 0, falsePositive: 0, falseNegative: 0, trueNegative: 0,
    expectedUnknown: 0, abstained: 0, riskAbstained: 0, incorrectCertainty: 0 };
  const mismatches = [];
  for (const [id, label, body, functions = ''] of qualityCases) {
    const r = analyze({ files: [{ filePath: 'functions/items.ts', content:
      `${functions} export async function onRequest({request,env}) {
        const db=env.DB; let q=new URL(request.url).searchParams.get('q'); const body=await request.text(); ${body} }` }] });
    const high = r.findings.some(f => f.confidence === 'HIGH');
    const uncertain = r.sqlUses.length === 0 || r.sqlUses.some(s => s.limitations.includes('QUERY_HAS_UNRESOLVED_VALUES'));
    if (label === 'UNKNOWN') {
      counts.expectedUnknown++;
      if (!high && uncertain) counts.abstained++; else { counts.incorrectCertainty++; mismatches.push(id); }
    } else if (label === 'RISK') {
      if (high) counts.truePositive++;
      else {
        if (uncertain) counts.riskAbstained++; else counts.falseNegative++;
        mismatches.push(id);
      }
    } else if (high) { counts.falsePositive++; mismatches.push(id); }
    else if (!uncertain) counts.trueNegative++;
    else { counts.abstained++; mismatches.push(id); }
  }
  t.diagnostic(JSON.stringify(counts));
  assert.deepEqual(mismatches, []);
});
