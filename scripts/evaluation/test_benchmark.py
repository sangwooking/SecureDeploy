import copy
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import benchmark as b


def case(label="DANGEROUS", **changes):
    c=dict(caseId="case-a",sourceDataset="synthetic-accounting-only",repositoryUrl="https://github.com/example/fixture",
           repositoryCommitSha="a"*40,repositoryGroup="fixture",forkGroup="fixture",vulnerabilityFamily="sql-a",
           groundTruthLabel=label,groundTruthConfidence="TEST",reviewed=True,license="CC0-1.0",labelEvidence=["synthetic test"],
           evaluationSplit="REGRESSION",language="JAVA",framework="Servlet",cwe="CWE-89",area="INPUT_INJECTION",
           targetSites=[dict(filePath="Endpoint.java",startLine=10,endLine=12)],sourceSites=[dict(filePath="Endpoint.java",startLine=3,endLine=4)],
           files=[dict(path="Endpoint.java",sha256="b"*64,url="https://raw.githubusercontent.com/example/fixture/"+"a"*40+"/Endpoint.java")],
           patternRules=["DANGEROUS_SQL"],flowRules=["JAVA_SQL_INPUT_FLOW"],requiredConditions="Synthetic only",
           sourceToSinkEvidence="request line 3 -> query line 11",mitigationEvidence="bind values")
    c.update(changes)
    return c


def manifest(*cases):
    return dict(schemaVersion=1,engineBaselineCommit="c"*40,cases=list(cases or [case()]))


def run():
    return dict(raw=[],filtered=[],reconciled=[],reviewCandidates=[],
                coverage=dict(selectedFiles=1,entries=[dict(filePath="Endpoint.java",status="SELECTED")]),
                java=dict(analysis=dict(status="PARTIAL",files=[dict(filePath="Endpoint.java",parseStatus="PARSED",entrypoints=1)],uses=[])),
                python=dict(files=[],findings=[]),typescript=dict(files=[],findings=[]),
                elapsedMs=12,parentHeapUsedBytes=40,risk=dict(prioritySummary=dict(BLOCKING=0),prioritizedDeploymentAssessment="REVIEW_REQUIRED",assessedAt="one"))


def result(row=None):
    row=row or run()
    return dict(schemaVersion=1,engineCommit="c"*40,manifestSha256="d"*64,runnerVersion='runner',split="REGRESSION",results=[dict(caseId="case-a",runs=[row,copy.deepcopy(row)])])


class AccountingTest(unittest.TestCase):
    def test_labels_must_have_review_evidence(self):
        self.assertEqual(b.validate(manifest())["cases"],1)
        with self.assertRaises(ValueError):b.validate(manifest(case(reviewed=False)))

    def test_same_repository_cannot_cross_splits(self):
        with self.assertRaises(ValueError):b.validate(manifest(case(),case(caseId="case-b",evaluationSplit="HOLDOUT")))

    def test_forks_and_families_cannot_cross_splits(self):
        for key in ("forkGroup","vulnerabilityFamily","cloneGroup"):
            a=case(**{key:"common"})
            c=case(caseId="case-b",repositoryGroup="different",forkGroup="different",vulnerabilityFamily="different",evaluationSplit="HOLDOUT",files=[dict(path="Endpoint.java",sha256="e"*64)],**({key:"common"}if key not in {"forkGroup","vulnerabilityFamily"}else{}))
            c[key]="common"
            with self.assertRaises(ValueError):b.validate(manifest(a,c))

    def test_exact_duplicate_source_never_crosses_splits(self):
        c=case(caseId="case-b",repositoryGroup="other",forkGroup="other",vulnerabilityFamily="other",evaluationSplit="VALIDATION",repositoryUrl='https://github.com/example/other')
        c['files'][0]['url']=c['files'][0]['url'].replace('/fixture/','/other/')
        with self.assertRaisesRegex(ValueError,'DUPLICATE_CONTENT_SPLIT_LEAKAGE'):b.validate(manifest(case(),c))

    def test_vulnerable_fixed_pairs_cannot_be_incomplete_or_split(self):
        a=case(pairId="pair",vulnerableCommitSha="a"*40,fixedCommitSha="b"*40)
        with self.assertRaises(ValueError):b.validate(manifest(a))
        safe=case("SAFE",caseId="case-b",pairId="pair",repositoryCommitSha='b'*40,vulnerableCommitSha="a"*40,fixedCommitSha="b"*40)
        safe['files'][0]['url']=safe['files'][0]['url'].replace('/'+'a'*40+'/', '/'+'b'*40+'/')
        self.assertEqual(b.validate(manifest(a,safe))["pairs"],1)
        safe['fixedCommitSha']='e'*40
        with self.assertRaisesRegex(ValueError,'PAIR_PROVENANCE_MISMATCH'):b.validate(manifest(a,safe))

    def test_path_traversal_and_invalid_ranges_rejected(self):
        for name in ("../x","/tmp/x","a/../../b","a\\b","x:y"):
            with self.assertRaises(ValueError):b.relative(name)
        with self.assertRaises(ValueError):b.validate(manifest(case(targetSites=[dict(filePath="other.java",startLine=0,endLine=2)])))

    def test_http_private_hosts_and_credentials_rejected(self):
        for url in ("http://github.com/x","https://127.0.0.1/x","https://user:secret@github.com/x","https://github.com/x?token=synthetic","https://github.com:8443/x"):
            with self.assertRaises(ValueError):b.check_url(url)

    def test_unrelated_rule_or_location_is_not_tp(self):
        c=case()
        self.assertEqual(b.matching(c,[dict(ruleId="OTHER",filePath="Endpoint.java",line=11)]),[])
        self.assertEqual(b.matching(c,[dict(ruleId="DANGEROUS_SQL",filePath="Endpoint.java",line=30)]),[])
        self.assertEqual(b.matching(c,[dict(ruleId="DANGEROUS_SQL",filePath="Other.java",line=11)]),[])

    def test_structural_match_requires_source_and_sink(self):
        found=dict(ruleId="JAVA_SQL_INPUT_FLOW",location=dict(filePath="Endpoint.java",line=11),trace=[dict(filePath="Endpoint.java",line=30,kind='REQUEST_INPUT')])
        self.assertEqual(b.matching(case(),[found]),[])
        found['trace'][0]['line']=3
        self.assertEqual(len(b.matching(case(),[found])),1)
        found['trace'][0]['kind']='SQL_CONSTRUCTION'
        self.assertEqual(b.matching(case(),[found]),[])

    def test_warning_and_path_evidence_are_distinct(self):
        row=run();row['raw']=[dict(ruleId="DANGEROUS_SQL",filePath="Endpoint.java",line=11)]
        self.assertEqual(b.outcome(case(),row,'rule')['evidenceKind'],'PATTERN_OR_MIXED')

    def test_unknown_and_unverified_truth_are_not_tn(self):
        for label in ('UNKNOWN','UNVERIFIED'):
            self.assertEqual(b.outcome(case(label),run(),'finalUser')['verdict'],label)

    def test_unsupported_and_missing_collection_are_not_tn(self):
        row=run();row['java']['analysis']['files'][0]['entrypoints']=0
        self.assertEqual(b.outcome(case('SAFE'),row,'finalUser')['verdict'],'NOT_SUPPORTED')
        row['coverage']['entries']=[]
        self.assertEqual(b.outcome(case('SAFE'),row,'finalUser')['verdict'],'NOT_INSPECTED')

    def test_parser_and_resource_failures_are_not_safe(self):
        for status,expected in [('PARSE_FAILED','PARSE_FAILED'),('LIMIT_EXCEEDED','RESOURCE_LIMIT')]:
            row=run();row['java']['analysis']['files'][0]['parseStatus']=status
            self.assertEqual(b.outcome(case('SAFE'),row,'ast')['verdict'],expected)

    def test_empty_partial_flow_is_not_tn(self):
        self.assertEqual(b.outcome(case('SAFE'),run(),'ast')['verdict'],'NOT_INSPECTED')

    def test_positive_static_binding_evidence_can_be_tn(self):
        row=run();row['java']['analysis']['uses']=[dict(kind='PARAMETERIZED_QUERY',location=dict(filePath='Endpoint.java',line=11))]
        self.assertEqual(b.outcome(case('SAFE'),row,'ast')['verdict'],'TN')

    def test_metrics_do_not_hide_uninspected_cases(self):
        m=b.metrics([dict(verdict=v)for v in ('TP','FP','FN','TN','UNKNOWN','NOT_SUPPORTED','NOT_INSPECTED')])
        self.assertEqual(m['scoredCoverage'],4/7);self.assertEqual(m['precision'],0.5)
        self.assertIsNone(b.metrics([dict(verdict='UNKNOWN')])['precision'])

    def test_repeated_times_are_ignored_but_finding_changes_are_not(self):
        raw=result();raw['results'][0]['runs'][1]['elapsedMs']=900
        self.assertTrue(b.score(manifest(),raw)['results'][0]['repeatConsistent'])
        raw['results'][0]['runs'][1]['filtered']=[dict(ruleId='DANGEROUS_SQL',filePath='Endpoint.java',line=11)]
        self.assertFalse(b.score(manifest(),raw)['results'][0]['repeatConsistent'])

    def test_distinct_sites_are_not_called_duplicates(self):
        a=dict(ruleId='DANGEROUS_SQL',filePath='Endpoint.java',line=10)
        self.assertEqual(b.exact_duplicates([a,dict(a,line=11)]),0)
        self.assertEqual(b.exact_duplicates([a,a]),1)

    def test_results_require_entire_selected_split(self):
        with self.assertRaises(ValueError):b.score(manifest(case(),case(caseId='case-b')),result())
        raw=result();raw['results'].append(raw['results'][0])
        with self.assertRaises(ValueError):b.score(manifest(),raw)

    def test_comparison_rejects_changed_dataset_or_split(self):
        a=b.score(manifest(),result());c=copy.deepcopy(a);c['manifestSha256']='x'
        with self.assertRaises(ValueError):b.compare(a,c)
        c=copy.deepcopy(a);c['split']='HOLDOUT'
        with self.assertRaises(ValueError):b.compare(a,c)

    def test_comparison_flags_regressions_and_never_auto_approves(self):
        a=b.score(manifest(),result());c=copy.deepcopy(a)
        a['results'][0]['layers']['finalUser']['verdict']='TP';c['results'][0]['layers']['finalUser']['verdict']='FN'
        self.assertTrue(b.compare(a,c)['regressions']);self.assertFalse(b.compare(a,c)['automaticSuccess'])

    def test_failure_packs_are_reproducible_without_source_or_evidence_values(self):
        m=manifest();raw=result();raw['results'][0]['runs'][0]['raw']=[dict(ruleId='DANGEROUS_SQL',filePath='Endpoint.java',line=11,evidence='synthetic-private-value')]
        scored=b.score(m,raw)
        with tempfile.TemporaryDirectory()as tmp:
            output=Path(tmp)/'packs';r=b.packs(m,raw,scored,output)
            self.assertEqual(r['packCount'],1)
            text=(output/'case-a.json').read_text()
            self.assertNotIn('synthetic-private-value',text);self.assertIn('automaticCauseHypothesis',text)
            self.assertIn('benchmarkCase=case-a',text)

    def test_manual_causes_require_matching_version_and_evidence(self):
        m=manifest();raw=result();s=b.score(m,raw)
        with tempfile.TemporaryDirectory()as tmp:
            with self.assertRaises(ValueError):b.packs(m,raw,s,Path(tmp)/'packs',dict(manifestSha256='wrong',engineCommit='c'*40,cases={}))

    def test_first_output_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory()as tmp:
            p=Path(tmp)/'result.json';b.write(p,{'first':True})
            with self.assertRaises(FileExistsError):b.write(p,{'first':False})
            self.assertTrue(b.read(p)['first'])

    def test_repository_is_never_a_source_cache_or_output_destination(self):
        with self.assertRaises(ValueError):b.outside(b.REPO/'download')

    def test_matching_structural_warning_already_in_legacy_is_not_a_candidate_miss(self):
        row=run();row['filtered']=[dict(ruleId='DANGEROUS_SQL',filePath='Endpoint.java',line=11)]
        row['java']['analysis']['uses']=[dict(kind='INPUT_IN_QUERY',location=dict(filePath='Endpoint.java',line=11),trace=[dict(filePath='Endpoint.java',line=3,kind='REQUEST_INPUT')])]
        self.assertEqual(b.outcome(case(),row,'reviewCandidate')['verdict'],'MERGED_WITH_LEGACY')

    def test_different_accounting_versions_are_not_an_engine_improvement(self):
        a=b.score(manifest(),result());c=copy.deepcopy(a);c['accountingVersion']='changed'
        with self.assertRaises(ValueError):b.compare(a,c)

    def test_runtime_failure_is_not_unsupported_or_safe(self):
        row=run();row['java']['analysis']['status']='TIMEOUT'
        self.assertEqual(b.outcome(case('SAFE'),row,'ast')['verdict'],'ANALYSIS_FAILED')

    def test_selected_case_replay_cannot_silently_omit_other_cases(self):
        m=manifest(case(),case(caseId='case-b'));raw=result();raw['selectionCaseId']='case-a'
        self.assertEqual(len(b.score(m,raw)['results']),1)

    def test_packs_reject_mixed_runs(self):
        raw=result();s=b.score(manifest(),raw);s['runnerVersion']='different'
        with tempfile.TemporaryDirectory()as tmp:
            with self.assertRaises(ValueError):b.packs(manifest(),raw,s,Path(tmp)/'packs')

    def test_source_urls_must_match_claimed_sha_and_repository(self):
        for changed in ('https://raw.githubusercontent.com/example/fixture/main/Endpoint.java',
                        'https://raw.githubusercontent.com/example/other/'+'a'*40+'/Endpoint.java'):
            c=case();c['files'][0]['url']=changed
            with self.assertRaisesRegex(ValueError,'SOURCE_URL_MUST_MATCH_PINNED'):b.validate(manifest(c))

    def test_unknown_or_cve_alias_group_leakage_is_rejected(self):
        a=case(cve='CVE-SYNTHETIC-ONLY')
        c=case(caseId='case-b',repositoryUrl='https://github.com/example/other',repositoryGroup='other',forkGroup='other',vulnerabilityFamily='other',evaluationSplit='HOLDOUT',cve='CVE-SYNTHETIC-ONLY')
        with self.assertRaisesRegex(ValueError,'SPLIT_LEAKAGE_cve'):b.validate(manifest(a,c))

    def test_sensitive_metadata_is_rejected_before_writing(self):
        with tempfile.TemporaryDirectory()as tmp:
            p=Path(tmp)/'result.json'
            with self.assertRaisesRegex(ValueError,'SENSITIVE_METADATA_PATTERN'):b.write(p,dict(value='ghp_'+'syntheticOnly'*4))
            self.assertFalse(p.exists())

    def test_combine_refuses_incomplete_or_mixed_version_splits(self):
        s=b.score(manifest(),result())
        with self.assertRaisesRegex(ValueError,'ALL_THREE_SPLITS'):b.combine(manifest(),[s])
        raws=[dict(result(),split=split)for split in ('REGRESSION','VALIDATION','HOLDOUT')]
        raws[0]['runnerVersion']='different'
        with self.assertRaisesRegex(ValueError,'RAW_COMBINATION_VERSION'):b.merge_raw(raws)

    def test_risk_matching_does_not_count_an_unrelated_blocker(self):
        row=run();row['filtered']=[dict(ruleId='OTHER',filePath='Other.java',line=90),dict(ruleId='DANGEROUS_SQL',filePath='Endpoint.java',line=11)]
        row['risk']['codeFindings']=[dict(findingId='code:index:0',priority='BLOCKING',reasonCode='OTHER'),dict(findingId='code:index:1',priority='REVIEW_REQUIRED',reasonCode='PATTERN_REQUIRES_CONTEXT')]
        self.assertEqual(b.score(manifest(),result(row))['results'][0]['targetRiskPriorities'],{'REVIEW_REQUIRED':1})

    def test_collector_rejects_large_or_credential_like_data_without_retry(self):
        for data in (b'x'*1_000_001,('ghp_'+'syntheticOnly'*4).encode()):
            fetcher=b.Fetcher()
            with patch.object(fetcher.opener,'open',return_value=io.BytesIO(data))as opener:
                with self.assertRaises(ValueError):fetcher.fetch('https://raw.githubusercontent.com/example/fixture/'+'a'*40+'/Endpoint.java')
                self.assertEqual(opener.call_count,1)
        fetcher=b.Fetcher();fetcher.requests=200
        with self.assertRaisesRegex(ValueError,'REQUEST_LIMIT'):fetcher.fetch('https://github.com/example/fixture')

    def test_cached_bytes_are_hash_checked_before_reuse(self):
        with tempfile.TemporaryDirectory()as tmp:
            url='https://raw.githubusercontent.com/example/fixture/'+'a'*40+'/Endpoint.java'
            fetcher=b.Fetcher(Path(tmp)/'cache')
            with patch.object(fetcher.opener,'open',return_value=io.BytesIO(b'public fixture')):
                self.assertEqual(fetcher.fetch(url),b'public fixture')
            blob=next((Path(tmp)/'cache').glob('*.blob'));blob.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'CACHE_INTEGRITY'):b.Fetcher(Path(tmp)/'cache').fetch(url)

    def test_redirect_cannot_escape_public_host_policy(self):
        with self.assertRaisesRegex(ValueError,'PUBLIC_URL_POLICY'):
            b.RedirectPolicy().redirect_request(None,None,302,'',{},'https://127.0.0.1/metadata')

    def test_whitespace_clones_are_not_a_new_holdout(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);a=case();c=case(caseId='case-b',repositoryUrl='https://github.com/example/other',repositoryGroup='other',forkGroup='other',vulnerabilityFamily='other',evaluationSplit='HOLDOUT')
            c['files'][0]['url']=c['files'][0]['url'].replace('/fixture/','/other/')
            for item,text in ((a,'class X {}'),(c,'class X{ }')):
                directory=root/'cases'/item['caseId'];directory.mkdir(parents=True)
                data=text.encode();(directory/'Endpoint.java').write_bytes(data);item['files'][0]['sha256']=b.digest(data)
            with self.assertRaisesRegex(ValueError,'WHITESPACE_DUPLICATE_SPLIT_LEAKAGE'):b.validate(manifest(a,c),root)


if __name__=='__main__':unittest.main()
