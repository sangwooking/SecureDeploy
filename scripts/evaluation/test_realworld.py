import json
from pathlib import Path
import struct
import unittest
import zlib
from cvefixes_metadata import LIMIT, MEMBER, parse_prefix
from prepare_realworld import SPECS, FAMILIES, patch_sites


def prefix(sql, name=MEMBER, method=8):
    gzip=zlib.compressobj(wbits=31)
    compressed=gzip.compress(sql)+gzip.flush()
    zipstream=zlib.compressobj(wbits=-15)
    data=zipstream.compress(compressed)+zipstream.flush()
    filename=name.encode()
    return struct.pack('<4s5H3L2H',b'PK\x03\x04',45,0,method,0,0,0,len(data),len(compressed),len(filename),0)+filename+data


START=b'PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\nCREATE TABLE IF NOT EXISTS "fixes" (\n"cve_id" TEXT);\n'
END=b'CREATE TABLE IF NOT EXISTS "commits" (\n'


class MetadataTests(unittest.TestCase):
    def test_select_only_exact_metadata_without_sql_execution(self):
        sql=START+b"INSERT INTO fixes VALUES('CVE-2020-1234','"+b'a'*40+b"','https://github.com/example/project');\n"+END
        rows,receipt=parse_prefix(prefix(sql))
        self.assertEqual(rows,[dict(cve='CVE-2020-1234',fixed='a'*40,repositoryUrl='https://github.com/example/project')])
        self.assertFalse(receipt['sqlExecuted'])
        self.assertFalse(receipt['databaseRestored'])
        self.assertIn('FULL_CHECKSUM_NOT_VERIFIED',receipt['integrity'])

    def test_untrusted_sql_and_non_github_rows_are_never_executed_or_selected(self):
        sql=START+b"INSERT INTO fixes VALUES('CVE-2020-1234','"+b'a'*40+b"','https://github.com/example/project');\n"
        sql+=b"INSERT INTO fixes VALUES('x'); DROP TABLE users;--\n"
        sql+=b"INSERT INTO fixes VALUES('CVE-2020-1235','"+b'b'*40+b"','https://gitlab.com/example/project');\n"+END
        rows,receipt=parse_prefix(prefix(sql))
        self.assertEqual(len(rows),1)
        self.assertEqual(receipt['otherRowsNotSelected'],2)

    def test_partial_table_is_not_success(self):
        with self.assertRaisesRegex(ValueError,'COMPLETE_FIXES_TABLE_REQUIRED'):
            parse_prefix(prefix(START))

    def test_archive_identity_and_format(self):
        for data in [prefix(START+END,'../../other'),prefix(START+END,method=0),b'bad',b'x'*(LIMIT+1)]:
            with self.subTest(size=len(data)),self.assertRaises(ValueError):
                parse_prefix(data)

    def test_decompression_bomb_is_bounded(self):
        with self.assertRaisesRegex(ValueError,'INNER_EXPANSION_LIMIT'):
            parse_prefix(prefix(START+b'x'*16_000_000+END))

    def test_patch_neighborhoods_have_both_revision_coordinates(self):
        before='\n'.join('line '+str(i) for i in range(50))
        after=before.replace('line 25','validate(value)\nline 25')
        sites=patch_sites('src/module.py',before,after)
        self.assertEqual(len(sites['parent']),1)
        self.assertTrue(sites['fixed'][0]['startLine']<=26<=sites['fixed'][0]['endLine'])
        self.assertEqual(patch_sites('same.py',before,before),{'parent':[],'fixed':[]})

    def test_curated_dataset_has_ten_distinct_vulnerabilities_per_source(self):
        self.assertEqual(len(SPECS),20)
        self.assertEqual(sum(s[0].startswith('vul4j-') for s in SPECS),10)
        self.assertEqual(len({s[0] for s in SPECS}),20)
        self.assertEqual({s[1] for s in SPECS},{'REGRESSION','VALIDATION','HOLDOUT'})
        self.assertGreaterEqual(len({s[2] for s in SPECS}),10)
        for s in SPECS:
            self.assertTrue(all(s[i] for i in (4,6,7,8,9)))

    def test_related_patch_families_never_cross_splits(self):
        splits={}
        self.assertEqual(set(FAMILIES),{s[0]for s in SPECS})
        for spec in SPECS:
            family=FAMILIES[spec[0]]
            self.assertEqual(splits.setdefault(family,spec[1]),spec[1])
        self.assertEqual(FAMILIES['vul4j-2'],FAMILIES['vul4j-51'])
        self.assertEqual(FAMILIES['vul4j-48'],FAMILIES['cvefixes-cve-2020-15084'])


if __name__=='__main__':unittest.main()
