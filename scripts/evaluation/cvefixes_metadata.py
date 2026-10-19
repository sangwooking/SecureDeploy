"""Read only the bounded fixes-table prefix of the official CVEfixes ZIP.

No SQL execution, archive extraction, source execution or complete DB download.
The partial archive has HTTPS provenance and a recorded SHA-256, not a verified
whole-archive checksum or complete gzip CRC. Fail closed if the layout changes.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import urllib.request
import zlib

URL = 'https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.zip'
OFFSET = 1485686
LIMIT = 2097152
MEMBER = 'CVEfixes_v1.0.8/Data/CVEfixes_v1.0.8.sql.gz'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('UNEXPECTED_ARCHIVE_REDIRECT')


def parse_prefix(data):
    if len(data) > LIMIT or len(data) < 30:
        raise ValueError('PREFIX_SIZE')
    header = struct.unpack_from('<4s5H3L2H', data)
    name_len, extra_len = header[-2:]
    start = 30 + name_len + extra_len
    if header[0] != b'PK\x03\x04' or header[2] & 1 or header[3] != 8:
        raise ValueError('ZIP_MEMBER_TYPE')
    if data[30:30 + name_len].decode('ascii') != MEMBER or start > len(data):
        raise ValueError('ZIP_MEMBER_IDENTITY')
    outer = zlib.decompressobj(-15)
    compressed = outer.decompress(data[start:], 3_000_000)
    if outer.unconsumed_tail:
        raise ValueError('OUTER_EXPANSION_LIMIT')
    inner = zlib.decompressobj(31)
    sql = inner.decompress(compressed, 16_000_000)
    if inner.unconsumed_tail:
        raise ValueError('INNER_EXPANSION_LIMIT')
    marker = b'CREATE TABLE IF NOT EXISTS "commits" ('
    end = sql.find(marker)
    if end < 0 or not sql.startswith(b'PRAGMA foreign_keys=OFF;\nBEGIN TRANSACTION;\nCREATE TABLE IF NOT EXISTS "fixes" ('):
        raise ValueError('COMPLETE_FIXES_TABLE_REQUIRED')
    rows = []
    pattern = re.compile(r"INSERT INTO fixes VALUES\('(CVE-[0-9]{4}-[0-9]+)','([0-9a-f]{40})','(https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)'\);")
    skipped = 0
    for line in sql[:end].decode('utf-8').splitlines():
        if line.startswith('INSERT INTO fixes '):
            match = pattern.fullmatch(line)
            if match:
                rows.append(dict(zip(('cve', 'fixed', 'repositoryUrl'), match.groups())))
            else:
                skipped += 1
    if not rows:
        raise ValueError('NO_VERIFIABLE_FIX_ROWS')
    return rows, {'sourceUrl': URL, 'rangeStart': OFFSET, 'rangeBytes': len(data),
                  'prefixSha256': hashlib.sha256(data).hexdigest(), 'fixesTableBytes': end,
                  'githubFixRows': len(rows), 'otherRowsNotSelected': skipped,
                  'integrity': 'PARTIAL_ARCHIVE_FULL_CHECKSUM_NOT_VERIFIED',
                  'sqlExecuted': False, 'databaseRestored': False}


def acquire(output):
    # Import only our trusted evaluation helper, never anything from the corpus.
    from benchmark import outside, write
    output = outside(output)
    output.mkdir(mode=0o700)
    request = urllib.request.Request(URL + '?section=securedeploy-fixes-v1', headers={
        'User-Agent': 'SecureDeploy-readonly-benchmark',
        'Range': f'bytes={OFFSET}-{OFFSET + LIMIT - 1}', 'Accept-Encoding': 'identity'})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
        if response.status != 206:
            raise ValueError('RANGE_RESPONSE_REQUIRED')
        content_range = response.headers.get('Content-Range')
        if content_range and not content_range.startswith(f'bytes {OFFSET}-{OFFSET + LIMIT - 1}/'):
            raise ValueError('RANGE_MISMATCH')
        data = response.read(LIMIT + 1)
    if len(data) != LIMIT:
        raise ValueError('RANGE_LENGTH')
    rows, receipt = parse_prefix(data)
    p = output / 'prefix.bin'
    with p.open('xb') as stream:
        p.chmod(0o600)
        stream.write(data)
    write(output / 'fixes.json', rows)
    write(output / 'receipt.json', receipt)
    print(json.dumps(receipt))


if __name__ == '__main__':
    import sys
    acquire(Path(sys.argv[1]))
