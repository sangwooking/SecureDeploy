# ZIP Upload Safety

## Limits and Source of Truth

`spring.servlet.multipart.max-file-size` is the authoritative upload limit, now
200MB (209,715,200 bytes). `max-request-size` is 205MB to allow multipart overhead.
Multipart content is spooled to disk (`file-size-threshold: 0B`). `UploadPolicy`
reads Spring's `MultipartProperties`; no separate service or frontend size constant
is used. Authenticated clients read `GET /api/reviews/upload-policy`. ZIP submission
is disabled until that policy loads; retry is available. GitHub submissions do not
depend on the ZIP policy request.

Both main and test application YAML previously set file and request limits to 50MB.
The exception handler also contained a hardcoded 50MB message. Services, frontend,
and the ZIP extractor had no size limits. No reverse proxy configuration is tracked.
If a proxy is introduced, configure its body limit at least as large as the 205MB
request limit and use suitable timeouts and temporary disk capacity.

Additional settings under `securedeploy.storage`:

| Setting | Default | Enforcement |
| --- | --- | --- |
| `max-expanded-size` | 1GB | Actual decompressed bytes across every entry |
| `max-archive-entries` | 50000 | ZIP entries including directories, and separately materialized files/implicit parent directories |
| `max-analysis-file-size` | 32MB | Per analyzed text file |
| `max-analysis-total-size` | 128MB | All analyzed source text per scan |
| `max-analysis-lines` | 500000 | All retained source lines per scan |

The text limits also apply to GitHub scans. Exceeding a text budget aborts with
413, rather than silently producing a partial clean result or false resolved
findings in Phase 5. Existing SCA manifest parsing limits remain unchanged.

## Archive and Filesystem Protection

- Upload and extraction use 8KB buffers. The upload service checks metadata and
  counts actual streamed bytes, including when a multipart size is incorrect.
- Expanded size is checked while reading, not only using ZIP header sizes.
  Ignored entries still count towards the byte and entry budgets, but are not
  materialized. Closing an entry never skips unmetered content.
- Compression ratio alone is not used: repeated static data can compress well.
  Per-request compressed, expanded and entry budgets are the current bomb defense.
- Reject traversal segments, Unix/Windows absolute paths, drive paths and invalid
  paths. Verify real parent directories remain inside a fresh extraction root.
  Do not overwrite files or follow symbolic links. ZIP UNIX link attributes are
  not restored as filesystem links; link payloads are ordinary files only.
- Save failures remove the workspace immediately. Extraction failures also remove
  it. The existing facade's `finally` cleanup covers analysis success and failure.
- A single wrapper directory is unwrapped only when it is the only root entry.
  Root manifests beside `src/` are preserved.

## Shared Ignore Policy

`ProjectIgnorePolicy` excludes exact path segments: `node_modules`, `.git`, `build`,
`dist`, `target`, `out`, `.gradle`, `coverage`, `vendor`. This policy is shared by
extraction, scanner and SCA collection. The scanner skips directory subtrees before
reading files, and does not follow file or directory symlinks. Root manifests such
as `package.json`, `package-lock.json`, `pom.xml`, `build.gradle` and `Dockerfile`
are still scanned. Names such as `vendor-api` are not excluded by substring.

## Errors, Privacy and Compatibility

- Upload/multipart, expanded-size, entry-count and source-budget errors return 413.
- Malformed ZIPs, unsafe paths and unsupported files return friendly 400 responses.
- Messages recommend removing generated or external library directories.
- Archive rejection logs include fixed reason codes and numeric sizes/counts only.
  Unknown multipart size is logged as -1. No archive name, entry path, source,
  credential, request body or exception dump is logged by this rejection path.
- Rule Engine, RiskPolicy, authentication and comparison algorithms are unchanged.
  Scanner coverage changes affect the existing Phase 5 analyzer fingerprint:
  comparisons against older scan coverage may conservatively report unavailable.
- No migration, commit, push or paid AI request is part of this task.

## Verification and Remaining Limits

Unit tests stream a real 199MB ZIP and test byte boundaries, actual 50,001 entries,
compressed bombs (including ignored directories), CRC corruption, path traversal,
UNIX symlink attributes, preexisting symlinks, ignored subtrees, root manifests and
cleanup. Embedded HTTP tests use smaller configured budgets to verify servlet
multipart and request-overhead failures, JSON 4xx responses and Phase 5 rescans.
Frontend tests and Playwright cover server-driven limits, policy retry, pre-request
rejection, normal uploads and rescans at 1440/390/320px.

Global concurrent upload admission, per-user quotas, disk reservation, extraction
wall-clock timeout and compression-ratio heuristics are not implemented. Multiple
simultaneous allowed requests can still consume substantial disk/CPU/memory. OS
permission/disk failures can prevent best-effort temporary-file deletion. This
does not promise that every archive under 200MB is acceptable: expanded size,
entry count, text budgets and existing parser constraints also apply.

Live development verification also checks policy values and a streamed
209,715,201-byte request returning JSON 413. A browser flow against PostgreSQL
checks login, normal ZIP, same-project rescan, snapshot/detail/history and UI.
Temporary accounts/projects are removed; preexisting table counts are unchanged.
An unrelated existing policy exposes ownerless legacy reviews to signed-in users.
This was left unchanged because authentication is outside this task; review that
legacy-data access policy before production use.

Reference: [Spring Boot multipart properties](https://docs.spring.io/spring-boot/3.3/api/java/org/springframework/boot/autoconfigure/web/servlet/MultipartProperties.html).
