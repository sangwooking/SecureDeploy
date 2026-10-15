# GitHub Source Hardening

## Acquisition and Identity

Previously, the GitHub service used a regular JGit clone with a transport timeout.
It shared the ZIP analysis pipeline but did not store the analyzed branch/commit.

The new flow is:

1. Parse a public `https://github.com/owner/repository[.git]` URL into a canonical lowercase identity.
2. Create an isolated temporary workspace and a bare object store.
3. Read the remote symbolic HEAD; never assume `main`.
4. Fetch only that branch at depth 1, without tags or recursive submodules.
5. Export the selected commit's tree with path, type and size checks, without checkout.
6. Run the existing scanner, rules/false-positive handling, SCA, risk and AI-mode pipeline.
7. Save the source metadata with the Review and copy before/after metadata into the comparison snapshot.
8. Clean up the workspace after success or failure.

No repository code, shell, hooks, filter, build, package install, or LFS download is executed.
JGit uses an anonymous Java HTTP transport, not a host Git command. TLS verification stays enabled.
Requests are restricted to the canonical repository's `info/refs?service=git-upload-pack` and
`git-upload-pack` endpoints. Redirects, alternate hosts/protocols, credentials, cookies and proxies are
not forwarded. Request gzip encoding is preserved; response compression is disabled for byte accounting.
Explicit HTTPS port 443 is accepted and removed during normalization; all other explicit ports are rejected.
URL userinfo, queries, fragments, percent-encoded paths, extra path segments and traversal are rejected.

Per-user project matching treats URL case and `.git` suffix variants as the same repository.
Legacy duplicate projects are not merged: automatic resolution returns 409 and asks the user to select
an existing project. A project-specific rescan uses its saved URL and verifies ownership before collection.
Each rescan produces a new Review, even at the same SHA. Prior Reviews and comparison snapshots are immutable.

## Metadata and Migration

`reviews.source_metadata_json` is nullable TEXT, mapped using `GitHubSourceSnapshotConverter`.
It records owner/repository, canonical URL, branch, full/short SHA, commit time, collection start/end,
analysis time, depth, excluded submodule/LFS/symlink counts and scope limitations.
ZIP and old Reviews have null metadata. No historic branch/commit is guessed or backfilled.

Apply before deploying the new backend, using a trusted local connection without credentials in command arguments:

```sh
psql -X -v ON_ERROR_STOP=1 -d securedeploy -f src/main/resources/db/postgresql/add-review-source-metadata.sql
```

The migration only adds a nullable column with `IF NOT EXISTS`. Run the application with
`--spring.jpa.hibernate.ddl-auto=validate` after migration to check the mapping without schema mutations.

The development migration was applied twice. Existing users (2), projects (10), reviews (9),
vulnerabilities (159) and snippets (30), including Review JSON snapshots, had unchanged row counts and
content digests. All nine legacy Review source metadata values remained null.

## Limits and Coverage

- `securedeploy.github.timeout-seconds`: 60 seconds, clamped to 1-300.
- `securedeploy.github.max-requests`: 12 HTTP requests per collection.
- `securedeploy.github.max-download-size`: 200 MB of response bytes per collection.
- At most two concurrent Git collections per application instance.
- Shared storage limits: 50,000 entries, 1 GB expanded source, 32 MB per analyzed text file,
  128 MB total analyzed text, 500,000 analyzed lines. Configured storage policy is the source of truth.
- Shared directory exclusions, including `.git`, `node_modules`, build outputs and coverage, remain active.
  Git entry/source budgets also account for ignored trees so they cannot bypass the collection limits.
- Recursive monorepo scanning includes nested Maven, Gradle, npm, Docker, Kubernetes and configuration files.
- Submodule gitlinks and `.gitmodules` are detected; external repositories are not cloned.
- LFS pointers are omitted, not treated as their referenced content. The shared ZIP scanner also ignores pointers.
- Symlinks are omitted and never followed. Review metadata and UI warn about excluded source scopes.

The deadline cancels network streams and is checked during JGit progress/tree export. It is not an
OS-level CPU/RAM/disk quota. Compressed Git objects still require parsing; deployment-level worker isolation
and filesystem quotas remain recommended. A hard process kill can bypass best-effort cleanup. Very large
or renamed repositories requiring redirect can be rejected; use the final canonical public URL.

Depth 1 retains normal JGit pack validation and the explicit exported-tree checks. JGit 6.10's optional
extra full-object-graph check is not enabled: it rejects deliberately absent shallow parents with
`peer did not supply a complete object graph`. This incompatibility is reproduced by `JGitProtocolTest`.

## Verification

```sh
AI_PROVIDER=template gradle test
cd frontend
npm test
npm run build
```

`GitHubSourceTest` covers URL/transport rejection, default branch, resource limits, cleanup and omitted scopes.
`PublicGitHubConnectionTest` verifies compressed request headers, credential stripping, redirect rejection
and timeout errors with a mocked HTTP client. `JGitProtocolTest` exercises the actual JGit smart-HTTP
advertisement/upload-pack/shallow-fetch protocol against an in-memory local repository, without network access.

`GitHubReviewIntegrationTest` compares identical Git/ZIP monorepo file sets, rule results, SCA results,
priority/assessment and semantic slice input. It also checks canonical identity, same/different commit rescans,
stored metadata, history/workspace APIs, legacy nulls, ownership, failure cleanup and comparison retention
after baseline deletion. Test credentials are generated in memory and are never real credentials.

Frontend unit and intercepted browser tests cover source metadata, escaped text, history, same/different
commit comparison, private-repository error copy, rescan and legacy metadata. Browser sizes: 1440/390/320.
Commit equality requires both canonical repository URL and full SHA; a changed commit does not imply security improvement.

### Optional Network Smoke Status

On 2026-10-15, two authorized anonymous read-only attempts against `octocat/Hello-World` failed:
the first exposed a missing compressed-request header, the second a shallow/full-graph-check incompatibility.
Both were fixed and verified offline, including the full JGit protocol. No further external request was made.
The final implementation was subsequently validated with one newly authorized live scan on 2026-10-15:

- Repository: `https://github.com/spring-guides/gs-rest-service` (canonical URL).
- Default branch: `main`.
- Commit: `3f4cef01152596c19bc4d37939409358812b1421` (`3f4cef0`).
- Commit timestamp: `2026-09-01T10:50:37Z`.
- Source collection: `2026-10-15T09:05:49.639433Z` to `2026-10-15T09:05:56.347767Z`.
- Analysis timestamp: `2026-10-15T09:05:56.367691Z`; 17 analyzed files; depth 1.
- Actual UI URL submission -> public anonymous Git collection -> shared analysis -> PostgreSQL Review.
- Persisted source metadata matched detail, project/history, global history and Workspace responses.
- The real browser overview/full-SHA details and History displayed the same branch/commit.
- Source submissions: **1**. No second repository or rescan was needed.
- Temporary repository directories: 0. Temporary account/project/review deleted; existing rows unchanged.

This source-only validation used a separate server with template AI, a blank OpenAI key, and external
SCA/threat-intelligence lookups disabled. No GitHub credential, repository mutation or OpenAI request was used.
It is not an additional live OSV/EPSS/KEV validation, nor a safety verdict on the example repository.
The collection succeeded on the first new submission. A temporary browser verification script then checked
the wrong semantic status field; the already-saved Review was verified through read-only API/browser calls
after correcting the harness. No application code change or repeated source collection was needed.

Final local verification: 258 backend tests passed (4 opt-in smoke tests skipped), 55 frontend tests
passed, frontend production build and `git diff --check` passed. All five browser suites
(`github-source`, `workspace`, `result-workspace`, `review-progress`, `zip-upload`) passed at
1440/390/320. The development backend restarted with the original environment and schema validation.
No actual environment secret matched the changed source; no build/log/environment artifacts are included.
After live validation, the directly related backend GitHub tests and four frontend source tests were rerun.
The final live-validation request authorizes closing the milestone once the Git/secret/artifact checks pass.

The opt-in smoke remains available for a separately authorized later check:

```sh
AI_PROVIDER=template GITHUB_SOURCE_SMOKE=true gradle test --tests 'com.securedeploy.github.service.GitHubSourceSmokeTest'
```

No OpenAI calls were made for this milestone. Private repositories/OAuth/PATs, GitHub App, alternate Git
hosts, writes/PRs, automatic code changes and full submodule/LFS support remain out of scope.
