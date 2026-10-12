# Synthetic Semantic Review fixtures

These Java sources are parse-only fixtures, not a runnable application. Undefined framework/model types intentionally demonstrate that the collector does not compile, load or execute uploaded code.

- User controller/service/repository: a small resource lookup for mocked IDOR review.
- File controller: a file/path flow for mocked additional verification.
- Admin controller: an authorization annotation to reduce unsupported access-control confidence.
- Source text includes a deliberately fake credential and an untrusted prompt-injection comment. Neither is a real account or API credential.

Mock proposals verify the server pipeline and rendering. They do not demonstrate live AI detection quality. All evidence must refer to excerpts actually supplied by the collector. The integration test exports a synthetic review JSON only under ignored `build/` for local browser checks; no authentication token is exported.
