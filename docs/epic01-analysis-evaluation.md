# EPIC-01 independent analysis evaluation

Run `node scripts/evaluation/epic01-independent.mjs /outside/git/results.json`.
These are newly authored synthetic evaluation cases, not independently acquired real
projects and not a general accuracy benchmark. Ground truth applies only to server
secret HTTP exposure. Authentication/SQL/dynamic registration cases have no complete
policy oracle and are UNKNOWN, excluded from precision/recall counts. Runtime env
contents and actual production exposure remain unknown even for static positives.

Measured on unchanged Worker v51: 3 TP, 3 TN, 0 FP, 1 FN, 3 UNKNOWN. All aggregate
statuses are PARTIAL; dynamic registration has 0 known entries and NOT_SUPPORTED
file flow. Cross-file exported helper secret and normal variants were distinguished.
Computed env name built by array join is missed (FN) despite a known synthetic
static oracle; it remains PARTIAL, never SAFE. No Worker source/Rule/Risk/Score
change was made to improve these counts. Seven unavailable historical app inputs
remain INPUT_UNAVAILABLE; no real-private-source validation is implied.

Coverage audit: analyzer.mjs performs bounded parsing, source/module selection and
calls into node-server/entry-contracts, export-links/module-resolution/wrapper-links,
object-data and dedicated async/callback/exception modules. Direct registered HTTP
handlers and selected bounded import/export/function/argument/return/object paths
are modeled. Branch merges, loops, async heap state, dynamic computed accesses,
unknown middleware and dynamic registration retain explicit partial/unknown limits.
Parsing a file does not mean every path was analyzed. 72 Rule IDs are checks, not
72 exhaustively verified vulnerability classes. Complex multi-file authentication,
ownership, SQL/NoSQL semantics and frontend/backend behavior cannot receive a whole
application safety conclusion from these cases. The measured computed-key gap is a
candidate for a separately bounded enhancement with pre/post identical-input evidence;
it is not silently repaired or relabeled in this task.

PHASE D+ continuation: see epic01-dplus-analysis.md for the separate v51/v52
same-input comparison, new handler support and retained FN/UNKNOWN cases. The
historical10-case measurements above are not rewritten as results of the new cohort.
