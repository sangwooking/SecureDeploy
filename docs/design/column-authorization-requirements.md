# Column Authorization Evidence And Requirements

## Confirmed Boundaries

Row policies describe which existing and replacement rows satisfy a condition.
They do not say which columns a caller may change. PostgreSQL object privileges
and SQL query prerequisites must also hold. Repository declarations do not prove
the active role, grantor, role memberships, owner/admin behavior or deployed state.

The optional `column-update-v1` evidence reports only explicit table/column UPDATE
declarations for static write fields and the `anon`/`authenticated` roles. A missing
grant is `NOT_ESTABLISHED`, never a runtime denial. Column SELECT/INSERT privileges,
DELETE column privileges (invalid PostgreSQL syntax), role inheritance and grant
options are outside this parser contract and preserve UNKNOWN where encountered.

Official semantics:
- https://www.postgresql.org/docs/16/sql-grant.html
- https://www.postgresql.org/docs/16/sql-revoke.html
- https://www.postgresql.org/docs/16/ddl-rowsecurity.html
- https://supabase.com/docs/guides/database/postgres/column-level-security
- https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/

## Original Grade B Error Meaning

The original 36 requirements and results are not changed. The six target misses
are layered capability/intent gaps, not six verified production exploits:

- Two private-read targets require an explicit private-data requirement. A broad
  SELECT declaration alone does not distinguish private from intentionally public
  data. The authenticated A/B controlled SQL permits the prohibited reads, but
  the actual deployed role and database remain unknown.
- Four protected-property targets have fixture requirements prohibiting changes
  to a designated management field. Existing own-row policies and table UPDATE
  declarations allow those changes in the controlled DB. The illustrative helper
  is not demonstrated to be invoked in a deployed application, and requirements
  are not product inputs. Field names alone cannot establish privilege escalation.
- All six additionally depend on real runtime role/project/policy alignment.

The two shared-data false positives measure unwanted review burden against the
authored shared intent. The declaration is genuinely broad; it is not a false SQL
fact. Suppressing it in an unlabeled project would assume unavailable intent.
The four no-alert normal cases with UNKNOWN policy evidence remain separate
from verified protection. No denominator is changed to improve scores.

## Proposal Only: Explicit Requirements

No configuration format, API, database table or user workflow is introduced here.
A later reviewed contract could carry:

- Version, author/approver, repository/project and exact commit or file hashes.
- Exact schema/table, operations and intended application roles (not guessed DB roles).
- Explicit public/shared/private intent, editable columns and protected columns.
- Owner-column relationship and documented exceptions for administrator actions.
- Requirement provenance, relevant code/configuration locations and verification tests.

Requirements must be tied to the current source revision, reviewed by the user,
and reported separately from observed SQL. Stale, conflicting, unapproved or absent
requirements remain UNKNOWN. Do not let an intent declaration suppress a factual
policy observation or override missing source/role evidence. It is an input to a
future conditional review, not proof of runtime security.

## Next Decision

Prioritize independently reviewed protected-data requirements and a small
column-permission matrix before adding framework/alias tracking. An actual
vulnerable/fixed application pair is still needed before claiming real-world
authorization detection accuracy. Do not auto-implement the proposed contract.
