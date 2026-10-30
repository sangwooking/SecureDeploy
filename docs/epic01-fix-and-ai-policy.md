# EPIC-01 modification and AI policy

Existing method values remain API compatible. Additive `supportLevel` maps
DETERMINISTIC_FIX to VERIFIED_AUTO_FIX, AI_ASSISTED to AI_ASSISTED_FIX,
MANUAL_REVIEW to GUIDED_REMEDIATION, otherwise UNSUPPORTED. This label is returned
only after existing ownership, original/current hash, Finding, Source/Sink and AST
support checks. No new vulnerability category or relaxed validation is introduced.

Express/Deno direct environment-value response fields retain existing deterministic
validators. Spring literal setting changes and npm generation are not newly promoted
to verified automatic code fixes. SCA uses its existing evidence/update-plan + npm
workflow; no AI-authored lockfile claim. SQL/NoSQL/XSS/SSRF/authentication/authorization
remain guided/manual unless a separate independently verifiable contract is supplied.

The Workspace shows one primary supported generation action. Deterministic cases do
not show a competing AI request action. Manual editing remains available. Existing
provider/model, server AST, npm, manual and approved provenance remains unchanged.

## Patch call policy (single instance, external calls default OFF)

`securedeploy.ai.patch-policy.external-enabled=false`. Mock providers must explicitly
identify MOCK; UNVERIFIED/NO_MODEL_PREVIEW do not enable AI requests. Provider flags
are independent of deterministic fix support. Actual external generation is permitted
only with configured provider, explicit one-use consent and original/context hashes,
then an admission permit. A new explicitly consented proposal is a new request; a
repeated consent/proposal cannot invoke twice. User <=6/hour, project <=12/hour,
concurrency <=2, bounded 6000 attempt ledger entries/day. Existing 10-second per-user
interval and executor capacity remain in force. Input body <=30720 bytes, output
<=2000 tokens via existing provider; policy text <=28000 UTF-8 bytes. Only model
snapshot gpt-5.4-mini-2026-03-17 has a cost bound in this policy. Reserve USD0.033576
per attempted live call (32768 input *0.75/1M +2000 output *4.50/1M); per-user daily
USD0.10, per-project daily USD0.20 conservative standard-token estimates. Unknown or
failed usage never refunds the reservation. Actual API usage stays separately recorded
by existing usage tracker; this is not an invoice, excludes tax/FX/account adjustments.
Rates reference verified official model documentation, not automatic billing discovery:
https://developers.openai.com/api/docs/models/gpt-5.4-mini

Limitations: the admission ledger is process-local, resets after restart, and applies
to Workspace code patch requests, not every AI feature. Do not activate operating AI
on this basis: a durable shared attempt/cost ledger, configurable verified tariffs and
unified admission for Semantic Review, SCA advice and explanation endpoints remain
required. Real model calls in EPIC-01 are forbidden and zero. Unit/Mock/replayed
stored outputs do not constitute new real-model validation.

## AI roles and remaining context gaps

Additional Semantic Review: existing bounded registered Express handler and up to two
same-file direct helper contexts, Mock verified; no proof of complete cross-file auth
or ownership analysis. Results stay AI_SECURITY_CANDIDATE/REVIEW_REQUIRED outside
confirmed Findings/Risk/Score. Korean explanations use existing immutable Evidence
and bounded snippets; explaining evidence is not discovering a new risk. Structured
Express plans use server-issued object/field IDs and server AST code generation;
LIVE-03 supplied the historical real-model A/B evidence, not this task. SCA direction
has historical AI-03 real-model evidence; npm product automation has independent Mock
validation. Deno/Spring have separate historical supported/Mock tests; do not infer
multi-file runtime compatibility. Complex auth/query/HTML/path/request policy needs
project-specific oracle and complete boundary/effect validation before executable
patch support; this task does not offer speculative automatic patches.
