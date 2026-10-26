# B: Declaration Cards

Release only after A's responses are frozen. No engine answer or expected result is
provided here. Documentation-only excerpts from authored controls; do not execute.
Formatting and omitted wrappers mean these blocks are not byte-exact source packets.
Coordinator C records the original source bindings for later verification.

## Common Source Context And Gaps

Both authored layouts use a supported Next.js declaration (Route Handler or a file-level
Server Function) and a relative SSR Client factory. A getUser result and terminating
absence guard precede the displayed data call. Route body or Server Function arguments
supply `body`. The excerpts below omit import/factory/wrapper text; none is evidence
that a production HTTP call, JWT validation or DB session occurred.

```typescript
const db = await make();
const {data: {user}} = await db.auth.getUser();
if (!user) throw new Error('missing');
// The card-specific data call follows.
```

The SQL excerpts describe one table. The original authored setup also gives a
`limited_admin` role SELECT and an unrestricted SELECT policy. It does not prove an
administrator write path. Role existence, schema privileges, migration execution and
grantor are assumptions; actual runtime role and project association are unverified.
The prior isolated oracle used an auth.uid() current_setting stub, not Supabase Auth.

## R14-01 And R14-02

These two proposed intents deliberately use the same read-policy content. Do not infer
the requirement from that content. Compare each with its separately frozen A response.

```sql
CREATE TABLE public.items (
  id integer, user_id uuid, payload text,
  role text DEFAULT 'member', is_admin boolean DEFAULT false
);
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
GRANT SELECT ON public.items TO anon, authenticated;
CREATE POLICY read ON public.items FOR SELECT TO public USING (true);
```

```typescript
return db.from('items').select().eq('id', body.id);
```

For each requirement, identify what a SELECT declaration says and what it cannot say
about anonymous availability, the real session or HTTP selector control. The current
Worker's SELECT evidence is not UPDATE-style argument provenance.

## R14-03

```sql
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.items TO authenticated;
CREATE POLICY p ON public.items FOR ALL TO authenticated
  USING (true) WITH CHECK (true);
```

```typescript
return db.from('items').update({payload: body.payload}).eq('id', body.id);
```

Assume the same authored table shape as the read card. Record which operations and
fields the A response actually approves. Explain what remains unconfirmed for the
other operations; do not treat a shared text edit as blanket policy approval.

## R14-04

```sql
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.items TO authenticated;
CREATE POLICY p ON public.items FOR ALL TO authenticated
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
```

```typescript
return db.from('items').update({role: body.role}).eq('user_id', user.id);
```

Use the same table shape. The illustrative management helper references role/is_admin
but its deployed invocation was not demonstrated. Separate row ownership, field update
permission, the proposed protection requirement and actual privilege escalation.

Additional permission contrast to assess independently (not a new benchmark case):

```sql
-- Variant X, with the same table, role and row-policy premises:
GRANT UPDATE ON public.items TO authenticated;
REVOKE UPDATE (role) ON public.items FROM authenticated;

-- Variant Y is a separate history, not a continuation of X:
REVOKE UPDATE ON public.items FROM authenticated;
GRANT UPDATE (payload) ON public.items TO authenticated;
```

State the effect of each history and the missing information. No column DELETE
privilege, inferred owner/admin role or missing-GRANT denial should be invented.

## R14-05

```sql
ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.items TO authenticated;
CREATE POLICY read ON public.items FOR SELECT TO authenticated USING (true);
CREATE POLICY change ON public.items FOR UPDATE TO authenticated
  USING (auth.uid() = user_id) WITH CHECK (true);
```

```typescript
return db.from('items').update({user_id: body.user_id}).eq('user_id', user.id);
```

Use the same table shape. Evaluate old-row selection and new-row ownership separately.
If an A response permits writing the owner field but forbids transferring ownership,
state the necessary consistency rule instead of assuming one flag takes precedence.
No expected result is supplied for that contract combination in this packet.
