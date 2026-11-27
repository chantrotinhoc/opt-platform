-- OPT initial schema. Every business table carries tenant_id and is protected by
-- Row-Level Security. The API sets `SET LOCAL app.tenant_id = '<id>'` per transaction
-- and connects as role opt_app, which is NOT the table owner and has no BYPASSRLS.

CREATE TABLE tenant (
    id              text PRIMARY KEY,
    name            text NOT NULL,
    plan            text NOT NULL DEFAULT 'starter',
    data_residency  text NOT NULL DEFAULT 'cloud_ok' CHECK (data_residency IN ('cloud_ok', 'local_only')),
    kms_key_id      text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE engagement (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    name            text NOT NULL,
    status          text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'active', 'locked', 'closed')),
    roe_object_uri  text,
    roe_valid_from  timestamptz NOT NULL,
    roe_valid_to    timestamptz NOT NULL,
    sensitivity     text NOT NULL DEFAULT 'internal' CHECK (sensitivity IN ('public', 'internal', 'restricted')),
    CHECK (roe_valid_from < roe_valid_to)
);

CREATE TABLE scope_rule (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    engagement_id   uuid NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('domain', 'cidr')),
    value           text NOT NULL,
    exclude         boolean NOT NULL DEFAULT false
);

CREATE TABLE target (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    value           text NOT NULL,
    verify_method   text CHECK (verify_method IN ('dns_txt', 'well_known_file')),
    verified_at     timestamptz,
    UNIQUE (tenant_id, value)
);

CREATE TABLE finding (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    engagement_id   uuid NOT NULL REFERENCES engagement(id),
    title           text NOT NULL,
    cwe             text,
    cvss_vector     text,
    cvss_score      numeric(3,1),
    epss            numeric(5,4),
    status          text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'confirmed', 'false_positive', 'fixed', 'accepted')),
    fingerprint     text NOT NULL,
    source_tool     text NOT NULL,
    UNIQUE (tenant_id, engagement_id, fingerprint)
);

CREATE TABLE agent_step (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    engagement_id   uuid NOT NULL REFERENCES engagement(id),
    agent           text NOT NULL,
    model           text NOT NULL,
    routed_to       text NOT NULL CHECK (routed_to IN ('cloud', 'local_large', 'local_small')),
    tool            text,
    risk            text,
    approved_by     text,
    tokens          integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- Append-only, hash-chained audit log.
CREATE TABLE audit_event (
    seq             bigserial PRIMARY KEY,
    tenant_id       text NOT NULL REFERENCES tenant(id),
    ts              timestamptz NOT NULL DEFAULT now(),
    actor           text NOT NULL,
    action          text NOT NULL,
    object          text NOT NULL,
    payload_hash    text NOT NULL,
    prev_hash       text NOT NULL
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['engagement', 'scope_rule', 'target', 'finding', 'agent_step', 'audit_event'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true))$p$, t);
    END LOOP;
END $$;

-- The application role may only append to the audit log.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_event FROM PUBLIC;
