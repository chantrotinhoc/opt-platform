-- Sprint 2: scans and richer findings, so one tenant can run recon -> findings -> report.

CREATE TABLE scan (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       text NOT NULL REFERENCES tenant(id),
    engagement_id   uuid NOT NULL,
    FOREIGN KEY (tenant_id, engagement_id) REFERENCES engagement (tenant_id, id),
    target          text NOT NULL,
    engine          text NOT NULL,
    status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    requested_by    text NOT NULL,
    steps           jsonb NOT NULL DEFAULT '[]',
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    UNIQUE (tenant_id, id)
);

ALTER TABLE finding
    ADD COLUMN scan_id     uuid,
    ADD COLUMN target      text,
    ADD COLUMN severity    text NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    ADD COLUMN description text,
    ADD COLUMN evidence    jsonb,
    ADD COLUMN created_at  timestamptz NOT NULL DEFAULT now(),
    ADD FOREIGN KEY (tenant_id, scan_id) REFERENCES scan (tenant_id, id),
    ADD UNIQUE (tenant_id, id);
COMMENT ON COLUMN finding.scan_id IS 'Last scan that observed the finding; scan_finding has every observation.';

-- Findings are deduplicated per engagement; this records every scan that saw one,
-- so the report of every scan keeps its findings after later scans re-observe them.
CREATE TABLE scan_finding (
    tenant_id   text NOT NULL REFERENCES tenant(id),
    scan_id     uuid NOT NULL,
    finding_id  uuid NOT NULL,
    PRIMARY KEY (scan_id, finding_id),
    FOREIGN KEY (tenant_id, scan_id) REFERENCES scan (tenant_id, id),
    FOREIGN KEY (tenant_id, finding_id) REFERENCES finding (tenant_id, id)
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['scan', 'scan_finding'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON %I
            USING (tenant_id = current_setting('app.tenant_id', true))
            WITH CHECK (tenant_id = current_setting('app.tenant_id', true))$p$, t);
    END LOOP;
END $$;

CREATE INDEX scan_engagement ON scan (tenant_id, engagement_id, created_at DESC);
CREATE INDEX finding_scan ON finding (tenant_id, scan_id);

GRANT SELECT, INSERT, UPDATE ON scan TO opt_app;
GRANT SELECT, INSERT ON scan_finding TO opt_app;
