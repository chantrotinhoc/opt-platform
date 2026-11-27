-- Application role. NOLOGIN here; each environment grants LOGIN + password
-- (dev: deploy/dev/10_dev_login.sql; prod: from OpenBao). The role is NOT the
-- table owner and has no BYPASSRLS, so Row-Level Security always applies to it.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opt_app') THEN
        CREATE ROLE opt_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END $$;
