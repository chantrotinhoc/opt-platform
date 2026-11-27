-- DEV ONLY: two demo tenants so isolation can be seen end to end.
INSERT INTO tenant (id, name, plan, data_residency, kms_key_id) VALUES
    ('demo-a', 'Demo tenant A', 'starter', 'cloud_ok', 'dev-key-a'),
    ('demo-b', 'Demo tenant B', 'starter', 'local_only', 'dev-key-b');

-- Verified targets (in production verification happens through E3).
INSERT INTO target (tenant_id, value, verify_method, verified_at) VALUES
    ('demo-a', 'juice.lab.example.vn', 'dns_txt', now()),
    ('demo-b', 'dvwa.lab.example.vn', 'dns_txt', now());
