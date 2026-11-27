# Test cách ly tenant

`test_tenant_isolation.py` chạy với PostgreSQL thật (job `db` trong CI, hoặc `make test-db` ở máy dev):

- Không đặt `app.tenant_id`: mọi bảng trả về 0 dòng với role `opt_app`.
- Tenant A không thấy, không sửa được và không chuyển được dữ liệu sang tenant B.
- API trả 404 khi tenant B gọi engagement của tenant A, và 403 với tenant không tồn tại.
- `audit_event` chỉ cho phép thêm; kể cả chủ bảng cũng bị trigger chặn UPDATE/DELETE.
- Role ứng dụng không tạo được tenant.

Đây là một phần của cổng G1; phần còn lại (egress gateway, Scope Guard ở tầng mạng) làm ở S3.
