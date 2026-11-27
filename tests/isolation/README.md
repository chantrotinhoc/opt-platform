# Test cách ly tenant (S2)

Chạy với PostgreSQL thật (service container trong CI), dùng role `opt_app`:

1. Tạo tenant A và B, mỗi tenant 1 engagement, 1 finding.
2. Với `app.tenant_id = 'a'`: SELECT trên mọi bảng chỉ thấy bản ghi của A.
3. INSERT bản ghi gắn `tenant_id = 'b'` khi đang là A phải bị từ chối (WITH CHECK).
4. Không đặt `app.tenant_id`: mọi SELECT trả về 0 dòng.
5. UPDATE/DELETE trên `audit_event` phải bị từ chối.

Cổng G1 yêu cầu bộ test này xanh trong CI.
