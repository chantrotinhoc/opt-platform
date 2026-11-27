# Đóng góp

- Mọi commit cần dòng `Signed-off-by` theo Developer Certificate of Origin (`git commit -s`).
- Nhánh: `feature/<epic>-<mô-tả>`, PR vào `main`, cần ít nhất 1 người duyệt và CI xanh.
- Thay đổi chạm `policies/`, `apps/agent/opt_agent/router.py` hoặc `redaction.py`, hay migration RLS cần thêm người duyệt từ vai trò Security Lead.
- Không thêm phụ thuộc có giấy phép không tương thích AGPL-3.0; CI chạy kiểm tra giấy phép.
