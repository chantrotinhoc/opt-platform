# ADR-0006: Xác thực bằng Keycloak OIDC, tenant lấy từ token

- Trạng thái: chấp nhận (S2, 2026-11-27)

## Bối cảnh

Sprint 1 nhận tenant qua header `X-OPT-Tenant`, ai gửi header cũng chọn được tenant. Pilot tháng 12/2026 cần đăng nhập thật và phân quyền.

## Quyết định

- API chỉ nhận access token của realm `opt`, kiểm tra chữ ký qua JWKS, `iss`, `aud=opt-api`, `exp`. Thiếu cấu hình `OPT_OIDC_ISSUER` thì API trả 503 (fail closed).
- Tenant = nhóm duy nhất có dạng `tenant-<id>` trong claim `groups`. Không đúng một nhóm thì 403.
- Vai trò theo thứ bậc: `opt-viewer` (đọc) < `opt-tester` (quét, kiểm tra scope) < `opt-lead` (tạo engagement, duyệt bước medium) < `opt-owner`.
- Actor trong audit log là `preferred_username` của token thay cho chữ `api`.

## Hệ quả

- Realm dev (`deploy/dev/keycloak/opt-realm.json`) có client `opt-cli` cho phép password grant để chạy smoke test. Realm production KHÔNG bật password grant và bắt buộc MFA TOTP (việc của DevOps khi dựng Keycloak HA tại DC).
- Một người dùng thuộc nhiều tenant (MSSP) chưa hỗ trợ; xử lý ở S8 bằng chọn tenant trong phiên.
