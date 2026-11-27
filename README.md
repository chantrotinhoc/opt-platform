# OPT — Offensive Pentest Orchestration Platform

Nền tảng SaaS đa tenant, mã nguồn mở (AGPL-3.0) cho kiểm thử xâm nhập có điều phối AI.
OPT kết hợp ba ý tưởng: pipeline recon khai báo bằng YAML (kiểu reNgine), agent AI có
người duyệt (kiểu CAI), và trải nghiệm workspace/báo cáo/lịch quét (kiểu Pentest-Tools).

> **Chỉ dùng trên hệ thống bạn sở hữu hoặc được ủy quyền bằng văn bản.** Xem [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

## Nguyên tắc thiết kế

Trạng thái ghi rõ cho từng nguyên tắc: **đã có** (có code và test trong repo) hoặc **dự kiến** (theo sprint plan).

1. **Scope-first (đã có ở API):** Scope Guard từ chối target ngoài scope, target chưa xác minh khi quét chủ động, RoE hết hạn, và quét chủ động ngoài khung giờ. Recon thụ động (OSINT) không bị giới hạn khung giờ. Kiểm soát tầng mạng qua egress gateway: dự kiến S3.
2. **Người duyệt theo rủi ro (đã có quy tắc + workflow):** bước rủi ro cao luôn chờ người duyệt; bước rủi ro trung bình chờ duyệt khi do agent AI đề xuất. Scope được kiểm tra lại sau khi duyệt.
3. **Dữ liệu nhạy cảm không rời hạ tầng (khung, dự kiến S6):** model router và lớp che dữ liệu đã có và có test, nhưng chưa gắn vào đường gọi LLM thật. Chưa nên coi là biện pháp bảo vệ đang hoạt động.
4. **Cách ly tenant:** PostgreSQL RLS đã có và có test trên PostgreSQL thật. Namespace Kubernetes, IP egress và khóa mã hóa riêng cho từng tenant: dự kiến (xem docs/onprem-deployment.md), Helm chart hiện chưa tạo các tài nguyên này.

## Cấu trúc

| Thư mục | Nội dung |
| --- | --- |
| `apps/api` | FastAPI: xác thực Keycloak, RBAC, engagement, Scope Guard, quét recon MVP, findings, báo cáo |
| `apps/worker` | Temporal worker chạy scan engine, adapter cho từng tool |
| `apps/agent` | Agent Planner/Reporter, model router cloud/local, lớp che dữ liệu |
| `apps/web` | Giao diện Next.js |
| `engines/` | Scan engine YAML và JSON Schema |
| `policies/` | Chính sách Rego cho OPA (Scope Guard) |
| `db/migrations` | Schema PostgreSQL có Row-Level Security |
| `deploy/` | Helm chart và hướng dẫn triển khai tại data center |
| `tests/` | Test cách ly tenant và an toàn LLM |
| `docs/` | Sprint plan, ADR, kiến trúc triển khai |

## Khởi động nhanh

Cần Docker (có Compose v2), `make`, `curl` và Python 3.12.

```bash
make up        # PostgreSQL (migrate + seed), Keycloak, API tại http://localhost:8000, mục tiêu lab
make smoke     # đăng nhập Keycloak, kiểm tra RBAC và scope, quét lab, đọc báo cáo, kiểm tra chuỗi audit
# Giao diện OpenAPI: http://localhost:8000/docs · Keycloak: http://localhost:8080 (admin / admin-dev)
make down      # dừng và xóa dữ liệu dev
```

API chỉ nhận token Keycloak (`Authorization: Bearer ...`). Tenant lấy từ nhóm `tenant-<id>` trong token, vai trò từ realm role: `opt-viewer` < `opt-tester` < `opt-lead` < `opt-owner`. Header `X-OPT-Tenant` của sprint 1 không còn tác dụng.

Tài khoản dev (realm `opt`, CHỈ DÙNG CHO DEV): `alice` / `alice-dev` (lead, demo-a), `victor` / `victor-dev` (viewer, demo-a), `bob` / `bob-dev` (lead, demo-b).

Luồng recon → báo cáo trên mục tiêu lab:

```bash
TOKEN=$(curl -s -X POST localhost:8080/realms/opt/protocol/openid-connect/token \
  -d grant_type=password -d client_id=opt-cli -d username=alice -d password=alice-dev | jq -r .access_token)
H=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
FROM=$(date -u -d '-1 day' +%FT%TZ); TO=$(date -u -d '+30 days' +%FT%TZ)   # RoE đang hiệu lực
EID=$(curl -s "${H[@]}" -X POST localhost:8000/api/v1/engagements \
  -d "{\"name\":\"Lab\",\"roe_valid_from\":\"$FROM\",\"roe_valid_to\":\"$TO\",
       \"rules\":[{\"kind\":\"domain\",\"value\":\"lab.example.vn\"}]}" | jq -r .id)
SID=$(curl -s "${H[@]}" -X POST localhost:8000/api/v1/engagements/$EID/scans \
  -d '{"target":"juice.lab.example.vn","engine":"lab-recon-v1"}' | jq -r .id)
until [ "$(curl -s "${H[@]}" localhost:8000/api/v1/scans/$SID | jq -r .status)" = done ]; do sleep 1; done
curl -s "${H[@]}" localhost:8000/api/v1/scans/$SID/report     # Markdown; thêm ?format=json để lấy JSON
```

Chỉ target **đã xác minh** và nằm trong scope mới được quét. Môi trường dev chỉ có mục tiêu lab `juice.lab.example.vn` (container `lab-web`, chỉ trong mạng compose). Tài sản production thật chỉ được thêm sau khi chủ tài sản ký RoE.

Temporal, OPA và MinIO (cần từ S3/S4): `docker compose -f docker-compose.dev.yml --profile full up -d`.

## Chạy test

```bash
pip install -r requirements-dev.txt
make test       # unit test, không cần dịch vụ nào
make test-db    # thêm test cách ly tenant trên PostgreSQL thật (sau `make up`)
```

## Tài liệu

- [Sprint plan MVP](docs/sprint-plan.md)
- [Triển khai tại data center](docs/onprem-deployment.md)
- [Quyết định kiến trúc (ADR)](docs/adr/)

## Giấy phép

AGPL-3.0-only. Các tool bên thứ ba được gọi như chương trình riêng và giữ giấy phép của chúng; xem [NOTICE](NOTICE).
