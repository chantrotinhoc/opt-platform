# OPT — Offensive Pentest Orchestration Platform

Nền tảng SaaS đa tenant, mã nguồn mở (AGPL-3.0) cho kiểm thử xâm nhập có điều phối AI.
OPT kết hợp ba ý tưởng: pipeline recon khai báo bằng YAML (kiểu reNgine), agent AI có
người duyệt (kiểu CAI), và trải nghiệm workspace/báo cáo/lịch quét (kiểu Pentest-Tools).

> **Chỉ dùng trên hệ thống bạn sở hữu hoặc được ủy quyền bằng văn bản.** Xem [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).

## Nguyên tắc thiết kế

1. **Scope-first:** không lệnh nào chạy khi target nằm ngoài scope, ngoài khung giờ, hoặc RoE hết hạn.
2. **Human-in-the-loop theo rủi ro:** recon thụ động tự chạy; bước rủi ro trung bình trở lên chờ người duyệt.
3. **Dữ liệu nhạy cảm không rời hạ tầng:** model router gửi dữ liệu `local_only` sang LLM local, và che dữ liệu trước khi gọi cloud.
4. **Cách ly tenant:** PostgreSQL RLS, namespace Kubernetes riêng và khóa mã hóa riêng cho từng tenant.

## Cấu trúc

| Thư mục | Nội dung |
| --- | --- |
| `apps/api` | FastAPI: tenant, RBAC, engagement, Scope Guard, findings, báo cáo |
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
make up        # PostgreSQL (đã migrate + seed 2 tenant demo) và API tại http://localhost:8000
make smoke     # tạo engagement, kiểm tra scope, thử truy cập chéo tenant, kiểm tra chuỗi audit
# Giao diện OpenAPI: http://localhost:8000/docs
make down      # dừng và xóa dữ liệu dev
```

Ở sprint 1, tenant được truyền qua header `X-OPT-Tenant` (`demo-a` hoặc `demo-b`). Từ S2, tenant lấy từ token Keycloak.

Ví dụ:

```bash
curl -s -H 'X-OPT-Tenant: demo-a' -H 'Content-Type: application/json' \
  -X POST localhost:8000/api/v1/engagements \
  -d '{"name":"Lab","roe_valid_from":"2026-11-01T00:00:00Z","roe_valid_to":"2026-12-31T00:00:00Z",
       "rules":[{"kind":"domain","value":"lab.example.vn"}]}'
```

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
