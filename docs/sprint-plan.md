# Sprint plan MVP (20 tuần, 10 sprint × 2 tuần)

Nguồn: Spec MVP nền tảng OPT. Đội tối thiểu 5 người, cộng Dr. Đẳng là Product Owner và kiến trúc sư an ninh.

## Phân vai

| Vai trò | Phụ trách chính | Epic dẫn dắt |
| --- | --- | --- |
| Tech Lead / Backend | FastAPI, mô hình dữ liệu, RLS, API, billing | E1, E5, E9 |
| Platform / DevOps | Kubernetes tại DC, CI/CD, Harbor, egress gateway, quan sát, sao lưu | Hạ tầng, HA/DR |
| Security Engineer | Scope Guard, OPA, scan engine YAML, tool adapter, lab kiểm thử, cổng G1/G3 | E2, E3, E4 |
| AI Engineer | Agent Planner/Reporter, model router, redaction, vLLM, test an toàn LLM | E6, E7 (phần nhập liệu AI) |
| Frontend | Next.js, luồng duyệt HITL, giao diện findings và báo cáo | E7, E8, UI các epic |
| Product Owner (Dr. Đẳng) | Ưu tiên backlog, nghiệm thu cổng, RoE mẫu, quan hệ khách hàng beta | — |

Nếu có người thứ 6, ưu tiên một QA/Backend để viết test cách ly tenant và hỗ trợ E5/E9.

## Sprint

| Sprint | Tuần | Mục tiêu | Cổng |
| --- | --- | --- | --- |
| S1 | 1–2 | Repo, CI, cụm K8s dev tại DC, Keycloak, khung API/web, schema RLS | |
| S2 | 3–4 | E1 tenant + RBAC, test cách ly trong CI, audit log chuỗi băm | |
| S3 | 5–6 | E2 engagement/RoE, OPA Scope Guard, egress gateway, E3 xác minh target | G1: 0 lệnh ngoài scope |
| S4 | 7–8 | Temporal + worker gVisor, adapter subfinder/httpx/katana/nuclei/naabu | |
| S5 | 9–10 | E4 đủ 3 engine, E5 Findings (chuẩn hóa, khử trùng, delta), chọn model local | |
| S6 | 11–12 | E6 model router + redaction, agent Planner + HITL | G2: an toàn LLM |
| S7 | 13–14 | Agent Reporter, E7 báo cáo DOCX/PDF song ngữ, E8 lịch quét | |
| S8 | 15–16 | E9 billing + quota, hoàn thiện UI, tài liệu API | |
| S9 | 17–18 | Hardening ASVS L2, pentest độc lập chính OPT | G3: 0 High/Critical |
| S10 | 19–20 | Beta 3–5 tenant thật, công bố mã AGPL-3.0, quy trình xử lý lạm dụng | |

## Sprint 1 — backlog chi tiết

| # | Hạng mục | Người | Tiêu chí xong |
| --- | --- | --- | --- |
| 1 | Scaffold monorepo, LICENSE, NOTICE, chính sách sử dụng | Tech Lead | PR này được merge |
| 2 | CI: pytest, OPA test, Trivy | DevOps | Pipeline xanh trên PR |
| 3 | Dựng cụm K8s dev (RKE2) tại DC ITSTARVN, Cilium, Harbor | DevOps | `kubectl get nodes` đủ 3 control-plane + 3 worker |
| 4 | Keycloak dev, realm mẫu, MFA bắt buộc | Tech Lead | Đăng nhập web bằng OIDC |
| 5 | Migration 0001 chạy được trên PostgreSQL thật; test cách ly bước 1–5 | Tech Lead + Security | Test cách ly xanh |
| 6 | Kiểm tra giấy phép CAI; ghi kết luận vào ADR-0003 | AI Engineer | ADR cập nhật |
| 7 | Dựng lab mục tiêu nội bộ (Juice Shop, DVWA) trong namespace riêng | Security | Lab truy cập được từ worker dev |
| 8 | Khung Next.js: layout, đăng nhập, trang engagement rỗng | Frontend | Chạy trên cụm dev |
| 9 | Hợp đồng RoE mẫu và mẫu KYC doanh nghiệp | Product Owner | Văn bản được pháp chế duyệt |

## Nghi thức

- Sprint planning thứ Hai tuần đầu, demo + retro thứ Sáu tuần thứ hai.
- Daily 15 phút. Definition of Done: test xanh, có người duyệt, không giảm độ phủ test của `scope.py`, `router.py`, `redaction.py`.
