# ADR 0002 — SaaS đa tenant ngay từ MVP

- Trạng thái: Chấp nhận (27/11/2026, Dr. Đẳng)

## Quyết định

Cách ly bằng PostgreSQL RLS + namespace K8s + khóa theo tenant + IP egress riêng. Đánh đổi: MVP kéo dài từ 12 lên 20 tuần.
