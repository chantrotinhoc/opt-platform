# Triển khai OPT tại data center ITSTARVN

OPT chạy SaaS đa tenant trên Kubernetes tự quản tại data center trong nước do ITSTARVN sở hữu.
Thiết kế ưu tiên: dữ liệu khách hàng ở lại Việt Nam, cách ly tenant ở mọi lớp, và có thể khôi phục khi mất một site.

## Kiến trúc vật lý (đề xuất, cần khảo sát lại năng lực DC)

| Thành phần | Site chính | Ghi chú |
| --- | --- | --- |
| Kubernetes control plane | 3 node, đặt trên 3 rack/nguồn điện khác nhau | RKE2 (cấu hình CIS hardened) |
| Worker chung (api, web, agent) | ≥ 3 node | |
| Worker quét | ≥ 3 node, VLAN riêng | gVisor, chỉ ra ngoài qua egress gateway |
| GPU cho LLM local | 2 node GPU, mỗi node ≥ 2 GPU 48 GB (ước lượng, chốt sau đánh giá model ở S5) | vLLM, namespace `opt-ai` |
| Lưu trữ | Ceph (Rook) 3 node hoặc SAN sẵn có | Block cho PostgreSQL, object qua MinIO |
| Mạng | Cilium (NetworkPolicy, egress gateway), MetalLB hoặc LB phần cứng | Dải IP public riêng cho egress |
| Registry | Harbor trong DC, chỉ nhận image đã ký cosign | |

## Dịch vụ nền

| Dịch vụ | Cách chạy | HA |
| --- | --- | --- |
| PostgreSQL 16 | CloudNativePG, 1 primary + 2 replica (1 đồng bộ) | Tự failover |
| Temporal | Cụm 3 frontend/history/matching, lưu trên PostgreSQL | |
| Keycloak | 2 replica, DB riêng | |
| OpenBao/Vault | 3 node Raft, auto-unseal bằng HSM nếu DC có | Khóa Transit theo tenant |
| MinIO | 4 node, erasure coding, object lock cho evidence + audit | |
| Quan sát | Prometheus, Grafana, Loki, OpenTelemetry | Cảnh báo về SOC OpenLAB |

## Cách ly tenant

1. **Dữ liệu:** PostgreSQL RLS (`db/migrations/0001_init.sql`), khóa mã hóa riêng trong OpenBao, prefix bucket riêng trên MinIO.
2. **Tính toán:** namespace worker riêng cho mỗi tenant, ResourceQuota theo gói, không mount service account token.
3. **Mạng:** NetworkPolicy chặn mọi lưu lượng chéo namespace; Cilium egress gateway gán IP public riêng cho tenant. Nhờ vậy khách hàng whitelist được IP quét, và mọi khiếu nại lạm dụng truy được về đúng tenant.
4. **LLM:** tenant `local_only` chỉ dùng vLLM trong DC; lời gọi cloud đi qua proxy ra ngoài có ghi log, sau khi đã che dữ liệu.

## HA/DR

| Chỉ tiêu | Mục tiêu MVP |
| --- | --- |
| Khả dụng API/UI | 99,5%/tháng |
| RPO (mất dữ liệu tối đa) | 15 phút |
| RTO (thời gian khôi phục) | 4 giờ |

- Trong site: mọi dịch vụ ≥ 2 replica, trải trên rack khác nhau; Temporal giữ trạng thái quét nên job tiếp tục sau khi pod khởi động lại.
- Sao lưu: CloudNativePG gửi WAL liên tục + base backup hằng ngày sang MinIO ở site dự phòng; Velero sao lưu tài nguyên K8s; OpenBao snapshot mỗi giờ (mã hóa).
- Site dự phòng: tối thiểu một cụm nhỏ ở địa điểm thứ hai (DC khác của ITSTARVN hoặc đối tác trong nước) nhận bản sao lưu; diễn tập khôi phục mỗi quý.
- Khóa mã hóa và bản sao lưu khóa phải nằm ở cả hai site; mất khóa đồng nghĩa mất dữ liệu tenant.

## Tuân thủ (cần pháp chế ITSTARVN xác nhận theo văn bản hiện hành)

- **Lưu trữ dữ liệu trong nước:** đặt toàn bộ dữ liệu khách hàng tại DC trong nước đáp ứng yêu cầu lưu trữ tại Việt Nam theo Luật An ninh mạng 2018 và Nghị định 53/2022/NĐ-CP.
- **Dữ liệu cá nhân:** Nghị định 13/2023/NĐ-CP và Luật Bảo vệ dữ liệu cá nhân mới. Cần đánh giá tác động xử lý dữ liệu cá nhân, và đánh giá việc chuyển dữ liệu ra nước ngoài nếu gọi LLM cloud ở nước ngoài. Việc che dữ liệu giảm rủi ro nhưng không thay được bước đánh giá này.
- **Cấp độ an toàn hệ thống thông tin:** đề xuất xác định OPT ở cấp độ 3 theo Luật An toàn thông tin mạng 2015 và Nghị định 85/2016/NĐ-CP, áp dụng các yêu cầu kỹ thuật tương ứng.
- **Kinh doanh dịch vụ kiểm tra, đánh giá ATTT:** cung cấp pentest dạng dịch vụ có thể cần giấy phép kinh doanh sản phẩm, dịch vụ an toàn thông tin mạng (Nghị định 108/2016/NĐ-CP và văn bản sửa đổi). Cần kiểm tra ITSTARVN đã có giấy phép phù hợp chưa.
- **Quốc tế (cho khách hàng nước ngoài sau này):** ISO/IEC 27001:2022, SOC 2.

## Hệ quả vận hành

- ITSTARVN tự chịu vá lỗi K8s, hệ điều hành, firmware và GPU driver. Cần lịch bảo trì hằng tháng và trực on-call 24/7 từ khi có khách beta.
- Năng lực GPU là chi phí cố định lớn nhất; theo dõi mức dùng để quyết định khi nào mua thêm hoặc giảm.
- Dải IP egress của OPT sẽ xuất hiện trong log IDS của khách hàng. Cần đăng ký thông tin liên hệ lạm dụng (abuse contact) trong WHOIS và có quy trình phản hồi.
