# ADR 0004 — LLM kết hợp cloud và local

- Trạng thái: Chấp nhận (27/11/2026, Dr. Đẳng)

## Quyết định

Model router định tuyến theo độ nhạy dữ liệu và loại tác vụ. Dữ liệu restricted hoặc local_only không bao giờ đến cloud; khi cloud lỗi được chuyển sang local, không có chiều ngược lại.
