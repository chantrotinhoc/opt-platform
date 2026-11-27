"""Scan report (Markdown). DOCX/PDF bilingual reports arrive in S7."""
from __future__ import annotations

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_VI = {"critical": "Nghiêm trọng", "high": "Cao", "medium": "Trung bình", "low": "Thấp", "info": "Thông tin"}


def _cell(value) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def render_markdown(tenant: str, engagement: dict, scan: dict, findings: list[dict]) -> str:
    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["title"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    lines = [
        f"# Báo cáo quét: {_cell(scan['target'])}",
        "",
        f"- Tenant: `{tenant}`",
        f"- Engagement: {_cell(engagement['name'])} (RoE {engagement['roe_valid_from']:%Y-%m-%d} – {engagement['roe_valid_to']:%Y-%m-%d})",
        f"- Engine: `{scan['engine']}` · Trạng thái: {scan['status']} · Người yêu cầu: {_cell(scan['requested_by'])}",
        f"- Bắt đầu: {scan['created_at']:%Y-%m-%d %H:%M %Z} · Kết thúc: "
        + (f"{scan['finished_at']:%Y-%m-%d %H:%M %Z}" if scan.get("finished_at") else "chưa xong"),
        "",
        "## Tóm tắt",
        "",
        "| Mức độ | Số lượng |",
        "| --- | --- |",
        *[f"| {SEVERITY_VI[s]} | {counts[s]} |" for s in SEVERITY_ORDER],
        "",
        "## Các bước",
        "",
        "| Bước | Kết quả |",
        "| --- | --- |",
    ]
    for step in scan.get("steps") or []:
        outcome = "hoàn thành" if step.get("ok") else ("bỏ qua: " + step["skipped"] if "skipped" in step
                                                         else "lỗi: " + str(step.get("error")))
        lines.append(f"| {_cell(step['step'])} | {_cell(outcome)} |")
    lines += ["", "## Phát hiện", ""]
    if not findings:
        lines.append("Không có phát hiện.")
    for i, f in enumerate(findings, 1):
        lines += [f"### {i}. {_cell(f['title'])}", "",
                  f"- Mức độ: {SEVERITY_VI[f['severity']]}" + (f" · {f['cwe']}" if f.get("cwe") else ""),
                  f"- Mục tiêu: {_cell(f['target'])} · Công cụ: `{f['source_tool']}`"]
        if f.get("description"):
            lines.append(f"- Mô tả: {_cell(f['description'])}")
        if f.get("evidence"):
            lines.append(f"- Bằng chứng: `{_cell(f['evidence'])}`")
        lines.append("")
    lines.append("_Báo cáo tạo tự động bởi OPT. Chỉ dùng trong phạm vi RoE đã ký._")
    return "\n".join(lines) + "\n"
