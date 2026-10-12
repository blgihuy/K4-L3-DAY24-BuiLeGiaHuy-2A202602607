"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).
"""
from __future__ import annotations

import re

# Regex patterns nhận diện 4 loại PII đặc thù
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_RE = re.compile(
    r"(?i:\b(?:stk|số\s+tài\s+khoản|so\s+tai\s+khoan|tài\s+khoản|tai\s+khoan)\b[:\s#]*?)(\d{8,16})(?!\d)"
)
CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
PHONE_RE = re.compile(
    r"(?<!\d)(?:(?:\+84\s*|0\d)\d{2}[\s.-]?\d{3}[\s.-]?\d{3}|0\d{9})(?!\d)"
)


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII (CCCD, SĐT, STK, Email) trong text.

    Trả về danh sách {"type": ..., "start": ..., "end": ...} đã sắp xếp
    theo thứ tự xuất hiện và không bị chồng lấn (overlap).
    """
    entities: list[dict] = []
    occupied: set[int] = set()

    # 1. VN_BANK_ACCOUNT: nhận diện trước CCCD và PHONE vì STK có độ dài linh hoạt (8-16 số)
    # và có thể trùng độ dài 10 hoặc 12 số nhưng có từ khóa STK đi kèm.
    for m in BANK_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if not any(i in occupied for i in range(s, e)):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": s, "end": e})
            occupied.update(range(s, e))

    # 2. EMAIL: email có thể chứa số trong local-part nên xử lý trước phone/cccd.
    for m in EMAIL_RE.finditer(text):
        s, e = m.start(), m.end()
        if not any(i in occupied for i in range(s, e)):
            entities.append({"type": "EMAIL", "start": s, "end": e})
            occupied.update(range(s, e))

    # 3. VN_CCCD: 12 chữ số liên tiếp không nằm trong số dài hơn.
    for m in CCCD_RE.finditer(text):
        s, e = m.start(), m.end()
        if not any(i in occupied for i in range(s, e)):
            entities.append({"type": "VN_CCCD", "start": s, "end": e})
            occupied.update(range(s, e))

    # 4. VN_PHONE: 10 chữ số bắt đầu bằng 0 (hoặc +84).
    for m in PHONE_RE.finditer(text):
        s, e = m.start(), m.end()
        if not any(i in occupied for i in range(s, e)):
            entities.append({"type": "VN_PHONE", "start": s, "end": e})
            occupied.update(range(s, e))

    # Sắp xếp theo vị trí ký tự tăng dần
    entities.sort(key=lambda x: (x["start"], x["end"]))
    return entities


def redact(text: str) -> str:
    """Che mọi thực thể PII phát hiện được bằng [REDACTED_<TYPE>].

    Thay thế từ cuối văn bản về đầu để offset các vùng chưa xử lý không bị lệch.
    """
    entities = detect(text)
    # Duyệt ngược từ cuối về đầu
    for ent in sorted(entities, key=lambda x: x["start"], reverse=True):
        replacement = f"[REDACTED_{ent['type']}]"
        text = text[: ent["start"]] + replacement + text[ent["end"] :]
    return text
