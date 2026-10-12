"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc CHECKPOINTS.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu một dòng còn trong file bị sửa mà không tính lại
        hash, nếu xoá/chèn giữa file làm đứt liên kết, hoặc thiếu reason.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64


def append(entry: dict, path: Path) -> dict:
    """Ghi thêm một bản ghi vào audit ledger kèm chuỗi hash chain."""
    record = dict(entry)
    path = Path(path)

    prev_hash = GENESIS_HASH
    if path.exists() and path.stat().st_size > 0:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                last_entry = json.loads(lines[-1])
                prev_hash = last_entry.get("hash", GENESIS_HASH)
            except Exception:
                prev_hash = GENESIS_HASH

    record["prev_hash"] = prev_hash
    record.pop("hash", None)

    serialized = json.dumps(record, sort_keys=True, ensure_ascii=False)
    entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    record["hash"] = entry_hash

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return record


def verify(path: Path) -> bool:
    """Xác minh tính toàn vẹn của file ledger theo chuỗi hash chain."""
    path = Path(path)
    if not path.exists():
        return True

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return True

    expected_prev_hash = GENESIS_HASH
    for line in lines:
        try:
            record = json.loads(line)
        except Exception:
            return False

        # 1. Bắt buộc có reason và không rỗng
        reason = record.get("reason")
        if not reason or not str(reason).strip():
            return False

        # 2. prev_hash phải khớp với hash dòng trước (hoặc genesis)
        if record.get("prev_hash") != expected_prev_hash:
            return False

        # 3. hash lưu phải khớp hash tính lại từ nội dung không bao gồm field hash
        stored_hash = record.get("hash")
        content_to_hash = {k: v for k, v in record.items() if k != "hash"}
        serialized = json.dumps(content_to_hash, sort_keys=True, ensure_ascii=False)
        computed_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        if computed_hash != stored_hash:
            return False

        expected_prev_hash = stored_hash

    return True
