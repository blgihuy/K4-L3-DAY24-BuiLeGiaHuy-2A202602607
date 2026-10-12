# Verification — điền trước khi nộp

- OS / Python / Gitleaks version:
- `python -m pytest tests/ -q`:
- `pre-commit run --all-files`:
- Ledger verify: True (`python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`)
- Các lỗi còn lại:

## Checkpoint 3a — PII Detection & Redaction

- **Lệnh thực thi:**
  ```bash
  python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp
  ```
- **Kết quả đo lường:**
  - `gold`: 118
  - `pred`: 118
  - `tp`: 118
  - `precision`: 1.000 (100%)
  - `recall`: 1.000 (100%) — Đạt mức tối đa theo RUBRIC (>95% đạt 10/10 điểm)
- **Giới hạn của Regex trong bài toán thực tế:**
  1. *Phụ thuộc ngữ cảnh từ khóa*: Để phân biệt STK (8–16 số) với SĐT (10 số) và CCCD (12 số), regex cần dựa vào tiền tố nhận diện (`STK`, `số tài khoản`). Nếu người dùng chỉ cung cấp số tài khoản trần không có nhãn chỉ thị, regex sẽ không nhận diện được hoặc nhận diện sai loại thực thể.
  2. *Thiếu xác thực ngữ nghĩa và Checksum*: Regex chỉ kiểm tra độ dài và mẫu chuỗi ký tự (CCCD 12 chữ số, SĐT bắt đầu bằng 0/84), không thể xác thực cấu trúc hành chính thực tế (mã tỉnh, năm sinh, giới tính của CCCD) hay đầu số viễn thông thực tế của nhà mạng Việt Nam.
  3. *Dễ bị né tránh bởi định dạng biến thể*: Khi gặp các kỹ thuật biến đổi văn bản (chèn zero-width spaces, teencode, viết số bằng chữ, ký tự leet, ngắt dòng bất thường), regex sẽ bỏ sót (False Negatives). Các hệ thống production cần kết hợp regex với mô hình NER (như Transformer/GLiNER) để xử lý ngữ cảnh đa dạng.

## Checkpoint 3d & 3e — Trifecta Split, OBO & Audit Ledger

- **Kiểm thử Trifecta Split:** `python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp` -> **PASSED (1/1)**
  - `KH-000777` xuất hiện trong free text của attacker nhưng không bao giờ bị đọc vì không nằm trong `related_tickets` của nguồn tin cậy (`customers.json`).
  - DPO vẫn đọc được các khách hàng hợp lệ gắn với ticket.
- **Kiểm thử Chặn Injection sau Containment:** `python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp` -> **PASSED (8/8)**
  - Cả 4 biến thể lure dưới 2 principal (`support_l1`, `dpo`) đều được kiểm soát an toàn, PII không rò rỉ ra sink.
- **Kiểm thử Audit Ledger & Hash Chain:** `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` -> **PASSED (3/3)**
  - Ledger chuỗi hash SHA-256 tamper-evident hoạt động chuẩn xác: phát hiện sửa dòng, xóa reason.
  - File `reports/ledger.jsonl` thật được tạo bởi `python -m agent.loop --mock --as dpo` chứa đầy đủ log tool calls, có dòng `tool="http_post", decision="deny"` với lý do cấm egress cho dữ liệu restricted, và `verify()` trả về `True`.


