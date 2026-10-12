# Verification — điền trước khi nộp

- **OS / Python / Gitleaks version:** Windows / Python 3.11.9 / Gitleaks v8.30.1
- **`python -m pytest tests/ -q`:** 33 passed in 2.75s (100% pass, 0 failed, 0 skipped)
- **`pre-commit run --all-files`:** Passed (`Detect hardcoded secrets... Passed`)
- **Ledger verify:** True (`python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`)
- **attack-after.log size:** 0 bytes (`(Get-Item reports/attack-after.log).Length` -> 0)
- **Các lỗi còn lại:** Không có (0 lỗi)

---

## Checkpoint 1 — Baseline Reading
- Đã phân tích hàm `_naive_loop()` và trả lời 3 câu hỏi trong `reports/baseline.md`:
  - Chưa có identity / context kiểm quyền mỗi run (`agent/loop.py:27`).
  - Không có cổng kiểm quyền trước `http_post`, kẻ tấn công điều khiển luồng qua prompt injection trong ticket (`agent/loop.py:39, 44`).
  - Body POST tạo tại `agent/loop.py:44`, sink ghi nhận tại `reports/sink.log` (`sink/sink.py:45-47`).

---

## Checkpoint 2 — Red Team & Injection Lures
- Đã tạo đủ 4 biến thể lure trong `corpus/`: `ticket-901.md`, `ticket-902.md`, `ticket-903.md`, `ticket-904.md` + `ticket-904b.md`.
- Lệnh kiểm tra: `python -m agent.check_lure corpus/ticket-90*.md` -> **4/4 lure sẵn sàng**.
- `reports/attack-before.log` ghi lại 4 lượt gửi thành công dữ liệu synthetic của `KH-000999` ra sink.

---

## Checkpoint 3a — PII Detection & Redaction
- **Lệnh thực thi:** `python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp` -> **PASSED (2/2)**
- **Kết quả đo lường:**
  - `gold`: 118, `pred`: 118, `tp`: 118
  - `precision`: 1.000 (100%), `recall`: 1.000 (100%) — Đạt band điểm tối đa theo RUBRIC (>95% đạt 10/10 điểm).
- **Giới hạn của Regex trong bài toán thực tế:**
  1. *Phụ thuộc ngữ cảnh từ khóa*: Cần tiền tố nhận diện (`STK`, `số tài khoản`) để phân biệt số tài khoản (8–16 số) với SĐT và CCCD.
  2. *Thiếu xác thực ngữ nghĩa và Checksum*: Chỉ so khớp độ dài và mẫu chuỗi, không kiểm tra mã hành chính/tỉnh thành của CCCD hay đầu số viễn thông thực tế.
  3. *Dễ bị né tránh bởi biến thể*: Các kỹ thuật can thiệp chuỗi (zero-width space, viết số bằng chữ, ký tự đặc biệt) có thể gây False Negatives nếu không kết hợp với mô hình NER.

---

## Checkpoint 3b & 3c — Policy PEP & On-Behalf-Of (OBO)
- **Kiểm thử Policy:** `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp` -> **PASSED (4/4)**
  - Cấm tuyệt đối egress khi data classification là restricted.
- **Kiểm thử OBO:** `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp` -> **PASSED (5/5)**
  - `support_l1` bị deny khi gọi `read_customer`, `dpo` được phép đọc khách gắn với ticket hợp lệ.
  - Agent con không thể mở rộng quyền vượt `parent_scopes`.

---

## Checkpoint 3d & 3e — Trifecta Split & Audit Ledger
- **Kiểm thử Trifecta Split:** `python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp` -> **PASSED (1/1)**
  - `KH-000777` xuất hiện trong free text của attacker nhưng không bao giờ bị đọc vì không nằm trong `related_tickets` của nguồn tin cậy (`customers.json`).
- **Kiểm thử Chặn Injection:** `python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp` -> **PASSED (8/8)**
  - Cả 4 biến thể lure dưới cả 2 principal đều an toàn, không có rò rỉ.
- **Kiểm thử Audit Ledger:** `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp` -> **PASSED (3/3)**
  - Ledger chuỗi hash SHA-256 tamper-evident phát hiện mọi hành vi sửa đổi.
  - `reports/ledger.jsonl` có dòng `tool="http_post", decision="deny"` với lý do cấm egress cho dữ liệu restricted, `verify()` trả về `True`.

---

## Checkpoint 4 — Supply Chain & Secrets
- Scanner: Gitleaks v8.30.1.
- Quét lịch sử: `gitleaks git --config .gitleaks.toml --redact .` -> Exit code 1, phát hiện đúng token giả tại commit `1bdd849` với rule `lab24-synthetic-token`.
- Quét file hiện tại: `gitleaks dir --config .gitleaks.toml --redact .` -> Exit code 0, không có leak (đã allowlist `.venv/` để loại trừ false positive từ thư viện bên thứ ba).
- Lockfile hash: `requirements.lock` được sinh bằng `pip-compile --generate-hashes` và cài đặt xác thực thành công qua `pip install --require-hashes`.
- Hook pre-commit: Đã cấu hình `.pre-commit-config.yaml` dùng `gitleaks-system` pinned `v8.30.1`, pass_filenames: false. Chạy `pre-commit run --all-files` đạt `Passed`.
- Unit test: `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp` -> **PASSED (3/3)**.
- Báo cáo sự cố: Hoàn thành đầy đủ trong `reports/secrets-incident.md`.

---

## Checkpoint 5 — Prove & Documentation
- Toàn bộ testsuite: `python -m pytest tests/ -q --basetemp=.pytest_tmp` -> **33 passed in 2.75s**.
- Chạy agent với `--as dpo`: Tạo `reports/attack-after.log` với kích thước đúng **0 bytes** (đối chiếu với `reports/attack-before.log` chứa 4 request leak).
- Báo cáo tuân thủ: Hoàn thành `reports/compliance-mapping.md` đối chiếu Luật 91/2025/QH15, NĐ 356/2025/NĐ-CP, Luật AI 134/2025/QH15, OWASP ASI01/03/04 kèm trích dẫn file:dòng thật và giới hạn.
- Đánh giá tác động DPIA: Hoàn thành `reports/dpia-lite.md` trả lời 4 câu hỏi về luồng dữ liệu, mục đích, cơ chế kiểm soát và giới hạn môi trường học tập.
