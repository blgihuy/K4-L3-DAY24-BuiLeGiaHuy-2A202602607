# DPIA-lite — điền trong checkpoint 5

1. **Loại dữ liệu và phân loại:**
   - *Nội dung Ticket hỗ trợ* (`corpus/*.md`): Dữ liệu nội bộ (`internal`) do khách hàng/người dùng gửi lên, có nguy cơ chứa prompt injection (untrusted content).
   - *Hồ sơ khách hàng* (`data/customers.json`): Dữ liệu hạn chế (`restricted`), chứa PII tổng hợp (CCCD 12 số, SĐT, STK ngân hàng, email, họ tên).
   - *Văn bản đầu ra cho người dùng*: Dữ liệu công khai/nội bộ sau khi đã chạy qua PII Redaction (`[REDACTED_<TYPE>]`).

2. **Mục đích xử lý và principal:**
   - *Mục đích hợp lệ*: `summarize-tickets` (tổng hợp trạng thái vé hỗ trợ tuần này), `support-reply` (hỗ trợ giải quyết khiếu nại khách hàng), `privacy-audit` (rà soát tuân thủ quyền riêng tư).
   - *Principal mô phỏng*:
     - `support_l1`: Nhân viên hỗ trợ L1, chỉ được phép gọi `search_docs` để tổng hợp ticket; bị cấm truy cập hồ sơ khách hàng nhạy cảm (`read_customer`).
     - `dpo`: Cán bộ bảo vệ dữ liệu (Data Protection Officer), được phép gọi `search_docs` và `read_customer` đối với các hồ sơ gắn liền với ticket hợp lệ.

3. **Dữ liệu đi qua những run/tool nào, endpoint nào:**
   - *Run A (Untrusted Context)*: Tiếp nhận câu hỏi người dùng -> gọi `search_docs` đọc toàn văn file `.md` trong `corpus/` -> trích xuất `ticket_id: int` duy nhất từ tên file -> che PII qua `pii.redact()` trước khi tóm tắt.
   - *Run B (Private Store)*: Nhận mảng `ticket_ids` đã được khử khuẩn -> tra cứu `related_tickets` trong `data/customers.json` để tìm `customer_id` -> kiểm tra PEP trước khi gọi `read_customer`.
   - *Policy Enforcement Point (PEP)*: Cổng kiểm tra tập trung, nhận `PolicyContext` trước mọi tool call (`search_docs`, `read_customer`, `http_post`).
   - *Endpoint gửi ra ngoài (Egress Sink)*: `http://127.0.0.1:10024/reconcile` (chỉ nghe trên localhost, hard-allowlist).
   - *Audit Ledger*: File `reports/ledger.jsonl` ghi vết từng tool call, bao gồm timestamp UTC, `on_behalf_of`, `run_id`, `tool`, `args_hash`, `decision` (allow/deny) và `reason`.

4. **Bằng chứng deny/allow và giới hạn của mock:**
   - *Bằng chứng kỹ thuật*:
     - `support_l1` bị deny khi cố đọc `read_customer`: Dòng deny ghi trong ledger, `tools.read_customer` không bị gọi.
     - `dpo` được allow đọc khách hàng hợp lệ gắn với ticket 901–905 (`KH-000999`).
     - Yêu cầu exfiltration tới sink bị PEP chặn đứng: Dòng `tool="http_post", decision="deny"` trong `reports/ledger.jsonl`.
     - File `reports/attack-after.log` hoàn toàn rỗng (0 bytes).
     - Test suite đạt 33/33 passed (`test_split.py`, `test_injection.py`, `test_obo.py`, `test_ledger.py`, `test_supply_chain.py`).
   - *Giới hạn của môi trường lab*:
     - MockLLM hoạt động dựa trên heuristic/marker so khớp sau chuẩn hóa, chưa phải là Large Language Model thực tế.
     - Cơ chế OBO dựa trên fixture mô phỏng tĩnh (`data/principals.json`), chưa tích hợp hệ thống xác thực AuthN/SSO thực tế (như OAuth2/OIDC/mTLS).
     - Regex PII Gate dựa vào cấu trúc và từ khóa ngữ cảnh; có thể gặp False Negatives với các biến thể văn bản tinh vi hoặc số tài khoản trần.
     - Hash chain cục bộ bảo đảm tính toàn vẹn bên trong file nhưng không chống được hành vi cắt đuôi dòng cuối nếu thiếu mốc thời gian ngoài (external WORM timestamp).
