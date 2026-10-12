# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Trong hàm `_naive_loop(message, llm)` tại `agent/loop.py:27`, đầu vào chỉ có `message` và đối tượng `llm`, hoàn toàn không có `agent_id`, `run_id` hay danh tính người dùng (`principal_id`) để kiểm tra quyền hạn. Dù hàm `run_once()` ở `agent/loop.py:57-58` nhận `principal_id`, tham số này hoàn toàn bị bỏ qua khi ủy quyền xuống `_naive_loop()` tại `agent/loop.py:74`.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Trước `http_post`, không có bất kỳ policy nào (PEP) kiểm tra mục đích, quyền hạn hay loại dữ liệu nhạy cảm được gửi. Kẻ tấn công cài prompt injection mới thực sự là bên quyết định: ticket vốn là dữ liệu nhưng baseline xử lý chỉ thị bên trong như lệnh, trực tiếp gọi `tools.read_customer()` tại `agent/loop.py:39` và `tools.http_post()` tại `agent/loop.py:44` mà chưa có cổng kiểm quyền. Hàm `http_post()` tại `agent/tools.py:76-83` chỉ kiểm tra URL thuộc localhost cứng chứ không quyết định hay kiểm soát dữ liệu nào được gửi.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Body POST được tạo trực tiếp tại dòng gọi hàm `agent/loop.py:44` với payload `{"records": collected}` chứa các bản ghi PII thu thập từ `read_customer()`. Việc sink đã nhận body đó được ghi lại trong file `reports/sink.log` bởi HTTP handler tại `sink/sink.py:45-47` (sau đó được lưu thành `reports/attack-before.log` làm bằng chứng).

