# Secret giả trong lịch sử Git — điền trong checkpoint 4

- **Scanner và phiên bản:** Gitleaks v8.30.1 (`gitleaks version` -> `8.30.1`).
- **Commit chứa token giả:** Commit `1bdd849` (`1bdd849922156c868a5ee9293d68f5b72e242d2c`) do tác giả `VinUni AI20k Lab` tạo ngày 2026-10-09.
- **File, rule và kết quả quét lịch sử:**
  - File: `lab-fake-secret.txt` (dòng 1).
  - Rule: `lab24-synthetic-token` được cấu hình trong `.gitleaks.toml`.
  - Kết quả: Lệnh `gitleaks git --config .gitleaks.toml --redact .` phát hiện 1 leak (`leaks found: 1`), exit code 1. Đây là kết quả mong đợi cho bài tập phát hiện secret giả trong lịch sử Git.
- **Kết quả quét file hiện tại:**
  - Ở lần quét đầu tiên với `gitleaks dir --config .gitleaks.toml --redact .`, scanner báo 1 finding dạng `generic-api-key` tại `.venv/Lib/site-packages/setuptools/_distutils/msvccompiler.py` (dòng 45). Đây là false positive từ mã nguồn thư viện bên thứ ba trong môi trường ảo `.venv/`.
  - Cách xử lý: Đã bổ sung `[allowlist]` cho đường dẫn `^\.venv/` và `^\.venv\\` vào `.gitleaks.toml` mà không tắt rule chính hay bỏ qua repository.
  - Sau khi thêm allowlist, lệnh quét thư mục hiện tại báo sạch (`no leaks found`, exit code 0).
- **Nếu đây là credential thật, cần xử lý thế nào:**
  1. *Thu hồi và rotate ngay lập tức*: Thực hiện rotate / thu hồi (revoke) credential tại dịch vụ cấp phát (Identity Provider / API Service). Đây là biện pháp duy nhất làm vô hiệu token đã lộ.
  2. *Audit & Forensic*: Rà soát access logs và audit trails từ thời điểm secret bị commit để kiểm tra xem token đã bị kẻ tấn công khai thác hay truy cập dữ liệu trái phép chưa.
  3. *Làm sạch lịch sử*: Sử dụng các công cụ như `git-filter-repo` hoặc BFG Repo-Cleaner để loại bỏ credential khỏi toàn bộ lịch sử Git của repository, đồng thời cập nhật tất cả bản clone/mirror.
- **Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:**
  - *Xóa file khỏi HEAD*: Chỉ xóa file ở commit mới nhất, nhưng credential vẫn tồn tại nguyên vẹn trong commit cũ (`1bdd849`) của lịch sử Git. Bất kỳ ai clone repo đều có thể dùng `git log` hay `git checkout 1bdd849` để lấy secret.
  - *Pin dependency và hook*: Chỉ ngăn việc cài đặt package giả mạo hoặc chặn commit secret mới trong tương lai, không có khả năng vô hiệu hóa credential đã bị lộ ra ngoài. Secret chỉ mất hiệu lực khi được thu hồi tại server cấp quyền.
