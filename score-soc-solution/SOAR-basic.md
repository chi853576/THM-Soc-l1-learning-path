# TryHackMe — SOAR Basics: Kiến thức cần nhớ

## 1. SOC truyền thống và những thách thức

**SOC (Security Operations Center)** là trung tâm giám sát và bảo vệ tài sản số của tổ chức, giúp phát hiện, điều tra và xử lý các sự cố bảo mật.

### Các năng lực chính của SOC

- **Monitoring and Detection:** Giám sát hệ thống, phát hiện hoạt động đáng ngờ, thường sử dụng SIEM.
- **Recovery and Remediation:** Khắc phục sự cố, cách ly endpoint nhiễm mã độc, chặn IP độc hại, vô hiệu hóa tài khoản.
- **Threat Intelligence (TI):** Thu thập thông tin về IP, domain, hash độc hại để hỗ trợ phát hiện và ngăn chặn mối đe dọa.
- **Communication:** Phối hợp với IT và ban quản lý, tạo ticket và theo dõi việc xử lý sự cố.

### Bốn thách thức của SOC

| Thách thức | Ý nghĩa |
|---|---|
| **Alert Fatigue** | Quá nhiều cảnh báo khiến analyst quá tải, có thể bỏ sót cảnh báo quan trọng. |
| **Too Many Disconnected Tools** | Nhiều công cụ hoạt động riêng lẻ, phải chuyển đổi liên tục giữa các giao diện. |
| **Manual Processes** | Điều tra và xử lý thủ công, phụ thuộc vào kinh nghiệm cá nhân. |
| **Talent Shortage** | Thiếu nhân lực có chuyên môn trong khi số lượng và độ phức tạp của mối đe dọa tăng lên. |

## 2. SOAR là gì?

**SOAR (Security Orchestration, Automation, and Response)** là giải pháp kết nối các công cụ bảo mật, tự động hóa quy trình điều tra và hỗ trợ thực hiện hành động ứng phó.

SOAR cung cấp giao diện tập trung để phối hợp các công cụ như SIEM, EDR, Firewall, Threat Intelligence và IAM. Nó cũng hỗ trợ quản lý case và ticket để ghi nhận, theo dõi và xử lý sự cố có hệ thống.

### Ba năng lực cốt lõi của SOAR

**1. Orchestration — Điều phối**

Kết nối các công cụ bảo mật và phối hợp chúng theo một quy trình thống nhất.

Ví dụ: Khi nhận cảnh báo VPN brute force, SOAR có thể truy vấn SIEM, kiểm tra danh tiếng IP qua Threat Intelligence và kiểm tra lịch sử đăng nhập.

**2. Automation — Tự động hóa**

Tự động thực hiện các bước đã được định nghĩa trước, giảm thao tác thủ công của analyst.

Ví dụ: Tự động truy vấn lịch sử đăng nhập, kiểm tra IP và tạo ticket nếu phát hiện dấu hiệu đáng ngờ.

**3. Response — Ứng phó**

Thực hiện hành động xử lý sự cố thông qua các công cụ đã tích hợp.

Ví dụ: Chặn IP trên firewall, vô hiệu hóa tài khoản qua IAM hoặc tạo ticket để điều tra.

### SOAR giải quyết thách thức của SOC như thế nào?

- Giảm khối lượng công việc lặp lại và tình trạng quá tải cảnh báo.
- Kết nối các công cụ bảo mật vốn hoạt động riêng lẻ.
- Chuẩn hóa quy trình điều tra và xử lý.
- Tiết kiệm thời gian, giúp analyst tập trung vào những sự cố phức tạp.

**Lưu ý:** SOAR không thay thế SOC analyst. Analyst vẫn cần xây dựng playbook, đánh giá ngữ cảnh, xử lý các trường hợp phức tạp và đưa ra quyết định quan trọng.

## 3. SOAR Playbook

**Playbook** là quy trình được định nghĩa trước, hướng dẫn SOAR thực hiện các bước điều tra và ứng phó với một loại cảnh báo cụ thể.

Playbook thường có các điều kiện và nhánh xử lý dạng *if/else*. Kết quả của một bước sẽ quyết định bước tiếp theo.

### Ví dụ: VPN Brute Force Playbook

1. SOAR nhận cảnh báo từ SIEM.
2. Kiểm tra lịch sử đăng nhập để xác định IP có quen thuộc với người dùng không.
3. Kiểm tra danh tiếng IP qua Threat Intelligence.
4. Kiểm tra có lần đăng nhập thành công nào sau các lần thất bại không.
5. Dựa vào kết quả, tiếp tục điều tra, tạo ticket hoặc thực hiện biện pháp containment phù hợp.

Không phải mọi cảnh báo đều cần xử lý giống nhau. Nếu IP quen thuộc và số lần thất bại ít, playbook có thể dừng sớm; nếu có dấu hiệu độc hại, quy trình có thể chuyển sang ứng phó.

## 4. Các loại Playbook trong room

### 4.1. Phishing Playbook

Mục tiêu: Tự động hỗ trợ điều tra email đáng ngờ và xử lý email lừa đảo.

Quy trình tổng quát:

1. Nhận cảnh báo **Suspicious email received**.
2. Tạo ticket để ghi nhận và theo dõi.
3. Kiểm tra email có URL hoặc file đính kèm không.
4. Nếu không có URL hay file đính kèm, thực hiện bước thông báo người dùng theo quy trình.
5. Nếu có URL hoặc file đính kèm, phân nhánh để phân tích nội dung và kiểm tra qua Threat Intelligence.
6. Nếu xác nhận email độc hại, thực hiện biện pháp khắc phục phù hợp.

Các bước cụ thể phụ thuộc vào kết quả phân tích và chính sách của tổ chức.

### 4.2. CVE Patching Playbook

**CVE (Common Vulnerabilities and Exposures)** là mã định danh cho một lỗ hổng bảo mật đã được công khai.

SOC cần theo dõi CVE mới, xác định hệ thống bị ảnh hưởng và phối hợp khắc phục trước khi lỗ hổng bị khai thác.

Quy trình tổng quát:

1. Tiếp nhận thông tin CVE mới.
2. Phân tích chi tiết và đánh giá mức độ rủi ro.
3. Xác định hệ thống có bị ảnh hưởng hay không.
4. Tạo ticket yêu cầu vá lỗi nếu cần.
5. Kiểm thử bản vá.
6. Triển khai vào môi trường production sau khi kiểm thử đạt yêu cầu.

Playbook giúp giảm thao tác thủ công, hạn chế tồn đọng công việc vá lỗi và chuẩn hóa quy trình quản lý lỗ hổng.

## 5. Phân biệt các khái niệm quan trọng

| Khái niệm | Vai trò chính |
|---|---|
| **SIEM** | Thu thập, phân tích và tương quan log để phát hiện sự kiện đáng ngờ. |
| **SOAR** | Kết nối công cụ, điều phối quy trình, tự động hóa điều tra và ứng phó. |
| **Playbook** | Quy trình định nghĩa các bước và điều kiện xử lý một loại cảnh báo. |
| **Ticket/Case Management** | Ghi nhận, phân công, theo dõi và quản lý tiến trình xử lý sự cố. |
| **Threat Intelligence** | Cung cấp thông tin về các mối đe dọa và chỉ dấu độc hại. |
