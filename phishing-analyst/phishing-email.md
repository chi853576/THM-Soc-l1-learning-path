# Phishing Emails in Action

**Nguồn:** [TryHackMe – Phishing Emails in Action](https://tryhackme.com/room/phishingemails2rytmuv)

## Task 1: Introduction

### Mục tiêu
Thực hành phân tích email phishing thực tế, nhận diện các dấu hiệu giả mạo và hiểu cách attacker lừa người dùng tương tác với nội dung độc hại.

Các kỹ thuật chính:
- Email spoofing và brand impersonation.
- URL shortening, link manipulation và redirect chains.
- Tracking pixels.
- Credential harvesting.
- Malicious attachments.

**Cảnh báo:** Các mẫu trong room có dữ liệu từ email spam/phishing thực tế. Không tự truy cập domain, mở link hoặc thực thi attachment đáng ngờ trên máy cá nhân.

---

## Task 2: Cancel Your Order

### Kịch bản
Email giả mạo biên nhận giao dịch PayPal, thông báo một giao dịch mua gift card và cung cấp nút **Cancel the order** để dụ người nhận nhấp vào.

### Dấu hiệu đáng ngờ
- Subject tạo cảm giác khẩn cấp về một giao dịch giả.
- Display name giả mạo PayPal nhưng địa chỉ email thực tế thuộc domain khác.
- Địa chỉ người nhận bất thường.
- HTML và hình ảnh thương hiệu được sử dụng để tạo vẻ đáng tin cậy.
- Nút hủy đơn hàng dẫn đến URL rút gọn.

### Kỹ thuật tấn công

**URL shortening:** Dịch vụ rút gọn URL che giấu đích đến thực sự, khiến người dùng khó nhận biết website cuối cùng.

**Brand impersonation:** Giả mạo giao diện và thương hiệu PayPal để tăng độ tin cậy.

### Cách phân tích
1. So sánh display name với địa chỉ email thực tế.
2. Xem raw source để tìm `href` của nút bấm.
3. Kiểm tra URL rút gọn bằng công cụ phân tích redirect như WhereGoes.
4. Không trực tiếp truy cập đích đến độc hại.

**Ghi nhớ:** Nội dung trông giống hóa đơn thật không có nghĩa là email hợp pháp.

---

## Task 3: Track Your Package

### Kịch bản
Email giả mạo thông báo vận chuyển, sử dụng mã tracking để dụ người nhận kiểm tra tình trạng kiện hàng.

### Dấu hiệu đáng ngờ
- Subject chứa mã tracking nhằm kích thích người nhận nhấp vào.
- Display name `Distribution Center` không khớp với địa chỉ gửi `contact@beginpro.club`.
- Hyperlink hiển thị như một mã tracking nhưng đích đến thực tế đáng ngờ.
- Email chứa hình ảnh tracking pixel.

### Tracking pixel là gì?

Tracking pixel thường là hình ảnh rất nhỏ, có thể không nhìn thấy trong email. Khi hình ảnh được tải, máy chủ từ xa có thể ghi nhận các thông tin như thời điểm mở email và một số metadata liên quan.

Attacker có thể dùng thông tin này để:
- Xác nhận địa chỉ email đang hoạt động.
- Ước tính thời điểm nạn nhân mở email.
- Theo dõi tương tác của người nhận.

Nhiều email client chặn tải hình ảnh từ xa nhằm hạn chế tracking và bảo vệ quyền riêng tư.

### Cách phân tích
1. Kiểm tra địa chỉ người gửi thực tế.
2. Mở raw source và tìm các thẻ HTML như `<a>` và `<img>`.
3. Kiểm tra thuộc tính `href` của hyperlink.
4. Kiểm tra thuộc tính `src` của hình ảnh tracking.
5. Xác định root domain của URL và defang trước khi ghi vào báo cáo.

**Ví dụ indicator được ghi nhận trong walkthrough:**

`devret[.]xyz`

Đây là ví dụ về cách ghi domain ở dạng defanged, không phải khuyến nghị truy cập domain đó.

---

## Task 4: Download Document Here

### Kịch bản
Email giả mạo thông báo có tài liệu fax cần tải xuống. Email sử dụng nhiều thương hiệu quen thuộc để tạo cảm giác đáng tin cậy, sau đó chuyển nạn nhân qua nhiều website trước khi đến trang đánh cắp credentials.

### Chuỗi tấn công

<escape>Email phishing → OneDrive giả mạo → Trang Adobe giả mạo → Trang đăng nhập giả → Credential harvesting</escape>

### Dấu hiệu đáng ngờ
- Email tạo áp lực bằng thời hạn tải tài liệu trong ngày.
- Nút `Download Document Here` dẫn đến trang chia sẻ tài liệu giả.
- Trang tiếp theo tiếp tục giả mạo dịch vụ Adobe.
- URL đáng ngờ và hướng dẫn sử dụng thiếu hợp lý.
- Trang cuối yêu cầu đăng nhập bằng tài khoản email, chẳng hạn Outlook.

### Credential harvesting

**Credential harvesting** là hành vi thu thập thông tin xác thực như username và password thông qua trang đăng nhập giả hoặc các phương thức lừa đảo khác.

Trong ví dụ này, trang giả không thực sự xác thực tài khoản với nhà cung cấp email. Thay vào đó, credentials được gửi về phía attacker.

Ngay cả khi người dùng nhập đúng thông tin đăng nhập, trang vẫn có thể trả về thông báo lỗi chung chung.

### Kỹ thuật cần nhớ
- **Artificial urgency:** Tạo áp lực bằng thời hạn.
- **Brand impersonation:** Giả mạo Microsoft, OneDrive và Adobe.
- **Multi-stage redirection:** Chuyển hướng qua nhiều website.
- **Credential harvesting:** Thu thập username và password.

**Ghi nhớ:** Một chuỗi redirect có thể đi qua các dịch vụ hợp pháp nhưng vẫn kết thúc tại website độc hại. Cần kiểm tra từng bước và domain cuối cùng.

---

## Task 5: Your Account Is on Hold

### Kịch bản
Email giả mạo thông báo thanh toán Netflix gặp vấn đề và tài khoản có thể bị đình chỉ nếu người nhận không hành động.

### Dấu hiệu đáng ngờ
- Display name `Netllx billing` gần giống Netflix nhưng có lỗi chính tả.
- Email tạo cảm giác cấp bách bằng thông báo tài khoản bị tạm ngưng.
- HTML và logo được dùng để giả mạo giao diện Netflix.
- Email yêu cầu mở file PDF đính kèm để cập nhật thông tin thanh toán.
- PDF chứa liên kết `Update Payment Account` dẫn đến domain không thuộc Netflix.
- Số điện thoại có định dạng bất thường.
- Việc nhắc đến một trang hỗ trợ hợp pháp không chứng minh email là thật.

### Phân tích attachment
1. Kiểm tra tên file và loại file.
2. Mở PDF trong môi trường phân tích an toàn.
3. Xác định các hyperlink nhúng trong PDF.
4. So sánh domain đích với domain chính thức của dịch vụ.
5. Ghi nhận URL đáng ngờ và các dấu hiệu liên quan.

**Ghi nhớ:** File PDF không mặc nhiên an toàn. Một tài liệu trông bình thường vẫn có thể chứa hyperlink dẫn đến trang phishing.

---

## Task 6: Your Recent Purchase

### Kịch bản
Email giả mạo Apple Support thông báo có giao dịch đáng ngờ và yêu cầu người nhận hành động ngay.

Điểm đặc biệt là email có body trống và dựa chủ yếu vào attachment để dẫn nạn nhân đến trang phishing.

### Dấu hiệu đáng ngờ
- Display name `Apple Support` không khớp với địa chỉ gửi thực tế.
- Địa chỉ email có lỗi chính tả.
- Email sử dụng trường **BCC (Blind Carbon Copy)**.
- Subject tạo cảm giác khẩn cấp với nội dung `Action Required`.
- File đính kèm có phần mở rộng `.dot`, là định dạng Microsoft Word Template, không phù hợp với một biên nhận thông thường.

### BCC là gì?

**BCC — Blind Carbon Copy** cho phép gửi bản sao email đến người nhận mà không hiển thị địa chỉ của họ cho những người nhận khác trong danh sách thông thường.

BCC là chức năng hợp pháp, không phải bằng chứng phishing tự thân. Tuy nhiên, trong mẫu này, nó là một dấu hiệu cần xem xét cùng các bất thường khác.

### Phân tích attachment
- Kiểm tra định dạng `.dot`.
- Không mở hoặc thực thi file trực tiếp trên máy cá nhân.
- Kiểm tra nội dung tài liệu và các hyperlink nhúng.
- Xác định URL đích thực tế thay vì tin vào phần chữ hiển thị.
- Chú ý URL dài, phức tạp hoặc chứa các từ quen thuộc như `apps` và `ios` để tạo vẻ hợp pháp.

**Ghi nhớ:** Email body trống không có nghĩa email vô hại. Attachment có thể là thành phần chính của cuộc tấn công.

---

## Task 7: Scheduled Shipment

### Kịch bản
Email giả mạo DHL Express thông báo lịch vận chuyển. Người nhận được dẫn đến file Excel có liên kết nhằm tải và thực thi payload độc hại.

### Dấu hiệu đáng ngờ
- Display name `DHL Express` không khớp với domain người gửi.
- HTML và logo được dùng để giả mạo DHL.
- Attachment là file `.xlsx` có nội dung liên quan đến vận chuyển nhưng chứa những chi tiết mâu thuẫn.

### Dấu hiệu trong tài liệu
- Domain người gửi có liên quan đến Đức.
- Hóa đơn ghi địa điểm tại Ấn Độ.
- Nội dung tài liệu sử dụng tiếng Trung.
- Một hyperlink trong file dẫn đến bước tiếp theo của cuộc tấn công.

Những khác biệt về địa lý và ngôn ngữ không tự chứng minh malware, nhưng khi kết hợp với email giả mạo và hành vi tải executable, chúng trở thành các dấu hiệu đáng ngờ.

### Payload: `regasms.exe`

Khi nhấp vào liên kết trong Excel, tài liệu cố gắng tải và thực thi file `regasms.exe`. Trong môi trường được mô tả ở room, quá trình này gặp lỗi.

Nếu chạy thành công, payload có thể được sử dụng để:
- Thiết lập persistence, chẳng hạn backdoor hoặc scheduled task.
- Đánh cắp dữ liệu và credentials.
- Triển khai ransomware hoặc payload khác.

### Quy trình phân tích
1. Kiểm tra header và địa chỉ người gửi.
2. Kiểm tra attachment mà không thực thi.
3. Xác định các hyperlink trong file Excel.
4. Phân tích domain, URL và hành vi tải file.
5. Ghi nhận tên executable và hành vi dự kiến.
6. Nếu có thể, phân tích payload bằng sandbox hoặc môi trường malware analysis chuyên dụng.

**Ghi nhớ:** File Excel có thể đóng vai trò trung gian để dẫn nạn nhân đến executable độc hại.

