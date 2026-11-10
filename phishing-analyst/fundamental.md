# Phishing Analysis Fundamentals

**Nguồn học:** [TryHackMe – Phishing Analysis Fundamentals](https://tryhackme.com/room/phishingemails1tryoe)

## Task 1: Introduction

### 1. Phishing là gì?

**Phishing** là hình thức tấn công sử dụng social engineering để lừa người dùng tiết lộ thông tin nhạy cảm, cung cấp thông tin đăng nhập, nhấp vào liên kết độc hại hoặc mở file chứa malware.

Một email phishing có thể giúp attacker:
- Đánh cắp credentials.
- Cài đặt malware.
- Chiếm quyền truy cập ban đầu vào hệ thống.
- Thực hiện các hành vi gian lận.

### 2. Mục tiêu của phishing analysis

- Hiểu cách email được gửi và nhận.
- Phân tích email headers.
- Kiểm tra email body, hyperlinks và attachments.
- Nhận diện các loại phishing.
- Thu thập indicators để đánh giá email là benign hay malicious.

---

## Task 2: The Email Address

### 1. Cấu trúc địa chỉ email

Ví dụ: `david@tryhackme.com`

| Thành phần | Ý nghĩa |
|---|---|
| `david` | Username — xác định mailbox của người dùng. |
| `@` | Phân cách username và domain. |
| `tryhackme.com` | Domain — xác định miền email liên quan. |

Có thể hình dung domain là tòa nhà, còn username là hộp thư của một người trong tòa nhà đó.

### 2. Dấu hiệu đáng ngờ

Khi kiểm tra email người gửi, cần chú ý:
- Domain gần giống domain hợp pháp nhưng bị viết sai.
- Ký tự bị thay thế, chẳng hạn `0` thay cho `o`.
- Tên hiển thị của người gửi không khớp với địa chỉ email.
- Email giả mạo thương hiệu hoặc tổ chức đáng tin cậy.

**Lưu ý:** Địa chỉ trông hợp pháp chưa đủ để chứng minh email an toàn. Cần kiểm tra thêm header, domain và nội dung.

---

## Task 3: Email Delivery

Ba giao thức email quan trọng:

| Giao thức | Chức năng | Ghi nhớ |
|---|---|---|
| SMTP | Gửi và chuyển tiếp email | Sending |
| POP3 | Tải email về thiết bị | Downloading |
| IMAP | Đồng bộ email giữa máy chủ và thiết bị | Synchronizing |

### POP3 và IMAP khác nhau thế nào?

**POP3**
- Thường tải email về một thiết bị.
- Email đã tải có thể bị xóa khỏi server tùy cấu hình.
- Việc đồng bộ giữa nhiều thiết bị bị hạn chế hơn.

**IMAP**
- Email được lưu trên server.
- Nhiều thiết bị có thể truy cập cùng mailbox.
- Trạng thái và thư mục email có thể được đồng bộ.

**Ghi nhớ nhanh:** SMTP = gửi; POP3 = tải về; IMAP = đồng bộ.

---

## Task 4: Email Headers

### 1. Hai thành phần chính của email

- **Email header:** Metadata về người gửi, người nhận, thời gian và quá trình chuyển tiếp.
- **Email body:** Nội dung email, có thể là plain text hoặc HTML.

### 2. Các header cơ bản

| Header | Ý nghĩa |
|---|---|
| `From` | Địa chỉ người gửi được khai báo trong email. |
| `To` | Người nhận. |
| `Reply-To` | Địa chỉ nhận phản hồi nếu được chỉ định. |
| `Subject` | Tiêu đề email. |
| `Date` | Ngày giờ được ghi nhận cho email. |
| `Received` | Thông tin về các máy chủ đã xử lý/chuyển tiếp email. |
| `Return-Path` | Địa chỉ liên quan đến việc xử lý email bị trả lại. |
| `Authentication-Results` | Kết quả xác thực email do hệ thống nhận ghi lại. |
| `X-Originating-IP` | Header có thể chứa IP nguồn ban đầu, tùy hệ thống gửi. |

Không phải email nào cũng có đầy đủ mọi header trên.

### 3. Xem raw email source

Trong Thunderbird:

1. Mở file email cần kiểm tra.
2. Chọn **View → Message Source**.
3. Hoặc nhấn `Ctrl + U`.
4. Tìm các header và nội dung gốc để phân tích.

Raw source cung cấp nhiều thông tin hơn giao diện email thông thường, bao gồm các trường kỹ thuật và cấu trúc MIME.

### 4. Quy trình phân tích header

1. Kiểm tra `From` và `Reply-To`.
2. So sánh domain người gửi với tổ chức được nhắc đến.
3. Xem `Received` để hiểu đường đi của email.
4. Kiểm tra `X-Originating-IP` nếu có.
5. Đọc `Authentication-Results` để đánh giá các kết quả xác thực.
6. Đối chiếu thời gian, domain và các thông tin khác để tìm dấu hiệu bất thường.

### 5. Các cơ chế xác thực email

- **SPF:** Kiểm tra máy chủ gửi có được phép gửi email cho domain theo chính sách SPF hay không.
- **DKIM:** Kiểm tra chữ ký số để xác minh tính toàn vẹn của những phần email được ký và liên kết với domain ký.
- **DMARC:** Xác định chính sách xử lý và báo cáo dựa trên kết quả SPF/DKIM cùng cơ chế alignment với domain trong `From`.

Không nên kết luận email an toàn chỉ vì một kết quả xác thực thành công. Email hợp pháp bị chiếm quyền hoặc cấu hình sai vẫn có thể gây rủi ro.

---

## Task 5: Email Body

### 1. Plain text và HTML

**Plain text**
- Chỉ chứa nội dung văn bản.
- Ít thành phần định dạng hơn.

**HTML**
- Có thể chứa hình ảnh, hyperlinks, định dạng và các thành phần nhúng.
- Nội dung hiển thị có thể khác với URL đích thực tế hoặc cấu trúc trong source.

Khi phân tích phishing, không nên chỉ nhìn phần email được hiển thị. Hãy kiểm tra cả raw source.

### 2. Phân tích attachments

Ba header thường gặp trong một phần MIME chứa file đính kèm:

| Header | Chức năng |
|---|---|
| `Content-Type` | Mô tả loại nội dung, ví dụ `application/pdf`. |
| `Content-Disposition` | Cho biết nội dung được hiển thị trực tiếp hay đính kèm; có thể chứa tên file. |
| `Content-Transfer-Encoding` | Cho biết cách dữ liệu được mã hóa để truyền tải, ví dụ `base64`. |

Ví dụ:

```text
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64
```

Dữ liệu Base64 phía sau có thể đại diện cho nội dung file đính kèm. Có thể sử dụng CyberChef hoặc công cụ giải mã phù hợp để tái tạo file phục vụ phân tích.

### 3. An toàn khi kiểm tra email

- Không nhấp trực tiếp vào liên kết đáng ngờ.
- Không mở file đính kèm không đáng tin cậy trên máy cá nhân.
- Sử dụng môi trường lab hoặc sandbox phù hợp.
- Không thực thi file chỉ vì tên hoặc phần mở rộng trông hợp pháp.
- Defang URL, domain và địa chỉ email khi đưa indicators vào báo cáo.

---

## Task 6: Types of Phishing

### 1. Các loại email và hình thức phishing

| Loại | Đặc điểm |
|---|---|
| Spam | Email không được yêu cầu, gửi hàng loạt. |
| Malspam | Spam có nội dung hoặc mục đích độc hại. |
| Phishing | Giả mạo nguồn đáng tin cậy để lừa người nhận. |
| Spear phishing | Phishing nhắm mục tiêu cụ thể, thường được cá nhân hóa. |
| Whaling | Spear phishing nhắm đến lãnh đạo cấp cao như CEO hoặc CFO. |
| Smishing | Phishing qua SMS hoặc tin nhắn văn bản. |
| Vishing | Phishing qua cuộc gọi thoại. |

### 2. Dấu hiệu phổ biến của phishing

- **Spoofed From Address:** Địa chỉ người gửi bị giả mạo.
- **Urgency:** Tạo áp lực thời gian, đe dọa khóa tài khoản hoặc yêu cầu xử lý ngay.
- **Brand Impersonation:** Giả mạo logo, màu sắc hoặc danh tính tổ chức.
- **Grammar and Spelling Issues:** Lỗi chính tả hoặc cách diễn đạt bất thường; tuy nhiên, email phishing hiện đại có thể viết rất chuẩn.
- **Generic Content:** Lời chào chung chung như “Dear Customer”.
- **Hidden or Shortened Links:** Liên kết hiển thị khác đích đến hoặc bị rút gọn.
- **Malicious Attachments:** File đính kèm giả dạng tài liệu hợp pháp.

Không có dấu hiệu đơn lẻ nào luôn chứng minh email là phishing. Cần đánh giá tổng hợp nhiều indicators.

### 3. Defanging

**Defanging** là biến URL, domain hoặc email thành dạng khó nhấp nhầm khi ghi vào báo cáo.

Ví dụ:

```text
Original:
http://www.suspiciousdomain.com

Defanged:
hxxp[://]www[.]suspiciousdomain[.]com
```

Defanging giúp giảm nguy cơ người đọc vô tình truy cập tài nguyên độc hại.

### 4. Thực hành: Phân tích `email3.eml`

Trong room, cần mở file `email3.eml` ở thư mục `Email Samples` trên máy lab và kiểm tra raw message source.

Quy trình:

1. Xác định tổ chức bị giả mạo.
2. Ghi lại địa chỉ email người gửi.
3. Tìm `X-Originating-IP` và chuyển IP sang dạng defanged.
4. Tìm `Authentication-Results` và xác định mail server ghi nhận header này.
5. Đối chiếu các dấu hiệu để đánh giá email.

**Lưu ý:** Những giá trị cụ thể của email này phụ thuộc vào mẫu `email3.eml` trong lab. Không thể suy ra chính xác các câu trả lời chỉ từ phần mô tả room.

