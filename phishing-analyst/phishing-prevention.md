# Phishing Prevention


## Task 1: Introduction

Phishing là một trong những phương thức phổ biến để attacker giành initial access vào hệ thống. Tổ chức cần kết hợp các biện pháp xác thực email, lọc nội dung, phân tích traffic và nâng cao nhận thức người dùng để giảm thiểu rủi ro.

### Learning objectives
- Hiểu các cơ chế bảo vệ email: SPF, DKIM, DMARC và S/MIME.
- Phân tích SMTP responses và email content.
- Tìm hiểu các biện pháp phát hiện, ngăn chặn phishing.

**MITRE ATT&CK – Software Configuration:** `M1054`

---

## Task 2: Sender Policy Framework (SPF)

### 1. SPF là gì?

**SPF (Sender Policy Framework)** là cơ chế xác thực email cho phép domain công bố những máy chủ được phép gửi email thay mặt domain đó.

SPF trả lời câu hỏi: *Máy chủ này có được phép gửi email cho domain đang được kiểm tra không?*

### 2. Cách SPF hoạt động

1. Mail server nhận email và xác định domain cần kiểm tra.
2. Tra cứu SPF record trong DNS.
3. So sánh IP của máy chủ gửi với các quy tắc trong record.
4. Trả về kết quả xác thực để hệ thống nhận quyết định cách xử lý email.

SPF record được công bố dưới dạng DNS TXT record.

### 3. Cấu trúc SPF record

Ví dụ:

```text
v=spf1 ip4:127.0.0.1 include:_spf.google.com -all
```

| Thành phần | Ý nghĩa |
|---|---|
| `v=spf1` | Khai báo phiên bản SPF. |
| `ip4:127.0.0.1` | Cho phép IP này gửi email. |
| `include:_spf.google.com` | Tham chiếu chính sách SPF của domain được chỉ định. |
| `-all` | Đánh dấu các nguồn không khớp là không được phép. |

Các qualifier thường gặp:

- `+`: Pass — cho phép.
- `-`: Fail — không cho phép.
- `~`: SoftFail — không được phép nhưng mức xử lý có thể mềm hơn.
- `?`: Neutral — không đưa ra kết luận rõ ràng.

### 4. SPF results

| Kết quả | Ý nghĩa |
|---|---|
| `Pass` | IP gửi phù hợp với chính sách SPF. |
| `Fail` | IP gửi không được SPF cho phép. |
| `SoftFail` | IP không được phép nhưng được đánh dấu ở mức mềm hơn. |
| `Neutral` | Domain không đưa ra kết luận xác thực rõ ràng. |
| `None` | Không tìm thấy SPF record phù hợp. |
| `PermError` | Lỗi cấu hình hoặc cú pháp khiến việc đánh giá không thể hoàn tất. |
| `TempError` | Lỗi tạm thời khi thực hiện kiểm tra. |

Kết quả SPF không tự chứng minh email an toàn hay độc hại. Cần kết hợp với DKIM, DMARC và các bằng chứng khác.

### 5. Công cụ phân tích SPF

- [dmarcian SPF Surveyor](https://dmarcian.com/spf-survey/) — kiểm tra và trực quan hóa SPF record.
- [Google Admin Toolbox](https://toolbox.googleapps.com/) — hỗ trợ kiểm tra email và header.

**Đáp án tham khảo của room:**
- Số domain được ủy quyền trong SPF record minh họa: `3`.
- Hành động mong đợi với `SoftFail`: `flag`.

---

## Task 3: DomainKeys Identified Mail (DKIM)

### 1. DKIM là gì?

**DKIM (DomainKeys Identified Mail)** sử dụng chữ ký số để hỗ trợ xác minh tính toàn vẹn của email và liên kết thông điệp với domain ký.

DKIM trả lời câu hỏi: *Email có chữ ký hợp lệ không, và những phần được ký có bị thay đổi không?*

### 2. Cách DKIM hoạt động

1. Máy chủ gửi tạo chữ ký bằng private key.
2. Chữ ký được thêm vào email qua header `DKIM-Signature`.
3. Máy chủ nhận lấy public key tương ứng từ DNS.
4. Máy chủ nhận xác minh chữ ký.
5. Kết quả được ghi nhận trong quá trình xác thực email.

DKIM thường dùng các DNS TXT record có selector để tìm public key.

Ví dụ dạng record:

```text
v=DKIM1; k=rsa; p=<public_key>
```

| Thành phần | Ý nghĩa |
|---|---|
| `v=DKIM1` | Phiên bản DKIM. |
| `k=rsa` | Thuật toán khóa được khai báo. |
| `p=` | Public key dùng để xác minh chữ ký. |

### 3. DKIM và email forwarding

SPF kiểm tra IP máy chủ gửi nên có thể thất bại khi email được chuyển tiếp qua một máy chủ khác.

DKIM kiểm tra chữ ký trên thông điệp. Vì vậy, chữ ký có thể vẫn hợp lệ sau khi forwarding nếu các phần được ký không bị thay đổi.

### 4. DKIM failure

Các kết quả thường gặp:
- `pass`: Chữ ký xác minh thành công.
- `fail`: Chữ ký không hợp lệ.
- `permerror`: Lỗi khiến việc xác minh không thể hoàn tất.

Nguyên nhân có thể bao gồm:
- Thiếu hoặc sai DKIM DNS record.
- Public key không tồn tại.
- Chữ ký không hợp lệ.
- Nội dung được ký bị thay đổi.
- Cấu hình DKIM sai.

**Đáp án tham khảo của room:**

Lý do gây `permerror` trong header mẫu:

`no key for signature`

---

## Task 4: Domain-Based Message Authentication, Reporting, and Conformance (DMARC)

### 1. DMARC là gì?

**DMARC (Domain-based Message Authentication, Reporting, and Conformance)** kết hợp kết quả SPF và DKIM với cơ chế **alignment** để giúp domain owner xác định cách xử lý email giả mạo.

DMARC trả lời câu hỏi: *Domain hiển thị trong email có phù hợp với domain đã được xác thực hay không, và nên xử lý email thất bại thế nào?*

### 2. Alignment

Alignment kiểm tra sự phù hợp giữa domain trong header `From` và domain được SPF hoặc DKIM xác thực.

DMARC có thể pass khi ít nhất một trong hai điều kiện sau được đáp ứng cùng alignment tương ứng:
- SPF pass và SPF alignment pass.
- DKIM pass và DKIM alignment pass.

### 3. DMARC record

Ví dụ:

```text
v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com
```

| Thành phần | Ý nghĩa |
|---|---|
| `v=DMARC1` | Phiên bản DMARC. |
| `p=quarantine` | Chính sách đề xuất đưa email thất bại vào spam/quarantine. |
| `rua=` | Địa chỉ nhận báo cáo DMARC tổng hợp. |

### 4. Ba chính sách DMARC

| Policy | Chức năng |
|---|---|
| `p=none` | Chỉ giám sát và thu thập dữ liệu. |
| `p=quarantine` | Đề xuất xử lý email thất bại như spam hoặc quarantine. |
| `p=reject` | Đề xuất từ chối email thất bại. |

Mức độ thực thi tăng dần:

`none → quarantine → reject`

**Ghi nhớ:** DMARC cung cấp chính sách xử lý và báo cáo; cách thực thi cuối cùng còn phụ thuộc vào hệ thống nhận.

### 5. So sánh SPF, DKIM và DMARC

- **SPF:** Kiểm tra máy chủ gửi có được domain cho phép không.
- **DKIM:** Xác minh chữ ký và tính toàn vẹn của các phần email được ký.
- **DMARC:** Kiểm tra alignment và xác định chính sách xử lý email.

**Đáp án tham khảo của room:** `p=reject`

---

## Task 5: Secure/Multipurpose Internet Mail Extensions (S/MIME)

### 1. S/MIME là gì?

**S/MIME (Secure/Multipurpose Internet Mail Extensions)** là tiêu chuẩn dùng chữ ký số và mã hóa để bảo vệ nội dung email.

Khác với SPF, DKIM và DMARC chủ yếu xác thực domain và nguồn gửi, S/MIME hỗ trợ bảo vệ tính xác thực, toàn vẹn và tính bảo mật của thông điệp.

### 2. Digital signatures

Chữ ký số hỗ trợ:
- **Authentication:** Xác minh danh tính người ký thông qua chứng thư số.
- **Integrity:** Phát hiện thay đổi đối với thông điệp đã ký.
- **Non-repudiation:** Hỗ trợ bằng chứng về việc ký, tùy thuộc vào độ tin cậy của khóa và quy trình sử dụng.

### 3. Encryption

Mã hóa bảo vệ tính bảo mật của nội dung email.

Trong quy trình mã hóa khóa công khai:
1. Người gửi sử dụng public key của người nhận để mã hóa nội dung.
2. Người nhận sử dụng private key tương ứng để giải mã.
3. Chỉ bên có khóa giải mã phù hợp mới đọc được nội dung.

### 4. S/MIME và các cơ chế khác

| Công nghệ | Trọng tâm |
|---|---|
| SPF | Quyền gửi của máy chủ. |
| DKIM | Chữ ký và tính toàn vẹn của email. |
| DMARC | Alignment và chính sách xử lý. |
| S/MIME | Chữ ký số và mã hóa nội dung email. |

S/MIME bổ sung cho SPF, DKIM và DMARC chứ không thay thế chúng.

**Đáp án tham khảo của room:** `Encryption`

---

## Task 6: Analyzing SMTP Responses

### 1. SMTP response codes

SMTP server trả về mã phản hồi để thông báo trạng thái của thao tác gửi email.

| Nhóm mã | Ý nghĩa chung |
|---|---|
| `2xx` | Thao tác thành công. |
| `3xx` | Cần thêm thông tin hoặc bước tiếp theo. |
| `4xx` | Lỗi tạm thời; có thể thử lại. |
| `5xx` | Lỗi hoặc từ chối vĩnh viễn đối với thao tác hiện tại. |

Ví dụ:
- `220`: Service ready.
- `250`: Requested mail action okay, completed.
- `354`: Start mail input.
- `450`: Mailbox unavailable hoặc lỗi tạm thời tương tự.
- `550`: Requested action not taken; thường liên quan đến mailbox không khả dụng hoặc bị từ chối.
- `552`: Thao tác bị từ chối do vượt giới hạn lưu trữ hoặc vì lý do chính sách/security tùy thông báo cụ thể.
- `553`: Thao tác bị từ chối do mailbox name hoặc địa chỉ không được chấp nhận.

Cần đọc cả mã và phần thông báo, vì cùng một mã có thể được dùng trong các tình huống khác nhau.

### 2. Phân tích SMTP bằng Wireshark

Mở file `traffic.pcap` trên máy lab.

Các display filter:

```text
smtp
```

Hiển thị traffic SMTP.

```text
smtp.response.code eq 220
```

Lọc các gói có SMTP response code `220`.

```text
smtp.response.code eq 552
```

Lọc các gói có SMTP response code `552`.

Có thể dùng **Find Packet** để tìm chuỗi `spamhaus.org`, sau đó xem response code và thông báo liên quan.

### 3. Kết quả thực hành tham khảo

| Câu hỏi | Kết quả |
|---|---|
| Wireshark filter cho SMTP response codes | `smtp.response.code` |
| Số packet có mã `220` | `19` |
| Response code khi email bị chặn liên quan đến Spamhaus | `553` |
| Full response message | `Requested action not taken: mailbox name not allowed (553)` |
| Số message bị chặn với mã `552` | `6` |

Các con số trên phụ thuộc vào file PCAP của room.

---

## Task 7: Inspecting Emails and Attachments

### 1. Internet Message Format (IMF)

**IMF (Internet Message Format)** là định dạng cấu trúc nội dung email, bao gồm các trường như:
- `From`
- `To`
- `Subject`
- `Date`
- Các header bổ sung.
- Nội dung email và các thành phần MIME.

Trong Wireshark, IMF có thể giúp analyst xem chi tiết email được truyền qua SMTP, bao gồm attachment và metadata.

### 2. Lọc SMTP và IMF

Dùng filter:

```text
smtp
```

Để hiển thị các packet SMTP.

```text
imf
```

Để lọc các packet được Wireshark nhận diện là Internet Message Format.

Để đi đến packet cụ thể:
1. Nhấn `Ctrl + G`.
2. Nhập số packet.
3. Xem phần packet details và mở các trường SMTP/IMF liên quan.

### 3. Attachment và MIME headers

Các trường quan trọng:

| Header | Chức năng |
|---|---|
| `Content-Type` | Xác định loại nội dung. |
| `Content-Disposition` | Cho biết nội dung được hiển thị hay đính kèm; có thể chứa filename. |
| `Content-Transfer-Encoding` | Cách dữ liệu được biểu diễn để truyền tải, chẳng hạn Base64. |
| `X-Mailer` | Có thể cho biết phần mềm email đã gửi thông điệp. |

Ví dụ:

```text
Content-Disposition: attachment; filename="document.zip"
Content-Transfer-Encoding: base64
```

Base64 là phương thức mã hóa biểu diễn dữ liệu, không phải mã hóa bảo mật. File được mã hóa Base64 vẫn có thể chứa nội dung độc hại.

### 4. Kết quả thực hành tham khảo

| Câu hỏi | Kết quả |
|---|---|
| Số packet SMTP trong capture | `512` |
| Attachment trong packet `270` | `document.zip` |
| Host IP không phản hồi trong thông báo lỗi | `212.253.25.152` |
| Email client trong mẫu có `attachment.scr` | `Microsoft Outlook Express 6.00.2600.0000` |
| Encoding của attachment đáng ngờ | `base64` |

**Lưu ý:** Không mở hoặc thực thi attachment được trích xuất từ PCAP. Hãy sử dụng môi trường phân tích an toàn.

---

## Task 8: How Organizations Stop Phishing

SPF, DKIM và DMARC là các lớp bảo vệ quan trọng nhưng không thể ngăn chặn mọi cuộc tấn công phishing. Tổ chức cần kết hợp nhiều biện pháp kỹ thuật và con người.

### 1. Technical defenses

**Email filtering**
- Kiểm tra IP/domain reputation.
- Phát hiện spam và email đáng ngờ.
- Chặn hoặc đưa email vào quarantine.

**Secure Email Gateway (SEG)**
- Kiểm tra email trước khi đến mailbox người dùng.
- Phát hiện spoofing, impersonation và các mẫu phishing.
- Áp dụng các chính sách bảo mật tập trung.

**Link rewriting**
- Thay URL gốc bằng một liên kết trung gian an toàn.
- Có thể kiểm tra đích đến khi người dùng nhấp vào.
- Hỗ trợ chặn hoặc cảnh báo nếu URL bị xác định là độc hại.

**Sandboxing**
- Mở file hoặc truy cập URL đáng ngờ trong môi trường cô lập.
- Quan sát hành vi mà không trực tiếp làm lây nhiễm hệ thống thật.
- Ghi nhận process, kết nối mạng và các hành vi đáng ngờ.

### 2. User-focused measures

**Trust and warning indicators**
- Hiển thị cảnh báo như `External Sender` hoặc `Suspicious Link`.
- Giúp người dùng nhận biết email đến từ bên ngoài hoặc có liên kết rủi ro.

**Phishing reporting**
- Cung cấp nút hoặc quy trình báo cáo email đáng ngờ.
- Cho phép SOC thu thập và điều tra các email bị báo cáo.

**User awareness training**
- Hướng dẫn người dùng nhận diện social engineering.
- Thực hành qua các phishing simulation có kiểm soát.
- Nhắc người dùng xác minh yêu cầu chuyển tiền, cung cấp credentials hoặc mở attachment.

### 3. Phòng thủ theo nhiều lớp

Một chiến lược hiệu quả kết hợp:

1. Xác thực domain bằng SPF, DKIM và DMARC.
2. Lọc email bằng SEG và reputation checks.
3. Kiểm tra URL và attachment bằng link rewriting, sandboxing.
4. Cảnh báo và đào tạo người dùng.
5. Cung cấp cơ chế báo cáo để SOC điều tra.
6. Theo dõi SMTP responses và log để cải thiện detection.


