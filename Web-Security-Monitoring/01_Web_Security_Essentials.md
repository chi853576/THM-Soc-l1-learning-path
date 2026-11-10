# Web Security Essentials

**Nguồn học:** [TryHackMe – Web Security Essentials](https://tryhackme.com/room/websecurityessentials)

## 1. Tổng quan về Web Security

Web application đã trở thành nền tảng cho nhiều dịch vụ như ngân hàng, thương mại điện tử, mạng xã hội và SaaS. Vì các ứng dụng này thường được public trên Internet và kết nối với database hoặc hệ thống backend, chúng là mục tiêu hấp dẫn đối với attacker.

Một web application bị khai thác có thể trở thành điểm truy cập ban đầu để attacker:
- Đánh cắp thông tin người dùng hoặc session.
- Đọc, thay đổi hoặc xóa dữ liệu trong database.
- Thực thi mã hoặc lệnh trên server.
- Duy trì quyền truy cập trái phép.
- Di chuyển sâu hơn vào hạ tầng nội bộ.

**Web security** không chỉ là bảo vệ website khỏi request độc hại. Cần bảo vệ đồng thời application, web server, host machine, dữ liệu và tài khoản quản trị.

## 2. Kiến trúc cơ bản của một Web Service

Một web service thường có ba thành phần chính:

| Thành phần | Vai trò | Rủi ro cần quan tâm |
|---|---|---|
| **Application** | Mã nguồn, logic nghiệp vụ, giao diện, API và xử lý input | XSS, SQL Injection, broken access control, command injection, lỗi xử lý file upload |
| **Web Server** | Nhận HTTP request và trả response; ví dụ Apache, Nginx, IIS | Cấu hình yếu, phiên bản lỗi thời, exposed admin interface, logging không đầy đủ |
| **Host Machine** | Hệ điều hành và môi trường chạy web server/application | Malware, quyền quá cao, dịch vụ không cần thiết, cấu hình hệ thống không an toàn |

### Request–response cycle

1. Browser/client gửi HTTP request đến web server.
2. Web server tiếp nhận request và chuyển tiếp đến application nếu cần.
3. Application kiểm tra input, xác thực người dùng, phân quyền và xử lý logic.
4. Application có thể truy vấn database hoặc gọi dịch vụ backend.
5. Server trả HTTP response về client.
6. Các hệ thống có thể ghi lại sự kiện trong access log, application log, WAF log hoặc network telemetry.

Attacker có thể lợi dụng bất kỳ bước nào: gửi input độc hại, vượt qua kiểm soát truy cập, gửi lượng request quá lớn hoặc khiến server thực thi thao tác ngoài dự kiến.

## 3. Web Server phổ biến

| Web server | Đặc điểm |
|---|---|
| **Apache HTTP Server** | Web server phổ biến, thường gặp trên Linux và các website dùng PHP/WordPress |
| **Nginx** | Web server/reverse proxy hiệu năng cao, thường dùng để phục vụ nội dung hoặc chuyển tiếp request đến application server |
| **Microsoft IIS** | Web server của Microsoft, thường gặp trong môi trường Windows Server và ứng dụng ASP.NET |

Khi điều tra, cần xác định web server và nền tảng thực tế vì vị trí log, format log, process name và đường dẫn web root khác nhau theo môi trường.

## 4. Những nguyên tắc bảo vệ Web Application

### 4.1 Secure coding
- Xử lý lỗi an toàn, không trả stack trace hoặc thông tin nội bộ cho người dùng.
- Tránh hàm/API nguy hiểm nếu không cần thiết.
- Không hard-code password, API key hoặc secret trong source code.
- Sử dụng thư viện và framework còn được hỗ trợ.
- Review code và kiểm thử bảo mật trong vòng đời phát triển.

### 4.2 Input validation và output encoding
- Xác định kiểu dữ liệu, độ dài và phạm vi hợp lệ cho từng input.
- Dùng allowlist khi có thể thay vì cố gắng liệt kê mọi chuỗi nguy hiểm.
- Encode output phù hợp với ngữ cảnh HTML, attribute, JavaScript hoặc URL để giảm nguy cơ XSS.
- Không xem input validation là biện pháp thay thế cho parameterized queries khi chống SQL Injection.

### 4.3 Access control
- Kiểm tra quyền ở phía server cho mọi request truy cập dữ liệu hoặc chức năng nhạy cảm.
- Áp dụng least privilege theo vai trò.
- Không dựa vào việc ẩn nút hoặc trang ở frontend để bảo vệ chức năng.
- Kiểm tra IDOR/broken access control: người dùng không được phép truy cập object của người khác chỉ bằng cách đổi ID trong URL/request.

### 4.4 Authentication và session
- Dùng mật khẩu mạnh, MFA cho tài khoản quan trọng và giới hạn thử đăng nhập.
- Bảo vệ session cookie bằng các thuộc tính phù hợp như `Secure`, `HttpOnly`, `SameSite`.
- Xoay vòng session sau khi đăng nhập hoặc thay đổi quyền khi phù hợp.
- Có cơ chế hết hạn, thu hồi session và phát hiện đăng nhập bất thường.

### 4.5 Database security
- Dùng prepared statements/parameterized queries.
- Tài khoản database của application chỉ có quyền cần thiết.
- Không để database public trực tiếp ra Internet nếu không có lý do và kiểm soát phù hợp.
- Ghi audit log cho truy cập và thay đổi dữ liệu quan trọng.

### 4.6 File upload
- Chỉ cho phép loại file cần thiết.
- Kiểm tra extension, MIME type và file signature; không tin riêng tên file do client gửi.
- Đổi tên file bằng tên do server tạo.
- Lưu file upload ngoài web root hoặc trong storage không thực thi script.
- Giới hạn kích thước, giải nén và thời gian xử lý.
- Quét malware và xử lý trong môi trường phù hợp.
- Không cấp quyền thực thi cho thư mục upload.

## 5. Bảo vệ Web Server và Host Machine

### Web Server
- Tắt directory listing và các module không cần thiết.
- Xóa trang mặc định, file test, backup và admin endpoint không sử dụng.
- Bật HTTPS/TLS và cấu hình certificate phù hợp.
- Giới hạn method, endpoint và nguồn truy cập theo nhu cầu nghiệp vụ.
- Bật access log và error log với trường cần thiết.
- Đặt reverse proxy/WAF/CDN khi phù hợp.

### Host Machine
- Chạy dịch vụ web bằng tài khoản có quyền thấp, không chạy bằng root/Administrator nếu không cần.
- Cập nhật OS, web server, runtime, framework và dependency.
- Tắt dịch vụ/port không sử dụng.
- Bật endpoint protection, EDR và file integrity monitoring khi có thể.
- Quản lý secret an toàn.
- Sao lưu và kiểm tra khả năng phục hồi.

## 6. Web Access Logs và giá trị đối với SOC

Access log ghi nhận các request được gửi đến web server. Các trường thường hữu ích:

| Trường | Ý nghĩa | Giá trị điều tra |
|---|---|---|
| Client IP (`c-ip`) | IP nguồn quan sát được | Nhóm request theo nguồn; lưu ý có thể là proxy/NAT |
| Date/Time | Thời điểm request | Xây dựng timeline và phát hiện burst |
| Method (`GET`, `POST`...) | HTTP method | Nhận diện hành vi truy cập hoặc gửi dữ liệu |
| URI stem/path | Đường dẫn được yêu cầu | Tìm endpoint nhạy cảm, file bất thường, scanning |
| URI query | Query string | Tìm tham số hoặc payload đáng ngờ nếu cấu hình có log |
| Status code | Kết quả xử lý HTTP | Phân tích 2xx, 3xx, 4xx, 5xx theo chuỗi |
| Bytes sent/received | Dữ liệu gửi/nhận | Phát hiện response hoặc request bất thường |
| User-Agent | Client khai báo | Nhận diện tool hoặc client bất thường; dễ giả mạo |
| Referrer | Trang dẫn đến request | Hỗ trợ dựng luồng điều hướng |
| Time taken | Thời gian xử lý | Phát hiện request chậm hoặc server bị quá tải |

### Ví dụ luồng truy cập bình thường
1. Client truy cập `/index.html` bằng `GET`.
2. Client mở `/login`.
3. Người dùng gửi thông tin qua `POST`.
4. Server phản hồi và chuyển hướng đến trang tài khoản.
5. Người dùng truy cập dữ liệu được cấp quyền.

SOC có thể dùng log để dựng lại luồng tương tự trong điều tra. Tuy nhiên, log cần được đọc theo chuỗi và theo baseline, không đánh giá một dòng độc lập.

## 7. CDN (Content Delivery Network)

CDN phân phối nội dung từ các edge server gần người dùng hơn, giảm độ trễ và giảm tải cho origin server.

### Lợi ích bảo mật
- **Origin IP protection:** giúp che giấu địa chỉ IP origin trong kiến trúc được cấu hình đúng.
- **DDoS absorption/mitigation:** hấp thụ và lọc một lượng lớn traffic trước khi đến origin.
- **TLS termination/enforcement:** hỗ trợ quản lý HTTPS.
- **WAF integration:** nhiều CDN tích hợp tính năng lọc request.
- **Caching:** giảm số request phải xử lý trực tiếp tại origin.

**Lưu ý:** CDN không thay thế việc bảo vệ origin. Nếu origin IP bị lộ và có thể truy cập trực tiếp, attacker có thể bỏ qua lớp CDN/WAF. Cần giới hạn origin chỉ nhận traffic từ các nguồn proxy/CDN được phép.

## 8. Web Application Firewall (WAF)

WAF kiểm tra HTTP/HTTPS request để phát hiện, ghi log, challenge hoặc chặn những request có dấu hiệu độc hại.

### Các kiểu triển khai

| Loại WAF | Vị trí triển khai | Đặc điểm |
|---|---|---|
| Cloud-based / Reverse proxy | Nằm trước origin server | Dễ mở rộng, lọc traffic trước khi đến máy chủ |
| Host-based | Cài trên máy chủ hoặc cùng môi trường ứng dụng | Kiểm soát ở cấp host/application |
| Network-based | Thiết bị vật lý/ảo tại biên mạng | Phù hợp một số kiến trúc doanh nghiệp |

### Các phương pháp phát hiện
- **Signature-based:** khớp request với mẫu/payload đã biết.
- **Heuristic-based:** đánh giá cấu trúc và ngữ cảnh request.
- **Anomaly/behavior-based:** phát hiện hành vi lệch baseline, ví dụ login attempts tăng đột ngột.
- **IP reputation/threat intelligence:** dựa vào nguồn đã biết có rủi ro.
- **Custom rules:** rule riêng cho endpoint, method, header, IP, tần suất hoặc điều kiện nghiệp vụ.

WAF có thể block, log, rate-limit hoặc đưa ra challenge như CAPTCHA/JavaScript challenge. Rule quá chặt có thể gây false positive và chặn người dùng hợp pháp; cần theo dõi tác động trước khi áp dụng chế độ block rộng.

## 9. Antivirus và Endpoint Protection

Antivirus/EDR chủ yếu bảo vệ endpoint và host khỏi file hoặc process độc hại. Trong web environment, chúng có thể hỗ trợ phát hiện:
- File độc hại được upload.
- Web shell hoặc post-exploitation tool.
- Process bất thường do web server khởi chạy.
- Thay đổi file hệ thống hoặc file ứng dụng ngoài dự kiến.

AV không thay thế secure coding, WAF, logging hay least privilege. Cần defense in depth.

## 10. Defense in Depth – cách nhìn của SOC

| Lớp | Kiểm soát | Telemetry nên thu thập |
|---|---|---|
| Application | Input validation, parameterized query, access control | Application/security logs |
| Web server | Hardening, patching, access/error logging | Access log, error log, process telemetry |
| Host | Least privilege, EDR, file integrity monitoring | Process, file, authentication, endpoint alerts |
| Network/edge | Firewall, CDN, WAF, rate limiting | WAF events, flow logs, DNS, firewall logs |
| Identity | MFA, session controls, account monitoring | Authentication and audit logs |

## 11. Checklist bảo vệ website trước khi triển khai

- [ ] Application đã được review input handling, authentication và authorization.
- [ ] Database dùng parameterized queries và tài khoản quyền tối thiểu.
- [ ] File upload được kiểm tra và lưu ở vị trí không thực thi script.
- [ ] Web server và host đã cập nhật, hardening.
- [ ] Admin interface không public rộng rãi nếu không cần.
- [ ] HTTPS/TLS đã cấu hình.
- [ ] Access log, error log và application security log đã bật.
- [ ] Log được chuyển về nơi lưu trữ tập trung và bảo vệ khỏi chỉnh sửa.
- [ ] WAF/CDN/firewall rule đã được kiểm thử.
- [ ] Có alert cho login abuse, scanning, upload bất thường, process lạ và traffic spike.
- [ ] Có backup, incident response plan và người chịu trách nhiệm xử lý.

## 12. Kỹ năng đạt được

- Hiểu kiến trúc cơ bản của web service và luồng HTTP request–response.
- Phân biệt vai trò application, web server và host machine.
- Nhận biết các lớp kiểm soát như secure coding, access control, CDN, WAF, AV/EDR.
- Hiểu giá trị của access log đối với việc dựng timeline và điều tra.
- Có thể trình bày cách bảo vệ web application theo hướng defense in depth.

## Tài liệu tham khảo

- [TryHackMe – Web Security Essentials](https://tryhackme.com/room/websecurityessentials)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [Microsoft – W3C Logging](https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging)
