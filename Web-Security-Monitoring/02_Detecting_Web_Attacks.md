# Detecting Web Attacks

**Nguồn học:** [TryHackMe – Detecting Web Attacks](https://tryhackme.com/room/detectingwebattacks)

## 1. Mục tiêu phát hiện Web Attacks

Web application thường là hệ thống public và kết nối với database/backend. Một cuộc tấn công web có thể bắt đầu từ thao tác của người dùng, request đến server hoặc lỗ hổng trong logic ứng dụng.

Đối với SOC Analyst, nhiệm vụ là:
- Phân biệt dấu hiệu client-side và server-side attack.
- Phân tích access/error/application logs.
- Kiểm tra HTTP traffic trong PCAP.
- Tương quan bằng chứng từ nhiều nguồn.
- Đánh giá mức độ ảnh hưởng và đề xuất xử lý.
- Hiểu vai trò của WAF trong detection và mitigation.

## 2. Client-Side Attacks

Client-side attack nhắm vào browser, thiết bị hoặc hành vi người dùng. Một số hoạt động có thể diễn ra bên trong browser mà server-side logs không ghi nhận đầy đủ.

### 2.1 Cross-Site Scripting (XSS)

**XSS** xảy ra khi ứng dụng đưa dữ liệu không đáng tin cậy vào trang web mà không encode/sanitize phù hợp, khiến script độc hại được thực thi trong browser của người dùng.

Các dạng phổ biến:
- **Stored XSS:** payload được lưu ở server/database và thực thi khi người dùng khác tải nội dung.
- **Reflected XSS:** payload được gửi trong request và phản chiếu ngay trong response.
- **DOM-based XSS:** lỗi xảy ra trong xử lý DOM phía client.

Rủi ro:
- Đánh cắp hoặc lạm dụng session.
- Thực hiện hành động dưới danh nghĩa người dùng.
- Thay đổi nội dung hiển thị hoặc chuyển hướng người dùng.
- Thu thập dữ liệu trong browser.

**Dấu hiệu có thể quan sát:**
- Request chứa chuỗi HTML/JavaScript đáng ngờ trong query hoặc body.
- WAF alert về XSS pattern.
- Application log ghi nhận input bất thường.
- CSP violation reports hoặc browser/endpoint telemetry.
- Những request tiếp theo từ session/người dùng bị ảnh hưởng.

**Giới hạn:** server logs có thể ghi payload gửi lên, nhưng không nhất thiết cho biết script đã chạy thành công trong browser. Cần browser telemetry, CSP reporting hoặc endpoint investigation để xác minh.

### 2.2 Cross-Site Request Forgery (CSRF)

CSRF lợi dụng việc browser tự động gửi cookie/session của người dùng đến website đã đăng nhập. Attacker lừa browser gửi một request mà người dùng không chủ ý thực hiện.

Dấu hiệu điều tra có thể gồm:
- Request thay đổi trạng thái không phù hợp với hoạt động người dùng.
- Thiếu hoặc không hợp lệ CSRF token nếu hệ thống ghi nhận.
- Origin/Referer không phù hợp, tùy ứng dụng.
- Hành động nhạy cảm xảy ra trong session hợp lệ nhưng không có hoạt động người dùng tương ứng.

Các biện pháp bảo vệ gồm CSRF token, kiểm tra Origin/Referer phù hợp và cookie `SameSite`. SOC cần hiểu chính sách của ứng dụng trước khi xem một request thiếu header nào đó là độc hại.

### 2.3 Clickjacking

Clickjacking lừa người dùng tương tác với thành phần giao diện bị che phủ hoặc đặt chồng lên nội dung trông có vẻ hợp pháp.

Biện pháp phòng vệ thường gồm:
- `Content-Security-Policy: frame-ancestors ...`
- `X-Frame-Options` trong môi trường phù hợp.
- Thiết kế UI và xác nhận lại các hành động nhạy cảm.

**Hạn chế detection:** clickjacking có thể không tạo ra request bất thường rõ ràng ở server. Cần browser telemetry, CSP reports và endpoint/user reports.

## 3. Server-Side Attacks

Server-side attack khai thác lỗi trong web server, application code hoặc hệ thống backend. Những request được gửi đến server thường để lại bằng chứng trong access logs, application logs hoặc network traffic.

### 3.1 Brute Force và Credential Stuffing

- **Brute force:** thử nhiều mật khẩu cho một hoặc một số tài khoản.
- **Credential stuffing:** dùng username/password đã bị lộ từ dịch vụ khác để thử đăng nhập.
- **Password spraying:** thử một số mật khẩu phổ biến trên nhiều tài khoản để tránh lockout theo từng tài khoản.

Dấu hiệu:
- Nhiều `POST` đến endpoint login trong thời gian ngắn.
- Nhiều lần đăng nhập thất bại từ một IP hoặc nhiều IP.
- Một IP thử nhiều username; một username bị thử từ nhiều IP.
- User-Agent hoặc pattern request lặp lại bất thường.
- Một lần đăng nhập thành công sau chuỗi thất bại, đặc biệt với tài khoản có quyền cao.
- Thay đổi IP, địa lý, thiết bị hoặc session ngay sau lần đăng nhập thành công.

Không kết luận chỉ từ số lần login thất bại: người dùng quên mật khẩu, ứng dụng di động lỗi hoặc hệ thống SSO cũng có thể tạo nhiều lần thử.

### 3.2 SQL Injection (SQLi)

SQLi xảy ra khi dữ liệu do người dùng kiểm soát được nối trực tiếp vào câu SQL thay vì xử lý bằng parameterized queries. Attacker có thể thay đổi ý nghĩa truy vấn, truy xuất hoặc sửa dữ liệu database.

Dấu hiệu trong request/log/PCAP:
- Chuỗi có toán tử, dấu nháy hoặc cú pháp SQL bất thường trong query/body.
- Nhiều request thử payload khác nhau trên cùng tham số.
- Response size/status thay đổi khác thường sau payload.
- Error log có database syntax errors.
- Application/database logs cho thấy truy vấn bất thường hoặc lượng dữ liệu trả về tăng.

**Lưu ý:** chuỗi như `SELECT`, dấu nháy hoặc `OR` có thể xuất hiện trong nội dung hợp lệ. Cần phân tích ngữ cảnh, tham số, endpoint và phản hồi.

**Phòng ngừa chính:** prepared statements/parameterized queries, quyền database tối thiểu và xử lý lỗi an toàn. WAF là lớp bổ trợ, không thay thế sửa lỗi trong code.

### 3.3 Command Injection

Command injection xảy ra khi application chuyển input không đáng tin cậy đến shell hoặc system command mà không kiểm soát đúng cách. Khi bị khai thác, server có thể thực thi lệnh với quyền của process ứng dụng.

Dấu hiệu có thể gồm:
- Request chứa ký tự hoặc cấu trúc shell bất thường.
- Application error hoặc log ghi nhận input có dấu hiệu command chaining.
- Web server process sinh ra shell/interpreter hoặc công cụ hệ thống ngoài dự kiến.
- Process tree bất thường, ví dụ worker web khởi chạy `cmd.exe`, `powershell.exe`, `sh`, `bash`, `curl`, `wget` hoặc `nc`.
- Kết nối outbound bất thường ngay sau request đến endpoint liên quan.

Cần xác minh bằng endpoint process telemetry; riêng access log không chứng minh lệnh đã thực thi.

## 4. Log-Based Detection

### 4.1 Access Log

Một access log thường chứa:

| Trường | Ý nghĩa phát hiện |
|---|---|
| Client IP | Nhóm hoạt động theo nguồn; có thể là proxy/NAT và cần xác minh forwarded headers |
| Timestamp | Tần suất, burst và timeline |
| Method | GET/POST/PUT/DELETE... |
| URI/Query | Endpoint và tham số bị nhắm mục tiêu |
| Status code | Thành công, redirect, lỗi client/server |
| Response size | Dữ liệu trả về bất thường hoặc khác baseline |
| Referrer | Ngữ cảnh điều hướng |
| User-Agent | Client hoặc công cụ tự động; có thể giả mạo |
| Time taken | Request chậm, backend bị quá tải hoặc xử lý bất thường |

Ví dụ về một dòng log kiểu combined:
```text
198.51.100.25 - - [02/Nov/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 512 "https://example.test/login" "Mozilla/5.0"
```

Dòng này cho biết request POST đến `/login` nhận HTTP 401. Nó không cho biết password thực tế đã gửi, trừ khi application có cơ chế ghi sự kiện riêng (và không nên log password nguyên văn).

### 4.2 HTTP status codes

| Nhóm | Ý nghĩa | Góc nhìn điều tra |
|---|---|---|
| 2xx | Request được xử lý thành công | Kiểm tra hành động thực hiện và dữ liệu trả về |
| 3xx | Redirect | Kiểm tra redirect chain và khả năng login thành công |
| 4xx | Lỗi phía client/request | Nhiều 404 có thể gợi ý scanning; 401/403 có thể gợi ý truy cập không hợp lệ |
| 5xx | Lỗi phía server | Tăng đột biến có thể phản ánh backend lỗi, quá tải hoặc input gây lỗi |

Status code riêng lẻ không xác nhận thành công khai thác. Ví dụ `200` có thể trả trang lỗi, còn `302` có thể là luồng ứng dụng bình thường.

### 4.3 Error và Application Logs

Access log thường không chứa đủ nội dung để biết application đã xử lý input như thế nào. Error/application logs có thể bổ sung:
- Lỗi parse/validation.
- Authentication/authorization failure.
- Database exceptions.
- Upload events.
- Thay đổi dữ liệu và thao tác quản trị.
- Business logic events.

Logging cần được thiết kế để bảo vệ dữ liệu nhạy cảm. Không ghi trực tiếp password, access token, session secret hoặc dữ liệu cá nhân không cần thiết.

### 4.4 Giới hạn của log-based detection

- Nhiều access log không lưu HTTP POST body.
- Query string có thể bị loại bỏ hoặc rút gọn.
- Log fields phụ thuộc web server và cấu hình.
- Reverse proxy/CDN có thể làm IP nguồn nhìn thấy ở origin khác IP client.
- Attacker có thể giả mạo User-Agent, Referrer và một số header.
- Log có thể thiếu, bị xoay vòng, mất đồng bộ thời gian hoặc bị sửa/xóa.

Vì vậy, cần kết hợp access log, error/application log, WAF, endpoint telemetry và network capture.

## 5. Network-Based Detection bằng Wireshark

PCAP cho phép xem request/response ở mức packet. Với HTTP không mã hóa, có thể nhìn thấy header, URI, một phần body, cookie hoặc file transfer tùy capture.

### Display filters hữu ích

```wireshark
http
http.request
http.response
http.request.method == "POST"
http.response.code >= 400
http.user_agent
ip.addr == 192.0.2.10 && http
tcp.port == 80
```

Một số filter có thể phụ thuộc protocol dissector và phiên bản Wireshark.

### Quy trình phân tích
1. Xác định IP/host của web server và khoảng thời gian incident.
2. Lọc `http` để thu hẹp traffic.
3. Nhóm request theo client IP, method, URI và User-Agent.
4. Tìm chuỗi hành vi: directory discovery → login attempts → request bất thường → phản hồi khác biệt.
5. Chọn packet liên quan và kiểm tra HTTP headers/body.
6. Dùng **Follow → HTTP Stream** để tái dựng request/response.
7. Ghi packet number, timestamp, endpoints và nội dung bằng chứng cần thiết.
8. Đối chiếu với access log và application/database log.

### HTTPS limitation
HTTPS mã hóa nội dung HTTP. Nếu không có session secrets/key log hợp lệ và được phép sử dụng, PCAP thường chỉ cho phép phân tích metadata như IP, port, timing, kích thước, TLS handshake/certificate và một số thông tin DNS/TLS còn nhìn thấy.

Không giả định mọi PCAP đều cho phép đọc password, cookie hoặc payload.

## 6. Web Application Firewall (WAF)

WAF kiểm tra request và áp dụng rule để allow, log, challenge, rate-limit hoặc block.

| Nhóm rule | Mục tiêu |
|---|---|
| Attack signatures | Chặn payload/pattern đã biết như SQLi hoặc XSS |
| Malicious source reputation | Giảm traffic từ nguồn có reputation xấu |
| Custom application rules | Giới hạn method, path, header hoặc hành vi theo nhu cầu ứng dụng |
| Rate limiting | Hạn chế request quá dày đến login, API hoặc endpoint tốn tài nguyên |
| Bot/challenge | Yêu cầu xác minh thêm khi traffic có dấu hiệu tự động |
| Virtual patching | Giảm rủi ro khai thác trong lúc chờ bản vá, nếu rule phù hợp |

### Hạn chế của WAF
- Có thể tạo false positive và ảnh hưởng người dùng thật.
- Attacker có thể thay đổi payload hoặc User-Agent.
- WAF không sửa lỗi logic trong application.
- Traffic mã hóa phải được WAF quan sát ở vị trí có thể giải mã/kiểm tra.
- Rule cần được theo dõi, cập nhật và kiểm thử.

## 7. SOC Investigation Workflow

1. **Triage:** xác định alert, web application, endpoint, thời gian và mức độ quan trọng.
2. **Scope:** tìm các request cùng nguồn, cùng session, cùng URI hoặc các host liên quan.
3. **Log review:** xem access, error, application, authentication và WAF logs.
4. **Traffic review:** dùng PCAP/Wireshark để xác minh request/response nếu có.
5. **Host correlation:** kiểm tra process, file, authentication và outbound network events trên server.
6. **Impact assessment:** xác định tài khoản, dữ liệu, endpoint hoặc hệ thống bị ảnh hưởng.
7. **Containment:** phối hợp chặn nguồn/URI, rate-limit, disable endpoint hoặc cô lập host theo quy trình.
8. **Reporting:** ghi evidence, timeline, confidence, scope, limitation và remediation.

### Mẫu ghi chú điều tra

```text
Incident:
Application / server:
Time window (timezone):
Source IP(s):
Target host / URI:
HTTP method and status:
User-Agent / Referrer:
Observed pattern:
Relevant log events:
PCAP packets / stream:
Endpoint or database evidence:
Assessment:
Impact / affected users:
Containment and remediation:
Confidence and limitations:
```

## 8. Ví dụ phát hiện theo tình huống

| Hành vi | Dấu hiệu ban đầu | Cần xác minh thêm |
|---|---|---|
| Directory fuzzing | Nhiều path khác nhau, nhiều 404/403 xen kẽ 200/301 | Tool/User-Agent, tốc độ, path phổ biến, response content |
| Brute force | Nhiều POST login, 401/403 hoặc message thất bại | Tài khoản bị nhắm, IP phân tán, lần login thành công sau chuỗi thất bại |
| SQLi attempt | Query/body có pattern giống SQL, WAF alert | Request context, database errors, response changes, DB audit |
| Command injection | Input lạ và lỗi application | Process tree, shell spawn, file/network activity |
| XSS attempt | Input chứa markup/script patterns | Stored/reflected behavior, CSP/browser telemetry |
| CSRF suspicion | Request thay đổi trạng thái không phù hợp | CSRF token, Origin/Referer, session và hoạt động user |

## 9. Kỹ năng đạt được

- Phân biệt nhóm client-side và server-side attacks.
- Nhận diện các dấu hiệu ban đầu của brute force, SQLi và command injection.
- Đọc access logs và hiểu giới hạn của chúng.
- Sử dụng Wireshark để kiểm tra HTTP traffic và Follow HTTP Stream.
- Hiểu vai trò của WAF, threat intelligence, custom rules và rate limiting.
- Tương quan log, PCAP và endpoint telemetry để đưa ra nhận định có căn cứ.

## Tài liệu tham khảo

- [TryHackMe – Detecting Web Attacks](https://tryhackme.com/room/detectingwebattacks)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [Microsoft – W3C Logging](https://learn.microsoft.com/en-us/windows/win32/http/w3c-logging)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
