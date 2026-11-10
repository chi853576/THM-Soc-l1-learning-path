# Detecting Web Shells

**Nguồn học:** [TryHackMe – Detecting Web Shells](https://tryhackme.com/room/detectingwebshells)

## 1. Web Shell là gì?

**Web shell** là một script hoặc thành phần được đặt trên web server và có thể được gọi thông qua HTTP/HTTPS để cung cấp cho attacker khả năng điều khiển hoặc thực thi thao tác trên server.

Web shell có thể cung cấp:
- Giao diện thực thi lệnh hệ thống.
- Khả năng đọc, ghi, tải lên hoặc tải xuống file.
- Khả năng tương tác với môi trường server.
- Một điểm truy cập để duy trì persistence sau khi khai thác thành công.

MITRE ATT&CK phân loại web shell là **T1505.003 – Server Software Component: Web Shell**, thuộc tactic **Persistence**. Web shell thường được đặt trên một web server có thể truy cập được và có thể trở thành gateway để attacker tiếp tục hoạt động trong mạng.

## 2. Vì sao Web Shell nguy hiểm?

Một web shell có thể biến một lỗ hổng web ban đầu thành quyền điều khiển lâu dài hơn đối với server.

Rủi ro gồm:
- Thực thi lệnh bằng quyền của web server process.
- Đọc source code, configuration hoặc secret.
- Truy cập dữ liệu ứng dụng/database qua credential của ứng dụng.
- Tải thêm malware hoặc công cụ hậu khai thác.
- Tạo kết nối outbound đến hạ tầng điều khiển.
- Dùng server bị xâm nhập làm điểm pivot vào mạng nội bộ.

Mức độ ảnh hưởng phụ thuộc quyền của tài khoản chạy web server, cấu hình hệ thống, phân đoạn mạng và quyền truy cập backend.

## 3. Web Shell thường xuất hiện như thế nào?

Một kịch bản tổng quát có thể diễn ra theo chuỗi:

1. Attacker tìm thấy web application có lỗ hổng hoặc cấu hình yếu.
2. Attacker khai thác chức năng upload, lỗ hổng xử lý file hoặc khả năng ghi file trên server.
3. Một file script trái phép được đặt trong thư mục có thể được web server xử lý.
4. Attacker gửi HTTP request đến file đó.
5. Web server xử lý script và có thể thực thi thao tác với quyền của process.
6. Attacker sử dụng khả năng này để thực hiện reconnaissance, đọc/ghi file hoặc tải công cụ khác.
7. Web shell được giữ lại như cơ chế persistence.

**Điểm cần nhớ:** file được upload chưa chắc đã là web shell; file chỉ trở thành nguy cơ thực thi khi có khả năng được server xử lý như script hoặc được gọi bởi một thành phần có quyền phù hợp.

## 4. Anatomy of a Web Shell – các thành phần ở mức khái niệm

Một web shell thường có hai phần logic:

| Thành phần | Vai trò |
|---|---|
| Server-side script | Nhận request, diễn giải tham số và thực hiện thao tác trên server |
| Client interface | Gửi command/parameters và hiển thị kết quả trả về |

Các web shell có thể được viết bằng PHP, ASP/ASPX, JSP, Python hoặc ngôn ngữ server-side khác tùy môi trường.

### Dấu hiệu trong mã nguồn
- Hàm thực thi command hoặc gọi shell.
- Hàm đánh giá/diễn giải nội dung đầu vào không an toàn.
- Chuỗi bị obfuscate hoặc decode trước khi sử dụng.
- Tham số request được chuyển trực tiếp vào chức năng nhạy cảm.
- Code ngắn bất thường, không giống coding style của ứng dụng.
- File mới hoặc file hợp lệ bị chỉnh sửa ở vị trí không mong đợi.

Không phải mọi hàm nguy hiểm hoặc mã bị obfuscate đều là web shell. Một số ứng dụng hợp pháp cũng dùng dynamic execution hoặc mã sinh tự động; cần so sánh với baseline và xác minh hành vi.

## 5. Nguồn dữ liệu phát hiện

Phát hiện web shell hiệu quả cần kết hợp nhiều nguồn dữ liệu.

| Nguồn | Dữ liệu cần xem | Giá trị |
|---|---|---|
| Web access logs | Request đến script lạ, POST bất thường, tần suất và User-Agent | Tìm thời điểm và nguồn truy cập web shell |
| Web error logs | Lỗi script, lỗi xử lý request hoặc lỗi runtime | Bổ sung ngữ cảnh cho request bất thường |
| Application logs | Upload event, authentication, thao tác quản trị | Tìm cách file được đưa vào hệ thống |
| File system monitoring | File mới, sửa đổi, quyền file và timestamp trong web root | Phát hiện script trái phép |
| Endpoint/EDR | Process tree, command line, process creation | Phát hiện web server sinh shell hoặc interpreter |
| Network telemetry | Inbound POST, outbound connection, DNS và flow | Liên kết request với hoạt động command/control hoặc tải công cụ |
| Authentication logs | Logon/session mới hoặc tài khoản bất thường | Xác định tài khoản và phạm vi xâm nhập |

## 6. Log-Based Detection

### 6.1 Dấu hiệu trong access logs

Một số hành vi đáng chú ý:
- Request đến file script không có trong inventory ứng dụng.
- POST request đến file `.php`, `.asp`, `.aspx`, `.jsp` hoặc endpoint có tên bất thường.
- Nhiều request lặp lại đến cùng một file với query/body thay đổi.
- User-Agent lạ hoặc không phù hợp với baseline.
- Request xuất hiện ngay sau một sự kiện upload thành công.
- Một endpoint script trả về response size hoặc status khác thường.
- Request đến web shell từ IP không liên quan đến hoạt động quản trị.

Ví dụ filter/sơ bộ khi log đã được parse:
```text
uri contains ".php"
method = "POST"
status = 200
```

Đây chỉ là điều kiện tìm kiếm rộng, không phải rule xác định web shell. Website PHP bình thường cũng có nhiều POST request và file `.php`.

### 6.2 Vì sao POST request cần được chú ý?

Web shell thường cần nhận tham số hoặc dữ liệu từ client. Vì vậy, POST đến script hiếm gặp hoặc mới xuất hiện có thể đáng điều tra, nhất là khi liên tiếp với file creation hoặc process spawn.

Tuy nhiên:
- Login forms, upload forms và API hợp pháp cũng dùng POST.
- Access log thường không lưu POST body.
- HTTP 200 chỉ cho biết server trả response thành công theo giao thức, không chứng minh lệnh đã được thực thi.

Cần dùng application logging, PCAP khi có thể quan sát payload, và endpoint telemetry để xác minh.

## 7. Beyond Logs – File System và Process Detection

Đây là phần quan trọng vì web shell có thể để lại dấu vết ngoài access log.

### 7.1 File system indicators
- File script mới xuất hiện trong web root mà không có change ticket/deployment.
- File được tạo trong thư mục upload hoặc thư mục vốn không nên chứa script.
- File có tên giả dạng ảnh/tài liệu hoặc tên gần giống file hệ thống.
- Timestamp file không khớp lịch deploy.
- File có hash khác phiên bản chuẩn trong source control hoặc package.
- File hợp pháp bị sửa nội dung ngoài quy trình triển khai.

Đường dẫn web root thay đổi theo hệ điều hành và cấu hình. Ví dụ thường gặp:
- Linux: `/var/www/html`, `/srv/http` hoặc đường dẫn tùy chỉnh.
- Windows/IIS: `C:\inetpub\wwwroot` hoặc web root được cấu hình riêng.
- macOS: vị trí web root phụ thuộc cấu hình và phiên bản dịch vụ.

Không dựa vào một đường dẫn mặc định; cần xác định cấu hình thực tế của host.

### 7.2 Process execution indicators

Một dấu hiệu mạnh là web server process khởi chạy process con không thuộc hoạt động bình thường.

Ví dụ:
- `w3wp.exe` (IIS worker process) khởi chạy `cmd.exe` hoặc `powershell.exe`.
- `apache2`/`httpd`/`nginx` khởi chạy `sh`, `bash`, `python`, `curl`, `wget` hoặc `nc` không có lý do nghiệp vụ.
- Process web server tạo file trong web root hoặc thư mục tạm rồi tiếp tục tạo kết nối outbound.

Các process có thể được dùng hợp pháp bởi script vận hành, backup hoặc health check. Cần kiểm tra parent-child relationship, command line, user context, timestamp và change record.

### 7.3 Telemetry tham khảo

Một số nguồn log có thể hỗ trợ:
- **Windows Sysmon Event ID 11:** FileCreate.
- **Windows Sysmon Event ID 1:** ProcessCreate.
- **Windows Security Event ID 4624:** Logon.
- **Windows Security Event ID 4648:** Explicit credentials used.
- **Linux auditd:** sự kiện tạo/sửa file và process execution.
- EDR process tree và file events.
- Web server access/error logs.

MITRE ATT&CK Detection Strategy DET0394 mô tả cách tương quan file bất thường được tạo trong web directory với web server process khởi chạy command shell/interpreter. Đây là một hướng phát hiện có giá trị hơn việc chỉ tìm file có extension đáng ngờ.

## 8. Network-Based Detection

Trong network telemetry/PCAP, có thể tìm:
- Inbound HTTP POST đến script không thường thấy.
- Request body lớn hoặc entropy cao bất thường.
- Request lặp lại đến cùng một URI với tham số thay đổi.
- User-Agent, source IP hoặc thời gian truy cập bất thường.
- Outbound connection từ web server ngay sau request đáng ngờ.
- DNS lookup hoặc kết nối đến domain/IP chưa từng xuất hiện trong baseline.

### Wireshark filters tham khảo
```wireshark
http
http.request
http.request.method == "POST"
http.user_agent
ip.addr == 192.0.2.10 && http
```

Nếu PCAP chứa HTTP không mã hóa, có thể dùng **Follow → HTTP Stream** để xem request/response. Với HTTPS, payload thường bị mã hóa nếu không có session secrets hợp lệ.

## 9. Quy trình điều tra Web Shell

### Bước 1 – Triage alert
- Ghi nhận host, URI, source IP, timestamp và alert source.
- Xác định web server/application và mức độ quan trọng.
- Kiểm tra xem có hoạt động deploy hoặc bảo trì hợp lệ không.

### Bước 2 – Dựng timeline
- Tìm các request đến endpoint liên quan.
- Tìm file upload hoặc file creation gần thời điểm đó.
- Tìm process creation và outbound connection tiếp theo.
- Chuẩn hóa timezone giữa web logs, endpoint logs và SIEM.

### Bước 3 – Xác minh file
- Xác định full path, owner, permissions, size và timestamps.
- Tính hash SHA-256 và so sánh với bản chuẩn.
- Kiểm tra source/repository, deployment logs và file integrity monitoring.
- Phân tích nội dung trong môi trường an toàn; không truy cập hoặc thực thi file để “thử”.

### Bước 4 – Xác minh hành vi
- Kiểm tra process tree do web server tạo.
- Kiểm tra command line, user account và network connections.
- Xem có hành động đọc/ghi file, tải công cụ hoặc kết nối ra ngoài không.
- Tương quan với authentication, WAF, firewall, DNS và database logs.

### Bước 5 – Đánh giá phạm vi
- Xác định web shell đã được truy cập hay chỉ mới được tạo.
- Xác định command hoặc hoạt động đã xảy ra nếu telemetry cho phép.
- Kiểm tra dữ liệu truy cập, account compromise và khả năng lateral movement.
- Xác định có thêm web shell hoặc persistence khác không.

### Bước 6 – Containment và recovery
- Phối hợp đội incident response để cô lập host hoặc hạn chế traffic theo quy trình.
- Bảo toàn evidence và bản sao log/PCAP trước khi xóa file.
- Gỡ web shell sau khi đã thu thập bằng chứng và xác định nguyên nhân.
- Vá lỗ hổng ban đầu, xoay vòng secret/credential có nguy cơ bị lộ.
- Kiểm tra persistence khác và phục hồi từ bản sạch nếu cần.

## 10. MITRE ATT&CK Mapping

| ATT&CK ID | Tên | Ý nghĩa |
|---|---|---|
| **T1505.003** | Web Shell | Cài web shell trên server để duy trì quyền truy cập |
| **T1190** | Exploit Public-Facing Application | Có thể là cách attacker khai thác ứng dụng public trước khi đặt web shell |
| **T1059** | Command and Scripting Interpreter | Có thể liên quan khi web shell dẫn đến việc chạy shell/script |
| **T1105** | Ingress Tool Transfer | Có thể xuất hiện khi attacker tải công cụ vào host |
| **T1041** | Exfiltration Over C2 Channel | Có thể liên quan nếu dữ liệu bị lấy qua kênh điều khiển |

Mapping chỉ nên sử dụng khi bằng chứng của incident hỗ trợ kỹ thuật tương ứng. Không gán ATT&CK technique chỉ vì thấy một process hoặc file có tên đáng ngờ.

## 11. Biện pháp phòng ngừa

- Chặn script execution trong thư mục upload.
- Lưu upload ngoài web root hoặc dùng object storage riêng.
- Kiểm tra file thực tế, không tin extension/MIME do client cung cấp.
- Giới hạn quyền ghi vào web directory; chỉ pipeline deploy được phép thay đổi code.
- Chạy web server bằng tài khoản least privilege.
- Vô hiệu hóa hàm hoặc chức năng dynamic execution không cần thiết.
- Cập nhật web server, framework và plugin.
- Bật file integrity monitoring, EDR và audit logs.
- Giám sát web server process tạo shell/interpreter.
- Bật WAF và rate limiting như lớp phòng thủ bổ sung.

## 12. Mẫu báo cáo điều tra

```text
Incident:
Affected web server / application:
Operating system / web server:
Time window:
Suspicious URI:
Source IP / User-Agent:
Suspected web shell path:
File hash (SHA-256):
File creation/modification evidence:
Web server process activity:
Outbound network activity:
Related authentication events:
Was the file accessed/executed?
Observed impact:
Containment actions:
Root cause:
Remediation:
Evidence preserved:
Confidence and limitations:
```

## 13. Kỹ năng đạt được

- Giải thích web shell và vai trò của nó trong persistence.
- Hiểu mối liên hệ giữa upload, file creation, HTTP request và process execution.
- Tìm dấu hiệu trong access logs, filesystem, EDR và network telemetry.
- Tương quan Sysmon/auditd với web server logs.
- Thực hiện triage và đề xuất containment/remediation dựa trên evidence.

## Tài liệu tham khảo

- [TryHackMe – Detecting Web Shells](https://tryhackme.com/room/detectingwebshells)
- [MITRE ATT&CK – T1505.003 Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK – DET0394 Web Shell Detection via Server Behavior and File Execution Chains](https://attack.mitre.org/detectionstrategies/DET0394/)
- [MITRE ATT&CK – T1505 Server Software Component](https://attack.mitre.org/techniques/T1505/)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
