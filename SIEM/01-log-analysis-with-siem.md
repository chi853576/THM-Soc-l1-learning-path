# Log Analysis with SIEM

**Nguồn học:** [TryHackMe – Log Analysis with SIEM](https://tryhackme.com/room/loganalysiswithsiem)  
**Module:** [SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)

## Task 1: Introduction

### 1. SIEM là gì?

**SIEM (Security Information and Event Management)** là nền tảng tập trung thu thập, lưu trữ, chuẩn hóa, tìm kiếm và phân tích dữ liệu bảo mật từ nhiều hệ thống. SIEM giúp analyst có cái nhìn tổng thể về hoạt động trong môi trường thay vì phải đăng nhập vào từng máy chủ, firewall hoặc endpoint để kiểm tra riêng lẻ.

Một SIEM thường hỗ trợ:

- **Log collection:** nhận log từ endpoint, server, firewall, IDS/IPS, ứng dụng, dịch vụ cloud và hệ thống định danh.
- **Parsing và normalization:** tách dữ liệu log thành các field và đưa về cấu trúc thống nhất.
- **Search và correlation:** truy vấn log, liên kết nhiều sự kiện và xây dựng ngữ cảnh.
- **Alerting:** phát hiện hành vi khớp với điều kiện hoặc detection rule.
- **Visualization và reporting:** biểu diễn xu hướng, thống kê và kết quả điều tra.
- **Historical analysis:** tìm kiếm lại dữ liệu quá khứ để xác định hoạt động bất thường đã bắt đầu từ khi nào.

### 2. Vai trò của SIEM trong SOC

SIEM không tự động kết luận một sự kiện là tấn công. Nó cung cấp dữ liệu và công cụ để analyst kiểm tra alert, đánh giá mức độ rủi ro và quyết định bước xử lý tiếp theo.

Ví dụ: IDS phát hiện một thiết bị có hành vi scan mạng nội bộ và chỉ cung cấp địa chỉ IP nguồn. Analyst có thể dùng SIEM để tìm thiết bị sở hữu IP đó, tài khoản đăng nhập, process đang chạy và các kết nối phát sinh gần thời điểm cảnh báo. Khi nhiều nguồn log được liên kết, analyst có thể trả lời các câu hỏi: **Ai thực hiện? Trên thiết bị nào? Thực hiện hành động gì? Vào thời điểm nào? Có dấu hiệu tiếp diễn hay không?**

### 3. Các khái niệm cần phân biệt

| Khái niệm | Ý nghĩa |
|---|---|
| Event | Một sự kiện được hệ thống ghi nhận, ví dụ đăng nhập hoặc tạo process. |
| Log | Bản ghi chứa thông tin về một hoặc nhiều sự kiện. |
| Alert | Thông báo được tạo khi dữ liệu đáp ứng một điều kiện phát hiện. |
| IOC | Indicator of Compromise, dấu hiệu có thể liên quan đến xâm nhập như IP, domain, hash hoặc URL. |
| Correlation | Liên kết các sự kiện khác nhau dựa trên thời gian, host, user, process hoặc network indicator. |
| Normalization | Chuyển dữ liệu từ nhiều định dạng về cấu trúc field nhất quán. |
| Enrichment | Bổ sung ngữ cảnh cho log, ví dụ thông tin asset, threat intelligence hoặc danh tính user. |

---

## Task 2: Benefits of SIEM for Analysts

### 1. Centralization – Tập trung dữ liệu

Log từ nhiều nguồn được đưa về một nền tảng chung. Điều này giúp giảm thời gian thu thập dữ liệu và cho phép analyst quan sát nhiều lớp của cùng một hoạt động.

Ví dụ, khi nhận cảnh báo về một kết nối mạng đáng ngờ, analyst có thể truy vấn đồng thời:

- Log firewall/IDS để xem nguồn, đích, port và thời điểm kết nối.
- Windows Event Logs hoặc Sysmon để xác định process và user liên quan.
- DNS logs để kiểm tra domain được truy vấn trước khi kết nối.
- Web hoặc proxy logs để xem thiết bị đã truy cập tài nguyên nào.

### 2. Correlation – Tương quan sự kiện

Correlation là việc liên kết các event dựa trên các thuộc tính chung. Những field thường dùng gồm:

- Timestamp và khoảng thời gian gần nhau.
- Hostname hoặc device ID.
- Username, domain hoặc Logon ID.
- Process ID, Process GUID, parent process.
- Source IP, destination IP, port và domain.
- File hash hoặc tên file.

Một event riêng lẻ có thể hợp pháp, nhưng chuỗi sự kiện theo đúng trình tự có thể cho thấy hành vi tấn công. Ví dụ: đăng nhập thành công bất thường → process lạ được khởi chạy → kết nối outbound đến IP lạ → file mới được tạo.

### 3. Historical Events – Dữ liệu lịch sử

Dữ liệu lịch sử cho phép so sánh hoạt động hiện tại với baseline trước đó. Analyst có thể kiểm tra:

- IP hoặc quốc gia đã từng đăng nhập vào tài khoản hay chưa.
- Process có thường xuất hiện trên host hay không.
- Một domain có phải đích kết nối quen thuộc của hệ thống hay không.
- Tần suất hoạt động có thay đổi bất thường không.

**Lưu ý:** Một hoạt động mới hoặc hiếm gặp chỉ là dấu hiệu cần kiểm tra, không tự động đồng nghĩa với độc hại.

---

## Task 3: Log Sources Overview

### 1. Host-based logs

Host-based logs được tạo trên workstation, server hoặc endpoint. Đây là nguồn dữ liệu quan trọng để hiểu hành động diễn ra bên trong thiết bị.

| Nguồn | Thông tin có thể thu thập |
|---|---|
| Windows Security Logs | Đăng nhập, đăng xuất, tạo tài khoản, thay đổi quyền, process creation và thay đổi chính sách bảo mật. |
| Windows System Logs | Dịch vụ, driver, trạng thái hệ điều hành và lỗi hệ thống. |
| Sysmon | Process, network connection, DNS query, file creation, registry và một số hành vi cấp thấp khác. |
| Linux authentication logs | SSH login, xác thực thành công/thất bại, sudo và hoạt động tài khoản. |
| Linux system logs / journald | Hoạt động service, kernel, systemd và lỗi vận hành. |
| EDR telemetry | Process tree, file activity, network connection và hành vi endpoint do agent ghi nhận. |

### 2. Network-based logs

Log từ firewall, router, IDS/IPS, DNS, proxy hoặc network monitoring giúp analyst hiểu các thiết bị giao tiếp với nhau như thế nào.

Các field quan trọng thường có:

- `source.ip`, `source.port`: nguồn phát sinh kết nối.
- `destination.ip`, `destination.port`: máy chủ hoặc dịch vụ đích.
- `network.protocol`, `network.transport`: giao thức hoặc lớp vận chuyển.
- `network.direction`: hướng của traffic nếu nguồn log có cung cấp.
- `event.action`, `event.outcome`: hành động và kết quả được ghi nhận.

Network log thường không đủ để xác định chính xác chương trình nào tạo kết nối. Cần đối chiếu với Sysmon/EDR hoặc log trên endpoint.

### 3. Web-based logs

Web server như IIS, Apache và Nginx thường ghi nhận request truy cập tài nguyên. Các field có ích gồm:

| Field | Ý nghĩa thường gặp |
|---|---|
| Client IP / `c-ip` | IP của client gửi request. |
| Method / `cs-method` | HTTP method như GET hoặc POST. |
| URI path / `cs-uri-stem` | Đường dẫn tài nguyên được yêu cầu. |
| Status / `sc-status` | HTTP response status code. |
| User-Agent | Thông tin client hoặc công cụ gửi request. |
| Timestamp | Thời điểm server xử lý request. |

Web access logs có thể hỗ trợ nhận diện brute-force, scanning, request bất thường, khai thác web application và hoạt động nghi vấn liên quan đến web shell. Error logs bổ sung thông tin về lỗi xử lý và trạng thái ứng dụng.

### 4. Time pitfalls – Sai lệch thời gian

Các nguồn log có thể ghi timestamp theo UTC, local time hoặc timezone không được chỉ rõ. SIEM có thể hiển thị thời gian đã được chuyển đổi theo timezone của giao diện.

Khi dựng timeline:

1. Xác định timezone của từng nguồn log.
2. Kiểm tra field timestamp gốc và thời gian SIEM hiển thị.
3. Quy đổi về một timezone thống nhất, thường là UTC trong quá trình phân tích.
4. Ghi rõ timezone trong báo cáo.
5. Không nhầm chênh lệch timezone với độ trễ ingest.

### 5. Log normalization – Chuẩn hóa log

Mỗi nhà cung cấp có thể sử dụng tên field và cấu trúc khác nhau. Normalization chuyển các dữ liệu này về một schema chung để truy vấn và correlation thuận tiện hơn.

Ví dụ trong Elastic Common Schema (ECS):

- `@timestamp`: thời điểm event.
- `host.name`: tên thiết bị.
- `user.name`: tài khoản liên quan.
- `process.name`: tên process.
- `source.ip` và `destination.ip`: địa chỉ nguồn và đích.
- `event.category`: nhóm hoạt động như process, network hoặc authentication.

Không phải mọi nguồn log đều có đầy đủ các field này. Analyst cần kiểm tra schema thực tế trước khi viết truy vấn.

---

## Task 4: Windows Logs

### 1. Windows Event Logs và Sysmon

Windows Event Logs ghi nhận các hoạt động của hệ điều hành, ứng dụng và bảo mật. Ba log channel thường gặp là **Security**, **System** và **Application**.

Sysmon là công cụ thuộc Microsoft Sysinternals, cung cấp telemetry chi tiết hơn về hành vi trên Windows. Sysmon phải được cài đặt và cấu hình phù hợp; số lượng và loại event được thu thập phụ thuộc cấu hình.

### 2. Một số Windows Event ID cần nhớ

| Event ID | Ý nghĩa | Hướng phân tích |
|---|---|---|
| 4624 | Đăng nhập thành công | Kiểm tra tài khoản, Logon Type, source IP và thời điểm. |
| 4625 | Đăng nhập thất bại | Tìm brute-force, password spraying hoặc lỗi đăng nhập hợp pháp. |
| 4688 | Process được tạo | Kiểm tra executable, command line, creator process và user. |
| 4698 | Scheduled task được tạo | Xác định task, command/action, creator và trigger. |
| 4720 | Tài khoản người dùng mới được tạo | Kiểm tra người tạo và mục đích tài khoản. |
| 4722 | Tài khoản được kích hoạt | Đối chiếu với yêu cầu quản trị hợp lệ. |
| 7045 | Service mới được cài đặt (System log) | Kiểm tra service name, binary path và account chạy service. |

Event ID cần được đọc cùng channel, provider và các field của event. Không phải tất cả Event ID đều nằm trong cùng một log channel.

### 3. Các Sysmon Event ID quan trọng

| Sysmon Event ID | Ý nghĩa | Giá trị khi điều tra |
|---|---|---|
| 1 | Process creation | Xem Image, CommandLine, ParentImage, User, Hashes và ProcessGUID. |
| 3 | Network connection | Xác định process nào tạo kết nối, IP/port nguồn và đích. |
| 5 | Process terminated | Xác định thời điểm process kết thúc. |
| 7 | Image loaded | Theo dõi module/DLL được nạp; có thể có volume lớn. |
| 8 | CreateRemoteThread | Dấu hiệu có thể liên quan đến process injection. |
| 10 | Process access | Kiểm tra process truy cập process khác, ví dụ hành vi liên quan đến credential access. |
| 11 | File create | Tìm file mới được tạo và process tạo file. |
| 12–14 | Registry events | Theo dõi thay đổi registry, có thể liên quan persistence. |
| 22 | DNS query | Liên kết process với domain được truy vấn. |

Sysmon Event ID 3 có thể không xuất hiện nếu cấu hình không bật thu thập network connection. Việc thiếu event không chứng minh hoạt động không xảy ra.

### 4. Ví dụ truy vấn Splunk – Process thực thi PowerShell

```spl
index=winenv EventCode=1 (Image="*powershell.exe" OR ParentImage="*powershell.exe")
| table _time ComputerName User Image ParentImage CommandLine ParentCommandLine ProcessGuid
| sort _time
```

Để tìm dấu hiệu command line có tham số mã hóa, có thể mở rộng bộ lọc:

```spl
index=winenv EventCode=1 "EncodedCommand"
| table _time ComputerName User ParentImage Image CommandLine
| sort _time
```

Ý nghĩa: xác định process PowerShell, parent process, tài khoản thực thi và nội dung command line. Không nên chỉ dựa trên từ khóa để kết luận độc hại; cần đọc toàn bộ chuỗi process và xác minh ngữ cảnh.

### 5. Ví dụ truy vấn Splunk – Network connection

```spl
index=winenv EventCode=3
| table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol
| sort _time
```

Khi phát hiện port hoặc IP bất thường:

1. Lọc theo host và khoảng thời gian liên quan.
2. Xác định process khởi tạo kết nối.
3. Kiểm tra file path và hash của process.
4. Tìm DNS query hoặc sự kiện tạo process trước đó.
5. Enrich IP/domain bằng threat intelligence.
6. Kiểm tra các host khác có cùng indicator hay không.

### 6. Tài khoản, service và persistence

Khi một host đã có dấu hiệu bị xâm nhập, analyst nên tìm các hành động tiếp theo như tạo tài khoản, bật lại tài khoản cũ, tạo service hoặc scheduled task.

Ví dụ:

```spl
index=winenv (EventCode=4720 OR EventCode=4722)
| table _time ComputerName Subject_Account_Name Target_Account_Name EventCode
| sort _time
```

```spl
index=winenv (EventCode=7045 OR EventCode=7036)
| table _time ComputerName Service_Name Service_Account Service_File_Name EventCode
| sort _time
```

Tên service trông hợp pháp không đủ để chứng minh service an toàn. Cần kiểm tra binary path, chữ ký, hash, account chạy service và thời điểm cài đặt.

---

## Task 5: Linux Logs

### 1. Nguồn log Linux thường gặp

| Nguồn | Nội dung |
|---|---|
| `/var/log/auth.log` | Thường gặp trên Debian/Ubuntu; SSH, sudo và xác thực. |
| `/var/log/secure` | Thường gặp trên một số hệ thống RHEL/CentOS; thông tin xác thực. |
| `/var/log/syslog` hoặc `/var/log/messages` | Hoạt động hệ thống và service, tùy distro. |
| `journalctl` | Truy vấn systemd journal. |
| `auditd` logs | Audit event như syscall, file access hoặc hành động theo rule. |

Vị trí và nội dung log phụ thuộc distro, cấu hình audit và cách tổ chức đẩy log lên SIEM.

### 2. SSH brute-force và đăng nhập bất thường

Các dấu hiệu cần kiểm tra:

- Nhiều lần đăng nhập thất bại trong thời gian ngắn.
- Một nguồn thử đăng nhập vào nhiều username.
- Nhiều nguồn cùng nhắm vào một tài khoản.
- Chuỗi thất bại theo sau bởi đăng nhập thành công.
- Đăng nhập thành công từ IP, thời gian hoặc vị trí không thường thấy.

Không phải tất cả chuỗi login fail đều là brute-force; cần xét số lượng, tần suất, username, source IP và hoạt động sau đăng nhập.

### 3. Sudo và privilege escalation

Khi điều tra hành vi nghi vấn trên Linux, cần xác định:

- Ai đã đăng nhập và từ IP nào.
- Tài khoản có sử dụng `sudo` hay chuyển sang root không.
- Lệnh nào được thực thi và vào thời điểm nào.
- Có tài khoản, SSH key hoặc cơ chế truy cập mới được thêm không.
- Có tiến trình hoặc kết nối mạng phát sinh sau khi tăng quyền không.

Ví dụ truy vấn log tại máy Linux:

```bash
sudo grep -Ei 'Failed password|Accepted password|Accepted publickey|sudo:' /var/log/auth.log
```

Tên file có thể khác trên hệ thống khác. Với systemd journal:

```bash
sudo journalctl -u ssh --since "today"
```

---

## Task 6: Web Application Logs

### 1. Brute-force trên trang đăng nhập

Đặc điểm có thể gặp:

- Nhiều HTTP POST đến endpoint đăng nhập.
- Tần suất request tăng cao từ một hoặc một số IP.
- Nhiều username bị thử hoặc một username bị thử nhiều lần.
- User-Agent cho thấy công cụ automation; đây là clue, không phải bằng chứng duy nhất.

Ví dụ truy vấn Splunk theo mẫu field web log của lab:

```spl
index=* method=POST uri_path="/wp-login.php"
| bin _time span=5m
| stats count values(status) as status values(useragent) as useragent by clientip _time
| where count > 25
| sort - count
```

Ngưỡng `25` chỉ là ví dụ minh họa. Threshold thực tế cần dựa trên baseline và đặc điểm ứng dụng.

### 2. Dấu hiệu web shell

Web shell là mã được đặt trên web server để cho phép thực thi lệnh hoặc điều khiển máy chủ thông qua request HTTP. Dấu hiệu cần xem xét:

- Request đến file script ít gặp hoặc mới xuất hiện.
- POST request bất thường đến endpoint không thuộc chức năng ứng dụng.
- Một endpoint nhận nhiều request ngắn, liên tiếp, có phản hồi thành công.
- User-Agent hoặc pattern request khác biệt.
- Web server process tạo child process bất thường như command shell hoặc scripting engine.

Chỉ riêng extension `.php`, `.asp` hoặc status `200` không chứng minh có web shell. Cần liên kết access logs với process creation và file activity trên máy chủ.

### 3. DDoS và request spike

Các dấu hiệu có thể gồm:

- Request volume tăng đột biến trong một khoảng thời gian ngắn.
- Một endpoint hoặc nhóm endpoint nhận lượng request rất lớn.
- Tỷ lệ HTTP 5xx tăng, ví dụ `503 Service Unavailable`.
- Nhiều IP gửi request hoặc một nhóm IP tạo lưu lượng tập trung.

HTTP 503 có thể xuất hiện do lỗi quá tải hoặc lỗi dịch vụ bình thường. Cần đối chiếu số request, thời lượng, nguồn traffic, trạng thái server và các log vận hành khác trước khi phân loại DDoS.

Ví dụ tổng hợp request theo IP và cửa sổ 10 phút:

```spl
index=* status=503
| bin _time span=10m
| stats count values(uri_path) as uri_path values(useragent) as useragent by clientip _time
| sort - count
```

---

## Task 7: Investigation Workflow

### 1. Quy trình phân tích log tổng quát

1. **Read the alert:** hiểu rule nào kích hoạt, nguồn log nào tạo alert và field nào được cung cấp.
2. **Validate scope:** xác định host, user, IP, process, thời gian và tài sản bị ảnh hưởng.
3. **Search supporting logs:** truy vấn nguồn log liên quan trước và sau thời điểm alert.
4. **Correlate events:** liên kết theo host, user, process ID/GUID, IP, domain và timestamp.
5. **Enrich indicators:** kiểm tra reputation và ngữ cảnh của IP, domain, hash hoặc URL.
6. **Build a timeline:** sắp xếp hành động theo thời gian, chuẩn hóa timezone.
7. **Assess impact:** xác định có execution, persistence, lateral movement, data access hoặc C2 hay không.
8. **Document and escalate:** ghi rõ bằng chứng, mức độ tin cậy, phạm vi và những gì cần kiểm tra tiếp.

### 2. Phân biệt anomaly và malicious activity

Một hành vi bất thường cần được đánh giá dựa trên nhiều yếu tố:

- **Identity:** tài khoản có hợp lệ và có quyền thực hiện hành động không?
- **Asset:** host có vai trò gì và hoạt động này có phù hợp với chức năng không?
- **Process:** executable, parent process, command line và path có hợp lý không?
- **Network:** đích kết nối, port, tần suất và chiều giao tiếp có đáng ngờ không?
- **Time:** hoạt động có xảy ra ngoài giờ hoặc khác baseline không?
- **Context:** có change ticket, tác vụ bảo trì hoặc hoạt động quản trị hợp lệ không?

### 3. Mẫu ghi nhận kết quả

| Trường | Nội dung cần ghi |
|---|---|
| Alert | Tên alert, rule và thời gian phát hiện. |
| Asset | Hostname, IP, hệ điều hành và vai trò. |
| Identity | Username, logon type và nguồn đăng nhập. |
| Activity | Hành động được quan sát, process hoặc network event. |
| Evidence | Log source, event ID, timestamp và các field liên quan. |
| Assessment | Benign, suspicious hoặc malicious; ghi rõ lý do. |
| Scope | Các host, user hoặc indicator khác đã được kiểm tra. |
| Next action | Theo dõi, truy vấn thêm hoặc escalation theo quy trình SOC. |

**Kết luận kiến thức:** SIEM hiệu quả không chỉ nằm ở việc tìm được một event khớp từ khóa, mà ở khả năng kết hợp nhiều nguồn dữ liệu để xây dựng ngữ cảnh và timeline có thể kiểm chứng.

---

## Tài liệu tham khảo

- [TryHackMe – Log Analysis with SIEM](https://tryhackme.com/room/loganalysiswithsiem)
- [Microsoft Learn – Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft Learn – Understanding Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft Learn – Windows Event ID 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft Learn – Windows Security Event ID reference](https://learn.microsoft.com/en-us/azure/sentinel/windows-security-event-id-reference)
- [Elastic – Elastic Common Schema](https://www.elastic.co/docs/reference/ecs)
