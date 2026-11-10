# Alert Triage With Splunk

**Nguồn học:** [TryHackMe – Alert Triage With Splunk](https://tryhackme.com/room/alerttriagewithsplunk)  
**Module:** [SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)

## Task 1: Introduction

### 1. Alert triage là gì?

**Alert triage** là quá trình đánh giá ban đầu một cảnh báo bảo mật để xác định mức độ đáng tin cậy, phạm vi ảnh hưởng và bước xử lý phù hợp. Analyst cần xác minh alert bằng log và ngữ cảnh, thay vì chỉ dựa vào tên rule hoặc mức độ severity.

Trong SOC, SOC L1 thường thực hiện các công việc:

- Xác nhận alert có dữ liệu và thời gian hợp lệ.
- Xác định host, user, IP, process hoặc ứng dụng liên quan.
- Thu thập log bổ trợ và tìm hoạt động trước/sau cảnh báo.
- Phân biệt hoạt động hợp pháp, false positive và hành vi đáng ngờ.
- Ghi nhận bằng chứng và escalation lên SOC L2 khi cần.

### 2. Phạm vi của room

Room thực hành ba tình huống điều tra bằng Splunk:

| Tình huống | Trọng tâm phân tích |
|---|---|
| Initial Access Alert | Điều tra dấu hiệu brute-force trên hệ thống Linux. |
| Persistence Alert | Phát hiện cơ chế persistence trên Windows. |
| Web Shell Alert | Phân tích hành vi đáng ngờ trên web server. |

Mục tiêu là luyện cách chuyển một alert thành cuộc điều tra có bằng chứng, không phải chỉ tìm một giá trị đơn lẻ.

---

## Task 2: Chuẩn bị môi trường và Splunk

### 1. Các thành phần giao diện cần biết

| Thành phần | Công dụng |
|---|---|
| Search bar | Nhập SPL để tìm kiếm event. |
| Time range picker | Giới hạn thời gian tìm kiếm. |
| Search results | Xem từng event và field được parse. |
| Fields sidebar | Chọn field phổ biến, xem giá trị và số lượng. |
| Event details | Đọc raw event và field đã trích xuất. |
| Statistics | Hiển thị kết quả tổng hợp từ `stats`, `chart`, `timechart`. |

Theo hướng dẫn lab, cần khởi động máy ảo và xác nhận Splunk đã sẵn sàng. Dùng đúng time range và index được chỉ định trong từng task. `All Time` chỉ nên dùng khi lab yêu cầu hoặc khi cần kiểm tra toàn bộ dữ liệu có sẵn; sau đó nên thu hẹp để phân tích chính xác hơn.

### 2. Cấu trúc SPL cơ bản

SPL (Search Processing Language) cho phép tìm kiếm và xử lý dữ liệu theo chuỗi lệnh.

```spl
index=<index_name> <field>=<value>
| table _time host user src_ip dest_ip process_name
| sort _time
```

Các thành phần phổ biến:

| Cú pháp | Chức năng |
|---|---|
| `index=` | Chọn nơi dữ liệu được lưu trữ. |
| `sourcetype=` | Lọc loại dữ liệu hoặc định dạng nguồn. |
| `field=value` | Lọc event theo field. |
| `table` | Chọn các cột cần hiển thị. |
| `stats` | Tổng hợp dữ liệu, đếm hoặc nhóm theo field. |
| `timechart` | Thống kê dữ liệu theo thời gian. |
| `sort` | Sắp xếp kết quả. |
| `where` | Lọc dựa trên biểu thức. |
| `bin` | Chia timestamp thành các khoảng thời gian. |
| `dedup` | Loại bỏ các kết quả trùng theo field. |

Tên index và field có thể khác giữa lab và môi trường doanh nghiệp. Cần kiểm tra dữ liệu thực tế trước khi sử dụng truy vấn.

---

## Task 3: Initial Access Alert – Linux Brute-force

### 1. Brute-force trên SSH là gì?

Brute-force là hành vi thử nhiều mật khẩu hoặc tổ hợp thông tin đăng nhập để truy cập tài khoản. Trên Linux server, SSH là một dịch vụ thường được kiểm tra khi điều tra dấu hiệu đăng nhập từ xa.

Các dấu hiệu có thể gặp:

- Nhiều lần đăng nhập thất bại từ một source IP.
- Một source IP thử nhiều username.
- Nhiều source IP nhắm vào cùng một account.
- Các lần thất bại diễn ra với tần suất cao và liên tục.
- Đăng nhập thành công xảy ra sau chuỗi thất bại.
- Login thành công từ nguồn không quen thuộc hoặc thời điểm bất thường.

### 2. Quy trình điều tra

1. Xác định server bị nhắm đến và thời điểm alert.
2. Tìm các sự kiện SSH authentication failure trong khoảng thời gian phù hợp.
3. Nhóm dữ liệu theo source IP, username và thời gian.
4. Tìm lần đăng nhập thành công có liên quan.
5. Kiểm tra user đó thực hiện lệnh gì sau khi đăng nhập.
6. Tìm dấu hiệu sử dụng `sudo`, chuyển sang root, tạo user hoặc thay đổi SSH configuration.
7. Đánh giá liệu đây là brute-force, password spraying hay lỗi đăng nhập hợp pháp.

### 3. Truy vấn SPL tham khảo

Tìm log authentication liên quan đến SSH (tùy sourcetype/field của lab):

```spl
index=<linux_index> ("Failed password" OR "Invalid user" OR "Accepted password" OR "Accepted publickey")
| table _time host user src message
| sort _time
```

Thống kê số lần thất bại theo source và account, nếu dữ liệu đã parse thành field:

```spl
index=<linux_index> action=failure
| stats count as failures values(user) as usernames by src_ip host
| sort - failures
```

Tìm sự kiện xác thực thành công:

```spl
index=<linux_index> ("Accepted password" OR "Accepted publickey")
| table _time host user src message
| sort _time
```

**Lưu ý:** Các tên field như `action`, `src_ip`, `user` chỉ là ví dụ. Nếu log được lưu dưới dạng raw text, hãy bắt đầu bằng tìm kiếm chuỗi và xem field có sẵn trước khi viết truy vấn tổng hợp.

### 4. Theo dõi hoạt động sau đăng nhập

Sau một lần đăng nhập đáng ngờ, cần tìm các hoạt động như:

- `sudo` hoặc command liên quan đến quyền root.
- Thay đổi file cấu hình SSH hoặc thêm public key.
- Tạo tài khoản hoặc thêm user vào group đặc quyền.
- Download hoặc chạy script, binary mới.
- Kết nối outbound đến hạ tầng không quen thuộc.

Một lần đăng nhập thành công sau nhiều lần thất bại là dấu hiệu quan trọng, nhưng vẫn cần kiểm tra user, nguồn IP, lịch sử hoạt động và tính hợp lệ của phiên đăng nhập.

---

## Task 4: Persistence Alert – Windows

### 1. Persistence là gì?

**Persistence** là kỹ thuật giúp attacker duy trì quyền truy cập sau khi thiết bị khởi động lại, phiên đăng nhập kết thúc hoặc tiến trình ban đầu bị đóng.

Một số vị trí/cơ chế persistence thường gặp:

- Scheduled Tasks.
- Windows Services.
- Registry Run/RunOnce keys.
- Startup folders.
- WMI event subscriptions.
- Tài khoản hoặc SSH key được tạo để duy trì truy cập.

### 2. Scheduled Task

Scheduled Task cho phép Windows tự động thực hiện một hành động theo thời gian hoặc điều kiện nhất định. Cơ chế này có thể được sử dụng hợp pháp cho quản trị, backup hoặc cập nhật; attacker cũng có thể lạm dụng để chạy payload định kỳ hoặc khi người dùng đăng nhập.

Khi phân tích scheduled task, cần kiểm tra:

- Tên task và thời điểm tạo.
- Tài khoản tạo task.
- Trigger: khi khởi động, đăng nhập hay theo lịch.
- Action: chương trình và arguments được thực thi.
- Đường dẫn binary/script được gọi.
- Account hoặc privilege dùng để chạy task.
- Task có xuất hiện cùng lúc với process/network event bất thường không.

Windows Security Event ID **4698** ghi nhận scheduled task được tạo trong trường hợp audit tương ứng đã được bật. Cấu hình audit và nguồn log quyết định event có xuất hiện hay không.

Truy vấn SPL mẫu:

```spl
index=<windows_index> EventCode=4698
| table _time ComputerName SubjectUserName TaskName TaskContent
| sort _time
```

Field `TaskName` và `TaskContent` có thể không tồn tại dưới đúng tên này nếu parser khác nhau. Có thể cần kiểm tra raw XML hoặc raw event.

### 3. Windows Service

Service là thành phần chạy nền của Windows. Khi điều tra service mới:

- Kiểm tra service name và display name.
- Xem binary path và arguments.
- Xác định service chạy dưới account nào.
- Kiểm tra chữ ký số và hash của file.
- Đối chiếu với thời gian tạo file/process và các alert khác.

Các event thường được tham khảo gồm Security Event ID 4697 (service được cài đặt khi audit phù hợp) và System Event ID 7045.

```spl
index=<windows_index> (EventCode=4697 OR EventCode=7045)
| table _time ComputerName ServiceName ServiceFileName ServiceAccount
| sort _time
```

### 4. Xác định persistence có đáng ngờ không

Tên task hoặc service có thể được đặt giống thành phần hệ thống. Analyst không nên kết luận chỉ từ tên. Hãy kiểm tra path, binary signature, hash, parent process, command line, user tạo và lịch sử thay đổi trên host.

---

## Task 5: Web Shell Alert

### 1. Web shell là gì?

Web shell là mã độc hoặc mã bị lạm dụng được đặt trên web server để nhận lệnh qua HTTP/HTTPS và thực thi hành động trên server. Nó có thể được dùng để chạy command, truy cập file hoặc làm bàn đạp cho hoạt động tiếp theo.

### 2. Phân tích access logs

Các field cần quan sát:

| Field | Câu hỏi điều tra |
|---|---|
| Client IP | Request đến từ đâu? Có bất thường so với baseline không? |
| URI path | Endpoint nào được truy cập? Có file script lạ không? |
| HTTP method | Có POST request bất thường không? |
| Status code | Server trả về mã nào? Request có nhận phản hồi thành công không? |
| User-Agent | Client có giống browser thông thường hay công cụ tự động? |
| Timestamp | Có nhiều request liên tiếp hoặc chuỗi hành động sau một khai thác không? |

Tìm các request đến script path đáng chú ý là điểm bắt đầu, không phải kết luận. Cần nối access logs với process telemetry của IIS/web server để tìm process con, command shell, PowerShell hoặc script engine bất thường.

### 3. Truy vấn SPL tham khảo

Tổng hợp POST request theo URI và IP:

```spl
index=<web_index> method=POST
| stats count values(status) as status values(useragent) as useragent by clientip uri_path
| sort - count
```

Tìm endpoint script có tần suất truy cập bất thường:

```spl
index=<web_index>
| where match(uri_path,"(?i)\\.(php|asp|aspx|jsp)$")
| stats count values(method) as methods values(status) as status values(useragent) as useragent by clientip uri_path
| sort - count
```

Tùy parser, field có thể là `cs_uri_stem`, `uri`, `url.path` hoặc tên khác. Điều chỉnh truy vấn theo schema của dataset.

### 4. Liên kết với Windows process logs

Nếu web server chạy trên Windows/IIS, cần kiểm tra process được khởi chạy bởi worker process hoặc service liên quan đến web server. Một chuỗi process bất thường có thể cung cấp bằng chứng mạnh hơn access log đơn lẻ.

Ví dụ hướng tìm kiếm:

- Process cha: IIS worker process hoặc web server service.
- Process con: `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe` hoặc tool không thường gặp.
- Command line: lệnh hệ thống, tải file, tạo user hoặc kết nối mạng.
- Timestamp: có khớp với HTTP request nghi vấn hay không.

Tên process hoặc parent process không tự động chứng minh web shell; cần xác minh theo vai trò ứng dụng và hoạt động hợp pháp.

---

## Task 6: Quy trình triage và báo cáo

### 1. Checklist trước khi đóng alert

- [ ] Đã đọc rule và xác định điều kiện kích hoạt.
- [ ] Đã kiểm tra time range, timezone và log source.
- [ ] Đã xác định host/user/IP/process liên quan.
- [ ] Đã tìm kiếm event trước và sau thời điểm alert.
- [ ] Đã đối chiếu ít nhất một nguồn log bổ trợ nếu có.
- [ ] Đã xem xét khả năng hoạt động quản trị hoặc ứng dụng hợp pháp.
- [ ] Đã đánh giá phạm vi ảnh hưởng và các indicator liên quan.
- [ ] Đã ghi rõ bằng chứng và lý do phân loại.

### 2. Mẫu ghi chú triage

```text
Alert name:
Severity / Priority:
Time observed (with timezone):
Affected host(s):
Affected user(s):
Source IP / Destination IP:
Relevant process / file / URL:
Log sources reviewed:
Observed sequence of events:
Evidence supporting suspicious activity:
Benign explanation considered:
Assessment: Benign / Suspicious / Malicious / Inconclusive
Impact and scope:
Recommended next action:
```

### 3. Phân loại kết quả

| Phân loại | Cách hiểu |
|---|---|
| Benign / Expected | Có bằng chứng cho thấy hoạt động hợp pháp và phù hợp với ngữ cảnh. |
| False Positive | Rule phát hiện nhầm do logic hoặc dữ liệu, nhưng cần ghi rõ nguyên nhân. |
| Suspicious | Có dấu hiệu bất thường nhưng bằng chứng chưa đủ để kết luận. |
| Malicious / True Positive | Có bằng chứng đáng tin cậy cho thấy hoạt động độc hại. |
| Inconclusive | Dữ liệu chưa đủ hoặc log source bị thiếu để đưa ra kết luận. |

**Kết luận kiến thức:** Triage tốt là một quy trình có thể tái hiện: từ alert, xác minh dữ liệu, pivot sang event liên quan, dựng timeline và ghi lại lập luận dựa trên evidence.

---

## Tài liệu tham khảo

- [TryHackMe – Alert Triage With Splunk](https://tryhackme.com/room/alerttriagewithsplunk)
- [TryHackMe – Log Analysis with SIEM](https://tryhackme.com/room/loganalysiswithsiem)
- [Microsoft Learn – Event 4688: A new process has been created](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft Learn – Event 4625: An account failed to log on](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [Microsoft Learn – Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- [Splunk Documentation](https://docs.splunk.com/Documentation)
