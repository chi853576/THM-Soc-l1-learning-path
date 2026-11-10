# Alert Triage With Elastic

**Nguồn học:** [TryHackMe – Alert Triage With Elastic](https://tryhackme.com/room/alerttriagewithelastic)  
**Module:** [SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)

## Task 1: Introduction

### 1. Mục tiêu của room

Room hướng dẫn sử dụng **Kibana thuộc Elastic Stack** để điều tra alert trên môi trường có IIS và Windows Server. Trọng tâm là đọc log, nhận diện Indicators of Compromise (IoC) và liên kết các sự kiện từ nhiều nguồn dữ liệu.

Các mục tiêu kiến thức:

- Sử dụng Kibana để tìm và phân tích security logs.
- Nhận diện các field và indicator có giá trị điều tra.
- Tương quan web logs, account activity và process execution.
- Xây dựng bối cảnh cho một chuỗi hoạt động đáng ngờ.

### 2. Elastic Stack và vai trò của Kibana

| Thành phần | Vai trò |
|---|---|
| Elasticsearch | Lưu trữ và tìm kiếm dữ liệu đã được ingest. |
| Logstash / Ingest Pipeline | Nhận, parse, biến đổi hoặc chuyển tiếp dữ liệu. |
| Beats / Elastic Agent | Thu thập log, metric và telemetry từ endpoint hoặc service. |
| Kibana | Giao diện để tìm kiếm, trực quan hóa và phân tích dữ liệu. |
| Elastic Security | Các khả năng security analytics, detection, alert và investigation trong Elastic. |

### 3. Discover và Data Views

**Discover** là nơi analyst truy vấn và xem các document log. Các bước cơ bản:

1. Mở Kibana và truy cập Discover.
2. Chọn Data View phù hợp với dữ liệu cần điều tra.
3. Đặt time range bao phủ thời điểm alert.
4. Kiểm tra field list và chọn các field có ích.
5. Dùng KQL hoặc filter controls để thu hẹp kết quả.
6. Mở từng document để đọc toàn bộ field và raw message.

Nếu không thấy kết quả, cần kiểm tra Data View, time range, ingest status và tên field trước khi kết luận không có event.

---

## Task 2: KQL và Elastic Common Schema

### 1. Kibana Query Language (KQL)

KQL được sử dụng trong thanh tìm kiếm của Kibana để lọc document theo field. Đây là ngôn ngữ lọc, không phải ngôn ngữ tổng hợp kết quả như SQL.

Một số cú pháp cơ bản:

| Cú pháp | Ý nghĩa |
|---|---|
| `field: value` | Field bằng hoặc khớp với giá trị. |
| `AND` | Cả hai điều kiện phải đúng. |
| `OR` | Một trong các điều kiện đúng. |
| `NOT` | Loại trừ điều kiện. |
| `field: *` | Field có tồn tại. |
| `field: prefix*` | Khớp wildcard ở cuối chuỗi. |
| `(condition1 OR condition2)` | Gom nhóm điều kiện. |

Ví dụ:

```text
host.name: "WEB01" AND event.category: web
```

```text
http.request.method: POST AND url.path: "/login"
```

```text
process.name: powershell.exe AND process.command_line: *EncodedCommand*
```

Tên field có thể khác theo dataset hoặc mapping. Hãy kiểm tra document và ECS mapping trước khi dùng các truy vấn mẫu.

### 2. Elastic Common Schema (ECS)

**ECS** là quy ước field chung trong Elastic để dữ liệu từ nhiều nguồn có cấu trúc nhất quán hơn.

| ECS field | Ý nghĩa |
|---|---|
| `@timestamp` | Thời điểm event. |
| `event.category` | Nhóm hoạt động như `web`, `process`, `network`, `authentication`. |
| `event.action` | Hành động cụ thể được ghi nhận. |
| `event.outcome` | Kết quả như `success`, `failure` hoặc `unknown`, nếu nguồn có thông tin. |
| `host.name` | Tên host. |
| `user.name` | Tài khoản liên quan. |
| `source.ip` | IP nguồn. |
| `destination.ip` | IP đích. |
| `process.name` | Tên process. |
| `process.command_line` | Command line, nếu được thu thập. |
| `process.parent.name` | Tên process cha. |
| `http.request.method` | HTTP method. |
| `http.response.status_code` | HTTP response status. |
| `url.path` | Đường dẫn URL. |

ECS không đảm bảo mọi log đều có đủ field. Field có thể vắng mặt vì nguồn log không ghi nhận, pipeline chưa parse hoặc cấu hình ingest chưa đúng.

---

## Task 3: Scenario Briefing – Xác định phạm vi

### 1. Đọc alert trước khi truy vấn

Đối với mỗi alert, cần ghi lại:

- Alert name và rule description.
- Timestamp, timezone và thời gian quan sát.
- Hostname hoặc asset bị ảnh hưởng.
- User/account liên quan.
- IP nguồn, IP đích, domain hoặc URL.
- Event category, action, severity và reference nếu có.

### 2. Xây dựng giả thuyết điều tra

Ví dụ khi alert liên quan đến web server:

1. Có request đáng ngờ nào được gửi đến IIS không?
2. Request đó có liên quan đến xác thực tài khoản hoặc truy cập file bất thường không?
3. Sau request, có process hoặc command nào được chạy trên host không?
4. Tài khoản thực thi có quyền gì?
5. Có network connection hoặc file creation tiếp theo không?

Giả thuyết chỉ giúp định hướng truy vấn; kết luận phải dựa trên evidence.

---

## Task 4: Investigating Web Attacks

### 1. IIS log và HTTP request

IIS access logs ghi nhận hoạt động request đến web server. Một số field thường có trong W3C Extended Log Format:

| Field | Ý nghĩa |
|---|---|
| `c-ip` | Client IP. |
| `cs-method` | HTTP method. |
| `cs-uri-stem` | URI path. |
| `cs-uri-query` | Query string. |
| `sc-status` | HTTP status code. |
| `sc-substatus` | IIS substatus. |
| `sc-win32-status` | Windows status code. |
| `cs(User-Agent)` | User-Agent của client, nếu cấu hình ghi nhận. |

Tên field đã ingest vào Elastic có thể được map sang ECS như `source.ip`, `http.request.method`, `url.path` và `http.response.status_code`.

### 2. Brute-force hoặc password guessing qua web

Dấu hiệu cần tìm:

- Nhiều POST đến endpoint đăng nhập.
- Số lượng login failure tăng trong khoảng thời gian ngắn.
- Một nguồn IP thử nhiều account hoặc nhiều IP nhắm vào một account.
- Tần suất request, User-Agent hoặc pattern request khác baseline.
- Một lần login success sau chuỗi failure.

KQL tham khảo:

```text
http.request.method: POST AND url.path: *login*
```

Hoặc lọc thêm host:

```text
host.name: "WEB01" AND http.request.method: POST AND url.path: *login*
```

Sau khi lọc, kiểm tra `source.ip`, `user.name` nếu có, `http.response.status_code`, `@timestamp` và raw message. KQL không thực hiện phép đếm hoặc group-by; dùng bảng Discover, visualization hoặc Lens để tổng hợp.

### 3. Request bất thường và web attack

Các hành vi nên kiểm tra gồm:

- Truy cập nhiều path không tồn tại hoặc endpoint nhạy cảm.
- Thử các payload có dấu hiệu path traversal, command injection hoặc SQL injection.
- Request đến file script lạ hoặc endpoint không thuộc chức năng ứng dụng.
- POST request với payload/chuỗi bất thường.
- Nhiều HTTP 4xx/5xx hoặc thay đổi response pattern.

Các chuỗi đặc biệt trong URL không tự động chứng minh exploitation. Cần đọc request, response, server logs và kết quả thực tế trên host.

### 4. Web shell investigation

Nếu một request có khả năng gọi web shell, analyst cần pivot từ web log sang endpoint telemetry:

1. Lấy timestamp, source IP, host và URI path.
2. Tìm process được tạo trên IIS server trong cùng khoảng thời gian.
3. Xem parent-child process relationship.
4. Kiểm tra command line và account thực thi.
5. Tìm file creation, hash hoặc network connection tiếp theo.
6. Đánh giá liệu web application có chức năng hợp pháp tạo các process đó không.

---

## Task 5: Uncovering Account Activity

### 1. Vì sao cần phân tích account activity?

Tài khoản có thể bị lạm dụng để truy cập trái phép, nâng quyền hoặc duy trì persistence. Cần xác định hành động được thực hiện bởi user nào, trên host nào và trong ngữ cảnh nào.

Các event Windows thường được tham khảo:

| Event ID | Hoạt động |
|---|---|
| 4624 | Logon thành công. |
| 4625 | Logon thất bại. |
| 4648 | Đăng nhập bằng explicit credentials. |
| 4672 | Đặc quyền đặc biệt được gán cho logon. |
| 4720 | Tạo tài khoản user. |
| 4722 | Kích hoạt tài khoản. |
| 4732 | Thêm thành viên vào local security-enabled group. |

Danh sách này là điểm bắt đầu. Cần đọc Subject, Target Account, Logon Type, source address, host và event details để hiểu chính xác event.

### 2. Truy vấn KQL tham khảo

Tìm logon failure:

```text
event.code: "4625"
```

Tìm logon success:

```text
event.code: "4624"
```

Tìm sự kiện tạo tài khoản:

```text
event.code: "4720"
```

Lọc theo user và host:

```text
user.name: "analyst" AND host.name: "WEB01"
```

Các event ID có thể được lưu ở field `event.code`, `winlog.event_id` hoặc tên field khác tùy integration. Kiểm tra document thực tế trước khi sử dụng.

### 3. Phân tích chuỗi xác thực

Để đánh giá login đáng ngờ:

1. Xác định source IP và account.
2. So sánh số lần thất bại với lần thành công.
3. Đọc Logon Type để hiểu loại phiên đăng nhập.
4. Kiểm tra host đích và vai trò của account.
5. Tìm các hành động sau khi đăng nhập như process creation, account change hoặc network activity.
6. Đối chiếu lịch sử account để xác định hành vi có khác baseline hay không.

---

## Task 6: Exposing Command Execution

### 1. Process creation và command line

Process telemetry giúp analyst xác định chương trình được thực thi, account thực thi và chuỗi tiến trình liên quan.

Một số field quan trọng:

| Field | Ý nghĩa |
|---|---|
| `process.name` | Tên executable. |
| `process.executable` | Đường dẫn executable. |
| `process.command_line` | Câu lệnh và tham số. |
| `process.pid` | Process ID. |
| `process.parent.name` | Process cha. |
| `process.parent.command_line` | Command line của process cha, nếu có. |
| `user.name` | User thực thi. |
| `host.name` | Thiết bị thực thi. |
| `process.hash.sha256` | SHA-256 của file, nếu được thu thập. |

### 2. Tìm PowerShell hoặc command shell

KQL tham khảo:

```text
process.name: (powershell.exe OR pwsh.exe OR cmd.exe)
```

Tìm các lệnh có dấu hiệu encoded command:

```text
process.command_line: *EncodedCommand*
```

Tìm process được tạo bởi IIS worker process (tên thực tế cần kiểm tra từ log):

```text
process.parent.name: w3wp.exe
```

Các truy vấn trên chỉ giúp thu hẹp kết quả. PowerShell, cmd.exe và IIS worker process đều có thể xuất hiện trong hoạt động hợp pháp.

### 3. Phân tích parent-child process

Một process cần được xem trong bối cảnh process cha và các hành động tiếp theo.

Ví dụ hướng điều tra:

- Xác định parent process và user context.
- Đọc command line đầy đủ, bao gồm arguments.
- Xem executable path và hash.
- Tìm file được tạo hoặc tải xuống gần thời điểm thực thi.
- Tìm DNS query và network connection do process tạo ra.
- Xác định process có chạy với quyền cao hơn dự kiến hay không.

### 4. Timeline và correlation

Liên kết các event bằng `host.name`, `user.name`, process ID hoặc Process GUID, file hash và timestamp. PID có thể được tái sử dụng sau khi process kết thúc; khi có thể, ưu tiên Process GUID hoặc entity identifier để correlation chắc chắn hơn.

---

## Task 7: Quy trình điều tra chuẩn trên Elastic

### 1. Investigation workflow

1. **Set time range:** bao phủ thời điểm alert và khoảng thời gian cần tìm kiếm trước/sau đó.
2. **Inspect alert fields:** đọc host, user, source/destination, event category và rule metadata.
3. **Pivot in Discover:** tìm event cùng host, IP, username hoặc process.
4. **Validate field mapping:** xác nhận field chứa đúng dữ liệu và kiểu dữ liệu.
5. **Correlate sources:** nối web, Windows Security, Sysmon và network logs.
6. **Enrich IoCs:** kiểm tra hash, IP, domain và URL bằng nguồn đáng tin cậy.
7. **Create timeline:** sắp xếp theo `@timestamp` và ghi timezone.
8. **Assess impact:** xác định account, host, service hoặc dữ liệu có thể bị ảnh hưởng.
9. **Document assessment:** ghi bằng chứng, giả thuyết đã loại trừ và phần còn thiếu.

### 2. Lỗi thường gặp khi sử dụng Kibana/KQL

- Chọn sai Data View nên không nhìn thấy dữ liệu.
- Time range quá hẹp hoặc sai timezone.
- Dùng field name không tồn tại trong mapping.
- Dùng wildcard đầu chuỗi trên lượng dữ liệu lớn làm truy vấn chậm.
- Cho rằng không có kết quả nghĩa là không có sự kiện.
- Nhầm KQL là ngôn ngữ tổng hợp; KQL chủ yếu dùng để lọc document.
- Kết luận dựa trên một event mà không đối chiếu log nguồn khác.

### 3. Mẫu ghi nhận alert

```text
Alert:
Rule / Detection source:
Time range and timezone:
Affected host:
Affected user:
Source / Destination:
Relevant URI / Process / Command line:
Related event IDs:
Timeline:
Indicators collected:
Evidence supporting the assessment:
Alternative benign explanation:
Assessment:
Scope / Impact:
Recommended escalation or next step:
```

**Kết luận kiến thức:** Elastic giúp phân tích alert bằng cách lọc và pivot dữ liệu trong Discover, sử dụng KQL và các field chuẩn hóa. Giá trị quan trọng nhất là khả năng nối web activity, account activity và process execution để dựng lại diễn biến sự cố.

---

## Tài liệu tham khảo

- [TryHackMe – Alert Triage With Elastic](https://tryhackme.com/room/alerttriagewithelastic)
- [TryHackMe – SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)
- [Elastic – KQL syntax reference](https://www.elastic.co/docs/reference/query-languages/kql)
- [Elastic – Filtering in Kibana](https://www.elastic.co/docs/explore-analyze/query-filter/filtering)
- [Elastic – Elastic Common Schema: Event fields](https://www.elastic.co/docs/reference/ecs/ecs-event)
- [Elastic – Elastic Common Schema: Process fields](https://www.elastic.co/docs/reference/ecs/ecs-process)
- [Microsoft Learn – Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
