# Benign

**Nguồn học:** [TryHackMe – Benign](https://tryhackme.com/room/benign)  
**Module:** [SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)

## Task 1: Introduction

### 1. Mục tiêu của challenge

Benign là challenge điều tra một host có dấu hiệu bị compromise. Nội dung tập trung vào **host-centric logs** và việc phân tích các hoạt động thực thi process được ghi nhận trong Windows event data.

Mục tiêu kiến thức:

- Truy vấn Windows event logs trong Splunk.
- Nhận diện process execution bất thường.
- Phân tích command line và parent-child process relationship.
- Pivot từ process sang user, host, file hash và các event liên quan.
- Phân biệt hoạt động quản trị/hệ thống hợp pháp với dấu hiệu bị lạm dụng.

### 2. Host-centric investigation là gì?

Host-centric investigation là cách điều tra bắt đầu từ dữ liệu được ghi nhận trên một thiết bị. Thay vì chỉ nhìn vào IP hoặc network traffic, analyst tập trung vào hoạt động bên trong endpoint:

- Tài khoản nào đã đăng nhập?
- Process nào được khởi chạy?
- Process được tạo bởi process cha nào?
- Command line chứa những tham số gì?
- Binary nằm ở thư mục nào và có hash/chữ ký ra sao?
- Hành động nào xảy ra trước và sau process đó?

### 3. Nguồn dữ liệu trong room

Theo mô tả công khai của TryHackMe, các log cần phân tích được ingest vào Splunk index `win_eventlogs`. Đây là thông tin về dataset của room; trong môi trường khác, index và field có thể được đặt tên khác.

---

## Task 2: Chuẩn bị Splunk

### 1. Truy vấn dữ liệu tổng quan

Bắt đầu bằng việc truy vấn index được lab chỉ định:

```spl
index=win_eventlogs
| head 20
```

Mục đích:

- Xác nhận có dữ liệu.
- Kiểm tra field được parse.
- Xác định tên host, event code và timestamp.
- Nhận biết log source trước khi viết truy vấn cụ thể.

### 2. Xem các EventCode có trong dataset

```spl
index=win_eventlogs
| stats count by EventCode
| sort - count
```

Truy vấn này cho biết dataset có những loại event nào và số lượng tương ứng. Sự vắng mặt của một EventCode có thể do audit chưa bật, log chưa được ingest hoặc dataset không chứa sự kiện đó.

### 3. Field hữu ích

| Field | Ý nghĩa |
|---|---|
| `_time` | Thời gian event trong Splunk. |
| `ComputerName` / `host` | Host tạo event. |
| `EventCode` | Windows Event ID hoặc Sysmon Event ID tùy nguồn. |
| `User` / `UserName` | User liên quan. |
| `Image` | Đường dẫn executable của process trong Sysmon. |
| `CommandLine` | Lệnh và tham số đã thực thi. |
| `ParentImage` | Executable của process cha. |
| `ParentCommandLine` | Command line của process cha, nếu có. |
| `ProcessId` | Process ID. |
| `Hashes` | Hash của file nếu nguồn log và cấu hình có thu thập. |

Tên field không thống nhất giữa Windows Security logs, Sysmon và các parser. Cần xem raw event để xác định field tương ứng.

---

## Task 3: Process Execution Analysis

### 1. Vì sao process creation quan trọng?

Process creation cung cấp bằng chứng về chương trình được khởi chạy và ngữ cảnh thực thi. Đây là một điểm pivot hữu ích khi điều tra malware execution, script abuse, living-off-the-land techniques hoặc hành vi quản trị bất thường.

Hai nguồn log thường gặp:

- **Windows Security Event ID 4688:** ghi nhận một process mới được tạo khi audit process creation phù hợp được bật. Command line chỉ có thể xuất hiện nếu chính sách ghi command line đã được cấu hình.
- **Sysmon Event ID 1:** ghi nhận process creation với thông tin mở rộng, có thể bao gồm parent process, command line, hash và Process GUID.

### 2. Tìm process creation trong Splunk

Với dataset dùng EventCode cho Sysmon Event ID 1:

```spl
index=win_eventlogs EventCode=1
| table _time ComputerName User Image ParentImage CommandLine Hashes ProcessGuid
| sort _time
```

Với Windows Security Event ID 4688:

```spl
index=win_eventlogs EventCode=4688
| table _time ComputerName SubjectUserName NewProcessName ParentProcessName CommandLine
| sort _time
```

Tên field có thể khác nhau tùy parser; kiểm tra event details nếu một số cột trống.

### 3. Phân tích command line

Khi đọc command line, chú ý:

- Executable và đường dẫn đầy đủ.
- Tham số truyền vào process.
- File/script được tham chiếu.
- URL hoặc địa chỉ mạng xuất hiện trong command.
- Các tham số mã hóa, obfuscation hoặc bypass.
- Lệnh tạo user, thay đổi quyền, sửa cấu hình hoặc xóa dấu vết.

Một command line dài hoặc có ký tự khó đọc không tự động là malicious. Công cụ quản trị, installer và updater hợp pháp cũng có thể sử dụng tham số phức tạp.

### 4. Parent-child process relationship

Process cha giúp giải thích process được khởi chạy như thế nào. Ví dụ cần xem xét:

- Office application khởi chạy command shell hoặc script engine.
- Web server worker process tạo command shell.
- Script host khởi chạy PowerShell.
- Một process từ thư mục tạm tạo thêm executable khác.
- Process hệ thống tạo child process không phù hợp với hoạt động bình thường.

Các mối quan hệ này chỉ là dấu hiệu cần kiểm tra. Phần mềm quản lý endpoint, script triển khai và công cụ IT hợp pháp cũng có thể tạo parent-child pattern tương tự.

Truy vấn thống kê process theo parent:

```spl
index=win_eventlogs EventCode=1
| stats count values(CommandLine) as commands by ParentImage Image
| sort - count
```

Tập trung xem các cặp parent-child hiếm gặp hoặc không phù hợp với vai trò của host.

---

## Task 4: Nhận diện hoạt động đáng ngờ

### 1. Các dấu hiệu cần ưu tiên xem xét

**Executable path bất thường**

- File thực thi nằm trong thư mục tạm, public, download hoặc profile user mà không có lý do rõ ràng.
- Tên file mô phỏng thành phần hệ điều hành nhưng path không đúng vị trí chuẩn.
- Binary mới xuất hiện ngay trước alert.

**Process lineage bất thường**

- Ứng dụng văn phòng hoặc web server khởi chạy command shell.
- Process cha không phù hợp với chức năng của child process.
- Nhiều cấp process được tạo nhanh theo chuỗi.

**Command line đáng chú ý**

- PowerShell hoặc script engine có tham số ẩn/mã hóa.
- Lệnh tải file từ Internet.
- Lệnh tạo Scheduled Task, Service hoặc thay đổi Registry.
- Lệnh truy vấn thông tin hệ thống hoặc tài khoản ở thời điểm bất thường.

**Identity và privilege**

- Process được chạy dưới tài khoản không thường dùng trên host.
- Tài khoản thường được dùng với quyền cao bất thường.
- Logon source hoặc Logon Type khác baseline.

### 2. Lệnh hệ thống hợp pháp có thể bị lạm dụng

Một số Windows utilities được sử dụng trong công việc quản trị bình thường nhưng cũng có thể bị attacker lợi dụng. Khi đánh giá, nên tập trung vào **ngữ cảnh sử dụng**:

- Ai chạy lệnh?
- Process cha nào khởi chạy?
- Command line sử dụng option gì?
- File hoặc URL nào được tham chiếu?
- Lệnh chạy ở host nào và thời điểm nào?
- Có kết quả tiếp theo như file creation hoặc network connection không?

Không nên phân loại một process là độc hại chỉ vì tên công cụ có thể được attacker sử dụng.

### 3. Pivot từ process sang hash và file

Nếu event có hash:

1. Xác định hash algorithm (MD5, SHA-1, SHA-256).
2. Ghi lại hash cùng file path và host.
3. Kiểm tra file reputation từ nguồn threat intelligence phù hợp.
4. Kiểm tra chữ ký số, publisher và metadata nếu có mẫu file.
5. Tìm các host khác có cùng hash.
6. Đối chiếu thời gian file được tạo và process được thực thi.

Một hash chưa có detection không có nghĩa file an toàn. File mới, private malware hoặc file chưa được phân tích có thể không có reputation.

---

## Task 5: Correlation và Timeline

### 1. Ghép nối process với authentication events

Có thể kết hợp process creation với logon events để xác định ai đã thực hiện hành động.

Windows Event ID tham khảo:

| Event ID | Nội dung |
|---|---|
| 4624 | Logon thành công. |
| 4625 | Logon thất bại. |
| 4648 | Sử dụng explicit credentials. |
| 4672 | Logon được gán special privileges. |
| 4688 | Process creation. |
| 4720 | Tạo user account. |
| 4698 | Tạo scheduled task. |

Cần đối chiếu Logon ID, username, host và timestamp. Chỉ ghép các event gần nhau theo thời gian có thể tạo ra liên kết sai.

### 2. Ghép process với network events

Nếu có Sysmon:

- Event ID 1: process creation.
- Event ID 3: network connection.
- Event ID 22: DNS query.

Process GUID có thể hỗ trợ liên kết process và network event. Nếu chỉ có PID, cần xét thời gian vì PID có thể được tái sử dụng.

### 3. Truy vấn timeline mẫu

```spl
index=win_eventlogs ComputerName=<host_name>
| sort 0 _time
| table _time EventCode User Image ParentImage CommandLine SourceIp DestinationIp DestinationPort
```

Kết quả có thể cần chỉnh field theo log source. Mục đích là xem chuỗi sự kiện theo thời gian trên cùng host.

### 4. Mẫu bảng timeline

| Thời gian | Event | User | Process / Artifact | Ý nghĩa |
|---|---|---|---|---|
| T0 | Authentication | User A | Remote logon | Điểm vào cần kiểm tra |
| T1 | Process creation | User A | Parent → Child | Hoạt động sau đăng nhập |
| T2 | File / Registry / Task | User A hoặc SYSTEM | Persistence-related artifact | Kiểm tra khả năng duy trì truy cập |
| T3 | Network connection | Process | Destination IP/port | Kiểm tra liên lạc ra ngoài |

Đây là bố cục ghi nhận, không phải dữ liệu hoặc đáp án của challenge.

---

## Task 6: Phân biệt benign và malicious

### 1. Benign không có nghĩa là mọi event đều an toàn

Tên challenge là **Benign**, nhưng mục tiêu điều tra vẫn là xác định hoạt động trên host có dấu hiệu compromise hay không. Không nên đưa ra kết luận dựa trên tên room hoặc một trường đơn lẻ.

### 2. Tiêu chí đánh giá

| Tiêu chí | Câu hỏi |
|---|---|
| User | Tài khoản có được phép thực hiện hành động này không? |
| Host role | Hành động có phù hợp với máy trạm/server đó không? |
| Process | Binary có hợp lệ, đúng path và đúng parent không? |
| Command line | Tham số có phù hợp với mục đích sử dụng không? |
| Time | Hành động có nằm trong cửa sổ bảo trì hoặc giờ làm việc không? |
| File | File có signature, hash và nguồn gốc rõ ràng không? |
| Network | Có kết nối đến domain/IP không phù hợp không? |
| Follow-on activity | Có persistence, account change hoặc hành động tiếp theo không? |

### 3. Khi nào kết luận inconclusive?

Nên giữ kết luận ở mức chưa đủ dữ liệu nếu:

- Log không ghi command line.
- Thiếu event trước/sau thời điểm đáng ngờ.
- Không có process lineage hoặc user context.
- Timestamp giữa nguồn log không đồng bộ.
- Không thể xác minh file hoặc network indicator.

Ghi rõ những dữ liệu còn thiếu thay vì tự suy diễn.

---

## Task 7: Báo cáo kết quả điều tra

### 1. Cấu trúc báo cáo ngắn

```text
Case / Alert:
Host:
Time range and timezone:
User(s):
Relevant Event IDs:
Suspicious process:
Parent process:
Command line:
File path / Hash:
Related network activity:
Timeline:
Evidence reviewed:
Benign explanations considered:
Assessment:
Impact / Scope:
Recommended next steps:
```

### 2. Kỹ năng thể hiện qua challenge

Hoàn thành dạng bài này giúp luyện tập:

- Tìm kiếm và lọc Windows event logs bằng SPL.
- Phân tích process creation và command-line telemetry.
- Đọc parent-child process relationship.
- Correlate process, user, host và network evidence.
- Nhận diện dấu hiệu persistence hoặc process abuse.
- Viết nhận định có căn cứ và nêu rõ giới hạn dữ liệu.

**Kết luận kiến thức:** Điều tra host-centric đòi hỏi phân tích hành vi trên endpoint theo chuỗi. Process đáng ngờ cần được đánh giá cùng parent process, user, command line, path, hash, network activity và các event liên quan để tránh nhầm lẫn với công việc quản trị hợp pháp.

---

## Tài liệu tham khảo

- [TryHackMe – Benign](https://tryhackme.com/room/benign)
- [TryHackMe – SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)
- [Microsoft Learn – Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [Microsoft Learn – Understanding Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Microsoft Learn – Event 4688: A new process has been created](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft Learn – Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- [Splunk Documentation](https://docs.splunk.com/Documentation)
