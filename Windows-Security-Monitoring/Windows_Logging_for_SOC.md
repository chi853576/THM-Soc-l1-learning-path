# Windows Logging for SOC

**Nguồn học:** [TryHackMe – Windows Logging for SOC](https://tryhackme.com/room/windowsloggingforsoc)  


## Task 1: Introduction

### Mục tiêu học tập
- Hiểu cách tìm và diễn giải các Windows Event Logs quan trọng.
- Làm quen với Sysmon và PowerShell logging.
- Thực hành phân tích các bộ dữ liệu event log.
- Biết dùng log để phân biệt hoạt động bình thường và dấu hiệu xâm nhập.

## Task 2: What Is Logged

### Logging là gì?
Windows có thể ghi lại sự kiện phát sinh khi người dùng đăng nhập, chạy chương trình, tạo file hoặc thay đổi cấu hình. Mỗi event thường có thời gian, nguồn ghi log, loại sự kiện và dữ liệu ngữ cảnh.

Log hỗ trợ:
- **Incident response:** dựng lại diễn biến sự cố.
- **Threat hunting:** tìm hành vi đáng ngờ.
- **Alerting/triage:** làm nguồn dữ liệu cho rule phát hiện.

### Event Viewer và EVTX
- Windows Event Logs thường được lưu dưới dạng `.evtx` tại `C:\Windows\System32\winevt\Logs`.
- Event Viewer cho phép duyệt log theo nguồn, lọc theo Event ID, thời gian và xem chi tiết dạng thân thiện hoặc XML.
- Timestamp trong Event Viewer thường hiển thị theo timezone của hệ thống; cần lưu ý timezone khi tương quan log từ nhiều nguồn.
- Không phải mọi loại sự kiện đều được bật ghi mặc định; chính sách audit và cấu hình hệ thống ảnh hưởng độ bao phủ.

### Thành phần cần đọc trong một event
- **Log source/channel:** nơi ghi nhận sự kiện.
- **TimeCreated:** thời điểm xảy ra/được ghi nhận.
- **Event ID:** mã phân loại sự kiện.
- **Level/Keywords:** mức độ hoặc thuộc tính sự kiện.
- **Event data:** user, process, IP, logon ID, command line… tùy event.

## Task 3: Security Log — Authentication

### Event ID thường gặp
| Event ID | Ý nghĩa | Ứng dụng phân tích |
|---|---|---|
| 4624 | Đăng nhập thành công | Xác định phiên đăng nhập, nguồn và loại logon |
| 4625 | Đăng nhập thất bại | Phát hiện brute force, password spraying hoặc lỗi đăng nhập bất thường |
| 4720 | Tạo tài khoản người dùng | Phát hiện tài khoản mới không được phê duyệt |
| 4732 | Thêm thành viên vào nhóm local security-enabled | Theo dõi thay đổi quyền nhóm |

### Logon Type
- **3 — Network:** truy cập qua mạng.
- **10 — RemoteInteractive:** đăng nhập Remote Desktop.
- Đọc Logon Type cùng Source IP, account, workstation và thời gian; một event riêng lẻ thường chưa đủ kết luận.

### Phân tích brute force/password spraying
- Nhiều lần thất bại trên một tài khoản có thể gợi ý brute force.
- Nhiều tài khoản bị thử từ một nguồn có thể gợi ý password spraying.
- Kiểm tra IP nguồn, tên máy trạm, khoảng thời gian, tài khoản và logon type.
- Tìm event đăng nhập thành công gần sau chuỗi thất bại để đánh giá khả năng tài khoản bị xâm nhập.

### Theo dõi tài khoản/nhóm bất thường
- Xem xét event tạo user hoặc thay đổi nhóm đặc quyền.
- Đối chiếu với change request, quy trình IT và thời điểm hoạt động.
- Liên kết Logon ID của thay đổi tài khoản với event đăng nhập tương ứng để xác định phiên thực hiện.

## Task 4: Security Log — Account and Session Context

### Logon ID
Logon ID là định danh phiên đăng nhập trên máy. Có thể dùng để liên kết các sự kiện trong cùng một phiên, ví dụ đăng nhập và hành động quản trị tiếp theo. Cần phân biệt Logon ID với Process ID.

### Phương pháp tương quan
1. Xác định event đáng chú ý và ghi lại Logon ID.
2. Tìm các event khác có cùng Logon ID.
3. Sắp xếp theo thời gian.
4. Xác định hành động trước/sau và chủ thể thực hiện.
5. Xác minh bằng nguồn log khác khi có thể.

## Task 5: Sysmon — Process Monitoring

### Vì sao cần Sysmon?
Security log có thể ghi nhận process creation (Event 4688 nếu audit được bật), nhưng Sysmon cung cấp nhiều trường phong phú hơn như hash, parent process và metadata executable.

### Sysmon Event ID 1 — Process Creation
Các trường quan trọng:
- Image / Process path
- CommandLine
- ProcessId
- ParentImage / ParentProcessId
- User / Logon ID
- Hashes và thông tin chữ ký nếu được cấu hình

### Dấu hiệu cần điều tra
- Executable chạy từ thư mục bất thường như Temp hoặc Public.
- Tên file ngẫu nhiên hoặc giả dạng phần mềm quen thuộc.
- Parent-child relationship không hợp lý (ví dụ ứng dụng văn phòng sinh ra shell).
- Hash hoặc chữ ký không đáng tin cậy.
- Command line chứa tải file, mã hóa, hoặc thực thi bất thường.

### Dựng process tree
- Tìm event có ProcessId tương ứng với ParentProcessId của tiến trình cần phân tích.
- Lặp lại để lần ngược nguồn khởi chạy.
- Kết hợp Logon ID và timestamp để nối hành vi vào phiên người dùng.

## Task 6: Sysmon — Files, Registry and Network

| Sysmon Event ID | Nội dung | Giá trị điều tra |
|---|---|---|
| 11 | FileCreate | Phát hiện file được tạo/đặt xuống |
| 13 | RegistryEvent — value set | Theo dõi thay đổi registry, có thể liên quan persistence |
| 3 | NetworkConnect | Xác định tiến trình tạo kết nối mạng |
| 22 | DNS Query | Theo dõi domain được truy vấn |

Các event này thường cần liên kết với Event ID 1 qua ProcessId để lấy command line, parent process và user context.

### Hunting file/registry/network
- Xem file được tạo ở đâu, tên/loại file gì và tiến trình nào tạo.
- Đánh giá registry key/value có liên quan cấu hình khởi động hay không.
- Với network event, kiểm tra đích IP, port, thời điểm và process.
- Với DNS, đánh giá domain, tần suất và ngữ cảnh tiến trình.
- Kiểm tra reputation bên ngoài chỉ như một nguồn bổ trợ, không phải bằng chứng duy nhất.

## Task 7: PowerShell History

### PSReadLine history
Đường dẫn phổ biến:
`C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

- File ghi lại các lệnh người dùng nhập trong PowerShell console có PSReadLine.
- Có thể hỗ trợ phát hiện discovery, tải file hoặc thao tác hệ thống.
- History không ghi output, không nhất thiết chứa nội dung script được gọi.
- Có thể bị xóa/chỉnh sửa; không phải nguồn log bất biến.
- Kiểm tra history của các tài khoản liên quan và tương quan với file, process, network logs.

## Quy trình phân tích SOC gợi ý
1. Xác định nguồn log và phạm vi thời gian.
2. Tìm event nền tảng (authentication/process).
3. Kiểm tra user, IP, command line, parent process và session ID.
4. Mở rộng sang file, registry, DNS và network.
5. Dựng timeline, ghi lại indicators và nêu rõ mức độ tin cậy.
6. Xác minh hoạt động hợp lệ qua baseline/change records.

## Ghi nhớ
- Event ID cần được hiểu trong ngữ cảnh, không dùng như kết luận độc lập.
- Liên kết **Logon ID** để theo phiên và **ProcessId/ParentProcessId** để theo cây tiến trình.
- Sysmon mở rộng visibility; chất lượng phát hiện phụ thuộc cấu hình.
- PowerShell history hữu ích nhưng có giới hạn về tính toàn vẹn và độ bao phủ.
