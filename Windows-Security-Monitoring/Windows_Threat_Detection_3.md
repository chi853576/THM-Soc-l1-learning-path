# Windows Threat Detection 3

**Nguồn học:** [TryHackMe – Windows Threat Detection 3](https://tryhackme.com/room/windowsthreatdetection3)  
**Trọng tâm:** Command and Control (C2), Persistence và Impact; phát hiện cách threat actor duy trì quyền kiểm soát và truy cập trên host Windows.

## Task 1: Introduction

### Mục tiêu học tập
- Ôn khái niệm Command and Control.
- Hiểu lý do và cách threat actor duy trì quyền kiểm soát host.
- Dùng Windows Event Logs để phát hiện các phương thức persistence.
- Thực hành điều tra các dấu vết trên endpoint.

### Vị trí trong chuỗi tấn công
Sau khi xâm nhập, đối thủ có thể thiết lập kênh liên lạc với hạ tầng bên ngoài, tạo cơ chế tự khởi động lại sau reboot/logon, hoặc thực hiện hành động gây ảnh hưởng đến hệ thống/dữ liệu.

## Task 2: Command and Control (C2)

### C2 là gì?
Command and Control là cơ chế cho phép host bị xâm nhập liên lạc với hạ tầng do attacker kiểm soát để nhận chỉ thị, gửi trạng thái hoặc trao đổi dữ liệu.

### Telemetry liên quan
- Sysmon Event ID 3: network connection.
- Sysmon Event ID 22: DNS query.
- Sysmon Event ID 1: process creation và command line.
- Windows Firewall, DNS logs, proxy logs hoặc network telemetry nếu có.

### Phân tích kết nối
- Xác định process sở hữu kết nối, không chỉ xem IP đích.
- Kiểm tra domain, IP, port, thời điểm, tần suất và hướng kết nối.
- Đối chiếu destination với hoạt động thông thường của host.
- Dùng DNS/network events để nối domain với tiến trình và thời gian.
- Một kết nối lạ hoặc port bất thường là dấu hiệu cần điều tra, không phải bằng chứng kết luận độc lập.

## Task 3: Persistence Overview

### Persistence là gì?
Persistence là các thay đổi giúp đối thủ tiếp tục có mặt hoặc có thể chạy lại sau khi đăng xuất, reboot hay tiến trình bị dừng.

### Các nhóm dấu vết thường gặp
- Scheduled Tasks.
- Windows Services.
- Registry Run/RunOnce keys.
- Startup folders.
- Các cơ chế khởi chạy tự động khác.

### Nguyên tắc điều tra
- Tìm thay đổi cấu hình hoặc đối tượng được tạo mới.
- Xác định account/parent process/time context khi có thể.
- Kiểm tra target command, executable path và arguments.
- So sánh với baseline và phần mềm được phê duyệt.
- Xác minh persistence entry có thực sự được kích hoạt hay không.

## Task 4: Persistence — Tasks and Services

### Scheduled Tasks
Scheduled Task có thể chạy theo lịch, khi đăng nhập, khi khởi động hoặc theo trigger khác. Nó có thể bị lạm dụng để tự động chạy script hay executable.

Điểm cần kiểm tra:
- Task name và thời điểm tạo/chỉnh sửa.
- Trigger, action và command line.
- Run-as account và quyền thực thi.
- Executable/script path, file metadata và parent process.
- Tên task có giả dạng tác vụ Windows/ứng dụng hợp pháp hay không.

### Windows Services
Service có thể chạy nền và thường có khả năng tự khởi động cùng hệ thống.

Điểm cần kiểm tra:
- Service name/display name.
- Image path/binary path và startup type.
- Account chạy service.
- Thời điểm service được tạo/thay đổi.
- File binary có nằm ở vị trí bất thường hoặc có metadata đáng ngờ không.

### Log correlation
- Tương quan các thay đổi service/task với process creation và file creation.
- Kiểm tra process nào tạo hoặc sửa cấu hình.
- Xem hành động có liên quan đến một phiên đăng nhập hoặc chuỗi xâm nhập trước đó không.

## Task 5: Persistence — Run Keys and Startup

### Registry Run / RunOnce
Các registry keys thuộc nhóm Run/RunOnce có thể chỉ định chương trình chạy khi user đăng nhập hoặc theo cơ chế khởi động tương ứng.

Điểm cần kiểm tra:
- Registry path và value name.
- Value data trỏ đến executable/script nào.
- User hive hay machine-wide hive.
- Thời điểm thay đổi và tiến trình thực hiện.
- Đường dẫn target, command arguments và chữ ký/hash.

### Startup folders
Các file/shortcut đặt trong Startup folder có thể được khởi chạy khi user đăng nhập.

Điểm cần kiểm tra:
- File hoặc shortcut mới xuất hiện.
- Target path/arguments của shortcut.
- Owner, timestamp và vị trí file.
- Liên kết với process creation và file events.

### Phân tích registry/file events
- Sysmon Event ID 13 ghi nhận Registry value set (khi cấu hình phù hợp).
- Sysmon Event ID 11 ghi nhận file creation.
- Liên kết các event với process context và timeline để xác định nguồn thay đổi.

## Task 6: Impact and Threat Detection Recap

### Impact
Impact là hành động làm thay đổi tính khả dụng, tính toàn vẹn hoặc trạng thái vận hành của hệ thống/dữ liệu. Trong điều tra endpoint, chú ý:
- Thay đổi hoặc xóa file hàng loạt.
- Thay đổi cấu hình hệ thống.
- Dấu hiệu ảnh hưởng đến dữ liệu hoặc khả năng vận hành.
- Hành động đi kèm với C2 hoặc persistence.

### Khung phân tích tổng hợp
| Nguồn dữ liệu | Câu hỏi điều tra |
|---|---|
| Security log | Ai đăng nhập? Từ đâu? Phiên nào? |
| Sysmon Process (ID 1) | Process nào chạy, command line và parent là gì? |
| Sysmon Network (ID 3) | Process nào kết nối tới đích nào? |
| Sysmon DNS (ID 22) | Host/process truy vấn domain nào? |
| Sysmon File (ID 11) | File nào được tạo và ở đâu? |
| Sysmon Registry (ID 13) | Value nào bị thay đổi? |
| Task/Service/Startup artifacts | Có cơ chế tự khởi chạy nào được thiết lập? |

## Quy trình điều tra persistence/C2
1. Bắt đầu từ process hoặc network event đáng ngờ.
2. Xác định process tree, user, thời gian và file liên quan.
3. Kiểm tra scheduled tasks, services, Run keys và Startup folders.
4. Xác minh target command/file và thời điểm tạo.
5. Dựng timeline giữa Initial Access, C2, persistence và impact.
6. Ghi rõ evidence, giả thuyết, độ tin cậy và các bước xác minh tiếp theo.

## Ghi nhớ
- C2 là kênh điều khiển/liên lạc; persistence là cơ chế duy trì hoặc khôi phục quyền truy cập.
- Scheduled Tasks, Services, Run keys và Startup folders là các vùng cần kiểm tra.
- Cần nối cấu hình persistence với process/file evidence để hiểu ai đã tạo nó.
- Network destination chỉ có ý nghĩa khi gắn với process, thời gian và baseline.
- Tài liệu này tập trung vào kiến thức và quy trình, không ghi đáp án, flag hay giá trị riêng của challenge.
