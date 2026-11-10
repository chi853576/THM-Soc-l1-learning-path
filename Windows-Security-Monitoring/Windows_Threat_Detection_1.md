# Windows Threat Detection 1

**Nguồn học:** [TryHackMe – Windows Threat Detection 1](https://tryhackme.com/room/windowsthreatdetection1)  
**Trọng tâm:** Phát hiện Initial Access và các hoạt động discovery ban đầu bằng Windows Event Logs.

## Task 1: Introduction

### Mục tiêu học tập
- Nhận diện cách threat actor xâm nhập máy Windows.
- Phân tích các kỹ thuật Initial Access thường gặp.
- Dùng Windows logs để phát hiện hành vi thay vì chỉ dựa trên alert.
- Áp dụng kiến thức về Event Viewer, Security logs, Sysmon và process context.

### Kiến thức nền
- MITRE ATT&CK mô tả hành vi adversary theo tactic và technique.
- Initial Access là giai đoạn đối thủ tìm cách có chỗ đứng ban đầu trong môi trường.
- `explorer.exe` thường là shell giao diện người dùng; quan hệ process với Explorer có thể giúp hiểu hành vi được kích hoạt bởi người dùng.

## Task 2: Initial Access Overview

### RDP brute force và đăng nhập từ xa
- RDP thường liên quan logon type 10; network logon type 3 cũng có thể xuất hiện trong quy trình xác thực.
- Event **4625** ghi nhận đăng nhập thất bại; **4624** ghi nhận đăng nhập thành công.
- Nhiều lần thất bại từ cùng IP, thử nhiều username hoặc nhắm một tài khoản có thể gợi ý brute force/password spraying.
- Sau chuỗi thất bại, tìm successful logon và kiểm tra account, source IP, logon type, thời gian.
- Kết luận cần dựa trên baseline, danh tính nguồn và xác minh hoạt động hợp lệ.

### Binary attachments và extension masquerading
- Windows có thể ẩn phần mở rộng file đã biết, khiến file như `report.pdf.exe` dễ bị hiểu nhầm.
- Một số định dạng thực thi không phải `.exe` gồm `.com`, `.scr`, `.cpl`.
- Tên, icon và phần mở rộng có thể bị giả dạng; kiểm tra extension thực tế, đường dẫn và metadata.
- Không mở/execute file nghi ngờ trên máy làm việc; dùng môi trường phân tích cô lập.

### LNK attachments
- Shortcut `.lnk` có thể trỏ đến chương trình hoặc command line thay vì tài liệu thông thường.
- Kiểm tra target path, arguments, working directory và tiến trình được khởi chạy.
- Quan hệ Explorer → process/script có thể giúp nhận diện file được người dùng mở.

## Task 3: Detecting Initial Access

### Quy trình kiểm tra authentication
1. Lọc Security log theo Event ID 4625.
2. Tập trung vào logon type 3/10 và nguồn bên ngoài hoặc không quen thuộc.
3. So sánh số lượng, tần suất và danh sách tài khoản bị thử.
4. Tìm 4624 tiếp theo có cùng nguồn/tài khoản hoặc tương quan thời gian.
5. Ghi lại Logon ID và mở rộng sang hoạt động sau đăng nhập.

### Phân biệt brute force và password spraying
- **Brute force:** thường tập trung nhiều mật khẩu vào một tài khoản.
- **Password spraying:** thử một vài mật khẩu phổ biến trên nhiều tài khoản nhằm tránh khóa tài khoản.
- Các pattern có thể bị phân tán theo thời gian/IP; cần xem toàn cảnh chứ không chỉ một cửa sổ ngắn.

### Xác định hành động sau đăng nhập
- Từ successful logon, dùng Logon ID để tìm process và hành động cùng phiên.
- Kiểm tra process mới, command line, parent process và những thay đổi trên hệ thống.
- Dựng timeline từ xác thực đến process/file/network events.

## Task 4: User-Triggered Execution and Process Context

### Process creation
- Security Event 4688 có thể ghi process creation nếu audit policy được bật.
- Sysmon Event ID 1 cung cấp process image, command line, parent process, user, hash và session context tùy cấu hình.
- Kiểm tra process được khởi chạy bởi Explorer, ứng dụng văn phòng, script host hay một process đáng ngờ khác.

### Dấu hiệu đáng chú ý
- Process chạy từ Downloads, Temp, Public hoặc thư mục người dùng bất thường.
- Tên file giả dạng tài liệu hoặc phần mềm tin cậy.
- Parent process không phù hợp với hành động.
- Command line gọi script interpreter, tải nội dung hoặc thực thi chuỗi lệnh bất thường.
- File mới tạo ngay trước/sau thời điểm process chạy.

## Task 5: Discovery Fundamentals

Discovery là hành vi thu thập thông tin về host và môi trường sau khi có quyền truy cập, chẳng hạn:
- Tên máy, user hiện tại, nhóm/quyền.
- Thông tin hệ điều hành và cấu hình.
- Process đang chạy, dịch vụ và kết nối mạng.
- Domain, network shares hoặc tài nguyên có thể truy cập.

### Phân tích qua log
- Tìm command line của process liên quan discovery.
- Xác định interpreter/parent process và user context.
- Phân biệt lệnh quản trị hợp lệ với chuỗi lệnh bất thường dựa trên thời điểm, tài khoản và hành động tiếp theo.
- Lưu ý một số lệnh discovery hợp pháp được dùng thường xuyên; hành vi và ngữ cảnh quan trọng hơn tên lệnh đơn lẻ.

## Quy trình điều tra Initial Access
1. Bắt đầu từ log authentication (4625/4624).
2. Xác định nguồn, account, logon type và session.
3. Kiểm tra process tree và command line.
4. Mở rộng sang file/registry/network events.
5. Dựng timeline, xác định điểm khởi đầu và các hành động tiếp theo.
6. Ghi nhận indicators theo dạng an toàn (defanged) và nêu rõ evidence.

## Ghi nhớ
- Phát hiện RDP intrusion cần liên kết failed logons, successful logon và hành vi sau đăng nhập.
- File có tên/icon hợp pháp vẫn có thể là executable hoặc shortcut nguy hiểm.
- Process tree và Logon ID là hai trục tương quan quan trọng.
- Discovery commands cần được đánh giá trong ngữ cảnh môi trường.
