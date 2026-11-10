# Windows Threat Detection 2

**Nguồn học:** [TryHackMe – Windows Threat Detection 2](https://tryhackme.com/room/windowsthreatdetection2)  
**Trọng tâm:** Phát hiện Discovery, Collection và Ingress Tool Transfer sau Initial Access; truy nguyên nguồn gốc hành vi qua process tree và Windows logs.

## Task 1: Introduction

### Mục tiêu học tập
- Phát hiện Discovery phổ biến bằng Windows Event Logs.
- Dựng process tree để lần ngược nguồn hành động.
- Hiểu dữ liệu mà threat actor tìm kiếm và cách dữ liệu có thể được thu thập.
- Quan sát cách command line và event logs phản ánh hành vi thực thi.

### Vị trí trong chuỗi tấn công
Sau Initial Access, đối thủ thường tìm hiểu host/mạng, xác định dữ liệu có giá trị, thu thập dữ liệu hoặc tải thêm công cụ. Những hoạt động này thường tạo dấu vết trong process, file và network telemetry.

## Task 2: Discovery Overview

### Discovery là gì?
Discovery là việc tìm hiểu hệ thống và môi trường để định hướng bước tiếp theo. Những nhóm thông tin thường được khảo sát:
- Hostname, OS, user và group membership.
- Process, service và phần mềm cài đặt.
- Network configuration, kết nối và domain context.
- File system, thư mục chia sẻ và dữ liệu có thể truy cập.

### Dấu vết trên Windows
- Process creation events (Security 4688 hoặc Sysmon 1) có thể ghi command line.
- PowerShell, command shell và tiện ích hệ thống có thể được sử dụng cho discovery.
- Nhiều thao tác quản trị hợp lệ cũng tạo dấu vết tương tự; đánh giá account, parent process, thời gian và chuỗi hoạt động.

## Task 3: Detecting Discovery

### Phương pháp phân tích
1. Xác định process/command line đáng chú ý.
2. Ghi lại ProcessId, ParentProcessId, user và timestamp.
3. Dựng cây tiến trình, lần ngược parent cho đến điểm khởi chạy hợp lý.
4. Tìm các lệnh liên quan được thực hiện trong cùng khoảng thời gian hoặc phiên.
5. Kiểm tra xem discovery có tiếp nối bằng tải file, truy cập dữ liệu hoặc kết nối mạng hay không.

### Các điểm cần xem xét
- Shell/PowerShell được khởi chạy bởi ứng dụng không thường xuyên sinh shell.
- Chuỗi nhiều lệnh discovery liên tiếp.
- Tài khoản hoặc thời gian hoạt động không phù hợp với baseline.
- Lệnh chạy từ thư mục lạ hoặc qua script/file mới xuất hiện.
- Kết hợp các event để xác định hành vi, tránh kết luận dựa trên một command.

## Task 4: Collection Overview

### Collection là gì?
Collection là việc xác định, gom hoặc chuẩn bị dữ liệu trước khi sử dụng hoặc chuyển dữ liệu ra ngoài. Dữ liệu có thể gồm tài liệu, thông tin cấu hình, dữ liệu người dùng hoặc nội dung từ thư mục chia sẻ.

### Dấu vết có thể gặp
- Process truy cập nhiều file/thư mục trong thời gian ngắn.
- Tạo archive hoặc staging file.
- File được tạo/đổi tên ở thư mục tạm hay vị trí ít thông thường.
- Các hoạt động file đi cùng process/command line hoặc network activity liên quan.

Không phải mọi truy cập file hàng loạt đều độc hại; cần đối chiếu vai trò người dùng, công việc thường ngày và loại dữ liệu.

## Task 5: Detecting Collection

### Cách điều tra
- Xác định process tạo hoặc thao tác file.
- Kiểm tra file path, extension, kích thước, thời gian tạo và parent process.
- Tìm các thao tác tạo archive/staging hoặc tập hợp file.
- Tương quan với process tree và các hoạt động trước/sau.
- Xác định dữ liệu nào có thể bị tác động và ghi lại evidence thay vì suy đoán nội dung.

### File và process context
- Sysmon Event ID 11 (FileCreate) hỗ trợ nhận diện file được tạo.
- Sysmon Event ID 1 cung cấp ngữ cảnh process.
- Dùng ProcessId để liên kết file event với tiến trình tạo file; kiểm tra cấu hình Sysmon vì độ bao phủ phụ thuộc rule.

## Task 6: Ingress Tool Transfer

### Khái niệm
Ingress Tool Transfer là việc đưa công cụ hoặc payload từ nguồn bên ngoài vào host bị xâm nhập. Công cụ có thể được tải qua browser, command line, PowerShell hoặc ứng dụng khác.

### Dấu vết điều tra
- Process thực hiện tải file và command line liên quan.
- Network connection/DNS activity của process.
- File mới xuất hiện trong Downloads, Temp, Public hoặc thư mục staging.
- Tên, loại, hash và metadata của file tải về.
- Tiến trình tiếp theo thực thi hoặc mở file đó.

### Phân tích chuỗi tải file
1. Xác định process có dấu hiệu tải nội dung.
2. Kiểm tra command line và parent process.
3. Tìm file được tạo, đối chiếu timestamp/path.
4. Liên kết với network/DNS events theo ProcessId và thời gian.
5. Theo dõi process khởi chạy từ file tải về.
6. Kiểm tra reputation/hash trong môi trường an toàn và lưu evidence.

## Quy trình threat detection
- **Process:** ai chạy gì, từ đâu, với parent nào?
- **File:** file nào được tạo/đọc/đóng gói, ở vị trí nào?
- **Network:** process liên hệ IP/domain nào và khi nào?
- **Timeline:** các hành động có tạo thành chuỗi hợp lý không?
- **Context:** hành vi có phù hợp với user, host role và baseline không?

## Ghi nhớ
- Discovery thường giúp đối thủ định hướng; Collection chuẩn bị dữ liệu; Ingress Tool Transfer đưa công cụ vào host.
- Process tree giúp truy ngược nguyên nhân, còn file/network logs cung cấp evidence bổ sung.
- Timestamp, ProcessId và parent-child relationship là các điểm tương quan quan trọng.
- Đánh giá hành vi theo chuỗi, không chỉ theo một event hoặc một lệnh.
