1. Junior Security Analyst Intro
SOC là gì? Là trung tâm vận hành an ninh, làm việc 24/7 để giám sát và bảo vệ công ty.
Công việc chia làm 3 cấp:
L1 (vị trí của mình): Người gác cổng. Nhiệm vụ là xem các cảnh báo (alert) từ hệ thống SIEM, xác định đâu là cảnh báo giả (false positive) để đóng lại, đâu là cảnh báo thật để ghi lại chi tiết và chuyển lên cho L2.
L2: Người điều tra sâu. Họ sẽ phân tích chi tiết vụ việc mà L1 chuyển lên.
L3: Chuyên gia. Họ đi săn lùng mối nguy hiểm (Threat Hunting) và phân tích mã độc.
3 chỉ số quan trọng cần nhớ:
MTTD: Mất bao lâu để phát hiện ra cuộc tấn công.
MTTA: Mất bao lâu để bắt đầu xử lý sau khi phát hiện.
MTTR: Mất bao lâu để xử lý xong hoàn toàn.

2. Vai trò của SOC trong Blue Team
Blue Team là đội phòng thủ. Red Team là đội tấn công giả lập để kiểm tra hệ thống.
Mọi hoạt động phòng thủ đều xoay quanh 3 nguyên tắc CIA:
Confidentiality: Giữ cho dữ liệu được bí mật.
Integrity: Đảm bảo dữ liệu không bị chỉnh sửa trái phép.
Availability: Đảm bảo hệ thống luôn hoạt động.
Quy trình làm việc: Ngăn chặn (Prevention) -> Phát hiện (Detection) -> Phản ứng (Response). Vị trí L1 của mình tập trung nhiều nhất ở bước Phát hiện.

3. Con người là mục tiêu tấn công (Humans as Attack Vectors)
Hacker thích tấn công con người hơn vì dễ hơn tấn công máy tính. Đây gọi là Tấn công phi kỹ thuật (Social Engineering).
Các hình thức cần phân biệt rõ:
Phishing: Gửi email lừa đảo hàng loạt.
Spear Phishing: Email lừa đảo nhưng nhắm vào 1 người cụ thể, có thông tin cá nhân nên rất đáng tin.
Vishing: Lừa đảo qua cuộc gọi điện thoại.
Smishing: Lừa đảo qua tin nhắn SMS.
Góc nhìn của SOC L1: Khi thấy cảnh báo về một email có link lạ hoặc file đính kèm đáng ngờ, hãy nghĩ ngay đến phishing. Cách phòng chống hiệu quả nhất là đào tạo nhân viên và bật xác thực 2 yếu tố (MFA).

4. Hệ thống là mục tiêu tấn công (Systems as Attack Vectors)
Hệ thống bị tấn công thường do chính chúng ta cấu hình sai hoặc lơ là.
Những lỗi phổ biến nhất:
Không cập nhật bản vá bảo mật.
Đặt mật khẩu yếu, dễ đoán.
Mở những cổng (port) không cần thiết ra ngoài Internet.
Cấu hình: lỗi cấu hình không phải là lỗi phần mềm mà là lỗi trong cách thiết lập hệ thống, thường là do nhóm CNTT gây ra.
Khái niệm Attack Surface (Bề mặt tấn công): Càng cài nhiều phần mềm, càng mở nhiều cổng thì càng tạo ra nhiều chỗ cho hacker chui vào.
Góc nhìn của SOC L1: Nếu hệ thống IDS báo có ai đó đang quét cổng (port scanning) hoặc có kết nối bất thường tới các cổng nhạy cảm như 445, 3389, thì đó là dấu hiệu có người đang thăm dò hệ thống.