> room này giúp tôi: hiểu khái niệm quan trọng với SOC  (SLA, MTTD, MTTA, and MTTR); tỉ lệ dương tính giả, làm sao cải thiện các chỉ số để tối ưu hiệu suất.

# Các chỉ số quan trọng:
- AC (số lượng cảnh báo) 
- FPR (tỉ lệ dương tính giả) = False Positives / Total Alerts
- AER (tỉ lệ leo thang cảnh báo) = Escalated Alerts / Total Alerts
- TDR (tỉ lệ phát hiện mối đe dọa) = Detected Threats / Total Threats
> Service Level Agreement (SLA): 1 văn bản đc ký giữa SOC và khách hàng hoặc công ty, chứa yêu cầu, thỏa thuận đảm bảo phát hiện, xử lý, ngăn chặn được mối đe dọa. Thỏa thuận bao gồm: 
- Thời gian trung bình để phát hiện (MTTD): Thời gian trung bình giữa thời điểm xảy ra cuộc tấn công và thời điểm các công cụ SOC phát hiện ra nó.

- Thời gian trung bình để xác nhận (MTTA): thời gian trung bình để cảnh báo có người tiếp nhận xử lý.
- Thời gian phản hồi trung bình (MTTR): thời gian trung bình để phát hiện và ngăn chặn được mối đe dọa.

# Cải thiện các chỉ số:

| Vấn đề | Ý tưởng cải thiện |
| ----------- | ----------- |
| Tỷ lệ dương tính giả trên 80% | loại trừ các hoạt động đáng tin cậy trên hệ thống bảo mật. cân nhắc sử dụng SOAR tự động hóa quá trình phân loại cảnh báo |
| tg phát hiện trung bình trên 30p | Liên hệ với các kỹ sư SOC để tăng tốc độ hoặc tỷ lệ chạy quy tắc phát hiện. Kiểm tra xem nhật ký SIEM có được thu thập theo thời gian thực hay không, mà không có độ trễ 10 phút. |
| tg xác nhận trung bình trên 30p | Đảm bảo các chuyên viên phân tích được thông báo ngay lập tức khi có cảnh báo mới xuất hiện. Phân bổ đều các cảnh báo trong hàng đợi giữa các chuyên viên phân tích đang làm việc. |
| tg phản hồi trung bình trên 4h | Với tư cách là nhóm hỗ trợ cấp 1, hãy làm mọi cách để nhanh chóng chuyển tiếp các mối đe dọa lên cấp 2. Đảm bảo nhóm của bạn đã ghi lại những việc cần làm trong các tình huống tấn công khác nhau. |