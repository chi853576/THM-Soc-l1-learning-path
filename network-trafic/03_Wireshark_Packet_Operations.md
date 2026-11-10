# Wireshark: Packet Operations

**Nguồn học:** [TryHackMe – Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations)

## 1. Mục tiêu

Sau khi biết cách đọc packet và áp dụng filter, bước tiếp theo là dùng thống kê và bộ lọc có hệ thống để tìm “needle in the haystack” — một sự kiện nhỏ giữa lượng traffic lớn.

Room tập trung vào:
- Thống kê tổng quan capture.
- Thống kê phân bố giao thức.
- Nguyên tắc xây dựng packet filter.
- Protocol filters.
- Advanced display filters.

## 2. Statistics: Summary

Mục **Statistics → Capture File Properties** và **Statistics → Summary** (tùy phiên bản) giúp hiểu nhanh file capture.

Các thông tin đáng quan tâm:
- Số packet và thời lượng capture.
- Thời điểm bắt đầu/kết thúc.
- Kích thước file và lượng dữ liệu.
- Tốc độ packet/byte trung bình.
- Thời gian hiển thị sau khi áp dụng filter, nếu có.
- Capture comments hoặc thông tin file liên quan.

### Vì sao summary quan trọng?
- Xác định capture có bao phủ đúng thời gian xảy ra alert không.
- Nhận biết file quá ngắn, rỗng hoặc có lượng dữ liệu khác kỳ vọng.
- Đặt nền tảng cho các phép so sánh và kiểm tra sau đó.

Không dùng tổng packet đơn lẻ để kết luận một capture là bình thường hay độc hại. Cần biết mạng, thời gian và thiết bị nào đã được capture.

## 3. Statistics: Protocol Hierarchy

**Statistics → Protocol Hierarchy** hiển thị giao thức theo cấu trúc phân cấp và thường cung cấp số packet, byte, tỷ lệ phần trăm cho từng protocol.

Có thể dùng để:
- Tìm giao thức chiếm tỷ lệ lớn bất thường.
- Xác định protocol cần điều tra sâu hơn.
- Phát hiện traffic không mong đợi trong môi trường, chẳng hạn FTP/HTTP dạng rõ tại nơi chỉ nên dùng giao thức mã hóa.
- Chọn protocol làm điểm bắt đầu cho filter.

Ví dụ: nếu capture của máy trạm có nhiều DNS query hoặc ICMP hơn bình thường, hãy lọc `dns` hoặc `icmp`, xác định host nguồn và xem tần suất, nội dung, thời điểm.

**Giới hạn:** protocol hierarchy phụ thuộc khả năng Wireshark giải mã packet. Traffic mã hóa vẫn có thể được nhận diện ở một mức độ nào đó, nhưng payload không nhất thiết đọc được.

## 4. Endpoints và Conversations

- **Endpoints:** liệt kê endpoint quan sát được, thường là địa chỉ IP, MAC hoặc endpoint theo protocol, kèm số packet/byte.
- **Conversations:** nhóm trao đổi giữa hai endpoint, có thể bao gồm thời lượng, packet, byte và tốc độ.

Ứng dụng trong điều tra:
1. Xác định host có lưu lượng cao nhất.
2. Tìm kết nối đến domain/IP/port không mong đợi.
3. Kiểm tra host bên trong đang liên lạc với bao nhiêu endpoint.
4. So sánh chiều gửi và chiều nhận để tìm pattern đáng chú ý.
5. Chọn conversation rồi lọc theo luồng để đọc packet liên quan.

Một endpoint truyền nhiều dữ liệu có thể là máy chủ hợp pháp hoặc máy đang tải bản cập nhật. Cần kiểm tra vai trò host, thời gian, ứng dụng và baseline.

## 5. Nguyên tắc packet filtering

Bộ lọc giúp thu hẹp dữ liệu, nhưng nên xây dựng từ câu hỏi điều tra thay vì thử ngẫu nhiên.

### Cách tiếp cận từ rộng đến hẹp
1. **Protocol:** bắt đầu với `dns`, `http`, `tcp`, `icmp`.
2. **Endpoint:** thêm IP nguồn/đích.
3. **Port hoặc trường giao thức:** xác định dịch vụ hoặc hành vi.
4. **Điều kiện hành vi:** TCP flags, response code, DNS record hoặc kích thước.
5. **Thời gian / packet number:** dùng để kiểm tra một đoạn cụ thể.
6. **Stream:** xem toàn bộ conversation khi cần.

Ví dụ:
```wireshark
dns
ip.addr == 192.0.2.10 && dns
tcp.port == 443 && ip.addr == 192.0.2.10
```

### Capture filter so với display filter
- Capture filter giảm dữ liệu được ghi ngay từ đầu, tiết kiệm dung lượng nhưng có thể làm mất bằng chứng nếu quá hẹp.
- Display filter chỉ ẩn/hiện packet trong giao diện; file gốc vẫn giữ dữ liệu.
- Khi điều tra sự cố chưa rõ phạm vi, ưu tiên giữ capture đầy đủ nếu khả thi, rồi dùng display filter để phân tích.

## 6. Protocol filters thường dùng

### IP và host
```wireshark
ip
ipv6
ip.addr == 192.0.2.10
ip.src == 192.0.2.10
ip.dst == 192.0.2.20
eth.addr == 00:11:22:33:44:55
```

### TCP và UDP
```wireshark
tcp
udp
tcp.port == 80
tcp.dstport == 443
udp.port == 53
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.reset == 1
tcp.analysis.retransmission
```

### DNS
```wireshark
dns
dns.qry.name == "example.org"
dns.flags.response == 0
dns.flags.response == 1
dns.qry.type == 16
```

`dns.qry.type == 16` tương ứng TXT record trong ngữ cảnh DNS. Query TXT không tự động là độc hại; hãy kiểm tra tên miền, nội dung, tần suất và endpoint.

### HTTP và TLS
```wireshark
http
http.request
http.response
http.request.method == "POST"
http.response.code >= 400
tls
tls.handshake
```

Trường filter cụ thể có thể thay đổi theo phiên bản Wireshark và cách protocol được giải mã. Dùng autocomplete hoặc Display Filter Expression dialog để kiểm tra field hợp lệ.

### ARP và ICMP
```wireshark
arp
icmp
icmp.type == 8
icmp.type == 0
```

Với IPv4 ICMP, type 8 thường là Echo Request và type 0 là Echo Reply. Cần xem ngữ cảnh và loại ICMP trước khi diễn giải.

## 7. Advanced filtering

### Kết hợp điều kiện
```wireshark
dns && ip.addr == 192.0.2.10
tcp.port == 80 || tcp.port == 443
!(arp)
(ip.src == 192.0.2.10 || ip.dst == 192.0.2.10) && tcp
```

### So sánh và tồn tại trường
```wireshark
frame.len > 1000
tcp.len > 0
http.response.code >= 400
dns.qry.name
```

Dòng cuối lọc packet có trường `dns.qry.name` hiện diện. Có thể dùng toán tử `contains` hoặc `matches` với trường hỗ trợ phù hợp, nhưng cần chú ý kiểu dữ liệu và cú pháp của Wireshark.

Ví dụ tìm chuỗi trong trường HTTP host:
```wireshark
http.host contains "example"
```

Ví dụ regex trên trường có hỗ trợ:
```wireshark
http.host matches "(?i)example|test"
```

Regex và tên field cần được kiểm tra theo phiên bản đang dùng. Không áp dụng regex phức tạp lên toàn bộ capture nếu filter đơn giản có thể thu hẹp dữ liệu trước.

### Ví dụ điều tra SYN scan
```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
Tiếp theo:
1. Xem source IP.
2. Đếm số destination port hoặc host được thử.
3. Kiểm tra thời gian giữa các kết nối.
4. Tìm phản hồi SYN/ACK, RST hoặc ICMP.
5. Xác định đây có phải scanner được phê duyệt hay hành vi lạ.

Filter trên chỉ lấy SYN không có ACK; nó không tự động chứng minh scan.

## 8. Workflow phân tích hiệu quả

1. Ghi lại số packet, thời lượng và phạm vi capture.
2. Mở Protocol Hierarchy để hiểu các giao thức xuất hiện.
3. Xem Endpoints và Conversations để xác định host/luồng nổi bật.
4. Chọn câu hỏi điều tra cụ thể, ví dụ “host này có kết nối tới port lạ không?”.
5. Áp dụng filter rộng rồi thu hẹp dần.
6. Kiểm tra các packet trước/sau và Follow Stream để giữ ngữ cảnh.
7. Ghi filter sử dụng, timestamp, packet number, endpoint và bằng chứng.
8. Xác minh phát hiện với log hoặc telemetry khác.

## 9. Lỗi phổ biến
- Dùng filter quá hẹp từ đầu và bỏ lỡ hoạt động liên quan.
- Chỉ dựa vào tỷ lệ protocol mà không xem endpoint và thời gian.
- Nhầm cú pháp capture filter với display filter.
- Cho rằng filter làm xóa packet khỏi file gốc.
- Coi port hoặc query DNS cụ thể là bằng chứng chắc chắn.
- Quên lưu chính xác filter và bằng chứng, khiến người khác không thể tái kiểm tra.

## 10. Kỹ năng đạt được
- Dùng thống kê để định hướng điều tra PCAP.
- Đọc Protocol Hierarchy, Endpoints và Conversations.
- Xây dựng display filter từ điều kiện đơn giản đến nâng cao.
- Dùng TCP flags, DNS, HTTP, ARP và ICMP fields để thu hẹp traffic.
- Ghi nhận kết quả theo quy trình có thể tái lập.

## Tài liệu tham khảo
- [TryHackMe – Wireshark: Packet Operations](https://tryhackme.com/room/wiresharkpacketoperations)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
