# Network Traffic Basics

**Nguồn học:** [TryHackMe – Network Traffic Basics](https://tryhackme.com/room/networktrafficbasics)

## 1. Network Traffic Analysis (NTA) là gì?

**Network Traffic Analysis (NTA)** là quá trình thu thập, kiểm tra và phân tích dữ liệu khi dữ liệu di chuyển qua mạng. Mục tiêu là hiểu hệ thống đang giao tiếp với ai, bằng giao thức nào, vào thời điểm nào và nội dung hoặc hành vi đó có bất thường hay không.

NTA không chỉ là mở Wireshark và xem packet. Một cuộc điều tra tốt có thể kết hợp:
- Packet capture (PCAP) và deep packet inspection.
- Network flow records, DNS logs, firewall/proxy logs.
- Endpoint logs, cảnh báo IDS/IPS và dữ liệu threat intelligence.
- Baseline hành vi thông thường của mạng để nhận ra sai lệch.

### NTA hữu ích trong công việc SOC như thế nào?
- Phát hiện hoạt động đáng ngờ hoặc độc hại.
- Xác minh và bổ sung ngữ cảnh cho alert.
- Tái dựng diễn biến của sự cố.
- Điều tra tải xuống file đáng ngờ, command-and-control (C2), lateral movement hoặc data exfiltration.
- Kiểm tra hiệu năng, độ trễ và các đợt tăng lưu lượng bất thường.

Một alert chỉ là điểm bắt đầu. Cần xác minh bằng nhiều nguồn dữ liệu trước khi kết luận.

## 2. Network traffic cho biết điều gì?

Lưu lượng mạng được đóng gói qua nhiều lớp. Mỗi lớp thêm header phục vụ việc chuyển dữ liệu.

| Lớp / thành phần | Thông tin thường quan sát | Ví dụ ứng dụng điều tra |
|---|---|---|
| Application | HTTP method, hostname, URI, DNS query, protocol metadata, payload nếu không mã hóa | Tìm request tải file hoặc DNS query bất thường |
| Transport | TCP/UDP, source/destination port, TCP flags, sequence/acknowledgment numbers | Nhận biết handshake, scan, reset hoặc dấu hiệu bất thường trong phiên |
| Internet / Network | Source/destination IP, TTL, fragmentation fields | Xác định hai đầu giao tiếp, kiểm tra fragment bất thường |
| Link | Source/destination MAC, ARP messages | Phát hiện ARP spoofing hoặc mapping IP–MAC thay đổi |
| Timing / flow | Timestamp, số byte, số packet, thời lượng và tần suất | Phát hiện beaconing, lưu lượng tăng đột biến hoặc truyền dữ liệu lớn |

Log của firewall thường chỉ lưu một phần metadata. PCAP có thể cung cấp chi tiết packet và payload mà log không có. Tuy nhiên, TLS/HTTPS và các giao thức mã hóa có thể che giấu nội dung; khi đó vẫn có thể phân tích metadata, endpoint, certificate, thời gian và kích thước truyền tải.

## 3. Thu thập lưu lượng mạng

### 3.1 Packet capture (PCAP)
PCAP lưu lại các packet được quan sát tại một điểm trong mạng. Các định dạng thường gặp:
- `.pcap`
- `.pcapng`

Capture có thể diễn ra trực tiếp trên interface hoặc được phân tích offline từ file đã ghi.

### 3.2 TAP và port mirroring
- **Network TAP:** thiết bị đặt trên đường truyền để sao chép traffic sang hệ thống giám sát.
- **Port mirroring / SPAN:** cấu hình switch sao chép traffic từ một hoặc nhiều port/VLAN sang port giám sát.
- **Virtual/cloud mirroring:** môi trường ảo hóa hoặc cloud có cơ chế tương tự để sao chép traffic.

| Yếu tố | Điều cần cân nhắc |
|---|---|
| Vị trí capture | Phải đặt đúng nơi có thể quan sát traffic liên quan; một điểm capture không nhìn thấy toàn bộ mạng |
| Thời lượng | Full packet capture tiêu tốn nhiều dung lượng |
| Tải mạng | Port mirroring có thể bị ảnh hưởng khi lưu lượng lớn; cần kiểm tra packet loss |
| Quyền riêng tư | PCAP có thể chứa thông tin nhạy cảm; cần kiểm soát quyền truy cập và thời hạn lưu trữ |
| Đồng bộ thời gian | Timestamp chính xác giúp tương quan sự kiện giữa nhiều nguồn |

Ví dụ, đường truyền 1 Gbps có thể tạo ra lượng dữ liệu rất lớn nếu capture liên tục cả ngày. Vì vậy, cần xác định mục tiêu, thời lượng và bộ lọc phù hợp thay vì ghi mọi thứ vô thời hạn.

## 4. Công cụ thường dùng

| Công cụ | Vai trò |
|---|---|
| **Wireshark** | Phân tích packet bằng giao diện đồ họa; xem protocol tree, payload, stream và thống kê |
| **tcpdump** | Capture và lọc packet từ dòng lệnh; phù hợp máy chủ Linux và xử lý nhanh |
| **TShark** | Phiên bản dòng lệnh của Wireshark; hỗ trợ display filter và tự động hóa |
| **Snort / Suricata** | IDS/IPS phát hiện hoạt động khớp với rule/signature |
| **Zeek** | Phân tích traffic và tạo log giàu ngữ cảnh ở mức giao thức |
| **NetworkMiner** | Network Forensics Analysis Tool, trích xuất host, session, file và certificate từ PCAP |
| **Firewall / proxy / DNS logs** | Bổ sung ngữ cảnh và cho biết hoạt động được thiết bị mạng ghi nhận |

Không có công cụ đơn lẻ nào trả lời mọi câu hỏi. Wireshark cho thấy chi tiết packet; các log và công cụ khác giúp mở rộng ngữ cảnh.

## 5. Ví dụ điều tra DNS tunneling và beaconing

Một endpoint gửi nhiều truy vấn DNS đến cùng domain nhưng dùng các subdomain dài, ngẫu nhiên hoặc thay đổi liên tục. Đây có thể là hoạt động hợp pháp, nhưng cũng có thể liên quan đến:
- **DNS tunneling:** mã hóa hoặc đóng gói dữ liệu trong truy vấn/phản hồi DNS để chuyển dữ liệu qua DNS.
- **C2 over DNS:** dùng DNS để trao đổi lệnh hoặc tín hiệu với máy chủ điều khiển.
- **Beaconing:** endpoint liên lạc định kỳ với hạ tầng bên ngoài.

### Quy trình phân tích
1. Xác định host nguồn, IP, thời gian và domain đích.
2. So sánh tần suất truy vấn với baseline của host và mạng.
3. Kiểm tra độ dài, tính ngẫu nhiên của subdomain, loại record (A, TXT, CNAME...) và phản hồi.
4. Mở PCAP để xem nội dung truy vấn/phản hồi mà log tổng quát không thể hiện.
5. Đối chiếu domain/IP với nguồn threat intelligence đáng tin cậy.
6. Tìm các sự kiện liên quan trên endpoint, DNS resolver, firewall và proxy.
7. Kết luận dựa trên bằng chứng tổng hợp; ghi rõ điều gì đã xác nhận và điều gì vẫn là giả thuyết.

Một truy vấn DNS bất thường chưa đủ để chứng minh có tấn công. Cần xem xét bối cảnh, ứng dụng, tần suất và các bằng chứng độc lập.

## 6. Các mẫu hành vi đáng chú ý

| Mẫu quan sát | Khả năng cần điều tra |
|---|---|
| Nhiều kết nối đến nhiều port trên một host | Port scanning hoặc service discovery |
| Nhiều truy vấn ARP bất thường, mapping IP–MAC xung đột | ARP spoofing / poisoning |
| DNS query có subdomain dài, entropy cao và tần suất lớn | DNS tunneling hoặc beaconing |
| ICMP payload lớn, lặp lại hoặc bất thường | Có thể là tunneling hoặc công cụ chẩn đoán; cần ngữ cảnh |
| HTTP tải file thực thi/archive từ domain lạ | Download đáng ngờ hoặc malware delivery |
| FTP/HTTP truyền thông tin đăng nhập dạng rõ | Credentials có thể bị lộ |
| Dữ liệu outbound lớn sau khi truy cập tài nguyên nhạy cảm | Có thể là exfiltration; cần xác minh |
| TCP sequence/flags hoặc luồng giao tiếp không khớp thông thường | Lỗi mạng, packet injection hoặc hoạt động bất thường |

## 7. Quy trình NTA thực tế cho SOC L1

1. **Triage alert:** ghi nhận alert, timestamp, host, user, IP, domain và lý do cảnh báo.
2. **Xác định câu hỏi:** cần xác minh scan, C2, tải file, credential exposure hay vấn đề hiệu năng?
3. **Thu thập dữ liệu:** lấy PCAP và các log liên quan trong khoảng thời gian đủ rộng.
4. **Lọc traffic:** bắt đầu từ host/domain/IP/port liên quan rồi mở rộng sang các kết nối lân cận.
5. **Dựng timeline:** sắp xếp DNS, TCP handshake, request/response và hoạt động endpoint theo thời gian.
6. **Tìm bằng chứng:** kiểm tra protocol, payload, file transfer, tần suất và dấu hiệu bất thường.
7. **Tương quan:** so sánh với endpoint logs, firewall/proxy logs, threat intel và baseline.
8. **Đánh giá:** phân biệt hoạt động hợp pháp, đáng ngờ và đã xác nhận độc hại.
9. **Báo cáo:** nêu phát hiện, bằng chứng, phạm vi ảnh hưởng, mức độ tin cậy và bước tiếp theo.

## 8. Những lưu ý quan trọng
- Một IP hoặc domain bị gắn cờ không tự động chứng minh host đã bị xâm nhập.
- Thiếu payload không đồng nghĩa không có hoạt động độc hại; traffic có thể được mã hóa hoặc capture thiếu dữ liệu.
- Kiểm tra packet ở đúng điểm mạng; capture không đầy đủ có thể dẫn đến kết luận sai.
- Không truy cập trực tiếp domain/IP độc hại trong quá trình phân tích. Dùng sandbox và quy trình được phê duyệt.
- Bảo vệ PCAP như dữ liệu nhạy cảm; không tải lên dịch vụ công cộng nếu chưa đánh giá chính sách dữ liệu.

## 9. Tóm tắt kỹ năng đạt được
- Giải thích được mục tiêu và giới hạn của Network Traffic Analysis.
- Biết phân biệt metadata trong log với chi tiết có thể quan sát từ PCAP.
- Hiểu cách capture traffic bằng TAP/port mirroring và các yếu tố vận hành.
- Nhận diện một số mẫu đáng điều tra như scanning, ARP poisoning, DNS tunneling và truyền file bất thường.
- Biết xây dựng quy trình điều tra dựa trên timeline, packet evidence và tương quan log.

## Tài liệu tham khảo
- [TryHackMe – Network Traffic Basics](https://tryhackme.com/room/networktrafficbasics)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
