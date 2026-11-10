# IDS Fundamentals

**Nguồn học:** [TryHackMe – IDS Fundamentals](https://desc.tryhackme.com/room/idsfundamentals)  
**Chủ đề:** Khái niệm IDS/IPS, các loại hệ thống phát hiện xâm nhập, phương pháp detection và vai trò của Snort.

> **Phạm vi ghi chú:** Room công khai các chủ đề chính gồm IDS là gì, các loại IDS, Snort và thực hành rule. Tài liệu này tập trung vào kiến thức nền tảng và tư duy phân tích alert, không ghi answer hoặc flag.

## 1. Intrusion Detection System (IDS) là gì?

**Intrusion Detection System (IDS)** là hệ thống giám sát hoạt động trên host hoặc network để phát hiện các dấu hiệu xâm nhập, policy violation hoặc hành vi bất thường. Khi phát hiện sự kiện phù hợp với rule/model, IDS tạo alert để security analyst điều tra.

IDS thường hoạt động theo hướng **phát hiện và thông báo**, không trực tiếp chặn traffic. Điều này khác với IPS, vốn được triển khai để có thể chủ động ngăn chặn traffic đáng ngờ.

### 1.1. Firewall và IDS khác nhau thế nào?

| Thành phần | Vai trò chính | Ví dụ |
|---|---|---|
| Firewall | Kiểm soát traffic dựa trên policy như source/destination, port, protocol, state hoặc application | Chặn inbound RDP không được phép. |
| IDS | Quan sát activity và phát hiện pattern/hành vi đáng ngờ; tạo alert | Phát hiện request chứa dấu hiệu khai thác hoặc một chuỗi scan. |
| IPS | Phân tích traffic và có thể block/drop/reject traffic theo policy/rule | Chặn packet phù hợp với signature độc hại khi chạy inline. |

Firewall thường quyết định traffic có được phép đi qua hay không. Tuy vậy, một kết nối được phép vẫn có thể bị lợi dụng. IDS bổ sung khả năng quan sát traffic sau khi nó đã vượt qua policy firewall hoặc hoạt động bên trong mạng.

**IDS không thay thế firewall**, và cũng không đảm bảo phát hiện được mọi cuộc tấn công. Các lớp bảo vệ này bổ sung cho nhau.

## 2. Các loại IDS theo vị trí triển khai

### 2.1. Host-based IDS (HIDS)

HIDS chạy trên một endpoint hoặc server và giám sát hoạt động cục bộ.

Nguồn dữ liệu có thể gồm:

- System logs và authentication logs.
- Process creation và process behavior.
- File integrity, thay đổi registry hoặc cấu hình hệ thống.
- Service, scheduled task và các thay đổi persistence.
- Hoạt động network của chính host đó.

**Ưu điểm:** có thể nhìn thấy nhiều chi tiết bên trong host, đặc biệt khi traffic đã được giải mã tại endpoint.  
**Hạn chế:** cần cài/duy trì agent, quản lý số lượng endpoint lớn và có thể bị ảnh hưởng nếu host bị attacker kiểm soát.

### 2.2. Network-based IDS (NIDS)

NIDS giám sát traffic tại một hoặc nhiều vị trí trên network, thường thông qua network TAP, SPAN/mirror port hoặc luồng dữ liệu từ sensor.

NIDS có thể quan sát:

- Source/destination IP và port.
- Protocol, connection state và flow behavior.
- Packet header và payload nếu dữ liệu không bị mã hóa hoặc được giải mã hợp lệ.
- Pattern phù hợp với signatures hoặc rule.

**Ưu điểm:** có thể quan sát nhiều thiết bị mà không cần cài agent trên từng host.  
**Hạn chế:** khó đọc payload của traffic mã hóa; có thể bỏ lỡ traffic nếu sensor không đặt đúng vị trí, mất packet hoặc không thấy cả hai chiều giao tiếp.

### 2.3. Hybrid IDS

Hybrid IDS kết hợp telemetry từ host và network để tăng ngữ cảnh. Ví dụ, NIDS phát hiện outbound connection bất thường; HIDS/EDR cung cấp process, user và file activity đã tạo ra kết nối đó.

## 3. Các phương pháp detection

### 3.1. Signature-based detection

Signature-based IDS so sánh traffic hoặc event với những pattern đã biết, ví dụ:

- Byte sequence hoặc payload pattern đặc trưng.
- Request format liên quan đến một exploit đã biết.
- Known malicious IP/domain hoặc protocol behavior.
- Rule mô tả một hành vi đáng ngờ cụ thể.

**Ưu điểm:** có thể phát hiện chính xác các threat đã biết nếu signature phù hợp và dữ liệu quan sát đầy đủ.  
**Hạn chế:** khó phát hiện threat mới hoặc payload bị thay đổi; cần cập nhật ruleset và kiểm tra false positive.

### 3.2. Anomaly-based detection

Anomaly-based IDS xây dựng baseline về hoạt động bình thường rồi phát hiện sự khác biệt đáng kể.

Ví dụ:

- Server chỉ thường giao tiếp với một số dịch vụ nội bộ nhưng đột nhiên kết nối tới nhiều IP Internet.
- Workstation tạo DNS query volume cao bất thường.
- Một máy kế toán upload lượng dữ liệu lớn ngoài giờ.
- Một host tạo nhiều kết nối tới nhiều port trong thời gian ngắn.

**Ưu điểm:** có khả năng phát hiện hành vi chưa có signature cụ thể.  
**Hạn chế:** dễ tạo false positive nếu baseline chưa tốt hoặc môi trường có nhiều biến động.

### 3.3. Stateful protocol analysis / protocol-aware detection

Phương pháp này hiểu trạng thái và quy tắc hoạt động của protocol, sau đó tìm hành vi không phù hợp với đặc tả hoặc trạng thái giao tiếp mong đợi.

Ví dụ: một luồng TCP có chuỗi packet không hợp lý, một protocol có command bất thường hoặc một request-response không đúng logic giao thức.

Nhiều hệ thống kết hợp nhiều phương pháp để cải thiện khả năng phát hiện.

## 4. IDS và IPS theo phạm vi bảo vệ

| Loại | Vị trí/đối tượng | Hành động |
|---|---|---|
| HIDS | Một host/endpoint | Phát hiện sự kiện trên thiết bị. |
| NIDS | Một segment hoặc vùng mạng | Phát hiện hoạt động trên network traffic. |
| HIPS | Một host/endpoint | Có thể ngăn hoặc chặn hành vi trên host. |
| NIPS | Một segment hoặc vùng mạng, thường triển khai inline | Có thể drop/reject traffic bị đánh giá là độc hại. |
| NBA / Network Behavior Analysis | Phân tích hành vi lưu lượng mạng | Phát hiện deviation so với baseline; tùy giải pháp có thể tích hợp cơ chế ngăn chặn. |

Cần phân biệt **vị trí triển khai** (host/network) với **chức năng** (detection/prevention). Một giải pháp cụ thể có thể hỗ trợ nhiều mode tùy cấu hình.

## 5. IDS hoạt động theo quy trình nào?

Một pipeline cơ bản có thể gồm:

1. **Data collection:** lấy packet, flow, host event hoặc log.
2. **Decoding / parsing:** tách header, protocol fields và nội dung cần phân tích.
3. **Preprocessing:** chuẩn hóa, tái lắp ghép hoặc xử lý protocol tùy công cụ.
4. **Detection engine:** áp dụng signatures, protocol rules hoặc anomaly models.
5. **Alert generation:** tạo cảnh báo với thời gian, source/destination, rule và priority.
6. **Logging / forwarding:** lưu event hoặc gửi tới SIEM.
7. **SOC triage:** analyst xác minh alert, tìm related events, đánh giá impact và quyết định escalation.

## 6. Alert không đồng nghĩa với incident đã xác nhận

### 6.1. False positive

Một hoạt động hợp lệ bị hệ thống đánh giá nhầm là malicious.

Ví dụ:

- Vulnerability scanner được phê duyệt tạo nhiều kết nối.
- Ứng dụng hợp pháp gửi payload có chuỗi trùng signature.
- Backup hoặc file synchronization tạo outbound traffic lớn.
- Một service mới triển khai làm thay đổi baseline.

### 6.2. False negative

Hoạt động độc hại không bị phát hiện.

Nguyên nhân có thể gồm:

- Không có signature phù hợp.
- Attacker thay đổi payload hoặc dùng encryption/obfuscation.
- Sensor không nhìn thấy đường traffic liên quan.
- Log/packet bị mất hoặc parser không giải mã được protocol.
- Rule quá rộng/hẹp hoặc detection threshold chưa phù hợp.

## 7. Quy trình SOC triage IDS alert

1. Đọc alert name, signature ID, severity/priority và thời điểm.
2. Xác định source, destination, port, protocol và hướng traffic.
3. Xem rule/signature mô tả điều gì và điều kiện nào đã kích hoạt nó.
4. Mở packet/flow/log liên quan để xác minh nội dung và trạng thái kết nối.
5. Tra asset inventory để hiểu vai trò của source/destination.
6. Correlate với firewall, DNS, proxy, VPN, endpoint/EDR và authentication logs.
7. Kiểm tra hoạt động trước/sau alert nhằm xác định scan, exploit attempt, successful access hoặc lateral movement.
8. Đánh giá mức độ ảnh hưởng và khả năng sự kiện là benign.
9. Escalate khi có bằng chứng phù hợp; ghi rõ bằng chứng, giả thuyết và những điểm chưa xác minh.

## 8. Snort trong hệ thống IDS

**Snort** là một công cụ open-source IDS/IPS dựa trên rule. Công cụ có thể phân tích traffic trực tiếp hoặc traffic đã capture, ghi log packet và tạo alert khi packet khớp rule.

Ba mode sử dụng cơ bản:

- **Sniffer mode:** hiển thị thông tin packet trong terminal.
- **Packet logger mode:** ghi packet ra log để phân tích sau.
- **IDS/IPS mode:** áp dụng rule để phát hiện hoặc xử lý traffic.

Snort thường được dùng như một ví dụ thực hành để hiểu cách một NIDS áp dụng rule. Chi tiết về command, configuration, packet logging và rule syntax được tách riêng trong tài liệu **Snort**.

## 9. Giới hạn và best practices

- Đặt sensor tại vị trí có thể quan sát đúng traffic cần bảo vệ.
- Kiểm tra traffic hai chiều và tránh bỏ sót do routing bất đối xứng.
- Theo dõi packet loss và hiệu năng sensor.
- Cập nhật ruleset có kiểm soát; test rule trong môi trường phù hợp trước khi triển khai.
- Tuning alert dựa trên baseline và business context, không chỉ tắt alert gây nhiễu.
- Với TLS/HTTPS, kết hợp metadata, endpoint telemetry và cơ chế inspection được phê duyệt.
- Phối hợp IDS với firewall, EDR, SIEM, asset inventory và incident response process.

## 10. Kiến thức và kỹ năng có thể thể hiện trong portfolio

- Phân biệt firewall, IDS và IPS.
- Phân biệt HIDS/NIDS và HIPS/NIPS.
- Giải thích signature-based, anomaly-based và protocol-aware detection.
- Hiểu pipeline collection → analysis → alert → triage.
- Nhận diện false positive/false negative và các giới hạn visibility.
- Phân tích IDS alert trong ngữ cảnh host, network và SIEM.
- Hiểu vai trò của Snort trong network intrusion detection/prevention.

## 11. Tài liệu tham khảo

- [TryHackMe – IDS Fundamentals](https://desc.tryhackme.com/room/idsfundamentals)
- [TryHackMe – Snort](https://tryhackme.com/room/snort)
- [CIS – Signature-Based vs Anomaly-Based Detection](https://www.cisecurity.org/insights/spotlight/cybersecurity-spotlight-signature-based-vs-anomaly-based-detection)
- [Check Point – What is an Intrusion Detection System?](https://www.checkpoint.com/cyber-hub/network-security/what-is-an-intrusion-detection-system-ids/)
