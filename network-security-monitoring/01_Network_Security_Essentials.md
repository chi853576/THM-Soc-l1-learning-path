# Network Security Essentials

**Nguồn học:** [TryHackMe – Network Security Essentials](https://tryhackme.com/room/networksecurityessentials)  
**Chủ đề:** Kiến trúc mạng doanh nghiệp, network perimeter, network visibility và giám sát log phục vụ SOC.

> **Phạm vi ghi chú:** Tài liệu hệ thống hóa kiến thức phòng thủ và kỹ năng phân tích log theo nội dung công khai của room. Không ghi lại đáp án, flag, IP hay kết quả riêng của lab.

## 1. Tổng quan về Network Security

Mạng doanh nghiệp là tập hợp các thiết bị và hệ thống kết nối với nhau để trao đổi dữ liệu, chia sẻ tài nguyên và cung cấp dịch vụ. Các thành phần này không hoạt động độc lập: một endpoint bị xâm nhập có thể trở thành bàn đạp để attacker truy cập server, di chuyển ngang (lateral movement) hoặc đánh cắp dữ liệu.

**Network security** tập trung bảo vệ tính bảo mật, tính toàn vẹn và tính sẵn sàng của dữ liệu cũng như dịch vụ được truyền qua mạng. Với góc nhìn SOC, mục tiêu không chỉ là chặn lưu lượng xấu mà còn phải có đủ telemetry để phát hiện, điều tra và xác định phạm vi ảnh hưởng.

### 1.1. Các thành phần thường gặp trong mạng doanh nghiệp

| Thành phần | Vai trò | Góc nhìn bảo mật |
|---|---|---|
| User Workstation / Endpoint | Máy tính, laptop của nhân viên | Có thể bị xâm nhập qua phishing, malware hoặc phần mềm không an toàn; cần theo dõi process, logon và kết nối mạng. |
| Application Server | Cung cấp ứng dụng nội bộ hoặc public-facing | Là mục tiêu của khai thác lỗ hổng ứng dụng, truy cập trái phép và đánh cắp dữ liệu. |
| File / Database Server | Lưu trữ tài liệu, dữ liệu nghiệp vụ | Cần kiểm soát quyền truy cập, theo dõi truy vấn và hoạt động đọc/ghi bất thường. |
| Switch | Kết nối các thiết bị trong LAN | Có vai trò trong phân đoạn mạng; cấu hình VLAN và bảo vệ cổng giúp hạn chế truy cập trái phép. |
| Router | Chuyển tiếp packet giữa các mạng | Là điểm quan trọng để kiểm soát đường đi của traffic và kết nối giữa các subnet. |
| Firewall | Cho phép hoặc chặn traffic theo policy | Log firewall giúp nhận diện port scan, brute-force, truy cập service không cần thiết và outbound bất thường. |
| WAF | Bảo vệ ứng dụng web ở tầng ứng dụng | Có thể phát hiện hoặc chặn SQL injection, XSS, path traversal và request độc hại khác. |
| IDS / IPS | Phát hiện hoặc ngăn chặn hành vi xâm nhập | Bổ sung khả năng quan sát hành vi vượt qua firewall hoặc xảy ra bên trong mạng. |
| VPN Gateway | Cung cấp truy cập từ xa qua kênh được bảo vệ | Cần theo dõi đăng nhập thất bại, đăng nhập bất thường, thiết bị và vị trí truy cập. |
| DNS / Proxy | Phân giải tên miền và trung gian truy cập Internet | Log DNS/proxy hữu ích để phát hiện truy cập domain độc hại, DNS tunneling và tải dữ liệu ra ngoài. |

### 1.2. Network perimeter là gì?

**Network perimeter** là ranh giới giữa mạng nội bộ được tổ chức kiểm soát và các mạng bên ngoài, thường là Internet. Đây là điểm dữ liệu đi vào hoặc đi ra khỏi môi trường doanh nghiệp.

Perimeter hiện đại không chỉ là một firewall vật lý. Nó còn có thể bao gồm:

- Firewall và các gateway định tuyến.
- DMZ chứa những dịch vụ cần công khai, ví dụ web server hoặc mail gateway.
- WAF bảo vệ ứng dụng web.
- VPN gateway phục vụ truy cập từ xa.
- Cloud gateway, kết nối site-to-site và các điểm truy cập từ xa.
- IDS/IPS hoặc network monitoring sensor.

Perimeter là tuyến phòng thủ quan trọng nhưng không thể bảo vệ tuyệt đối. Một kết nối có thể được firewall cho phép vì phù hợp policy, sau đó vẫn bị lợi dụng bởi malware hoặc tài khoản bị chiếm quyền. Vì vậy, cần giám sát cả traffic đã được cho phép và các hoạt động bên trong mạng.

## 2. Network Visibility và nguồn log

**Network visibility** là khả năng quan sát và hiểu hoạt động đang diễn ra trong mạng. Nếu thiếu log hoặc telemetry, SOC khó xác định thiết bị nào giao tiếp với thiết bị nào, kết nối được cho phép hay bị chặn, và một sự kiện đơn lẻ có nằm trong chuỗi tấn công hay không.

Hai nhóm log quan trọng cần phân biệt:

### 2.1. Host-centric logs

Được tạo ra bởi từng máy chủ hoặc endpoint. Nhóm log này cung cấp chi tiết về hoạt động bên trong một thiết bị.

| Nguồn log | Thông tin có thể khai thác |
|---|---|
| Windows Event Logs | Đăng nhập thành công/thất bại, tạo process, thay đổi service, thay đổi tài khoản và sự kiện hệ thống. |
| Linux syslog / auth logs | SSH login, sudo, hoạt động service, lỗi hệ thống và xác thực. |
| Application logs | Request đến web server, truy vấn database, lỗi ứng dụng và thao tác của người dùng. |
| EDR / Antivirus / HIDS | Process đáng ngờ, file bị phát hiện, persistence, hành vi độc hại trên endpoint. |

Host log giúp trả lời: **Điều gì đã xảy ra trên máy? Process nào thực thi? Tài khoản nào đăng nhập? File nào bị truy cập hoặc thay đổi?**

### 2.2. Network-centric logs

Được tạo bởi các thiết bị hoặc hệ thống quan sát traffic giữa các máy.

| Nguồn log | Thông tin có thể khai thác |
|---|---|
| Firewall | Source/destination IP, port, protocol, action allow/deny, rule được áp dụng, thời gian và số byte. |
| IDS / IPS | Signature hoặc hành vi bị phát hiện, mức độ ưu tiên, packet/flow liên quan và hành động xử lý. |
| WAF | HTTP request, URL, method, source IP, rule ID, attack type và action. |
| VPN | Tài khoản, source IP, thời gian, trạng thái xác thực, session và thông tin thiết bị nếu có. |
| DNS / Proxy | Domain được truy vấn, URL, user/device, destination, category và thời điểm truy cập. |
| NetFlow / Zeek / NDR | Metadata về flow, connection state, protocol, bytes, duration và hành vi giao tiếp. |

Network log trả lời: **Thiết bị nào kết nối đến đâu, vào thời điểm nào, qua protocol/port nào và kết nối có được cho phép không?**

**Kết hợp host log và network log** giúp dựng timeline đầy đủ hơn. Ví dụ: endpoint tạo file nén, sau đó process lạ kết nối ra Internet và firewall ghi nhận lượng dữ liệu outbound lớn. Chỉ nhìn firewall có thể không biết process nào khởi tạo kết nối; chỉ nhìn endpoint có thể không biết dữ liệu đã đi đến máy chủ nào.

## 3. Những trường log cần chú ý

Tên field có thể thay đổi giữa firewall, WAF, VPN, Zeek và SIEM, nhưng các trường thường cần kiểm tra gồm:

| Field | Ý nghĩa |
|---|---|
| `timestamp` / `@timestamp` | Thời điểm sự kiện. Cần kiểm tra timezone và độ lệch đồng hồ. |
| `source.ip` / `src_ip` | Địa chỉ IP nguồn. |
| `source.port` / `src_port` | Port nguồn. |
| `destination.ip` / `dest_ip` | Địa chỉ IP đích. |
| `destination.port` / `dest_port` | Port đích. |
| `network.transport` / `protocol` | TCP, UDP, ICMP hoặc protocol khác. |
| `action` / `rule.action` | Allow, deny, block, drop, reject hoặc hành động tương ứng. |
| `user.name` / `username` | Tài khoản liên quan đến sự kiện nếu có. |
| `bytes` / `bytes_out` / `bytes_in` | Lượng dữ liệu truyền nhận. |
| `duration` | Thời lượng kết nối. |
| `rule.name` / `rule.id` | Rule tạo ra sự kiện hoặc alert. |

Không nên mặc định mọi thiết bị đều đặt tên field giống nhau. Khi điều tra, cần kiểm tra schema và sample event trước khi viết truy vấn SIEM.

## 4. Các nhóm nguy cơ tại perimeter

### 4.1. Port scanning và reconnaissance

Attacker có thể thử kết nối tới nhiều port của một host hoặc cùng một port trên nhiều host để tìm service đang mở.

Dấu hiệu thường gặp:

- Một source IP tạo nhiều kết nối tới nhiều destination port trong thời gian ngắn.
- Một source IP truy cập cùng một port trên nhiều destination IP.
- Nhiều kết nối bị từ chối hoặc không hoàn tất handshake.
- Các lần dò quét lặp lại theo từng khoảng thời gian.

Một đợt scan không tự động chứng minh hệ thống đã bị xâm nhập. Cần xác định nguồn scan là scanner nội bộ được phê duyệt, dịch vụ giám sát hợp lệ hay nguồn không rõ.

### 4.2. Brute-force và password guessing

Attacker thử nhiều mật khẩu hoặc nhiều username để chiếm tài khoản, thường nhắm vào VPN, SSH, RDP hoặc portal đăng nhập.

Dấu hiệu:

- Nhiều sự kiện `FAILED_AUTH` từ cùng một IP hoặc cùng một cụm IP.
- Nhiều username phổ biến được thử liên tục.
- Tần suất đăng nhập thất bại tăng đột biến.
- Đăng nhập thành công xuất hiện ngay sau một chuỗi thất bại.
- Một tài khoản đăng nhập từ thiết bị hoặc vị trí bất thường.

Cần phân biệt brute-force với người dùng nhập sai mật khẩu nhiều lần, ứng dụng dùng credential cũ hoặc hệ thống kiểm tra định kỳ.

### 4.3. Web attacks qua WAF

WAF có thể ghi nhận các dạng request như:

- **SQL Injection:** input có dấu hiệu thao túng truy vấn database.
- **Cross-Site Scripting (XSS):** input chứa script có khả năng được trình duyệt thực thi.
- **Directory / Path Traversal:** cố gắng truy cập file ngoài thư mục được phép.
- **Local File Inclusion hoặc request bất thường:** tùy khả năng và rule của WAF.

Khi phân tích, nên đọc cả `attack_type`, `rule_id`, request URI, HTTP method, source IP và action. `BLOCK` cho biết WAF đã chặn request theo rule, nhưng vẫn cần kiểm tra xem có request liên quan nào được `ALLOW` hay không.

### 4.4. Suspicious outbound traffic

Không chỉ inbound traffic mới đáng chú ý. Máy nội bộ có thể kết nối ra máy chủ C2 hoặc truyền dữ liệu trái phép.

Dấu hiệu:

- Kết nối outbound tới domain/IP hiếm gặp hoặc chưa từng thấy trong baseline.
- Lượng dữ liệu upload lớn bất thường.
- Kết nối lặp lại với chu kỳ đều đặn (có thể là beaconing).
- Máy trạm thông thường sử dụng protocol hoặc port không phù hợp vai trò.
- Kết nối ngoài giờ làm việc hoặc do process không quen thuộc tạo ra.

## 5. Quy trình phân tích log perimeter

1. **Xác định phạm vi:** thời gian, hệ thống bị ảnh hưởng, loại log và mục tiêu điều tra.
2. **Kiểm tra schema:** xem các field quan trọng và format timestamp.
3. **Tìm event bất thường:** lọc theo source IP, destination IP, port, action, username hoặc rule.
4. **Nhóm sự kiện:** đếm số destination, port, username, lần thất bại và tổng bytes theo source.
5. **Dựng timeline:** sắp xếp các sự kiện theo thời gian và kiểm tra hoạt động trước/sau alert.
6. **Đối chiếu asset inventory:** xác định host nào là workstation, server, VPN gateway hoặc thiết bị mạng.
7. **Kết hợp nguồn log:** đối chiếu firewall với WAF, VPN, IDS, DNS, proxy và endpoint logs.
8. **Đánh giá kết quả:** phân biệt activity bị block, activity được allow, login thất bại và truy cập thành công.
9. **Ghi nhận bằng chứng:** query, time range, log source, các field quan trọng và nhận định có căn cứ.

### 5.1. Ví dụ truy vấn Splunk mang tính khung

Các field và `index` cần thay theo dữ liệu thực tế trong SIEM.

**Thống kê kết nối theo source và destination:**

```spl
index=network sourcetype=firewall
| stats count by src_ip dest_ip dest_port action
| sort - count
```

**Tìm nhiều lần xác thực thất bại:**

```spl
index=vpn sourcetype=vpn_auth action="FAILED_AUTH"
| stats count values(username) as usernames by src_ip
| sort - count
```

**Tìm outbound volume lớn:**

```spl
index=network direction="outbound"
| stats sum(bytes_out) as total_outbound_bytes count by src_ip dest_ip dest_port
| sort - total_outbound_bytes
```

Các truy vấn trên chỉ là ví dụ khung; cần xác nhận field, data model và cách chuẩn hóa log trong môi trường đang phân tích.

## 6. Phân biệt tín hiệu và kết luận

| Quan sát | Có thể gợi ý | Cần xác minh thêm |
|---|---|---|
| Một nguồn truy cập nhiều port/host | Port scan hoặc inventory scan | Scanner có được phê duyệt không? Có schedule không? |
| Nhiều login thất bại | Brute-force hoặc lỗi xác thực | User, source IP, MFA, login thành công sau đó và lịch sử tài khoản. |
| WAF block SQLi/XSS | Web exploitation attempt | Request khác có được allow không? Có dấu hiệu truy cập dữ liệu thành công không? |
| Outbound bytes tăng cao | Upload hợp lệ, backup hoặc exfiltration | Process, user, destination, dữ liệu liên quan và baseline. |
| Kết nối lặp lại đều đặn | Beaconing hoặc health check | Destination, process, lịch tác vụ và chu kỳ bình thường. |

**Nguyên tắc:** Alert là điểm bắt đầu điều tra, không phải kết luận cuối cùng. Một sự kiện cần được đánh giá theo bối cảnh, vai trò asset, hành động thực tế và bằng chứng liên quan.

## 7. Kiến thức và kỹ năng có thể thể hiện trong portfolio

- Hiểu các thành phần mạng doanh nghiệp và vai trò của network perimeter.
- Phân biệt host-centric logs với network-centric logs.
- Đọc các trường quan trọng trong firewall, WAF và VPN logs.
- Nhận diện dấu hiệu port scanning, brute-force, web attack và outbound anomaly.
- Sử dụng SIEM để lọc, nhóm, thống kê và dựng timeline.
- Correlate nhiều nguồn log thay vì kết luận dựa trên một alert đơn lẻ.

## 8. Tài liệu tham khảo

- [TryHackMe – Network Security Essentials](https://tryhackme.com/room/networksecurityessentials)
- [TryHackMe – Intro to SIEM](https://tryhackme.com/room/introtosiem)
- [MITRE ATT&CK – Reconnaissance](https://attack.mitre.org/tactics/TA0043/)
- [MITRE ATT&CK – Exfiltration](https://attack.mitre.org/tactics/TA0010/)
