# Network Discovery Detection

**Nguồn học:** [TryHackMe – Network Discovery Detection](https://tryhackme.com/room/networkdiscoverydetection)  
**Chủ đề:** Nhận diện hoạt động network discovery, host discovery và port scanning qua firewall logs, Zeek logs và SIEM.

> **Phạm vi ghi chú:** Tập trung vào tư duy phát hiện ở góc nhìn blue team/SOC. Không bao gồm IP, subnet, số lượng event hoặc đáp án riêng của lab.

## 1. Network Discovery là gì?

**Network discovery** là quá trình thu thập thông tin về các host, địa chỉ IP, port, service và đặc điểm hệ thống đang tồn tại trong một mạng.

Attacker thường thực hiện discovery để trả lời các câu hỏi:

- Có những host nào có thể truy cập?
- Host nào đang online?
- Port và service nào đang mở?
- Service đang chạy phiên bản nào?
- Có cấu hình yếu hoặc lỗ hổng nào có thể khai thác?
- Hệ thống nào có giá trị cao hoặc có thể làm bàn đạp để tiến sâu hơn?

Defender cũng thực hiện network discovery để lập inventory, tìm thiết bị không được quản lý, kiểm tra port/service không cần thiết và giảm attack surface. Do đó, **không thể kết luận một hoạt động scan là độc hại chỉ vì nó tạo ra nhiều kết nối**.

## 2. Attacker discovery và defender discovery

| Góc nhìn | Mục tiêu | Dấu hiệu cần quan sát |
|---|---|---|
| Attacker | Tìm host, port, service, phiên bản và điểm yếu để chuẩn bị xâm nhập | Nguồn không rõ, scan ngoài giờ, scan nhiều mục tiêu, không có change ticket hoặc hoạt động tiếp nối đáng ngờ. |
| Defender / Vulnerability scanner | Kiểm kê tài sản, đánh giá exposure và kiểm tra lỗ hổng | Source IP đã đăng ký, lịch scan định kỳ, owner rõ ràng và phạm vi được phê duyệt. |
| Search engine / Internet research scanner | Thu thập thông tin tài nguyên công khai | Có thể tạo traffic tương tự scan; cần kiểm tra nguồn, tần suất và chính sách tổ chức. |

### 2.1. External scanning

External scanning xảy ra khi source ở ngoài mạng tổ chức và destination là các IP thuộc tổ chức, thường là tài sản public-facing.

- Có thể là reconnaissance trước khi attacker tìm cách initial access.
- Thường bắt đầu từ Internet hướng vào các service công khai.
- Có thể được firewall ghi nhận dưới dạng nhiều kết nối bị block hoặc các lần thử vào port khác nhau.

External scan không đồng nghĩa attacker đã có foothold trong mạng. Mức độ nghiêm trọng cần xét đến việc có khai thác thành công, đăng nhập thành công hay dấu hiệu tiếp theo hay không.

### 2.2. Internal scanning

Internal scanning xảy ra giữa các địa chỉ thuộc mạng nội bộ.

- Có thể do vulnerability scanner hoặc IT administrator thực hiện.
- Cũng có thể cho thấy một endpoint đã bị xâm nhập và đang dò tìm hệ thống khác.
- Cần chú ý đặc biệt khi một workstation thông thường bắt đầu quét nhiều server, port hoặc subnet không nằm trong hoạt động thường ngày.

Internal scan có thể đáng lo hơn external scan vì nguồn phát sinh có thể đã nằm trong vùng mạng nội bộ. Tuy nhiên, phải xác minh thiết bị và lịch vận hành trước khi kết luận.

## 3. Các dạng scanning phổ biến

### 3.1. Host discovery / Ping sweep

**Ping sweep** dùng ICMP để kiểm tra nhiều địa chỉ IP nhằm tìm host đang phản hồi.

Mô hình thường gặp:

- Một source IP gửi ICMP Echo Request tới nhiều destination IP trong cùng subnet hoặc một dải IP.
- Các host còn hoạt động có thể trả lời bằng ICMP Echo Reply.
- Nếu ICMP bị firewall chặn, host đang online vẫn có thể không phản hồi.

**Dấu hiệu phát hiện:** cùng một source IP tạo nhiều ICMP request tới nhiều destination IP trong một khoảng thời gian ngắn, đặc biệt khi các destination tạo thành một subnet liên tiếp.

Không nên đánh đồng “không ping được” với “host không tồn tại”. ICMP có thể bị lọc hoặc host được cấu hình không phản hồi.

### 3.2. Horizontal scanning

Horizontal scan kiểm tra **cùng một destination port trên nhiều destination IP** để tìm host nào cung cấp một service cụ thể.

Ví dụ logic: một source IP thử kết nối tới TCP port 445 trên nhiều địa chỉ nội bộ nhằm tìm máy có SMB mở.

| Trường | Mẫu hình |
|---|---|
| Source IP | Giữ nguyên |
| Destination IP | Thay đổi liên tục |
| Destination port | Thường giữ nguyên |
| Mục đích | Tìm nhiều host có cùng một service/port |

### 3.3. Vertical scanning

Vertical scan kiểm tra **nhiều destination port trên cùng một destination IP** để tìm service được mở trên host đó.

| Trường | Mẫu hình |
|---|---|
| Source IP | Giữ nguyên |
| Destination IP | Giữ nguyên |
| Destination port | Thay đổi liên tục |
| Mục đích | Lập bản đồ service/port của một host cụ thể |

Attacker có thể kết hợp horizontal và vertical scanning: trước tiên tìm host có một port nhất định, sau đó quét sâu các port trên host được quan tâm.

## 4. Cơ chế của một số loại port scan

### 4.1. TCP SYN scan

TCP sử dụng three-way handshake:

1. Client gửi `SYN`.
2. Server phản hồi `SYN-ACK` nếu port đang lắng nghe.
3. Client gửi `ACK` để hoàn tất kết nối.

Trong SYN scan, scanner gửi SYN để kiểm tra phản hồi nhưng thường không hoàn tất một TCP session thông thường.

| Phản hồi | Diễn giải thường gặp |
|---|---|
| `SYN-ACK` | Port có khả năng đang mở và host phản hồi. |
| `RST` / `RST-ACK` | Port thường đang đóng hoặc kết nối bị từ chối. |
| Không có phản hồi | Có thể bị firewall lọc, packet bị mất hoặc thiết bị không phản hồi; không thể khẳng định port mở. |
| ICMP unreachable / prohibited | Có thể cho thấy traffic bị chặn hoặc không thể định tuyến. |

SYN scan đôi khi khó nhận ra hơn một full connection scan vì không hoàn tất handshake. SOC cần xem số lượng SYN, phản hồi tương ứng và trạng thái connection.

### 4.2. UDP scan

UDP không thiết lập kết nối bằng three-way handshake. Scanner có thể gửi UDP packet tới các port để quan sát phản hồi.

| Kết quả quan sát | Diễn giải |
|---|---|
| UDP response từ service | Có bằng chứng port đang mở. |
| ICMP Destination Unreachable – Port Unreachable | Thường cho thấy port đóng, đồng thời host đã phản hồi. |
| Không có phản hồi | Có thể là open hoặc filtered; UDP scan thường khó kết luận hơn TCP. |
| ICMP administratively prohibited | Có thể cho thấy traffic bị policy chặn. |

Không có phản hồi **không phải bằng chứng chắc chắn port đang mở**. Cần xét timeout, firewall, packet loss và hành vi của service.

## 5. Phân tích dữ liệu bằng SIEM và Kibana

Room sử dụng các bản ghi được export từ SIEM và giao diện Kibana Discover để quan sát network events. Trong thực tế, các log có thể chứa field chuẩn hóa cùng một trường `message` chứa JSON gốc của Zeek.

### 5.1. Các field quan trọng

| Field | Ý nghĩa |
|---|---|
| `@timestamp` | Thời gian ghi nhận event. |
| `source.ip` / `source.port` | IP và port nguồn. |
| `destination.ip` / `destination.port` | IP và port đích. |
| `network.transport` / `proto` | TCP, UDP hoặc protocol khác. |
| `event.dataset` | Loại dữ liệu, ví dụ `zeek.conn`. |
| `zeek.conn.conn_state` | Trạng thái kết nối được Zeek ghi nhận. |
| `orig_pkts` / `resp_pkts` | Số packet từ originator và responder trong Zeek connection record. |
| `orig_ip_bytes` / `resp_ip_bytes` | Số byte IP theo từng chiều. |

Tên field có thể khác theo pipeline ingest. Cần mở sample event và xác nhận schema trước khi truy vấn.

### 5.2. Một số giá trị `conn_state` của Zeek

Các trạng thái thường gặp trong `conn.log`:

| Giá trị | Cách hiểu tổng quát |
|---|---|
| `S0` | Thấy nỗ lực kết nối nhưng chưa ghi nhận phản hồi. |
| `S1` | Kết nối đã được thiết lập nhưng chưa kết thúc theo cách bình thường tại thời điểm ghi nhận. |
| `SF` | Kết nối được thiết lập và kết thúc bình thường. |
| `REJ` | Nỗ lực kết nối bị từ chối. |
| `RSTO` | Kết nối bị reset bởi originator. |
| `RSTR` | Kết nối bị reset bởi responder. |

Các trạng thái này cần được diễn giải cùng protocol, packet direction, firewall policy và dữ liệu capture. Ví dụ, `S0` xuất hiện hàng loạt tới nhiều port có thể phù hợp với scan, nhưng một vài `S0` riêng lẻ có thể chỉ là timeout hoặc packet loss.

### 5.3. Quy trình dùng Kibana Discover

1. Mở **Discover** và chọn đúng Data View.
2. Chọn khoảng thời gian đủ rộng để bao phủ hoạt động cần phân tích.
3. Thêm `source.ip`, `destination.ip`, `destination.port`, `network.transport` và `zeek.conn.conn_state` làm cột.
4. Filter theo một source IP để xem tất cả destination mà nguồn đó đã liên hệ.
5. Nhóm hoặc thống kê destination IP và destination port để phân loại horizontal/vertical scan.
6. Kiểm tra các event ICMP để tìm ping sweep.
7. Kiểm tra protocol UDP và các phản hồi ICMP port unreachable để đánh giá UDP scan.
8. Đối chiếu với scanner nội bộ được phê duyệt, asset inventory và lịch scan.

### 5.4. Kiểm tra log CSV từ terminal

Khi log CSV khó đọc, có thể xem header và một vài dòng đầu bằng:

```bash
head -n 5 log-session-1.csv
```

Đọc tên cột trước giúp xác định source/destination, port, action và nơi chứa JSON message. Không nên chỉ tìm kiếm bằng mắt trong một file lớn mà chưa hiểu cấu trúc dữ liệu.

## 6. Logic phát hiện và cách tránh false positive

| Mẫu hình | Có thể là | Cần kiểm tra |
|---|---|---|
| Một source IP → nhiều destination IP, cùng port | Horizontal scan | Scanner đã được phê duyệt chưa? Port đó có service phổ biến hay nhạy cảm không? |
| Một source IP → một destination IP, nhiều port | Vertical scan | Destination là server quan trọng hay host cá nhân? Có hoạt động quản trị hợp lệ không? |
| Một source IP → nhiều host bằng ICMP | Ping sweep | ICMP có bị chặn không? Có script monitoring hoặc inventory không? |
| Nhiều SYN không có phản hồi | SYN scan hoặc kết nối lỗi | Có firewall drop, mất packet hoặc host không hoạt động không? |
| UDP probe nhiều port và không có phản hồi | UDP scan có thể xảy ra | Không kết luận port open chỉ dựa vào timeout. |

### 6.1. Allowlist và threat intelligence

- Duy trì danh sách IP của vulnerability scanner, monitoring server và công cụ quản trị hợp lệ.
- Lưu lịch scan, phạm vi scan, owner và mục đích để SOC có thể xác minh.
- Dùng threat intelligence như một tín hiệu tăng mức độ ưu tiên, không nên chỉ dựa vào reputation để quyết định có alert hay không.
- Không allowlist quá rộng; nếu scanner bị chiếm quyền, một allowlist rộng có thể che khuất hoạt động độc hại.

## 7. Quy trình SOC khi gặp alert network scanning

1. Xác định source IP, destination IP/subnet, port, protocol và time range.
2. Phân loại scan: host discovery, horizontal, vertical, TCP SYN hay UDP.
3. Xác định hướng: external-to-internal hay internal-to-internal.
4. Tra cứu asset inventory để biết source/destination là thiết bị gì và owner nào quản lý.
5. Kiểm tra scanner allowlist, lịch vulnerability assessment và thay đổi hệ thống.
6. Tìm hoạt động tiếp nối: exploit attempt, authentication, process execution, lateral movement hoặc outbound traffic.
7. Đánh giá impact và độ tin cậy của bằng chứng trước khi escalate.
8. Lưu query, log sample và timeline vào incident ticket.

## 8. Kiến thức và kỹ năng có thể thể hiện trong portfolio

- Giải thích được mục đích network discovery của attacker và defender.
- Phân biệt external scanning và internal scanning.
- Phân biệt horizontal scan với vertical scan dựa trên quan hệ source/destination/port.
- Hiểu cơ chế cơ bản của ping sweep, TCP SYN scan và UDP scan.
- Đọc các field network và trạng thái kết nối của Zeek.
- Dùng Kibana Discover hoặc SIEM để lọc, nhóm và đối chiếu hoạt động scan.
- Đánh giá scanner hợp lệ và giảm false positive bằng allowlist có kiểm soát.

## 9. Tài liệu tham khảo

- [TryHackMe – Network Discovery Detection](https://tryhackme.com/room/networkdiscoverydetection)
- [TryHackMe – Network Security Essentials](https://tryhackme.com/room/networksecurityessentials)
- [Zeek – conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html)
- [MITRE ATT&CK – Active Scanning (T1595)](https://attack.mitre.org/techniques/T1595/)
