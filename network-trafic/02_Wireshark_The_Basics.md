# Wireshark: The Basics

**Nguồn học:** [TryHackMe – Wireshark: The Basics](https://tryhackme.com/room/wiresharkthebasics)

## 1. Wireshark là gì?

**Wireshark** là công cụ phân tích giao thức mạng mã nguồn mở, đa nền tảng. Nó có thể capture traffic trực tiếp từ network interface và phân tích file capture đã lưu như `.pcap` hoặc `.pcapng`.

Các mục tiêu sử dụng chính:
- Xem những host đang giao tiếp với nhau.
- Kiểm tra giao thức, port, flags và dữ liệu của từng packet.
- Theo dõi một phiên giao tiếp qua nhiều packet.
- Lọc lượng traffic lớn để tập trung vào sự kiện cần điều tra.
- Xây dựng bằng chứng phục vụ troubleshooting, incident response và network forensics.

Wireshark không tự động kết luận traffic là độc hại. Analyst cần diễn giải dữ liệu trong bối cảnh.

## 2. Giao diện chính

| Khu vực | Chức năng |
|---|---|
| **Packet List** | Danh sách packet; thường hiển thị số thứ tự, thời gian, source, destination, protocol, length và thông tin tóm tắt |
| **Packet Details** | Cấu trúc phân cấp của packet: các lớp và trường giao thức |
| **Packet Bytes** | Dữ liệu packet dưới dạng hex và ASCII |
| **Display Filter bar** | Lọc packet đang hiển thị mà không sửa file capture gốc |
| **Status bar** | Thông tin về packet được hiển thị, tổng packet và trạng thái capture |

Màu sắc có thể giúp phân biệt loại traffic hoặc packet bất thường, nhưng màu không phải bằng chứng độc lập. Quy tắc coloring có thể được tùy chỉnh.

## 3. Capture trực tiếp và phân tích file

### Capture trực tiếp
1. Mở Wireshark.
2. Chọn interface phù hợp (Ethernet, Wi-Fi hoặc interface ảo).
3. Bắt đầu capture.
4. Tạo hoặc chờ traffic liên quan.
5. Dừng capture và lưu file nếu cần.

Cần chọn đúng interface và có quyền phù hợp. Trên mạng chuyển mạch, máy tính thường không nhìn thấy toàn bộ unicast traffic của các thiết bị khác trừ khi có cơ chế mirror/TAP hoặc vị trí capture thích hợp.

### Phân tích PCAP
1. Chọn **File → Open** và mở file `.pcap` / `.pcapng`.
2. Xem tổng quan packet và thời gian.
3. Dùng Statistics để hiểu thành phần traffic.
4. Lọc theo protocol, host, port hoặc điều kiện cụ thể.
5. Mở packet và đọc protocol tree.
6. Follow TCP/UDP stream khi cần tái dựng trao đổi.
7. Lưu ghi chú và export artifacts theo quy trình được phê duyệt.

File PCAP có thể chứa dữ liệu cá nhân, token, cookie hoặc credentials. Hạn chế chia sẻ và bảo vệ bản gốc.

## 4. Đọc cấu trúc packet

Khi chọn một packet, Wireshark giải mã các trường dựa trên protocol dissector. Ví dụ một frame Ethernet mang IPv4, TCP và HTTP có thể được phân tích theo chuỗi:

1. **Frame:** thông tin capture, độ dài frame và timestamp.
2. **Ethernet II:** source/destination MAC và EtherType.
3. **IPv4/IPv6:** source/destination IP, TTL/Hop Limit, protocol và các trường liên quan.
4. **TCP/UDP:** source/destination port và thông tin vận chuyển.
5. **Application protocol:** HTTP, DNS, TLS hoặc giao thức khác.
6. **Payload:** dữ liệu ứng dụng nếu có thể giải mã và không bị mã hóa.

### Trường thường gặp
- **Source / Destination:** địa chỉ đầu gửi và đầu nhận ở lớp đang xem.
- **Port:** giúp xác định endpoint dịch vụ; port chỉ là manh mối, không đảm bảo ứng dụng thực tế.
- **TTL:** giới hạn thời gian sống của gói IP; không phải thời gian tồn tại của ứng dụng.
- **TCP flags:** SYN, ACK, FIN, RST, PSH, URG...
- **Length:** cần phân biệt frame length, IP length và TCP payload length.
- **Checksum:** dùng phát hiện lỗi dữ liệu ở một số lớp; checksum “incorrect” trong capture trên máy gửi đôi khi do checksum offloading, nên phải kiểm tra ngữ cảnh.

## 5. TCP handshake cơ bản

TCP thường thiết lập kết nối bằng three-way handshake:

1. Client → Server: `SYN`
2. Server → Client: `SYN, ACK`
3. Client → Server: `ACK`

Sau handshake, hai đầu có thể trao đổi dữ liệu. Kết thúc bình thường thường dùng FIN/ACK; RST có thể báo kết thúc/reset bất ngờ.

Các bộ lọc hữu ích:
```wireshark
tcp
tcp.flags.syn == 1
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.flags.reset == 1
```

Một lượng lớn SYN không có kết nối hoàn tất có thể gợi ý scan hoặc vấn đề kết nối, nhưng cũng có thể xuất phát từ packet loss hay server quá tải.

## 6. Packet navigation và Follow Stream

- **Go to packet:** nhảy tới packet theo số thứ tự.
- **Find Packet:** tìm chuỗi hoặc dữ liệu theo các tiêu chí có sẵn.
- **Mark Packet:** đánh dấu packet quan trọng trong phiên phân tích.
- **Packet comments:** ghi chú về bằng chứng nếu workflow hỗ trợ.
- **Follow → TCP Stream:** xem lại dữ liệu trao đổi của một TCP conversation theo luồng.
- **Follow → UDP Stream:** xem dữ liệu thuộc luồng UDP nếu Wireshark xác định được.
- **Conversation view:** nhóm traffic theo cặp endpoint và protocol.

Follow Stream hữu ích khi cần đọc request/response HTTP hoặc dữ liệu giao thức dạng rõ. Nội dung mã hóa như HTTPS không trở thành plaintext chỉ bằng cách Follow Stream; cần khóa phiên hợp lệ hoặc phương pháp giải mã được phép.

## 7. Display filters

Display filter chỉ quyết định packet nào được hiển thị; nó không loại bỏ packet khỏi file capture gốc.

### Bộ lọc cơ bản

| Mục đích | Filter |
|---|---|
| Chỉ DNS | `dns` |
| Chỉ HTTP | `http` |
| Chỉ TCP | `tcp` |
| Chỉ UDP | `udp` |
| Một IP ở source hoặc destination | `ip.addr == 192.0.2.10` |
| IP nguồn | `ip.src == 192.0.2.10` |
| IP đích | `ip.dst == 192.0.2.20` |
| Port đích 443 | `tcp.dstport == 443` |
| Hostname DNS cụ thể | `dns.qry.name == "example.org"` |
| SYN không có ACK | `tcp.flags.syn == 1 && tcp.flags.ack == 0` |
| HTTP response lỗi | `http.response.code >= 400` |
| Nhiều điều kiện | `ip.addr == 192.0.2.10 && dns` |

### Toán tử
- `&&` hoặc `and`: cả hai điều kiện đúng.
- `||` hoặc `or`: ít nhất một điều kiện đúng.
- `!` hoặc `not`: phủ định điều kiện.
- `==`, `!=`, `>`, `<`, `>=`, `<=`: so sánh.
- Dùng dấu ngoặc để làm rõ thứ tự đánh giá: `(dns || http) && ip.addr == 192.0.2.10`.

### Display filter và capture filter khác nhau
- **Capture filter:** áp dụng trước/trong lúc capture để quyết định packet nào được ghi lại; cú pháp thường dựa trên libpcap/BPF.
- **Display filter:** áp dụng sau khi có packet, dùng cú pháp riêng của Wireshark để lọc hiển thị.

Ví dụ capture filter:
```text
host 192.0.2.10
port 53
tcp
```

Ví dụ display filter:
```wireshark
ip.addr == 192.0.2.10
dns
tcp.port == 443
```

Không nên nhầm hai cú pháp này với nhau.

## 8. Protocol thường gặp khi phân tích

| Protocol | Điều cần quan sát |
|---|---|
| ARP | Mapping IPv4–MAC, request/reply bất thường |
| ICMP | Echo request/reply, unreachable, kích thước và tần suất bất thường |
| DNS | Query, response, domain, record type, response code |
| TCP | Handshake, retransmission, reset, sequence/acknowledgment |
| HTTP | Method, Host, URI, status code, headers và payload dạng rõ |
| TLS/HTTPS | Handshake metadata, certificate nếu có, SNI/ALPN tùy phiên bản; payload thường được mã hóa |
| DHCP | Discover/Offer/Request/Ack và thông tin cấu hình IP |

## 9. Quy trình phân tích PCAP cho người mới

1. Mở file và ghi lại tên file, kích thước, thời gian capture và số packet.
2. Kiểm tra **Statistics → Capture File Properties**, **Protocol Hierarchy**, **Endpoints** và **Conversations**.
3. Xác định host/port/protocol nổi bật.
4. Dùng display filter để thu hẹp phạm vi.
5. Chọn packet và mở rộng từng lớp trong Packet Details.
6. Dùng Follow Stream để hiểu cuộc trao đổi khi thích hợp.
7. Đối chiếu timestamp và các packet trước/sau để tránh tách một sự kiện khỏi ngữ cảnh.
8. Ghi lại bằng chứng: filter, packet number, timestamp, endpoints, protocol và diễn giải.
9. Nêu giới hạn: packet loss, traffic mã hóa, thiếu chiều giao tiếp hoặc capture không bao phủ toàn bộ mạng.

## 10. Các lỗi diễn giải thường gặp
- Coi port 80/443 là bằng chứng chắc chắn ứng dụng HTTP/HTTPS; port có thể được dùng cho giao thức khác.
- Kết luận độc hại chỉ vì một packet có màu cảnh báo.
- Coi mọi TCP retransmission là tấn công; chúng cũng xảy ra do mất gói hoặc chất lượng mạng.
- Cho rằng HTTPS không thể phân tích; metadata và hành vi kết nối vẫn có giá trị.
- Không kiểm tra timezone hoặc timestamp khi ghép log từ nhiều hệ thống.
- Chỉ nhìn một packet mà không xem cả stream và bối cảnh.

## 11. Kỹ năng đạt được
- Điều hướng Wireshark và đọc packet ở nhiều lớp.
- Phân biệt capture trực tiếp, file PCAP, capture filter và display filter.
- Lọc traffic theo IP, port, protocol và TCP flags.
- Theo dõi một conversation bằng Follow Stream.
- Ghi lại bằng chứng có thể tái kiểm tra, thay vì chỉ ghi một câu trả lời của lab.

## Tài liệu tham khảo
- [TryHackMe – Wireshark: The Basics](https://tryhackme.com/room/wiresharkthebasics)
- [Wireshark User’s Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
