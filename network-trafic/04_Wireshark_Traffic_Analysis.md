# Wireshark: Traffic Analysis

**Nguồn học:** [TryHackMe – Wireshark: Traffic Analysis](https://tryhackme.com/room/wiresharktrafficanalysis)

## 1. Mục tiêu phân tích traffic

Phân tích traffic không chỉ là tìm một packet riêng lẻ. Analyst cần kết hợp protocol, thời gian, endpoint, payload và hành vi để hiểu toàn bộ sự kiện.

Room tập trung vào các tình huống:
- Nmap scanning.
- ARP poisoning và Man-in-the-Middle (MitM).
- Nhận diện host qua DHCP, NetBIOS và Kerberos.
- DNS/ICMP tunneling.
- Phân tích FTP và HTTP dạng rõ.
- Phân tích HTTPS và điều kiện giải mã.
- Tìm credential dạng rõ và tạo kết quả có thể hành động.

> Chỉ phân tích PCAP trong môi trường được phép. Không chủ động truy cập IP/domain đáng ngờ chỉ vì chúng xuất hiện trong capture.

## 2. Nmap scans trong PCAP

Nmap có thể thực hiện nhiều kiểu dò host/port. Mỗi kiểu tạo ra pattern packet khác nhau.

| Kiểu scan | Hành vi quan sát thường gặp | Ghi chú |
|---|---|---|
| TCP SYN scan | Gửi SYN đến nhiều port; phản hồi SYN/ACK có thể chỉ port mở, RST thường chỉ port đóng | Có thể nhận diện qua TCP flags và nhiều đích port |
| TCP Connect scan | Hoàn thành TCP handshake với các port được thử | Tạo kết nối TCP đầy đủ hơn SYN scan |
| UDP scan | Gửi UDP probes; phản hồi ICMP Port Unreachable có thể cho biết port đóng | UDP thường khó kết luận vì nhiều dịch vụ không trả lời |
| Host discovery | ARP, ICMP hoặc probes TCP/UDP tùy mạng và cấu hình | Có thể tìm host hoạt động trước khi quét port |

### Bộ lọc khởi đầu
```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
icmp
udp
```

### Quy trình xác minh scan
1. Xác định source IP và khoảng thời gian.
2. Xem có nhiều destination port trên một host hay nhiều host trong cùng subnet không.
3. Kiểm tra tốc độ, pattern lặp lại và phản hồi.
4. Đối chiếu với lịch quét nội bộ hoặc hoạt động quản trị được phép.
5. Ghi rõ bằng chứng thay vì chỉ kết luận từ một SYN.

Một vulnerability scanner hợp pháp có thể tạo traffic giống scan độc hại; cần xác minh nguồn và lịch hoạt động.

## 3. ARP poisoning và Man-in-the-Middle

**ARP** ánh xạ địa chỉ IPv4 sang địa chỉ MAC trong mạng LAN. Vì ARP không có cơ chế xác thực mạnh, host có thể chấp nhận ARP reply không đáng tin trong một số điều kiện.

**ARP poisoning/spoofing** xảy ra khi kẻ tấn công gửi thông điệp ARP giả để khiến một host gắn IP của thiết bị khác với MAC của attacker. Điều này có thể đưa traffic qua attacker và hỗ trợ MitM.

### Dấu hiệu đáng kiểm tra
- Một IP được quảng bá bởi nhiều MAC không mong đợi.
- Nhiều unsolicited/gratuitous ARP reply.
- Mapping gateway IP–MAC thay đổi bất thường.
- ARP reply xuất hiện mà không khớp với chuỗi request/bối cảnh thông thường.

### Bộ lọc
```wireshark
arp
arp.opcode == 2
```

### Quy trình
1. Xác định IP của gateway và các host liên quan.
2. Theo dõi mapping IP–MAC theo thời gian.
3. Kiểm tra packet ARP reply và sender hardware/protocol address.
4. Đối chiếu với switch logs, endpoint ARP cache và cấu hình mạng.
5. Kiểm tra xem traffic có tiếp tục qua host nghi vấn hay không.

Không phải mọi ARP reply không được yêu cầu đều là tấn công. Thiết bị failover, proxy ARP và thay đổi mạng hợp pháp cũng có thể làm mapping thay đổi.

## 4. Nhận diện host: DHCP, NetBIOS và Kerberos

### DHCP
DHCP tự động cấp cấu hình mạng như IP, subnet mask, gateway, DNS server và lease time.

Các thông điệp thường gặp: Discover, Offer, Request, Acknowledge (DORA).

Filter:
```wireshark
dhcp
```
Ở một số phiên bản hoặc capture cũ, tên field/protocol có thể hiển thị dưới dạng BOOTP.

Thông tin DHCP có thể giúp ghép IP được cấp với client identifier, hostname hoặc MAC. Đây là bằng chứng hữu ích khi dựng timeline, nhưng cần lưu ý IP có thể thay đổi theo thời gian.

### NetBIOS
NetBIOS over TCP/IP có thể tiết lộ tên máy tính và thông tin dịch vụ trong mạng Windows cũ hoặc môi trường còn sử dụng nó.

Filter:
```wireshark
nbns
nbss
```
Tên máy và thông tin NetBIOS hỗ trợ nhận diện host, nhưng có thể bị giả mạo hoặc không còn phản ánh trạng thái hiện tại.

### Kerberos
Kerberos là giao thức xác thực mạng thường gặp trong môi trường Active Directory. Traffic có thể cho biết hoạt động xác thực và các trao đổi ticket, nhưng nội dung nhạy cảm thường không thể đọc đầy đủ nếu không có ngữ cảnh/khóa thích hợp.

Filter:
```wireshark
kerberos
```

Các truy vấn Kerberos bất thường, lượng lớn request hoặc pattern khác baseline có thể cần điều tra. Không kết luận tấn công chỉ dựa vào sự hiện diện của Kerberos.

## 5. DNS tunneling và ICMP tunneling

### DNS tunneling
DNS tunneling nhúng dữ liệu vào tên miền truy vấn hoặc nội dung phản hồi DNS. Nó có thể bị lợi dụng để điều khiển máy bị xâm nhập hoặc chuyển dữ liệu ra ngoài.

Dấu hiệu có thể gồm:
- Subdomain dài hoặc có entropy cao.
- Nhiều query tới một domain/subdomain hierarchy.
- Tần suất không phù hợp với hoạt động thông thường.
- TXT record hoặc phản hồi chứa chuỗi mã hóa/không giống dữ liệu DNS thường thấy.
- Host gửi query theo chu kỳ, có thể liên quan beaconing.

Filter:
```wireshark
dns
dns.qry.type == 16
dns.flags.response == 0
```

### ICMP tunneling
ICMP thường phục vụ thông báo lỗi và công cụ chẩn đoán như ping. Kẻ tấn công có thể nhúng dữ liệu trong ICMP payload để tạo kênh truyền thông.

Dấu hiệu cần xem:
- Payload lớn hoặc có cấu trúc bất thường.
- Nhiều ICMP packet đều đặn giữa cùng các endpoint.
- Payload chứa chuỗi có vẻ mã hóa hoặc dữ liệu không liên quan đến ping.
- Dung lượng hoặc tần suất vượt baseline.

Filter:
```wireshark
icmp
icmp.type == 8
icmp.type == 0
```

### Phân tích an toàn
1. Xác định host, domain/IP và timestamp.
2. So sánh tần suất, kích thước và payload.
3. Kiểm tra cả request lẫn response.
4. Giải mã nội dung chỉ trong môi trường an toàn và khi có lý do rõ ràng.
5. Tương quan với endpoint telemetry và DNS/firewall logs.

Tần suất cao hoặc chuỗi mã hóa không tự động chứng minh tunneling. Cần kết hợp bằng chứng.

## 6. Cleartext protocol: FTP

FTP truyền lệnh và dữ liệu qua các kết nối riêng; trong FTP không mã hóa, thông tin đăng nhập và lệnh có thể xuất hiện dạng rõ trong PCAP.

### Điều cần tìm
- `USER` và `PASS` trong control channel.
- Lệnh `RETR` tải file hoặc `STOR` tải file lên.
- Phản hồi server và mã trạng thái.
- Các kết nối data channel và file được truyền.

Filter:
```wireshark
ftp
ftp-data
tcp.port == 21
```

Có thể dùng **Follow TCP Stream** để xem lệnh và phản hồi theo đúng thứ tự. Tuy nhiên, không nên chia sẻ credentials phát hiện được; ghi nhận chúng theo quy trình xử lý dữ liệu nhạy cảm và báo cáo sự phơi lộ.

FTP qua TLS (FTPS) khác FTP dạng rõ. SFTP là giao thức truyền file qua SSH, không phải cùng giao thức với FTP.

## 7. Cleartext protocol: HTTP

HTTP không mã hóa có thể để lộ request, response, URI, header, cookie và payload trong capture.

### Trường cần kiểm tra
- Request method: GET, POST, PUT...
- Host và URI.
- User-Agent và Referer.
- Status code.
- Content-Type và Content-Length.
- Cookie hoặc Authorization header nếu được gửi dạng rõ.
- File tải lên/tải xuống và response body.

Filter:
```wireshark
http
http.request
http.response
http.request.method == "POST"
http.response.code >= 400
```

### Quy trình
1. Lọc HTTP.
2. Tìm host/URI và request đáng ngờ.
3. Xem response và status code.
4. Dùng Follow TCP Stream để đọc request/response.
5. Nếu PCAP chứa file truyền qua HTTP, dùng chức năng export object phù hợp để trích xuất trong môi trường phân tích.
6. Tính hash, kiểm tra metadata và phân tích file theo quy trình malware triage; không chạy trực tiếp trên máy cá nhân.

HTTP `200 OK` cho biết request được xử lý thành công theo giao thức, không chứng minh nội dung an toàn. Tên file hoặc MIME type cũng có thể bị giả mạo.

## 8. Encrypted protocol: HTTPS/TLS

HTTPS dùng HTTP bên trong TLS để bảo vệ nội dung. Khi traffic được mã hóa đúng, người phân tích thường không thể đọc URI, header và body chỉ từ PCAP.

Thông tin vẫn có thể quan sát tùy phiên bản TLS, cấu hình và capture:
- IP/port, thời gian, lượng byte và pattern kết nối.
- TLS handshake và phiên bản cipher/protocol được thương lượng.
- Certificate information.
- SNI hoặc ALPN nếu được truyền rõ; một số cơ chế hiện đại có thể che giấu thêm metadata.
- DNS lookup trước khi kết nối, nếu capture bao phủ DNS.

### Giải mã TLS
Có thể giải mã trong điều kiện phù hợp khi có key log/session secrets hợp lệ và được thu thập theo chính sách tổ chức. Với Wireshark, TLS key log file thường được cấu hình trong phần Protocols → TLS → (Pre)-Master-Secret log filename, tùy phiên bản.

Không nên giả định private key của server luôn đủ để giải mã TLS hiện đại; các bộ trao đổi khóa có forward secrecy thường yêu cầu session secrets thích hợp. Chỉ giải mã traffic được phép phân tích.

## 9. Hunt cleartext credentials

Credential có thể xuất hiện trong các giao thức không mã hóa như FTP, HTTP Basic Authentication hoặc các ứng dụng cũ.

Quy trình:
1. Xác định protocol và conversation liên quan.
2. Dùng filter phù hợp và Follow Stream.
3. Kiểm tra xem dữ liệu có thật sự là credential hay chỉ chuỗi tương tự.
4. Ghi nhận endpoint, thời gian, protocol và bằng chứng tối thiểu cần thiết.
5. Không đưa password/token nguyên văn vào báo cáo phổ thông.
6. Thông báo theo quy trình, cân nhắc đổi credential/loại bỏ giao thức không an toàn và kiểm tra khả năng sử dụng lại.

Việc phát hiện một chuỗi giống password không đủ; cần xác minh trường giao thức và ngữ cảnh, đồng thời bảo vệ bí mật phát hiện được.

## 10. Từ packet evidence đến actionable results

Một kết quả điều tra tốt cần trả lời:
- **What happened?** Sự kiện quan sát được là gì?
- **When?** Timestamp và khoảng thời gian.
- **Who/what?** Source/destination IP, hostname, user hoặc asset nếu xác định được.
- **How?** Protocol, port, pattern và packet evidence.
- **Why suspicious?** Điều gì lệch baseline hoặc khớp TTP đáng ngờ?
- **Confidence and limitations:** Điều gì đã xác nhận, điều gì chỉ là giả thuyết?
- **Recommended action:** Bước kiểm tra, containment hoặc remediation tiếp theo.

### Mẫu ghi chú điều tra
```text
Summary:
Time window:
Source host/IP:
Destination host/IP/domain:
Protocol / port:
Observed behaviour:
Evidence (filter, packet numbers, timestamps):
Related logs / corroboration:
Assessment and confidence:
Limitations:
Recommended next steps:
```

## 11. Quy trình tổng hợp cho analyst
1. Đọc alert và xác định câu hỏi điều tra.
2. Xác nhận capture có đủ phạm vi thời gian và endpoint.
3. Dùng Statistics để tìm host/protocol nổi bật.
4. Lọc theo hành vi: scan, ARP, DNS, ICMP, FTP, HTTP hoặc TLS.
5. Kiểm tra packet lân cận và Follow Stream.
6. Tương quan với DHCP, DNS, firewall, proxy và endpoint logs.
7. Phân biệt bằng chứng trực tiếp với suy luận.
8. Ghi kết luận, độ tin cậy, giới hạn và hành động đề xuất.

## 12. Kỹ năng đạt được
- Nhận diện các pattern của scanning và một số hành vi mạng đáng ngờ.
- Kiểm tra ARP, DHCP, NetBIOS và Kerberos trong PCAP.
- Phân tích dấu hiệu DNS/ICMP tunneling.
- Hiểu rủi ro của FTP/HTTP cleartext và giới hạn khi phân tích HTTPS.
- Trích xuất bằng chứng có thể kiểm chứng và chuyển thành báo cáo hữu ích cho SOC.

## Tài liệu tham khảo
- [TryHackMe – Wireshark: Traffic Analysis](https://tryhackme.com/room/wiresharktrafficanalysis)
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/)
- [Wireshark TLS documentation](https://wiki.wireshark.org/TLS)
