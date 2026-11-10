# Data Exfiltration Detection

**Nguồn học:** [TryHackMe – Data Exfiltration Detection](https://tryhackme.com/room/dataexfildetection)  
**Chủ đề:** Phát hiện hành vi đưa dữ liệu trái phép ra khỏi hệ thống qua DNS, FTP, HTTP và ICMP.

> **Phạm vi ghi chú:** Room công khai các mục tiêu học tập và các kênh phân tích chính; một số phần lab yêu cầu đăng nhập/Premium. Tài liệu dưới đây hệ thống hóa kiến thức tương ứng với các nội dung đó và bổ sung nguồn tham khảo kỹ thuật. Không chứa answer, flag hoặc dữ liệu độc quyền từ lab.

## 1. Data Exfiltration là gì?

**Data exfiltration** là hành vi chuyển dữ liệu nhạy cảm hoặc dữ liệu nội bộ ra khỏi hệ thống/mạng mà không được phép. Đây thường là mục tiêu sau khi attacker đã có quyền truy cập vào môi trường.

Dữ liệu bị đánh cắp có thể bao gồm:

- Credentials, token, cookie và thông tin xác thực.
- Tài liệu nội bộ, hợp đồng, dữ liệu khách hàng.
- Source code, cấu hình hệ thống và thông tin hạ tầng.
- Database export, backup hoặc file được nén từ nhiều thư mục.
- Dữ liệu tài chính, sở hữu trí tuệ hoặc thông tin vận hành.

SOC analyst cần phát hiện không chỉ một kết nối outbound lớn mà cả chuỗi hoạt động trước đó: truy cập file, thu thập dữ liệu, staging, nén/encode và truyền dữ liệu ra ngoài.

## 2. Chuỗi hành vi thường gặp

Một hoạt động exfiltration có thể diễn ra qua các bước sau:

1. **Discovery:** attacker tìm file, database, share hoặc dữ liệu có giá trị.
2. **Collection:** đọc hoặc sao chép dữ liệu từ nhiều vị trí.
3. **Staging:** gom dữ liệu vào một thư mục tạm hoặc khu vực dễ truyền đi.
4. **Archive / Encode:** nén, mã hóa hoặc encode dữ liệu để giảm kích thước hay che giấu nội dung.
5. **Exfiltration:** truyền dữ liệu qua một kênh mạng hoặc kênh vật lý.
6. **Cleanup:** xóa file tạm, log hoặc dấu vết nếu attacker có khả năng thực hiện.

Không phải incident nào cũng có đầy đủ tất cả giai đoạn. Một số malware có thể truyền dữ liệu ngay sau khi thu thập; một số attacker sử dụng kênh C2 đã tồn tại.

## 3. Các kênh exfiltration trong room

### 3.1. DNS tunneling

DNS bình thường được dùng để phân giải domain thành địa chỉ IP. Trong **DNS tunneling**, dữ liệu có thể được encode vào các DNS query/response, thường nằm trong subdomain hoặc các trường DNS khác, rồi đi qua hạ tầng phân giải tên miền.

Ví dụ về logic bất thường:

- Một endpoint tạo ra nhiều DNS query tới cùng một domain nhưng mỗi query có subdomain dài và khác nhau.
- Subdomain chứa chuỗi trông giống dữ liệu đã encode, có entropy cao hoặc ký tự ngẫu nhiên bất thường.
- Tần suất query DNS tăng mạnh so với baseline của endpoint.
- Một máy trạm tạo DNS traffic với tần suất/khối lượng không phù hợp với vai trò của nó.
- Process ít khi cần truy vấn DNS (ví dụ script hoặc công cụ dòng lệnh) lại tạo nhiều query ra Internet.

**Indicators cần xem xét:**

| Indicator | Vì sao đáng chú ý |
|---|---|
| Subdomain rất dài | Có thể mang payload đã encode. |
| Nhiều subdomain duy nhất cho một domain | Có thể là các chunk dữ liệu được gửi liên tiếp. |
| Entropy cao | Chuỗi có tính ngẫu nhiên cao, đôi khi phù hợp với dữ liệu encode. |
| Query rate tăng bất thường | Tunneling có thể cần nhiều query để truyền dữ liệu. |
| DNS TXT record hoặc record type ít phổ biến | Có thể bị lạm dụng làm nơi truyền dữ liệu, nhưng vẫn có use case hợp lệ. |
| DNS được tạo bởi process lạ | Cần xác minh binary, parent process, user và command line. |

**Lưu ý:** Domain có nhiều subdomain hoặc DNS traffic lớn không tự động là tunneling. CDN, dịch vụ cloud, tracking và ứng dụng hợp pháp cũng có thể tạo traffic phức tạp. Cần baseline và đối chiếu endpoint telemetry.

### 3.2. FTP exfiltration

FTP là giao thức truyền file. Attacker có thể sử dụng FTP để upload dữ liệu tới máy chủ bên ngoài.

Các dấu hiệu cần quan sát:

- Máy nội bộ kết nối đến FTP server hiếm gặp hoặc không nằm trong danh sách được phê duyệt.
- Có authentication thành công trên FTP ngay trước hoạt động upload.
- Lệnh truyền file như `STOR` xuất hiện từ host/user không có nhu cầu sử dụng FTP.
- Số lượng file, tổng dung lượng upload hoặc thời lượng session tăng bất thường.
- Process như script, command shell hoặc binary lạ khởi tạo kết nối FTP.
- Hoạt động FTP diễn ra ngoài giờ hoặc từ server vốn không có nhiệm vụ truyền file.

Cần phân biệt file transfer hợp lệ như backup, đồng bộ hoặc job tích hợp dữ liệu với hành vi upload trái phép. FTPS/SFTP là các giao thức khác về bảo mật; không nên gọi mọi traffic mã hóa qua port 22 là FTP.

### 3.3. HTTP / HTTPS exfiltration

HTTP là giao thức ứng dụng phổ biến và thường được phép đi qua proxy/firewall, vì vậy có thể bị lợi dụng để chuyển dữ liệu ra ngoài.

Các request đáng chú ý:

- HTTP `POST` hoặc `PUT` có body/upload lớn.
- Request tới domain hoặc endpoint hiếm gặp.
- Upload do process không phải browser hoặc ứng dụng doanh nghiệp quen thuộc tạo ra.
- User-Agent bất thường hoặc thiếu thông tin trong bối cảnh không phù hợp.
- Nhiều request upload nhỏ lặp lại trong thời gian dài.
- File được nén hoặc thu thập ngay trước khi xuất hiện outbound HTTP transfer.

HTTPS mã hóa nội dung nên network sensor có thể chỉ nhìn thấy metadata như IP, domain (tùy cơ chế), port, thời gian và byte count. Muốn xác định nội dung upload cần endpoint logs, proxy telemetry hoặc cơ chế TLS inspection được tổ chức cho phép.

### 3.4. ICMP exfiltration

ICMP thường được sử dụng cho các chức năng chẩn đoán mạng, ví dụ ping. Tuy nhiên, attacker có thể lợi dụng payload trong ICMP packet để vận chuyển dữ liệu hoặc điều khiển thiết bị.

Dấu hiệu bất thường:

- ICMP echo request/reply có payload dài hơn đáng kể so với baseline.
- Tần suất ICMP cao, liên tục hoặc theo chu kỳ không bình thường.
- Một endpoint gửi lượng ICMP outbound đáng kể tới một destination bên ngoài.
- Payload chứa chuỗi có cấu trúc giống dữ liệu encode thay vì nội dung test thông thường.
- ICMP được tạo bởi process hoặc host không có lý do vận hành rõ ràng.

Không phải ICMP packet lớn nào cũng độc hại. Một số công cụ giám sát, kiểm tra MTU hoặc troubleshooting có thể tạo payload khác thường. Cần xem nội dung packet, nguồn phát sinh và lịch sử hoạt động.

## 4. So sánh các kênh phát hiện

| Kênh | Dữ liệu/field cần quan sát | Dấu hiệu nghi vấn |
|---|---|---|
| DNS | Query name, record type, subdomain length, query rate, response, client IP | Query dài, nhiều subdomain duy nhất, entropy cao, volume đột biến. |
| FTP | Source/destination, user, login result, command, file name, bytes, duration | Upload `STOR`, destination lạ, nhiều file hoặc lượng upload lớn. |
| HTTP/S | URL, method, host, user agent, status, request size, bytes out, process | POST/PUT lớn, endpoint lạ, upload lặp lại hoặc process không quen thuộc. |
| ICMP | Source/destination, type/code, packet length, payload, frequency | Payload dài, tần suất bất thường, flow outbound không phù hợp. |

## 5. Endpoint telemetry cần correlate

Network traffic cho biết dữ liệu đã đi đâu; endpoint logs giúp xác định process và hành động khởi tạo luồng traffic.

Các nguồn có thể dùng:

- **Process creation:** process nào chạy, parent process, user, command line và thời điểm.
- **File access / file creation:** file nào được đọc, sao chép, tạo archive hoặc staging.
- **Network connection:** process nào tạo kết nối tới destination nào.
- **DNS client logs:** process/host nào truy vấn domain bất thường.
- **EDR telemetry:** hành vi nén file, truy cập nhiều tài liệu, thực thi script hoặc persistence.

Ví dụ với Sysmon trên Windows, các Event ID thường hữu ích gồm:

| Sysmon Event ID | Nội dung |
|---|---|
| `1` | Process creation. |
| `3` | Network connection. |
| `11` | File create. |
| `22` | DNS query. |

Việc có event không chứng minh dữ liệu đã bị đánh cắp. Cần nối chuỗi thời gian: process/file activity → network connection → bytes outbound → destination và kết quả thực tế.

## 6. Phân tích bằng Wireshark / tshark

Wireshark giúp kiểm tra packet và protocol. Một số display filter hữu ích:

```text
dns
```
Hiển thị DNS traffic.

```text
dns.flags.response == 1
```
Lọc DNS response.

```text
ftp || ftp-data
```
Lọc FTP control/data traffic nếu protocol được decode.

```text
http.request.method == "POST" || http.request.method == "PUT"
```
Lọc HTTP POST/PUT request.

```text
icmp
```
Lọc ICMP packet để kiểm tra type/code, payload length và tần suất.

Dùng `tshark` đọc capture từ command line:

```bash
tshark -r capture.pcap -Y 'dns'
tshark -r capture.pcap -Y 'icmp'
tshark -r capture.pcap -Y 'http.request.method == "POST"'
```

Filter chỉ giúp thu hẹp dữ liệu. Sau đó cần xem packet details, source/destination, frame length, payload, thời điểm và các packet liên quan trong cùng flow.

## 7. Phân tích bằng SIEM

Mục tiêu là xác định **ai gửi dữ liệu, gửi đến đâu, bằng protocol nào, bao nhiêu dữ liệu, vào thời điểm nào và process nào chịu trách nhiệm**.

### 7.1. Tìm outbound volume cao

Ví dụ truy vấn Splunk dạng khung (điều chỉnh index và field theo môi trường):

```spl
index=network direction="outbound"
| stats sum(bytes_out) as outbound_bytes count by src_ip dest_ip dest_port
| sort - outbound_bytes
```

### 7.2. Tìm DNS client có tần suất query cao

```spl
index=dns
| stats count as query_count dc(query) as unique_domains values(query) as sample_domains by src_ip
| sort - query_count
```

Truy vấn thực tế nên nhóm theo client và domain phù hợp. Không nên chỉ sort theo số lượng mà không xem query length, subdomain diversity, thời gian và reputation.

### 7.3. Tìm HTTP upload bất thường

```spl
index=proxy (http_method="POST" OR http_method="PUT")
| stats sum(bytes_out) as uploaded_bytes count by src_ip dest_domain http_method
| sort - uploaded_bytes
```

Cần kiểm tra process/host, domain, user, business purpose và TLS visibility. Trường `bytes_out` có thể được tính theo request, connection hoặc flow tùy nguồn log.

## 8. Quy trình điều tra data exfiltration

1. **Xác định host nghi vấn:** IP, hostname, user, asset role và mức độ quan trọng.
2. **Xác định luồng dữ liệu:** outbound/inbound, destination, protocol, port, time range và byte count.
3. **So sánh baseline:** host này bình thường gửi dữ liệu đến đâu, qua protocol nào, vào khung giờ nào và với lượng bao nhiêu.
4. **Phân tích kênh:** DNS, FTP, HTTP/S hay ICMP; kiểm tra metadata và packet nếu có capture.
5. **Pivot sang endpoint:** process, parent process, user, file access, archive creation và command line.
6. **Tìm hoạt động staging:** file nén, thư mục tạm, file export hoặc dữ liệu được gom trước khi truyền.
7. **Correlate với threat intelligence:** domain/IP/hash và lịch sử hoạt động liên quan; reputation chỉ là một tín hiệu bổ sung.
8. **Đánh giá impact:** loại dữ liệu, số lượng, khả năng đã truyền thành công và host/tài khoản bị ảnh hưởng.
9. **Escalate và bảo toàn bằng chứng:** lưu PCAP, query, endpoint timeline, log và các chỉ số byte/time.

## 9. False positive và những giới hạn cần nhớ

Các hoạt động hợp pháp có thể tạo pattern giống exfiltration:

- Cloud backup hoặc đồng bộ file.
- Upload tài liệu lên SaaS được doanh nghiệp cho phép.
- DNS traffic của ứng dụng lớn, CDN hoặc endpoint monitoring.
- FTP/SFTP của hệ thống tích hợp cũ.
- ICMP troubleshooting hoặc giám sát mạng.

Các giới hạn kỹ thuật:

- HTTPS mã hóa payload và có thể làm giảm khả năng quan sát nội dung.
- NAT có thể làm nhiều endpoint dùng chung một public IP.
- Proxy có thể thay đổi source hoặc destination nhìn thấy trong log.
- Flow log không nhất thiết cung cấp nội dung packet.
- Một lượng nhỏ dữ liệu bị đánh cắp có thể không tạo spike rõ rệt.

## 10. Biện pháp giảm thiểu

- Áp dụng egress filtering: chỉ cho phép protocol/destination cần thiết.
- Giới hạn DNS outbound qua resolver được quản lý; giám sát DNS tunneling.
- Dùng DLP để phát hiện dữ liệu nhạy cảm bị upload trái phép.
- Network segmentation để giảm đường truy cập tới dữ liệu quan trọng.
- Quản lý quyền truy cập file/database theo nguyên tắc least privilege.
- Theo dõi process và hành vi file staging trên endpoint.
- Duy trì baseline network traffic cho từng nhóm thiết bị.
- Thiết lập quy trình phê duyệt và giám sát transfer tới cloud/SaaS.

## 11. Kiến thức và kỹ năng có thể thể hiện trong portfolio

- Giải thích được data exfiltration và chuỗi collection → staging → transfer.
- Nhận diện các kênh DNS, FTP, HTTP/S và ICMP có thể bị lạm dụng.
- Phân tích DNS query length, frequency, subdomain pattern và HTTP upload behavior.
- Đọc metadata và payload trong Wireshark/tshark.
- Kết hợp firewall/proxy/DNS/flow logs với endpoint telemetry.
- Đánh giá baseline, false positive và khả năng exfiltration thành công.
- Đề xuất egress filtering, DLP, segmentation và endpoint monitoring.

## 12. Tài liệu tham khảo

- [TryHackMe – Data Exfiltration Detection](https://tryhackme.com/room/dataexfildetection)
- [MITRE ATT&CK – Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/)
- [MITRE ATT&CK – Exfiltration Over Unencrypted Non-C2 Protocol (T1048.003)](https://attack.mitre.org/techniques/T1048/003/)
- [MITRE ATT&CK – Detection Strategy DET0131](https://attack.mitre.org/detectionstrategies/DET0131/)
- [MITRE ATT&CK – Detection of DNS Tunneling and Application Layer Abuse](https://attack.mitre.org/detectionstrategies/DET0400/)
- [Cisco – Network Integrity Monitoring](https://sec.cloudapps.cisco.com/security/center/resources/network_integrity_monitoring.html)
