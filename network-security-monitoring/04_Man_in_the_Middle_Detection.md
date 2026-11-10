# Man-in-the-Middle Detection

**Nguồn học:** [TryHackMe – Man-in-the-Middle Detection](https://tryhackme.com/room/mitmdetection)  
**Chủ đề:** Phát hiện MITM thông qua ARP spoofing, DNS spoofing và SSL stripping.

> **Phạm vi ghi chú:** Nội dung room công khai xác định ba trọng tâm phân tích là ARP spoofing, DNS spoofing và SSL stripping; phần lab yêu cầu đăng nhập/Premium. Tài liệu này trình bày nguyên lý, dấu hiệu phát hiện và quy trình phòng thủ, không chứa kết quả hoặc đáp án riêng của lab.

## 1. Man-in-the-Middle (MITM) là gì?

**Man-in-the-Middle (MITM)** là kiểu tấn công trong đó attacker tìm cách đứng giữa hai endpoint đang giao tiếp để nghe lén, chặn, chuyển hướng hoặc sửa đổi dữ liệu.

Trong giao tiếp bình thường:

`Client  <-------------------->  Server`

Trong một tình huống MITM:

`Client  <------>  Attacker  <------>  Server`

Nếu attacker thành công, dữ liệu có thể đi qua thiết bị của attacker trước khi đến đích. Tác động phụ thuộc vào cơ chế mã hóa và xác thực của kết nối:

- Nếu traffic không được mã hóa, attacker có thể đọc hoặc thay đổi nội dung.
- Nếu TLS được cấu hình và xác thực đúng, attacker thường không thể đọc nội dung chỉ bằng cách chuyển tiếp packet.
- Nếu attacker có thể downgrade kết nối, đánh lừa người dùng bỏ qua certificate warning hoặc chiếm được endpoint/certificate đáng tin cậy, mức độ rủi ro tăng lên.

## 2. Những kỹ thuật trong phạm vi room

| Kỹ thuật | Cơ chế | Mục tiêu của attacker |
|---|---|---|
| ARP spoofing / ARP poisoning | Gửi thông tin ARP giả trong LAN để làm sai mapping IP–MAC | Chuyển traffic của nạn nhân qua thiết bị attacker. |
| DNS spoofing | Trả về DNS response giả hoặc làm sai cache DNS | Chuyển người dùng tới IP/server do attacker kiểm soát. |
| SSL stripping | Can thiệp quá trình chuyển từ HTTP sang HTTPS để hạ cấp kết nối | Khiến nạn nhân giao tiếp qua HTTP không mã hóa trong một số tình huống. |

## 3. Detecting ARP Spoofing

### 3.1. ARP hoạt động như thế nào?

**Address Resolution Protocol (ARP)** giúp thiết bị trong mạng IPv4 LAN tìm MAC address tương ứng với một địa chỉ IP.

Ví dụ: máy tính cần gửi traffic tới default gateway. Nó tra ARP cache; nếu chưa có mapping, nó broadcast ARP request hỏi thiết bị nào sở hữu IP của gateway. Thiết bị sở hữu IP đó phản hồi bằng MAC address của mình.

ARP không cung cấp cơ chế xác thực mạnh cho mapping IP–MAC. Vì vậy, thiết bị trong cùng LAN có thể bị đánh lừa bởi ARP reply giả.

### 3.2. ARP poisoning diễn ra ra sao?

Attacker gửi các ARP reply hoặc gratuitous ARP không hợp lệ, khiến victim lưu mapping sai, ví dụ IP của gateway bị gắn với MAC của attacker. Khi victim gửi traffic tới gateway, frame có thể được chuyển tới attacker trước.

Nếu attacker tiếp tục forward traffic tới gateway, kết nối có thể vẫn hoạt động và người dùng khó nhận ra. Nếu attacker không forward, có thể xuất hiện mất kết nối hoặc gián đoạn dịch vụ.

### 3.3. Indicators of Compromise (IoC)

- Một IP quan trọng (đặc biệt là default gateway) đột ngột được gắn với MAC address mới.
- Cùng một IP được nhiều MAC address khác nhau tuyên bố sở hữu trong thời gian gần nhau.
- Một MAC address bất thường tuyên bố sở hữu nhiều IP không liên quan.
- Nhiều ARP reply xuất hiện mà không có request tương ứng.
- Gratuitous ARP tăng đột biến hoặc xuất hiện từ thiết bị không quen thuộc.
- ARP cache trên endpoint thay đổi không khớp với inventory/network documentation.
- Traffic của victim hướng tới MAC không phải MAC hợp lệ của gateway.

Một số dấu hiệu có thể xuất hiện trong quá trình failover, thay card mạng, DHCP renewal hoặc thay đổi thiết bị mạng hợp lệ. Cần xác minh lịch sử thay đổi trước khi kết luận spoofing.

### 3.4. Kiểm tra ARP trên endpoint

Windows:

```cmd
arp -a
```

Linux:

```bash
ip neigh show
```

So sánh mapping IP–MAC hiện tại với thông tin gateway, DHCP snooping, switch, asset inventory hoặc dữ liệu đã xác minh trước đó.

### 3.5. Wireshark filters

```text
arp
```
Hiển thị ARP traffic.

```text
arp.opcode == 2
```
Lọc ARP reply.

```text
arp.duplicate-address-detected
```
Tìm các packet mà Wireshark nhận diện có dấu hiệu trùng địa chỉ ARP.

Sau khi lọc, kiểm tra các trường `arp.src.proto_ipv4`, `arp.src.hw_mac`, `eth.src`, sender IP/MAC và thời điểm. Câu hỏi quan trọng là: **IP của gateway có đang được nhiều MAC khác nhau tuyên bố sở hữu không?**

### 3.6. Biện pháp phòng chống

- **Dynamic ARP Inspection (DAI):** switch kiểm tra ARP packet dựa trên binding hợp lệ, thường phối hợp với DHCP snooping.
- **DHCP snooping:** tạo bảng binding IP–MAC–port để hỗ trợ kiểm tra nguồn hợp lệ.
- **Port security:** giới hạn hoặc giám sát MAC address trên switch port.
- Dùng static ARP cho một số hệ thống quan trọng khi phù hợp; không phải giải pháp dễ mở rộng cho mạng lớn.
- Phân đoạn mạng/VLAN để giới hạn phạm vi tác động.
- Dùng HTTPS, SSH và VPN để bảo vệ nội dung truyền; mã hóa không ngăn attacker redirect traffic nhưng giảm khả năng đọc/sửa nội dung nếu xác thực đúng.

## 4. Unmasking DNS Spoofing

### 4.1. DNS resolution cơ bản

DNS chuyển tên miền (ví dụ `example.com`) thành record như địa chỉ IPv4/IPv6 hoặc thông tin dịch vụ. Client thường gửi truy vấn tới recursive resolver; resolver có thể truy vấn các authoritative DNS server rồi trả lời client.

### 4.2. DNS spoofing và cache poisoning

**DNS spoofing** là hành vi giả mạo DNS response hoặc làm client/resolver nhận dữ liệu DNS không chính xác. **DNS cache poisoning** là trường hợp dữ liệu giả được lưu vào cache, khiến truy vấn sau đó tiếp tục nhận kết quả sai.

Ví dụ rủi ro: người dùng truy cập domain hợp pháp nhưng DNS trả về IP của máy chủ giả mạo. Người dùng có thể bị chuyển tới phishing page hoặc proxy độc hại.

### 4.3. Indicators cần kiểm tra

- Domain quen thuộc trả về IP không khớp với nguồn DNS đáng tin cậy hoặc dữ liệu authoritative.
- Các endpoint trong cùng môi trường nhận câu trả lời DNS khác nhau mà không có lý do split-horizon hợp lệ.
- Một DNS response đáng ngờ xuất hiện từ resolver không được phê duyệt.
- Nhiều DNS response không tương ứng với request hợp lệ hoặc có dấu hiệu transaction mismatch.
- DNS cache trên endpoint/resolver chứa mapping không mong đợi.
- DNSSEC validation failure có thể là tín hiệu cần điều tra, nhưng cũng có thể do cấu hình zone sai.

### 4.4. Kiểm tra DNS

Dùng `nslookup` hoặc `dig` để so sánh kết quả từ resolver được tổ chức tin cậy:

```bash
nslookup example.com
```

```bash
dig example.com
```

Truy vấn một resolver được chỉ định (thay địa chỉ bằng resolver hợp lệ trong môi trường):

```bash
dig @<DNS_RESOLVER_IP> example.com
```

Để phân tích sâu hơn, so sánh câu trả lời với authoritative DNS và kiểm tra DNSSEC validation khi domain hỗ trợ. Không nên chỉ dựa vào một resolver công cộng để đưa ra kết luận cuối cùng vì CDN, geo-DNS và split-horizon DNS có thể trả về các IP khác nhau một cách hợp lệ.

### 4.5. Wireshark filters

```text
dns
```
Hiển thị DNS packet.

```text
dns.flags.response == 1
```
Chỉ hiển thị DNS response.

```text
dns.qry.name == "example.com"
```
Lọc theo domain cần kiểm tra (thay bằng domain thực tế).

Kiểm tra query name, transaction ID, source/destination IP, response code, answer record, TTL và thứ tự response. Đối chiếu câu trả lời với resolver/authoritative data đáng tin cậy.

### 4.6. DNSSEC

**DNS Security Extensions (DNSSEC)** bổ sung cơ chế chữ ký số để resolver có thể xác minh tính xác thực và toàn vẹn của DNS data đối với zone đã được ký.

DNSSEC không mã hóa nội dung DNS query và không che giấu domain người dùng truy cập. Mục tiêu chính của nó là xác thực dữ liệu DNS, giúp phát hiện response giả mạo hoặc dữ liệu không xác minh được.

## 5. Spotting SSL Stripping in Action

### 5.1. TLS và HTTPS

TLS bảo vệ dữ liệu giữa client và server bằng mã hóa, integrity protection và cơ chế xác thực certificate. HTTPS là HTTP được truyền qua TLS.

Một website có thể nhận request HTTP ban đầu rồi phản hồi redirect sang HTTPS. Nếu attacker kiểm soát đường truyền ban đầu, họ có thể cố gắng chặn hoặc sửa redirect để client tiếp tục dùng HTTP.

### 5.2. SSL stripping là gì?

**SSL stripping** (một dạng downgrade attack) là kỹ thuật MITM tìm cách ngăn việc nâng cấp từ HTTP lên HTTPS. SSL là tên giao thức tiền nhiệm; trong hệ thống hiện đại, kết nối web an toàn sử dụng TLS.

Trong tình huống dễ bị ảnh hưởng:

1. Người dùng truy cập website bằng `http://`.
2. Server bình thường sẽ redirect sang `https://`.
3. Attacker đứng giữa và can thiệp response/redirect.
4. Kết nối giữa victim và attacker có thể vẫn là HTTP, trong khi attacker tạo kết nối HTTPS riêng tới server.
5. Dữ liệu giữa victim và attacker có nguy cơ bị đọc hoặc sửa đổi.

### 5.3. Dấu hiệu cần quan sát

- Người dùng truy cập website lẽ ra dùng HTTPS nhưng session vẫn tiếp tục qua HTTP.
- Redirect từ HTTP sang HTTPS bị thiếu hoặc bị thay đổi bất thường.
- Cookie hoặc thông tin nhạy cảm được truyền trên HTTP.
- Certificate warning hoặc certificate chain bất thường xuất hiện trong cùng thời điểm.
- Endpoint đang dùng mạng Wi-Fi công cộng hoặc mạng LAN không đáng tin cậy và đồng thời có ARP/DNS anomalies.

Không phải mọi HTTP request đều là SSL stripping. Một số website có endpoint HTTP riêng, nội dung public hoặc cấu hình redirect chưa tốt. Cần xác định domain có yêu cầu HTTPS và đối chiếu request/response theo thời gian.

### 5.4. HSTS và phòng chống downgrade

**HTTP Strict Transport Security (HSTS)** là HTTP response header yêu cầu browser chỉ truy cập domain qua HTTPS trong khoảng thời gian được chỉ định.

Ví dụ header:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Ý nghĩa:

- `max-age`: thời gian browser ghi nhớ chính sách HTTPS.
- `includeSubDomains`: áp dụng chính sách cho subdomain.
- HSTS giúp browser tự nâng cấp request HTTP lên HTTPS và ngăn người dùng bỏ qua một số certificate warning.

HSTS giảm rủi ro SSL stripping. Tuy nhiên, bảo vệ lần truy cập đầu tiên phụ thuộc vào HSTS preload hoặc cách domain được bootstrap; cấu hình HSTS cần đi kèm HTTPS hoạt động đúng.

Các biện pháp khác:

- Không bỏ qua certificate warning.
- Chỉ sử dụng website HTTPS và ứng dụng có certificate validation đúng.
- Tránh sử dụng mạng không tin cậy khi truy cập dịch vụ nhạy cảm; dùng VPN đáng tin cậy khi phù hợp.
- Bật HSTS trên web server và cân nhắc preload theo chính sách tổ chức.
- Theo dõi redirect, TLS handshake, certificate issuer và các thay đổi bất thường.

## 6. Quy trình phân tích MITM từ góc nhìn SOC

1. **Xác định endpoint và thời gian:** host, user, VLAN, gateway và session bị nghi ngờ.
2. **Kiểm tra Layer 2:** xem ARP cache, gateway MAC và các ARP reply bất thường.
3. **Kiểm tra DNS:** domain được truy vấn, response IP, resolver, TTL và tính nhất quán của kết quả.
4. **Kiểm tra Layer 7/TLS:** xem HTTP/HTTPS, redirect, certificate và HSTS behavior.
5. **Tương quan sự kiện:** ARP anomaly → DNS response lạ → kết nối tới IP không mong đợi → truy cập HTTP không mã hóa.
6. **Đối chiếu hạ tầng:** switch port, DHCP lease, gateway inventory, DNS resolver và change records.
7. **Đánh giá dữ liệu có thể bị lộ:** credential, cookie, session token hoặc nội dung truyền không mã hóa.
8. **Bảo toàn bằng chứng:** PCAP, ARP table, DNS logs, endpoint logs, certificate details và timeline.

## 7. Ứng phó và khắc phục

- Cô lập endpoint hoặc segment bị ảnh hưởng theo quy trình incident response.
- Xác minh và khôi phục mapping IP–MAC của gateway từ nguồn tin cậy.
- Kiểm tra switch port và thiết bị lạ; áp dụng DAI/DHCP snooping nếu hạ tầng hỗ trợ.
- Kiểm tra và làm sạch DNS cache sau khi đã xác định resolver/record hợp lệ.
- Chặn domain/IP độc hại khi có bằng chứng và đánh giá phạm vi ảnh hưởng.
- Nếu credential/session có thể đã đi qua HTTP, ưu tiên reset password, revoke session/token và kiểm tra MFA.
- Sửa cấu hình HTTPS/HSTS và kiểm tra certificate chain.
- Không xóa cache hoặc thay đổi hệ thống trước khi lưu lại bằng chứng cần thiết.

## 8. Kiến thức và kỹ năng có thể thể hiện trong portfolio

- Giải thích được MITM và cách attacker can thiệp vào đường truyền.
- Phân tích ARP spoofing qua IP–MAC mapping, gratuitous ARP và Wireshark.
- Xác minh DNS spoofing bằng cách đối chiếu DNS response, resolver và DNSSEC.
- Nhận diện SSL stripping/downgrade và hiểu vai trò của HTTPS, TLS, HSTS.
- Correlate bằng chứng ở Layer 2, DNS và HTTP/TLS thay vì chỉ dựa trên một indicator.
- Đưa ra biện pháp containment và khắc phục phù hợp.

## 9. Tài liệu tham khảo

- [TryHackMe – Man-in-the-Middle Detection](https://tryhackme.com/room/mitmdetection)
- [FIRST – DNS Abuse Detection: Cache Poisoning](https://www.first.org/global/sigs/dns/stakeholder-advice/cache-poisoning)
- [Microsoft Learn – Validate and secure DNS responses using DNSSEC](https://learn.microsoft.com/windows-server/networking/dns/validate-dnssec-responses)
- [ICANN – DNSSEC: What Is It and Why Is It Important?](https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en/)
- [MDN – Transport Layer Security (TLS)](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Transport_Layer_Security)
- [OWASP – HTTP Strict Transport Security](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/07-HTTP_Strict_Transport_Security/)
- [Bitdefender – ARP Spoofing](https://www.bitdefender.com/en-us/business/infozone/what-is-arp-spoofing)
