# IP and Domain Threat Intel

**Nguồn học chính:** [TryHackMe – IP and Domain Threat Intel](https://tryhackme.com/room/ipanddomainthreatintel)  
**Module:** [Threat Analysis Tools](https://tryhackme.com/module/threat-analysis-tools)  
**Chủ đề:** Enrichment domain và IP, DNS/WHOIS/TLS, ASN/geolocation, dịch vụ public-facing và nhận diện VPN/proxy/Tor.

> **Phạm vi ghi chú:** Trang room công khai xác nhận các phần học gồm Domain Enrichment, IP Enrichment, Service Exposure và VPN Detection. Một số nội dung chi tiết thuộc lab có yêu cầu đăng nhập/Premium; ghi chú dưới đây kết hợp mục tiêu học tập chính thức với tài liệu kỹ thuật tham khảo. Không ghi lại đáp án hoặc giá trị IOC của challenge.

---

## Task 1: Introduction

### 1. Vai trò của IP và Domain Threat Intelligence

IP và domain là các artefact thường xuất hiện trong firewall logs, DNS logs, proxy logs, EDR alerts và email investigation.

Một địa chỉ IP hoặc domain riêng lẻ chưa đủ để kết luận độc hại. Analyst cần enrichment để hiểu:

- Domain được đăng ký khi nào, dùng nameserver nào và có lịch sử DNS ra sao?
- Domain phân giải đến IP nào? Có sử dụng hosting, CDN hoặc shared infrastructure không?
- IP thuộc ASN/nhà cung cấp nào và được định tuyến từ khu vực nào?
- IP đang phơi bày dịch vụ hoặc port nào trên Internet?
- IP có thuộc VPN, proxy, Tor exit node, residential proxy hay hosting provider không?
- Những nguồn threat intelligence khác có ghi nhận indicator này không?

### 2. Quy trình cơ bản

`Verify → Enrich → Decide`

1. **Verify:** Chuẩn hóa IP/domain và xác nhận indicator được trích xuất chính xác.
2. **Enrich:** Thu thập thông tin WHOIS, DNS, TLS, ASN, geolocation, reputation, service exposure và proxy classification.
3. **Correlate:** Đối chiếu kết quả từ nhiều nguồn và với telemetry nội bộ.
4. **Decide:** Đưa ra nhận định có mức confidence và hành động phù hợp.

### 3. Công cụ được đề cập trong room

| Công cụ | Mục đích chính |
|---|---|
| **WHOIS** | Tra cứu thông tin đăng ký domain hoặc phân bổ tài nguyên IP (tùy registry/service). |
| **VirusTotal** | Enrichment reputation và quan hệ của IP/domain với file, URL hoặc indicator khác. |
| **Shodan** | Tìm kiếm thiết bị/dịch vụ public-facing và banner được quan sát trên Internet. |
| **Censys** | Tìm kiếm host, service, certificate và các tài sản Internet-facing. |
| **IP2Proxy** | Phân loại IP có liên quan đến VPN, proxy, Tor, hosting/datacenter và các nhóm hạ tầng khác. |
| **Spur** | Enrichment IP context, tập trung vào VPN, residential proxy, ISP proxy, hosting và các network classification. |

---

## Task 2: Domain Enrichment

### 1. WHOIS và thông tin đăng ký domain

WHOIS là giao thức tra cứu thông tin đăng ký. Kết quả tùy thuộc registrar, registry và chính sách riêng tư; nhiều thông tin chủ thể đăng ký có thể bị ẩn hoặc thay bằng privacy service.

Những trường nên xem:

| Trường | Ý nghĩa | Giá trị khi phân tích |
|---|---|---|
| Registrar | Đơn vị cung cấp dịch vụ đăng ký domain. | Tạo bối cảnh về nơi domain được quản lý. |
| Creation Date | Ngày domain được tạo/đăng ký. | Domain mới đăng ký có thể cần được chú ý hơn khi xuất hiện trong chiến dịch đáng ngờ. |
| Updated Date | Lần cập nhật thông tin gần nhất. | Có thể hỗ trợ xây dựng timeline, nhưng không đồng nghĩa domain vừa bị chiếm quyền. |
| Expiration Date | Ngày hết hạn đăng ký. | Hữu ích khi đánh giá trạng thái domain. |
| Name Servers | Máy chủ DNS có thẩm quyền cho domain. | Có thể tìm ra hạ tầng hoặc nhà cung cấp DNS liên quan. |
| Domain Status | Trạng thái đăng ký/bảo vệ domain. | Bổ sung bối cảnh về trạng thái quản lý. |

**Lưu ý:** WHOIS không chứng minh chủ domain là attacker. Ngày đăng ký mới chỉ là một yếu tố rủi ro; cần kết hợp DNS, TLS, reputation và hoạt động quan sát được.

### 2. DNS Records

DNS ánh xạ tên miền sang thông tin mạng. Các record thường gặp:

| Record | Chức năng | Góc nhìn phân tích |
|---|---|---|
| **A** | Ánh xạ hostname đến IPv4. | Xác định IP đang được domain trỏ tới. |
| **AAAA** | Ánh xạ hostname đến IPv6. | Kiểm tra hạ tầng IPv6, tránh bỏ sót kết nối. |
| **CNAME** | Tạo alias trỏ tới một hostname khác. | Có thể làm lộ dịch vụ hoặc nhà cung cấp đích. |
| **MX** | Chỉ định mail server của domain. | Bổ sung thông tin hạ tầng email. |
| **NS** | Chỉ định authoritative name servers. | Nhận diện DNS provider và cấu hình quản lý zone. |
| **TXT** | Lưu dữ liệu dạng text, thường dùng cho SPF, xác minh domain và chính sách khác. | Có thể dùng để kiểm tra cấu hình email hoặc xác minh dịch vụ. |
| **PTR** | Reverse DNS: ánh xạ IP về hostname. | Bổ sung bối cảnh về host name gắn với IP. |
| **SOA** | Thông tin quản lý zone và authoritative DNS. | Có thể hỗ trợ nhận diện hạ tầng DNS và thông tin zone. |

**TTL (Time To Live)** là thời gian một bản ghi DNS có thể được cache. TTL thấp có thể khiến record thay đổi thường xuyên hơn, nhưng bản thân TTL không chứng minh domain độc hại.

### 3. Truy vấn DNS bằng `dig` và `nslookup`

**Dùng `dig` (Linux/macOS hoặc môi trường có BIND utilities):**

```bash
# Lấy IPv4
 dig example.com A

# Lấy IPv6
 dig example.com AAAA

# Mail servers
 dig example.com MX

# Name servers
 dig example.com NS

# TXT records
 dig example.com TXT

# Reverse DNS
 dig -x 203.0.113.10
```

**Dùng `nslookup`:**

```text
nslookup -type=A example.com
nslookup -type=MX example.com
nslookup -type=TXT example.com
```

`dig` thường thuận tiện hơn cho scripting và xem chi tiết câu trả lời DNS; `nslookup` phổ biến trên Windows và trong tài liệu cũ.

### 4. TLS Certificate Enrichment

Khi domain sử dụng HTTPS, chứng thư TLS cung cấp thêm dữ liệu về danh tính và cấu hình dịch vụ.

Các trường có thể xem:

- **Subject / Common Name (CN):** Danh tính được khai báo trong chứng thư.
- **Subject Alternative Name (SAN):** Các hostname được chứng thư bao phủ.
- **Issuer:** Certificate Authority phát hành chứng thư.
- **Validity:** Thời gian bắt đầu và kết thúc hiệu lực.
- **Serial number / Fingerprint:** Giá trị hỗ trợ nhận diện chứng thư.
- **Certificate Transparency:** Dữ liệu công khai về chứng thư đã được cấp, có thể hỗ trợ phát hiện subdomain hoặc hostname liên quan.

Chứng thư TLS hợp lệ chỉ xác nhận một số thuộc tính về kết nối/chứng thư; nó không chứng minh nội dung website an toàn.

Lệnh xem nhanh thông tin TLS từ môi trường có OpenSSL:

```bash
openssl s_client -connect example.com:443 -servername example.com -showcerts
```

Khi dùng lệnh này, hãy chỉ kết nối tới hệ thống thuộc phạm vi được phép kiểm tra. Nếu chỉ cần enrichment thụ động, ưu tiên các dịch vụ tra cứu certificate transparency hoặc dữ liệu public có sẵn.

### 5. Domain Age và các dấu hiệu cần chú ý

Domain mới được đăng ký, tên miền có ký tự gần giống thương hiệu, DNS thay đổi đột ngột hoặc hostname không liên quan đến nội dung email có thể là dấu hiệu cần điều tra.

Tuy nhiên:

- Domain mới cũng có thể thuộc dự án hợp pháp.
- Domain lâu năm vẫn có thể bị xâm nhập hoặc bị lạm dụng.
- Cloud/CDN có thể khiến nhiều domain chia sẻ một IP.
- Cần so sánh domain với nguồn giao tiếp, certificate, DNS history và nội dung ứng dụng.

---

## Task 3: IP Enrichment

### 1. Geolocation

Geolocation cung cấp vị trí địa lý ước tính của IP, thường ở mức quốc gia, khu vực hoặc thành phố.

Ứng dụng:

- So sánh vị trí ước tính với bối cảnh đăng nhập hoặc truy cập.
- Nhận diện kết nối bất thường theo vị trí và thời gian.
- Bổ sung thông tin cho timeline điều tra.

**Giới hạn:** Geolocation không phải vị trí vật lý chính xác của người dùng. VPN, proxy, carrier-grade NAT, cloud hosting và anycast có thể làm kết quả khác xa vị trí thực tế.

### 2. ASN – Autonomous System Number

ASN là mã định danh của một Autonomous System, tức hệ thống mạng có chính sách định tuyến chung và được quản lý bởi một tổ chức/nhà mạng.

Thông tin ASN có thể giúp analyst xác định:

- IP được công bố/định tuyến bởi mạng nào.
- Tổ chức hoặc nhà cung cấp nào liên quan đến prefix IP.
- IP có thuộc hosting provider, ISP, cloud hoặc network đặc thù không.
- Nhiều IP có cùng thuộc một mạng hoặc nhà cung cấp không.

ASN chỉ cho biết bối cảnh mạng và định tuyến, không tự động chứng minh chủ sở hữu IP là đối tượng tấn công.

### 3. Các thông tin bổ sung cần kiểm tra

- **IP reputation:** Nguồn nào đã ghi nhận IP và vào thời điểm nào?
- **Passive DNS:** Domain nào từng hoặc đang phân giải tới IP?
- **Reverse DNS:** IP có hostname liên quan không?
- **Hosting provider / ISP:** IP thuộc cloud, datacenter, ISP hay mạng tổ chức?
- **Related infrastructure:** Có liên hệ với domain, URL hoặc malware sample khác không?
- **Historical context:** IP đã được dùng cho mục đích nào trong khoảng thời gian liên quan?

### 4. Cách tránh kết luận sai về IP

- Không block một IP chỉ vì geolocation ở quốc gia bị đánh giá rủi ro.
- Không coi mọi IP datacenter là độc hại.
- Không mặc định một IP luôn đại diện cho một domain; CDN và shared hosting có thể dùng chung IP.
- Kiểm tra timestamp vì IP có thể được tái phân bổ hoặc thay đổi mục đích sử dụng.
- Đối chiếu nhiều nguồn và local telemetry trước khi quyết định.

---

## Task 4: Service Exposure

### 1. Shodan

Shodan là công cụ tìm kiếm các thiết bị và dịch vụ kết nối Internet. Shodan thu thập dữ liệu công khai từ thiết bị/dịch vụ, trong đó có **banner** – metadata mà dịch vụ gửi ra khi được truy vấn.

Thông tin thường thấy:

- IP và hostname.
- Port đang mở được ghi nhận.
- Protocol và service.
- Banner hoặc thông tin phiên bản phần mềm.
- ASN, nhà cung cấp và vị trí ước tính.
- Tags hoặc thông tin liên quan đến lỗ hổng nếu hệ thống phát hiện được.

Ví dụ bộ lọc tìm kiếm trên Shodan:

```text
hostname:example.com
port:443
org:"Example Hosting"
```

Shodan hữu ích để quan sát bề mặt dịch vụ công khai, nhưng snapshot có thể cũ hơn trạng thái hiện tại. Cần xác minh thời gian quan sát và không thực hiện truy cập hoặc kiểm tra chủ động ngoài phạm vi được phép.

### 2. Censys

Censys cung cấp dữ liệu có cấu trúc về host, service, certificate và các tài sản Internet-facing. Có thể pivot giữa IP, DNS name, certificate và dịch vụ liên quan.

| Khía cạnh | Shodan | Censys |
|---|---|---|
| Trọng tâm | Thiết bị Internet-connected và banner/service. | Host, web properties, certificates và quan hệ tài sản. |
| Câu hỏi thường dùng | IP đang phơi bày port/service nào? Banner hiển thị gì? | Host nào dùng certificate này? Những hostname/asset nào có liên quan? |
| Cách sử dụng trong CTI | Enrichment bề mặt dịch vụ và dấu hiệu phơi bày. | Liên kết hạ tầng, dịch vụ và chứng thư. |

Kết quả của Shodan/Censys không phải bản quét bảo mật toàn diện và không thay thế vulnerability assessment có ủy quyền.

---

## Task 5: VPN Detection

### 1. Vì sao cần nhận diện VPN, Proxy và Tor?

Một IP nguồn có thể đại diện cho kết nối trực tiếp, VPN, proxy, Tor exit node hoặc hạ tầng hosting. Nhận diện loại network giúp SOC hiểu rõ hơn nguồn traffic và mức độ ẩn danh.

| Nhóm | Mô tả tổng quát | Lưu ý phân tích |
|---|---|---|
| **VPN** | Tunnel mã hóa lưu lượng qua một máy chủ trung gian. | VPN có thể được dùng hợp pháp bởi nhân viên hoặc người dùng cá nhân. |
| **Open / Public Proxy** | Máy chủ trung gian chuyển tiếp kết nối cho client. | Có thể bị lạm dụng để che giấu nguồn truy cập. |
| **Web Proxy** | Proxy xử lý truy cập web/HTTP(S). | Cần phân biệt proxy doanh nghiệp hợp pháp với proxy ẩn danh. |
| **Tor Exit Node** | Điểm thoát cuối của lưu lượng Tor ra Internet. | IP exit node không cho biết danh tính người dùng cuối. |
| **Datacenter / Hosting IP** | IP thuộc nhà cung cấp hosting hoặc trung tâm dữ liệu. | Có thể được dùng cho dịch vụ hợp pháp hoặc hạ tầng tấn công. |
| **Residential Proxy** | Lưu lượng proxy đi qua địa chỉ IP thuộc mạng người dùng dân dụng. | Khó phân biệt hơn do IP có thể trông giống kết nối hộ gia đình bình thường. |
| **ISP Proxy** | Proxy hoạt động trên hạ tầng ISP hoặc mạng liên quan. | Cần kết hợp hành vi quan sát, không chỉ dựa vào ASN. |

### 2. IP2Proxy

IP2Proxy phân loại IP theo nhiều loại sử dụng như VPN, Tor exit node, public proxy, web proxy, datacenter/hosting và residential proxy.

Dữ liệu enrichment có thể bao gồm:

- IP có được đánh dấu là proxy/VPN hay không.
- Proxy type hoặc usage type.
- Quốc gia/khu vực/ISP liên quan đến proxy.
- ASN hoặc nhà cung cấp nếu gói dữ liệu hỗ trợ.
- Thời điểm hoặc dấu hiệu ghi nhận theo database.

### 3. Spur

Spur cung cấp IP context, gồm các phân loại VPN, residential proxy, ISP proxy, hosting provider và một số risk/network signals.

Điểm quan trọng khi đọc kết quả:

- Phân loại dựa trên hoạt động và nhiều loại bằng chứng, không chỉ đơn thuần dựa trên tổ chức đứng tên IP.
- Một IP có thể thay đổi phân loại theo thời gian.
- VPN/proxy không mặc định là malicious.
- Một IP dân dụng có thể bị nhận diện là residential proxy nếu hoạt động relay được quan sát trên IP đó.

### 4. Diễn giải kết quả VPN/Proxy Detection

Không nên viết “IP độc hại vì dùng VPN”. Nên trình bày chính xác hơn:

- Nguồn A phân loại IP là VPN/datacenter/residential proxy.
- Nguồn B có/không có reputation liên quan đến abuse.
- Telemetry nội bộ cho thấy IP thực hiện hành vi gì, vào thời điểm nào.
- Các nguồn có đồng thuận không và dữ liệu được cập nhật khi nào.
- Kết luận chỉ phản ánh mức confidence và ngữ cảnh hiện tại.

---

## Task 6: Challenge – Quy trình phân tích tổng hợp

Có thể dùng workflow dưới đây để xử lý một cặp IP/domain đáng ngờ:

1. **Chuẩn hóa indicator:** Kiểm tra định dạng IP/domain, loại bỏ khoảng trắng và giữ nguyên giá trị gốc trong evidence.
2. **WHOIS/domain age:** Ghi nhận registrar, creation date, nameserver và trạng thái domain.
3. **DNS enrichment:** Tra cứu A, AAAA, MX, NS, TXT, CNAME, PTR và TTL khi phù hợp.
4. **TLS enrichment:** Xem issuer, SAN, validity, fingerprint và certificate history.
5. **IP enrichment:** Lấy ASN, ISP/hosting, geolocation ước tính, reverse DNS và reputation.
6. **Service exposure:** Kiểm tra snapshot dịch vụ/port/banner trên Shodan và Censys.
7. **VPN/proxy classification:** Đối chiếu IP2Proxy và Spur.
8. **Correlate:** Tìm liên hệ giữa domain, IP, certificate, URL, hash, malware family và campaign.
9. **Local validation:** Tìm dấu vết trong DNS/firewall/proxy/EDR/SIEM logs.
10. **Decision:** Đánh giá confidence, nêu giới hạn dữ liệu và đề xuất block/alert/monitor/escalate.

### Mẫu bảng ghi chép IP/Domain

| Trường | Nội dung cần ghi |
|---|---|
| Indicator | Domain hoặc IP đã chuẩn hóa. |
| First seen / Last seen | Thời gian quan sát từ từng nguồn. |
| WHOIS | Registrar, creation date, nameserver, status. |
| DNS | Record types, TTL, resolved IPs, passive DNS. |
| TLS | Issuer, SAN, validity, fingerprint. |
| ASN / ISP | Autonomous System và network owner/provider. |
| Geolocation | Country/city ước tính, kèm nguồn. |
| Service exposure | Port, protocol, banner, scan observation time. |
| VPN/Proxy | Classification từ IP2Proxy/Spur và thời điểm. |
| Reputation | Kết quả từ các nguồn threat intelligence. |
| Internal evidence | Log nội bộ hoặc alert liên quan. |
| Assessment | Kết luận và confidence có giải thích. |
| Recommendation | Block, alert, monitor, hunt hoặc escalate. |

---

## Ghi nhớ và giá trị ứng dụng

- WHOIS giúp hiểu lịch sử đăng ký và thông tin quản lý domain, nhưng không xác định chắc chắn danh tính attacker.
- DNS records cho thấy quan hệ giữa domain, hostname, IP và mail infrastructure.
- TLS certificate cung cấp metadata và có thể hỗ trợ pivot sang các hostname liên quan.
- ASN/geolocation bổ sung bối cảnh mạng; geolocation chỉ mang tính ước tính.
- Shodan và Censys giúp quan sát dịch vụ public-facing và mối quan hệ giữa hạ tầng.
- IP2Proxy và Spur hỗ trợ phân loại VPN/proxy/Tor; các phân loại này không đồng nghĩa IP độc hại.
- Cần correlate nhiều nguồn và local telemetry trước khi quyết định xử lý.

**Năng lực có thể thể hiện trong portfolio:** Tra cứu WHOIS/DNS/TLS, enrichment IP/domain, đọc ASN và geolocation, kiểm tra service exposure, phân biệt hosting/VPN/proxy và xây dựng bảng đánh giá indicator có nguồn, thời điểm và confidence.

---

## Tài liệu tham khảo

1. [TryHackMe – IP and Domain Threat Intel](https://tryhackme.com/room/ipanddomainthreatintel)
2. [TryHackMe – Threat Analysis Tools module](https://tryhackme.com/module/threat-analysis-tools)
3. [RFC 3912 – WHOIS Protocol Specification](https://www.rfc-editor.org/info/rfc3912/)
4. [Google Cloud – DNS overview and record types](https://docs.cloud.google.com/dns/docs/dns-overview)
5. [Cloudflare – DNS record types](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/)
6. [Shodan – What is Shodan?](https://help.shodan.io/the-basics/what-is-shodan)
7. [Censys – Platform Quickstart Guide](https://docs.censys.com/docs/platform-quickstart-guide)
8. [IP2Location – IP2Proxy Database](https://www.ip2location.com/database/ip2proxy)
9. [Spur – How VPNs and proxies are detected](https://docs.spur.us/knowledgebase/faqs/how-does-spur-detect-vpns-residential-proxies-and-isp-proxies)
10. [RFC 8805 – A Format for Self-Published IP Geolocation Feeds](https://www.rfc-editor.org/info/rfc8805/)
