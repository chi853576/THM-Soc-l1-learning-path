# Pyramid of Pain

## 1. Tổng quan

**Pyramid of Pain** mô tả mức độ khó khăn mà attacker phải đối mặt khi defender phát hiện và chặn các dấu hiệu tấn công.

- **Càng lên cao:** Attacker càng khó thay đổi những gì đã bị phát hiện.
- **Càng xuống thấp:** Attacker càng dễ thay đổi dấu hiệu để né tránh phát hiện.

Pyramid of Pain hữu ích trong **Cyber Threat Intelligence (CTI), Threat Hunting và Incident Response**.

## 2. Sáu cấp độ chính và các dấu hiệu phát hiện

### 2.1. Hash Values — Màu xanh lá

Hash là giá trị có độ dài cố định được tạo ra từ dữ liệu bằng thuật toán hashing. Security professionals sử dụng hash để nhận diện và tham chiếu đến file độc hại.

Các thuật toán phổ biến:

| Thuật toán | Độ dài hash | Ghi nhớ |
|---|---:|---|
| MD5 | 128 bit | Không còn an toàn về mặt mật mã |
| SHA-1 | 160 bit | Đã bị suy yếu; nên chuyển sang thuật toán mạnh hơn |
| SHA-256 | 256 bit | Thuộc họ SHA-2, được sử dụng phổ biến |

**Công cụ tra cứu:** VirusTotal, MetaDefender Cloud.

**Hạn chế:** Chỉ cần sửa đổi file, thậm chí một bit, hash có thể thay đổi. Vì vậy, attacker dễ né phát hiện dựa trên hash bằng cách tạo biến thể malware mới.

### 2.2. IP Addresses — Màu xanh lá

IP address giúp xác định thiết bị giao tiếp trên mạng. Defender có thể chặn IP độc hại bằng firewall.

**Hạn chế:** Attacker có thể đổi sang IP công khai khác.

**Fast Flux:** Kỹ thuật DNS sử dụng nhiều địa chỉ IP thay đổi liên tục để che giấu hạ tầng độc hại, chẳng hạn máy chủ Command and Control (C2).

### 2.3. Domain Names — Màu xanh ngọc

Domain name là tên miền được sử dụng để truy cập dịch vụ trên mạng, ví dụ `evilcorp.com` hoặc `tryhackme.evilcorp.com`.

Attacker có thể đổi domain hoặc sửa DNS records để né phát hiện. Tuy nhiên, việc đăng ký và quản lý domain mới thường tốn công sức hơn việc thay đổi hash hoặc IP.

Các kỹ thuật cần nhớ:

- **Punycode:** Chuyển các ký tự Unicode thành dạng ASCII tương thích; có thể bị lợi dụng để tạo tên miền giả mạo trông giống tên miền hợp pháp.
- **URL shortener:** Rút gọn URL và chuyển hướng người dùng đến website đích. Ví dụ: bit.ly, tinyurl.com.

**Phát hiện:** Phân tích proxy logs, web server logs và DNS logs.

**Trong Any.run:**
- **HTTP Requests:** Các yêu cầu HTTP được ghi nhận khi chạy mẫu.
- **Connections:** Các kết nối mạng do mẫu thực hiện.
- **DNS Requests:** Các truy vấn DNS do mẫu tạo ra.

Không truy cập trực tiếp IP hoặc URL đáng ngờ lấy từ báo cáo malware.

### 2.4. Host Artifacts — Màu vàng

Host artifacts là dấu vết attacker để lại trên máy tính hoặc hệ thống bị xâm nhập.

Ví dụ:
- Registry values đáng ngờ.
- Process execution bất thường.
- File độc hại được tạo, thả xuống hoặc sửa đổi.
- Các sự kiện hệ thống liên quan đến hoạt động tấn công.
- Indicators of Compromise (IOCs).

**Ý nghĩa:** Khi phát hiện được host artifacts, attacker thường phải thay đổi công cụ hoặc phương pháp tấn công, tốn nhiều thời gian và nguồn lực hơn.

### 2.5. Network Artifacts — Màu vàng

Network artifacts là các dấu hiệu đáng ngờ trong hoạt động giao tiếp mạng.

Ví dụ:
- User-Agent bất thường.
- URI patterns đáng ngờ.
- Thông tin liên quan đến C2.
- Các HTTP POST requests có dấu hiệu độc hại.

**Công cụ phát hiện:**
- **Wireshark / TShark:** Phân tích PCAP và lưu lượng mạng.
- **Snort:** IDS dùng để phát hiện hoạt động mạng đáng ngờ.

Ví dụ: Một User-Agent chưa từng xuất hiện trong môi trường hoặc có đặc điểm bất thường có thể là dấu hiệu cần điều tra. Các User-Agent liên quan đến Emotet là ví dụ về network indicators có thể hỗ trợ nhận diện malware.

### 2.6. Tools — Màu cam

Ở cấp độ này, defender phát hiện được công cụ mà attacker sử dụng. Attacker có thể phải tìm công cụ thay thế, sửa đổi công cụ hoặc tự phát triển công cụ mới.

Ví dụ:
- Công cụ tạo malicious documents có macro.
- Backdoor phục vụ C2.
- File thực thi `.EXE`, thư viện `.DLL` và payload độc hại.
- Password crackers.

**Biện pháp phát hiện:**
- Antivirus signatures.
- Detection rules.
- YARA rules.

**Nguồn tham khảo:**
- MalwareBazaar: Mẫu malware và thông tin liên quan.
- Malshare: Mẫu malware và dữ liệu phục vụ nghiên cứu.
- SOC Prime Threat Detection Marketplace: Các detection rules.

**Fuzzy hashing:** Kỹ thuật xác định độ tương đồng giữa các file dù chúng có một số khác biệt.

- Công cụ/thuật toán ví dụ: **SSDeep**.
- Khác với hashing thông thường, fuzzy hashing hỗ trợ so sánh mức độ tương đồng giữa các file thay vì chỉ đối chiếu hash chính xác.

### 2.7. TTPs — Màu đỏ, đỉnh kim tự tháp

**TTPs = Tactics, Techniques and Procedures.**

- **Tactics:** Mục tiêu hoặc kết quả attacker muốn đạt được.
- **Techniques:** Phương pháp attacker sử dụng để đạt mục tiêu.
- **Procedures:** Cách triển khai cụ thể các phương pháp đó.

TTPs bao gồm toàn bộ chuỗi hành động của attacker, từ phishing, duy trì quyền truy cập (persistence), di chuyển ngang (lateral movement) đến đánh cắp dữ liệu (exfiltration).

**MITRE ATT&CK Matrix** là nguồn tham khảo quan trọng để nghiên cứu và phân loại các tactics, techniques của adversary.

Ví dụ: Phát hiện tấn công **Pass-the-Hash** thông qua giám sát Windows Event Logs có thể giúp xác định máy bị xâm nhập và ngăn attacker di chuyển ngang trong mạng.

**Ý nghĩa:** TTPs khó thay đổi hơn các dấu hiệu đơn lẻ vì attacker phải thay đổi cách thức hoạt động, không chỉ thay đổi một file, IP hoặc domain.

---

## 3. tóm tắt

| Cấp độ | Dấu hiệu | Cách phát hiện / công cụ | Khả năng né tránh |
|---|---|---|---|
| 1. Hash Values | Hash của file độc hại | VirusTotal, MetaDefender | Rất dễ: sửa file để đổi hash |
| 2. IP Addresses | IP độc hại | Firewall, phân tích kết nối | Dễ: đổi IP; dùng Fast Flux |
| 3. Domain Names | Domain độc hại | DNS, proxy, web server logs | Khó hơn: đăng ký hoặc đổi domain |
| 4. Host Artifacts | Registry, process, file, IOC | Phân tích endpoint và system logs | Khó hơn: phải thay đổi dấu vết trên host |
| 5. Network Artifacts | User-Agent, URI, C2 patterns | Wireshark, TShark, Snort | Khó hơn: phải sửa dấu hiệu giao tiếp mạng |
| 6. Tools | Công cụ và payload độc hại | Antivirus, detection rules, YARA | Khó: cần thay thế hoặc phát triển công cụ |
| 7. TTPs | Hành vi và quy trình tấn công | MITRE ATT&CK, log monitoring, threat hunting | Khó nhất: cần thay đổi cách thức tấn công |

## 4. Những điểm cần nhớ

1. **Hash không phải danh tính bất biến của malware:** Một thay đổi nhỏ có thể tạo hash mới.
2. **Chặn IP chưa đủ:** Attacker có thể đổi IP hoặc sử dụng Fast Flux.
3. **Domain có thể bị ngụy trang:** Chú ý Punycode, URL shorteners và DNS requests.
4. **Host artifacts cho biết điều gì xảy ra trên máy:** Kiểm tra process, registry, file và các sự kiện liên quan.
5. **Network artifacts cho biết cách malware giao tiếp:** Kiểm tra User-Agent, URI, HTTP requests và C2.
6. **Tools là công cụ attacker sử dụng:** YARA và detection rules giúp nhận diện công cụ hoặc mẫu độc hại.
7. **TTPs là cấp độ có giá trị nhất để phát hiện hành vi:** Kết hợp MITRE ATT&CK với log monitoring và threat hunting giúp phát hiện hoạt động tấn công ngay cả khi IOC thay đổi.

