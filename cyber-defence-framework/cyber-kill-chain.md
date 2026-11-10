#  Cyber Kill Chain

## 1. Tổng quan

**Cyber Kill Chain** là framework do Lockheed Martin phát triển năm 2011, dựa trên khái niệm kill chain trong quân sự. Framework mô tả các giai đoạn attacker thường trải qua để thực hiện một cuộc tấn công mạng.

### 7 giai đoạn

1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control (C2)
7. Actions on Objectives

**Mục đích:** Giúp SOC Analyst, Threat Hunter và Incident Responder nhận diện hoạt động của attacker, tìm điểm yếu trong hệ thống phòng thủ và ngăn chặn cuộc tấn công trước khi attacker đạt mục tiêu.

## 2. Chi tiết từng giai đoạn

### 2.1. Reconnaissance — Trinh sát

Attacker thu thập thông tin về mục tiêu để lên kế hoạch tấn công, chẳng hạn:
- Hạ tầng và công nghệ đang sử dụng.
- Thông tin nhân viên, email và quy trình doanh nghiệp.
- Các dịch vụ hoặc hệ thống có thể bị khai thác.

**OSINT (Open-Source Intelligence):** Thu thập thông tin từ các nguồn công khai:
- Search engines, báo chí, mạng xã hội, diễn đàn.
- Cơ sở dữ liệu công khai.
- WHOIS và dữ liệu kỹ thuật.

**Hai loại reconnaissance:**
- **Passive Recon:** Không tương tác trực tiếp với mục tiêu, ví dụ tra cứu WHOIS hoặc xem thông tin công khai.
- **Active Recon:** Tương tác trực tiếp với mục tiêu, ví dụ port scanning, banner grabbing hoặc probing dịch vụ.

**Email harvesting:** Thu thập địa chỉ email từ các nguồn dữ liệu để phục vụ những hoạt động như phishing.

Công cụ tiêu biểu:
- **theHarvester:** Thu thập email, tên, subdomain, IP và URL từ các nguồn công khai.
- **Hunter.io:** Tìm thông tin liên hệ gắn với domain.
- **OSINT Framework:** Tập hợp công cụ OSINT theo từng nhóm.

### 2.2. Weaponization — Vũ khí hóa

Attacker chuẩn bị hoặc tạo công cụ tấn công bằng cách kết hợp malware, exploit và payload.

**Khái niệm cần nhớ:**
- **Malware:** Phần mềm được thiết kế để gây hại, làm gián đoạn hoặc truy cập trái phép hệ thống.
- **Exploit:** Mã hoặc chương trình khai thác lỗ hổng của phần mềm hoặc hệ thống.
- **Payload:** Phần mã độc được thực thi để thực hiện hành động mà attacker mong muốn.

Các hoạt động thường gặp:
- Tạo tài liệu Microsoft Office có macro/VBA độc hại.
- Chuẩn bị malware hoặc worm để phát tán.
- Thiết lập hạ tầng C2.
- Chuẩn bị backdoor.
- Tạo email phishing hoặc ứng dụng OAuth giả mạo để đánh lừa nạn nhân.

### 2.3. Delivery — Phân phối

Attacker đưa payload hoặc malware vào môi trường mục tiêu.

Các phương thức phổ biến:

- **Phishing Email:** Email chứa liên kết hoặc tệp đính kèm độc hại. **Spear phishing** nhắm đến một cá nhân hoặc nhóm cụ thể.
- **USB Drop Attack:** Đặt hoặc gửi USB có chứa mã độc để dụ nạn nhân sử dụng.
- **Watering Hole Attack:** Xâm nhập website mà nhóm mục tiêu thường truy cập, sau đó chuyển hướng hoặc dụ họ tải nội dung độc hại.

**Drive-by download:** Malware được tải xuống thông qua quá trình truy cập hoặc tương tác với website bị xâm nhập, tùy vào cách thức tấn công.

### 2.4. Exploitation — Khai thác

Payload hoặc mã khai thác được thực thi trên hệ thống mục tiêu, lợi dụng lỗ hổng để thực hiện hành động trái phép.

Các phương thức:
- **Malicious macro execution:** Macro độc hại được thực thi khi người dùng mở hoặc tương tác với tài liệu.
- **Zero-day exploit:** Khai thác lỗ hổng chưa được biết đến rộng rãi hoặc chưa có bản vá phù hợp.
- **Known CVEs:** Khai thác lỗ hổng đã được công bố nhưng hệ thống chưa được vá.

Sau khi xâm nhập, attacker có thể tìm cách:
- **Privilege escalation:** Leo thang đặc quyền.
- **Lateral movement:** Di chuyển sang các hệ thống khác trong mạng.

**Dấu hiệu cần điều tra:**
- Process khởi chạy bất thường.
- Registry bị thay đổi hoặc service mới được tạo.
- Command-line arguments đáng ngờ trong system logs.

### 2.5. Installation — Cài đặt và duy trì quyền truy cập

Attacker cài đặt backdoor hoặc cơ chế persistence để giữ quyền truy cập, kể cả khi kết nối bị gián đoạn hoặc quyền truy cập ban đầu bị loại bỏ.

Các phương thức persistence:
- **Web shell:** Script độc hại trên web server, có thể viết bằng PHP, ASP hoặc JSP.
- **Backdoor:** Cung cấp một cách truy cập trái phép trở lại hệ thống; Meterpreter là một ví dụ về payload trong Metasploit Framework.
- **Windows services:** Tạo hoặc sửa đổi service để thực thi payload định kỳ. MITRE ATT&CK: **T1543.003**.
- **Registry Run Keys / Startup Folder:** Tự động chạy payload khi người dùng đăng nhập. MITRE ATT&CK: **T1547.001**.

Kỹ thuật liên quan:
- **Masquerading (T1036):** Ngụy trang tên hoặc đặc điểm của payload để trông giống thành phần hợp pháp.
- **Timestomping (T1070.006):** Thay đổi timestamp của file nhằm gây khó khăn cho quá trình điều tra pháp chứng.

### 2.6. Command & Control (C2) — Điều khiển và kiểm soát

Sau khi thiết lập persistence và thực thi malware, attacker tạo kênh liên lạc với hệ thống bị xâm nhập để điều khiển từ xa.

**C2 Beaconing:** Máy bị xâm nhập liên lạc định kỳ với máy chủ C2. Hoạt động này có thể tạo ra mẫu lưu lượng đáng ngờ.

Các kênh C2 phổ biến:
- **HTTP — port 80:** Có thể hòa lẫn vào lưu lượng web thông thường.
- **HTTPS — port 443:** Mã hóa lưu lượng và có thể làm việc phân tích khó khăn hơn.
- **DNS / DNS Tunneling:** Lợi dụng truy vấn DNS để truyền thông tin hoặc duy trì liên lạc với hạ tầng C2.

C2 infrastructure có thể do attacker trực tiếp vận hành hoặc nằm trên một máy chủ đã bị xâm nhập.

**Góc nhìn SOC:** Điều tra kết nối ra ngoài bất thường, DNS requests lặp lại, domain đáng ngờ và các mẫu beaconing.

### 2.7. Actions on Objectives — Thực hiện mục tiêu

Đây là giai đoạn attacker thực hiện mục tiêu cuối cùng sau khi đã xâm nhập và thiết lập quyền kiểm soát.

Các hành động có thể bao gồm:
- Thu thập thông tin xác thực (**credential collection**).
- Leo thang đặc quyền, chẳng hạn chiếm quyền Domain Administrator.
- Trinh sát hệ thống nội bộ (**internal reconnaissance**).
- Di chuyển ngang (**lateral movement**).
- Thu thập và đánh cắp dữ liệu (**data exfiltration**).
- Xóa bản sao lưu hoặc Shadow Copies để cản trở khôi phục.
- Ghi đè hoặc làm hỏng dữ liệu.

**Lưu ý:** Không phải cuộc tấn công nào cũng thực hiện đầy đủ mọi hành động hoặc diễn ra theo trình tự hoàn toàn giống nhau.

## 3. Bảng ôn tập nhanh

| Giai đoạn | Câu hỏi cần nhớ | Ví dụ |
|---|---|---|
| Reconnaissance | Attacker tìm hiểu mục tiêu ra sao? | OSINT, email harvesting |
| Weaponization | Attacker chuẩn bị gì? | Malware, exploit, payload |
| Delivery | Payload được đưa vào bằng cách nào? | Phishing, USB drop, watering hole |
| Exploitation | Attacker khai thác hoặc thực thi mã ra sao? | Macro, zero-day, CVE |
| Installation | Attacker duy trì quyền truy cập thế nào? | Web shell, backdoor, Run Keys |
| Command & Control | Attacker điều khiển máy bị xâm nhập ra sao? | HTTP/HTTPS, DNS tunneling |
| Actions on Objectives | Attacker muốn đạt mục tiêu gì? | Đánh cắp dữ liệu, leo thang quyền, phá hủy backup |

## 4. Cách áp dụng khi phân tích sự cố SOC

Khi điều tra một sự cố, hãy dùng Cyber Kill Chain như khung tư duy để đặt câu hỏi:

1. **Reconnaissance:** Có dấu hiệu thu thập thông tin hoặc dò quét không?
2. **Weaponization / Delivery:** Người dùng có nhận email đáng ngờ, mở file hoặc truy cập liên kết độc hại không?
3. **Exploitation:** Có process bất thường, khai thác lỗ hổng hoặc hành vi thực thi đáng ngờ không?
4. **Installation:** Có persistence mới, web shell hoặc service bất thường không?
5. **C2:** Có kết nối ra ngoài hoặc DNS requests đáng ngờ không?
6. **Actions on Objectives:** Có dấu hiệu đánh cắp dữ liệu, di chuyển ngang hoặc xóa backup không?

Không nhất thiết phải tìm thấy bằng chứng ở cả bảy giai đoạn. Một số giai đoạn có thể bị bỏ qua, diễn ra gần như đồng thời hoặc không để lại log đầy đủ.

**Mục tiêu phòng thủ:** Phát hiện và ngăn chặn càng sớm càng tốt để phá vỡ chuỗi tấn công trước khi attacker đạt được mục tiêu cuối cùng.
