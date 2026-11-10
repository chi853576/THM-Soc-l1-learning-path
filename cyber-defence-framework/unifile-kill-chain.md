# Unified Kill Chain (UKC)

## 1. Introduction

**Unified Kill Chain (UKC)** là framework mô tả các giai đoạn và hành vi của attacker trong một cuộc tấn công mạng. Framework do Paul Pols công bố năm 2017, nhằm **bổ trợ chứ không cạnh tranh** với các framework như Lockheed Martin Cyber Kill Chain và MITRE ATT&CK.

### Learning Objectives
- Hiểu vai trò của framework trong việc xây dựng tư thế phòng thủ an ninh mạng.
- Phân tích động cơ, phương pháp và chiến thuật của attacker.
- Hiểu các phase của UKC.
- Biết cách UKC bổ trợ cho MITRE ATT&CK và các framework khác.

## 2. What is a Kill Chain?

**Kill Chain** mô tả chuỗi giai đoạn mà attacker thực hiện để tiếp cận, xâm nhập và đạt được mục tiêu trên hệ thống hoặc mạng.

Ví dụ: Attacker quét hệ thống → khai thác lỗ hổng web → nâng quyền → truy cập dữ liệu.

Mục đích của việc phân tích Kill Chain là xác định các bước tấn công để triển khai biện pháp phòng thủ, phát hiện và ngăn chặn trước khi attacker hoàn thành mục tiêu.

## 3. Threat Modelling

**Threat Modelling** là quá trình xác định tài sản, phân tích mối đe dọa và lập kế hoạch giảm thiểu rủi ro.

### Các bước chính
1. **Identify:** Xác định hệ thống, ứng dụng, chức năng và dữ liệu nhạy cảm.
2. **Assess:** Đánh giá lỗ hổng, điểm yếu và cách chúng có thể bị khai thác.
3. **Plan:** Lập kế hoạch bảo vệ hệ thống và khắc phục điểm yếu.
4. **Implement policies:** Thiết lập chính sách để ngăn vấn đề tái diễn, ví dụ Secure SDLC và đào tạo nhận thức phishing.

UKC hỗ trợ Threat Modelling bằng cách giúp xác định attack surface và hiểu cách attacker có thể khai thác hệ thống.

Một số framework liên quan: **STRIDE, DREAD, CVSS**.

## 4. Benefits of UKC

UKC có **18 phases chính thức**, bao quát toàn bộ cuộc tấn công và động cơ của attacker.

Các ưu điểm:
- **Modern:** Được công bố năm 2017 và cập nhật năm 2022.
- **Detailed:** Có 18 phase, chi tiết hơn các framework có ít giai đoạn.
- **End-to-end:** Bao quát từ reconnaissance, exploitation, post-exploitation đến mục tiêu cuối cùng.
- **Realistic:** Attacker có thể quay lại các phase trước. Ví dụ, sau khi xâm nhập một máy, attacker tiếp tục reconnaissance để tìm máy khác trong mạng.

## 5. The Three Goals of UKC

UKC được chia trong room thành ba nhóm lớn: **In, Through và Out**.

### 5.1. In — Establish Initial Foothold

Mục tiêu: Tiếp cận và giành quyền truy cập ban đầu vào hệ thống hoặc mạng, đồng thời thiết lập khả năng duy trì truy cập.

| Phase | Ý nghĩa | Ví dụ |
|---|---|---|
| Reconnaissance | Thu thập thông tin mục tiêu | Tìm dịch vụ, nhân viên, thông tin xác thực và cấu trúc mạng |
| Weaponization | Chuẩn bị hạ tầng phục vụ tấn công | Dựng máy chủ C2 hoặc hạ tầng phát tán payload |
| Social Engineering | Thao túng con người để hỗ trợ tấn công | Phishing, giả mạo trang đăng nhập, giả danh nhân viên |
| Exploitation | Khai thác lỗ hổng để thực thi mã | Khai thác lỗi web để chạy code |
| Persistence | Duy trì quyền truy cập | Tạo service, backdoor hoặc cơ chế truy cập từ xa |
| Defence Evasion | Né tránh biện pháp phòng thủ | Né firewall, antivirus hoặc IDS |
| Command & Control (C2) | Thiết lập liên lạc với hệ thống bị xâm nhập | Gửi lệnh, đánh cắp dữ liệu hoặc điều khiển máy từ xa |
| Pivoting | Dùng hệ thống đã xâm nhập làm điểm trung gian | Từ web server truy cập các máy nội bộ không public Internet |

**Reconnaissance** có thể là passive hoặc active. Thông tin thu thập được hỗ trợ các giai đoạn tiếp theo, như xác định dịch vụ, tìm tài khoản và lựa chọn mục tiêu.

**Persistence** giúp attacker quay lại hệ thống sau khi foothold ban đầu được thiết lập.

**Defence Evasion** quan trọng với đội phòng thủ vì giúp xác định các biện pháp đang bị né tránh và cải thiện khả năng phát hiện.

### 5.2. Through — Expand Access and Move Through the Network

Mục tiêu: Mở rộng quyền truy cập, khám phá mạng nội bộ và di chuyển sang các hệ thống khác khi attacker đã có foothold.

| Phase | Ý nghĩa | Ví dụ |
|---|---|---|
| Pivoting | Dùng máy đã chiếm làm điểm trung gian | Tạo đường đi vào mạng nội bộ |
| Discovery | Thu thập thông tin hệ thống và mạng | Tìm user, quyền, phần mềm, file, thư mục và network shares |
| Privilege Escalation | Nâng cấp quyền truy cập | Lợi dụng lỗ hổng hoặc cấu hình sai để có quyền cao hơn |
| Execution | Thực thi mã độc hoặc lệnh | Chạy trojan, C2 script hoặc scheduled task |
| Credential Access | Đánh cắp thông tin xác thực | Keylogging, credential dumping |
| Lateral Movement | Di chuyển ngang qua mạng | Dùng tài khoản hoặc quyền đã có để truy cập máy khác |

Các mức quyền attacker có thể nhắm đến gồm:
- SYSTEM / root
- Local Administrator
- Tài khoản có quyền tương đương admin
- Tài khoản có quyền truy cập hoặc chức năng cụ thể

**Discovery** giúp attacker xây dựng hiểu biết về môi trường. **Credential Access** hỗ trợ Privilege Escalation và Lateral Movement vì attacker có thể sử dụng thông tin xác thực hợp lệ để tiếp tục xâm nhập.

### 5.3. Out — Achieve Objectives

Mục tiêu: Truy cập tài sản quan trọng và hoàn thành mục tiêu tấn công. Các hành vi ở giai đoạn này thường tác động đến bộ ba CIA.

| Phase | Ý nghĩa | Ví dụ |
|---|---|---|
| Collection | Thu thập dữ liệu có giá trị | Tập hợp file, email, dữ liệu trình duyệt, âm thanh hoặc video |
| Exfiltration | Đưa dữ liệu ra khỏi môi trường mục tiêu | Nén hoặc mã hóa dữ liệu rồi truyền qua C2 channel |
| Impact | Làm tổn hại tính toàn vẹn hoặc tính sẵn sàng | Ransomware, xóa ổ đĩa, defacement, DoS |

#### Objectives — Mục tiêu cuối cùng

Động cơ của attacker quyết định cách sử dụng quyền truy cập đã có. Ví dụ:
- **Tài chính:** Mã hóa hệ thống bằng ransomware và đòi tiền chuộc.
- **Phá hoại danh tiếng:** Công khai dữ liệu riêng tư hoặc bí mật.
- **Phá hoại hoạt động:** Làm gián đoạn dịch vụ hoặc phá hủy dữ liệu.

#### CIA Triad

- **Confidentiality (Tính bảo mật):** Bảo vệ dữ liệu khỏi truy cập hoặc tiết lộ trái phép.
- **Integrity (Tính toàn vẹn):** Đảm bảo dữ liệu không bị sửa đổi hoặc phá hoại trái phép.
- **Availability (Tính sẵn sàng):** Đảm bảo hệ thống và dữ liệu có thể được sử dụng khi cần.

Collection và Exfiltration thường đe dọa Confidentiality; Impact có thể đe dọa Integrity và Availability.

## 6. UKC and MITRE ATT&CK

UKC bổ trợ cho MITRE ATT&CK bằng cách cung cấp góc nhìn về tiến trình tổng thể của cuộc tấn công, trong khi MITRE ATT&CK mô tả các tactics và techniques mà adversary sử dụng.

Một số MITRE ATT&CK tactics liên quan trong room:

| Tactic | ID |
|---|---|
| Reconnaissance | TA0043 |
| Initial Access | TA0001 |
| Execution | TA0002 |
| Persistence | TA0003 |
| Privilege Escalation | TA0004 |
| Defence Evasion | TA0005 |
| Credential Access | TA0006 |
| Discovery | TA0007 |
| Lateral Movement | TA0008 |
| Collection | TA0009 |
| Command and Control | TA0011 |
| Exfiltration | TA0010 |
| Impact | TA0040 |

*Lưu ý: Các phase của UKC và tactics của MITRE ATT&CK không phải lúc nào cũng tương ứng một-một. Bảng trên ghi lại các ID được đề cập trong nội dung room.*

## 7. Key Takeaways

- **Kill Chain:** Mô tả tiến trình attacker thực hiện để đạt mục tiêu.
- **Threat Modelling:** Xác định tài sản, phân tích rủi ro và lập kế hoạch phòng thủ.
- **UKC:** Có 18 phase chính thức và bao quát toàn bộ cuộc tấn công.
- **In:** Thu thập thông tin, xâm nhập và thiết lập foothold.
- **Through:** Khám phá, nâng quyền, đánh cắp credentials và di chuyển ngang.
- **Out:** Thu thập dữ liệu, đưa dữ liệu ra ngoài và gây tác động.
- **Pivoting:** Dùng hệ thống đã xâm nhập làm điểm trung gian.
- **Persistence:** Duy trì khả năng truy cập.
- **Lateral Movement:** Di chuyển sang hệ thống khác trong mạng.
- **CIA Triad:** Confidentiality, Integrity, Availability — ba thuộc tính bảo mật cần bảo vệ.
- **UKC và MITRE ATT&CK:** Bổ trợ nhau để hiểu tiến trình tấn công và các kỹ thuật cụ thể của attacker.
