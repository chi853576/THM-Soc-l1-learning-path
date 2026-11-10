# MITRE

## Task 1: Introduction to MITRE ATT&CK

### 1. MITRE là gì?
MITRE là tổ chức phi lợi nhuận hoạt động trong các lĩnh vực như cybersecurity, AI, healthcare và space systems. Sứ mệnh của tổ chức là giải quyết các vấn đề nhằm xây dựng một thế giới an toàn hơn.

Các tài nguyên chính trong room:
- **MITRE ATT&CK:** Knowledge base về hành vi của adversary.
- **CAR (Cyber Analytics Repository):** Tập hợp các analytics phục vụ phát hiện hành vi tấn công.
- **D3FEND:** Framework về kỹ thuật phòng thủ.
- **MITRE Engage:** Framework hỗ trợ xây dựng chiến lược tương tác với adversary.
- **Caldera, ATLAS, AADAPT:** Các công cụ và framework chuyên biệt.

### 2. MITRE ATT&CK
MITRE ATT&CK là knowledge base công khai, mô tả tactics và techniques của adversary dựa trên các quan sát thực tế.

Năm 2013, MITRE nhận thấy cần chuẩn hóa việc ghi nhận và phân loại **TTPs** được sử dụng bởi các nhóm APT.

| Thành phần | Ý nghĩa | Câu hỏi |
|---|---|---|
| Tactic | Mục tiêu của adversary | Why? |
| Technique | Cách adversary đạt mục tiêu | How? |
| Procedure | Cách triển khai technique cụ thể | How exactly? |

### 3. Sự phát triển của ATT&CK
Ban đầu tập trung vào Windows, ATT&CK đã mở rộng sang nhiều môi trường:
- **Enterprise:** Windows, macOS, Linux, Cloud và các môi trường doanh nghiệp khác.
- **Mobile:** Các mối đe dọa trên thiết bị di động.
- **ICS:** Các hệ thống điều khiển công nghiệp.

ATT&CK được sử dụng cho cả phòng thủ lẫn mô phỏng tấn công. Red team có thể dựa vào framework để xây dựng các cuộc tấn công mô phỏng thực tế và kiểm tra khả năng phòng thủ.

### 4. ATT&CK Matrix
ATT&CK Matrix trình bày trực quan các tactics và techniques:
- Tactics nằm ở phía trên ma trận.
- Techniques được liệt kê bên dưới từng tactic.
- Một technique có thể chứa nhiều sub-techniques.

**Ví dụ:**

Reconnaissance → Active Scanning → Scanning IP Blocks / Vulnerability Scanning / Wordlist Scanning.

Trang chi tiết của mỗi technique thường có:
- ID và mô tả.
- Sub-techniques.
- Procedure examples: các nhóm, phần mềm và chiến dịch từng sử dụng technique.
- Mitigations và detections.
- References.

**ATT&CK Navigator** hỗ trợ khám phá ma trận, đánh dấu techniques và trực quan hóa phạm vi phân tích.

---

## Task 2: How Is ATT&CK Used?

### 1. Tại sao ATT&CK quan trọng?
ATT&CK cung cấp thuật ngữ chuẩn hóa và ID riêng cho hành vi adversary, giúp:
- Mô tả và so sánh các sự cố bảo mật.
- Giao tiếp nhất quán giữa các nhóm security.
- Chuyển threat intelligence thành detection logic, truy vấn SIEM/EDR và playbooks.
- Xác định các kỹ thuật chưa được phòng thủ hoặc phát hiện đầy đủ.

### 2. Các đối tượng sử dụng ATT&CK

| Đối tượng | Cách sử dụng |
|---|---|
| CTI teams | Ánh xạ hành vi threat actor vào TTPs để xây dựng threat profile. |
| SOC analysts | Liên kết hoạt động đáng ngờ với tactics/techniques để hiểu alert và ưu tiên xử lý. |
| Detection engineers | Ánh xạ detection rules vào ATT&CK để đánh giá độ bao phủ. |
| Incident responders | Phân tích timeline sự cố theo tactics và techniques. |
| Red/Purple teams | Xây dựng kế hoạch mô phỏng và kiểm thử phòng thủ. |

### 3. Ví dụ: Mustang Panda
**Mustang Panda (G0129)** là nhóm threat actor được ATT&CK ghi nhận, có hoạt động nhắm vào các tổ chức như cơ quan chính phủ, tổ chức phi lợi nhuận và NGO.

Một số hành vi có thể phân tích:
- Phishing để giành initial access.
- Scheduled Tasks để duy trì persistence.
- File obfuscation để né tránh phát hiện.
- Ingress Tool Transfer để đưa công cụ vào hệ thống.

Khi phân tích một threat group, nên xem trang Groups, các techniques được liên kết và ATT&CK Navigator layer để hiểu cách nhóm đó hoạt động.

---

## Task 3: Threat Intelligence and Threat Profiling

### Tình huống
Bạn là security analyst tại một tổ chức thuộc ngành hàng không. Tổ chức đang chuyển hạ tầng lên cloud và cần đánh giá các mối đe dọa liên quan.

### Quy trình phân tích
1. Truy cập mục **Groups** trong ATT&CK.
2. Tìm các APT groups nhắm vào ngành hàng không.
3. Xem tactics và techniques được ghi nhận cho từng nhóm.
4. Sử dụng ATT&CK Navigator để trực quan hóa các techniques.
5. Đối chiếu với hệ thống hiện tại để xác định khoảng trống phòng thủ.
6. Ưu tiên các biện pháp bảo vệ phù hợp với môi trường cloud đang triển khai.

**Mục tiêu:** Chuyển thông tin về threat actors thành threat profile có thể hành động, phục vụ đánh giá rủi ro và cải thiện khả năng phòng thủ.

---

## Task 4: Cyber Analytics Repository (CAR)

### 1. CAR là gì?
**Cyber Analytics Repository (CAR)** là tập hợp các detection analytics được xây dựng xoay quanh MITRE ATT&CK.

Mỗi analytic mô tả cách phát hiện một hành vi adversary và có thể cung cấp:
- Mô tả hành vi cần phát hiện.
- Logic hoặc mẫu nhận diện.
- Pseudocode.
- Ví dụ truy vấn cho các công cụ như Splunk hoặc LogPoint.
- Unit tests trong một số trường hợp để xác thực hành vi mong đợi.

Không phải analytic nào cũng có đầy đủ mọi loại triển khai.

### 2. Ví dụ
`CAR-2020-09-001: Scheduled Task - File Access`

Đây là ví dụ về analytic liên quan đến việc truy cập file thông qua Scheduled Task.

### 3. CAR và ATT&CK
CAR có **ATT&CK Navigator layer** giúp hiển thị các techniques mà những analytics hiện có bao phủ.

Quy trình sử dụng:
1. Tìm analytic phù hợp trong CAR Analytics List.
2. Đọc mô tả và logic phát hiện.
3. Xem truy vấn hoặc pseudocode có sẵn.
4. Đối chiếu với log và công cụ đang sử dụng.
5. Kiểm tra độ bao phủ thông qua Navigator layer.

**Ghi nhớ:** ATT&CK mô tả hành vi adversary; CAR cung cấp analytics hỗ trợ phát hiện những hành vi đó.

---

## Task 5: D3FEND

### 1. D3FEND là gì?
**D3FEND** là viết tắt của *Detection, Denial, and Disruption Framework Empowering Network Defense*.

Đây là framework có cấu trúc nhằm mô tả các defensive techniques và tạo ngôn ngữ chung cho các biện pháp phòng thủ an ninh mạng.

D3FEND tổ chức các defensive techniques theo các nhóm tactics; mỗi technique có ID riêng.

### 2. Ví dụ: Credential Rotation
- **ID:** `D3-CRO`
- **Mục tiêu:** Thường xuyên thay đổi thông tin xác thực để hạn chế khả năng sử dụng lại credential bị đánh cắp.
- **Nội dung tham khảo:** Cách thức hoạt động, lưu ý khi triển khai và mối liên hệ với digital artifacts cũng như ATT&CK techniques.

### 3. ATT&CK và D3FEND

| Framework | Trọng tâm | Mục đích |
|---|---|---|
| MITRE ATT&CK | Hành vi của adversary | Hiểu và phân loại cách attacker hoạt động. |
| MITRE D3FEND | Biện pháp phòng thủ | Xác định và mô tả các defensive techniques. |

**Ghi nhớ:** ATT&CK giúp xác định attacker làm gì; D3FEND giúp tìm hiểu các biện pháp phòng thủ có thể áp dụng.

---

## Task 6: Other MITRE Tools and Frameworks

### 1. Adversary Emulation Library
Thư viện miễn phí cung cấp các kế hoạch mô phỏng tấn công từng bước, dựa trên hành vi của các threat groups ngoài đời thực.

- Hỗ trợ xây dựng các bài kiểm thử sát với hành vi adversary.
- Chủ yếu được duy trì và đóng góp bởi **CTID (Center for Threat-Informed Defense)**.

### 2. Caldera
**Caldera** là công cụ tự động hóa adversary emulation dựa trên ATT&CK.

Mục đích sử dụng:
- Mô phỏng hành vi attacker trong môi trường có kiểm soát.
- Kiểm tra detection và khả năng phòng thủ.
- Thực hành incident response.
- Hỗ trợ các bài tập red team và blue team.

### 3. AADAPT
**AADAPT (Adversarial Actions in Digital Asset Payment Technologies)** là knowledge base/framework về các tactics và techniques nhắm vào hệ thống quản lý, thanh toán tài sản số.

Phạm vi có thể bao gồm:
- Blockchain networks.
- Smart contracts.
- Digital wallets.

### 4. ATLAS
**ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)** là framework và knowledge base về các mối đe dọa nhắm vào hệ thống AI/ML.

Nội dung tập trung vào:
- Các kỹ thuật tấn công thực tế.
- Vulnerabilities của hệ thống AI/ML.
- Các biện pháp giảm thiểu rủi ro.

---

## Task 7: MITRE ATT&CK Framework

### 1. TTPs
MITRE ATT&CK chuẩn hóa cách mô tả hành vi adversary thông qua TTPs:

- **Tactic:** Mục tiêu của cuộc tấn công — *Why*.
- **Technique:** Cách đạt được mục tiêu — *How*.
- **Procedure:** Cách technique được thực hiện cụ thể.

### 2. ATT&CK Matrix và Sub-techniques
Ma trận sắp xếp tactics và techniques theo cấu trúc trực quan. Các techniques có thể được mở rộng để xem sub-techniques.

Ví dụ:

| Cấp độ | Ví dụ | Ý nghĩa |
|---|---|---|
| Tactic | Reconnaissance | Thu thập thông tin về mục tiêu. |
| Technique | Active Scanning | Chủ động quét mục tiêu. |
| Sub-technique | Scanning IP Blocks | Quét các dải địa chỉ IP. |
| Sub-technique | Vulnerability Scanning | Quét tìm lỗ hổng. |
| Sub-technique | Wordlist Scanning | Quét bằng danh sách từ. |

### 3. Trang chi tiết technique
Khi nghiên cứu một technique, cần chú ý:
- **Technique ID:** Mã định danh để tra cứu và tham chiếu.
- **Description:** Mô tả hành vi.
- **Sub-techniques:** Các phương pháp cụ thể hơn.
- **Procedure examples:** Ví dụ từ các threat groups, phần mềm hoặc chiến dịch.
- **Mitigations:** Biện pháp giảm thiểu.
- **Detections:** Hướng dẫn hoặc thông tin hỗ trợ phát hiện.
- **References:** Nguồn tham khảo.

### 4. Công cụ hỗ trợ
- **ATT&CK Navigator:** Khám phá ma trận, đánh dấu và phân tích độ bao phủ techniques.
- **ATT&CK Groups:** Nghiên cứu threat actors và các hành vi được ghi nhận.
- **ATT&CK Matrix:** Tổng quan tactics và techniques theo từng môi trường.


