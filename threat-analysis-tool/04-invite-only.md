# Invite Only

**Nguồn học chính:** [TryHackMe – Threat Analysis Tools module](https://tryhackme.com/module/threat-analysis-tools)  
**Room:** Invite Only (Challenge)  
**Chủ đề:** Pivoting giữa các artefact, điều tra mối quan hệ file–process–IP, xác định malware/campaign và chuyển kết quả thành threat intelligence có thể hành động.

> **Phạm vi và tính minh bạch của tài liệu:** Trang module công khai của TryHackMe mô tả *Invite Only* là challenge yêu cầu trích xuất insight từ các artefact được gắn cờ và chuyển chúng thành threat intelligence. Nội dung chi tiết của room/lab không được hiển thị đầy đủ khi chưa truy cập môi trường học. Vì vậy, tài liệu này ghi lại phương pháp điều tra phù hợp với mục tiêu room và bổ sung bối cảnh chiến dịch từ báo cáo nghiên cứu công khai của Check Point Research. Đây không phải bản chép nội dung lab và không chứa đáp án/flag của challenge.

---

## Task 1: Introduction – Bối cảnh điều tra

### 1. Vai trò của analyst

Room đặt người học vào vai trò SOC analyst hỗ trợ một analyst cấp cao hơn trong quá trình điều tra các indicator đáng ngờ. Đầu vào là những artefact đã được phát hiện và chuyển cấp; nhiệm vụ là bổ sung bối cảnh để xác định chúng có liên hệ với nhau như thế nào và tạo ra intelligence có thể sử dụng.

Điểm cốt lõi không phải chỉ tra một IP hoặc một hash, mà là **pivoting** – dùng kết quả của một lượt tra cứu để mở rộng sang artefact liên quan.

### 2. Công cụ chính

**TryDetectThis 2.0** là ứng dụng threat-intelligence trong môi trường lab, được dùng để tra cứu và kết nối dữ liệu liên quan đến file, hash, process, IP, malware family và các nguồn threat report.

Có thể hình dung công cụ như một điểm tập trung enrichment: analyst tra cứu một indicator, đọc các tab/thông tin liên quan, sau đó pivot sang indicator kế tiếp.

### 3. Vì sao pivoting quan trọng?

Một hash riêng lẻ chỉ cung cấp thông tin nhận diện file. Khi pivot qua process ancestry, dropped files, network indicators và threat reports, analyst có thể hình thành chuỗi sự kiện rõ hơn:

`Hash → File → Process chain → Dropped files → Network indicators → Malware family → Campaign / TTP`

Một kết quả riêng lẻ có thể chưa đủ ý nghĩa; các mối quan hệ giữa nhiều artefact mới giúp mô tả cách thức xâm nhập và hoạt động của đối phương.

---

## Task 2: Điều tra file artefact và process lineage

### 1. File identification

Khi nhận một file hash đáng ngờ, cần xác minh file mà hash đại diện và thu thập metadata liên quan.

Các trường nên quan sát:

- Filename và file type.
- SHA-256/MD5 nếu có.
- Kích thước file và metadata.
- Thời gian first seen/first submitted nếu nguồn cung cấp.
- Detection labels và malware family.
- Nguồn dữ liệu tạo ra nhận định.

Tên file có thể bị thay đổi; hash giúp pivot tới cùng một nội dung file qua nhiều nguồn khác nhau.

### 2. Process ancestry – Quan hệ tiến trình cha/con

**Process ancestry** mô tả tiến trình nào khởi tạo tiến trình nào. Khi điều tra malware, cần đọc process tree theo trình tự thời gian.

Các câu hỏi nên đặt ra:

- Process ban đầu xuất phát từ user action, trình duyệt, email client hay một scheduled task?
- Process cha có hợp lý với vai trò của process con không?
- Command line có chứa tham số tải file, chạy script hoặc ẩn cửa sổ không?
- Có tiến trình nào được khởi chạy từ thư mục tạm hoặc thư mục user-writable không?
- Process có tạo ra file, sửa registry hoặc kết nối mạng bất thường không?

Không nên đánh giá tiến trình chỉ dựa trên tên. Cần đối chiếu executable path, signature, hash, parent process, command line và thời điểm thực thi.

### 3. Dropped files và second-stage payload

Malware nhiều giai đoạn có thể tải hoặc giải nén các thành phần khác nhau trong quá trình thực thi.

Khi phát hiện file được tạo ra bởi một process:

1. Ghi lại tên file, path và thời gian tạo.
2. Tính hash của file đó nếu mẫu được cung cấp an toàn.
3. Tra cứu hash độc lập, không giả định file con cùng verdict với file cha.
4. Tìm process tạo file và process thực thi file đó.
5. Ghi nhận các network connections liên quan đến quá trình tải xuống.
6. Liên kết file con với process cha trong timeline.

Việc pivot từ file cha sang dropped files giúp phát hiện payload mà alert ban đầu chưa trực tiếp chỉ ra.

---

## Task 3: Network pivot và malware attribution

### 1. IP enrichment

Khi một process hoặc malware sample có liên hệ với IP đáng ngờ, cần bổ sung:

- ASN và network owner.
- Hosting provider / ISP.
- Geolocation ước tính.
- Reputation từ nhiều nguồn.
- Service exposure hoặc banner nếu có dữ liệu.
- Quan hệ với domain, URL, hash và các campaign khác.
- Thời gian indicator được quan sát.

Không kết luận một IP độc hại chỉ vì nó thuộc datacenter, VPN hoặc một quốc gia nhất định. Cần xác định IP đó liên quan đến hành vi nào trong chuỗi điều tra.

### 2. Malware family identification

Một malware family label giúp analyst hiểu loại năng lực mà mẫu file có thể sở hữu, ví dụ remote access, credential theft, information stealing hoặc downloader.

Khi đọc malware family attribution:

- Kiểm tra label đến từ nguồn nào.
- Xem có nhiều nguồn độc lập đồng thuận không.
- Đối chiếu hành vi của sample với đặc điểm family.
- Ghi lại mức độ chắc chắn; không coi tên family là kết luận tuyệt đối.
- Tìm threat report gốc để hiểu mục tiêu, phương thức phát tán và hạ tầng của campaign.

### 3. Community / report references

Phần community hoặc các tham chiếu trong threat-intelligence platform có thể dẫn tới:

- Bình luận của analyst khác.
- Threat report của security vendor.
- Malware family hoặc campaign liên quan.
- IOC bổ sung và mối quan hệ hạ tầng.

Thông tin community hữu ích cho pivot nhưng phải được kiểm chứng bằng báo cáo kỹ thuật hoặc dữ liệu độc lập. Không nên sao chép kết luận chưa xác minh vào báo cáo của mình.

---

## Task 4: Threat report research – Đọc báo cáo chiến dịch

Một phần quan trọng của threat intelligence là chuyển các indicator kỹ thuật thành bối cảnh chiến dịch. Room này liên hệ với báo cáo công khai của Check Point Research:

**“From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery”** (12 June 2025).

### 1. Ý tưởng tấn công: Lạm dụng liên kết Discord invite

Báo cáo mô tả việc attacker lợi dụng các Discord invite link đã hết hạn hoặc được giải phóng để chiếm quyền sử dụng mã invite và chuyển hướng người dùng từ nguồn từng đáng tin cậy sang server độc hại.

Bài học về trust:

- Một đường dẫn được chia sẻ trên website cộng đồng hoặc mạng xã hội có thể từng hợp pháp.
- Khi invite hết hạn và bị chiếm dụng, cùng một đường dẫn có thể dẫn tới server khác.
- Người dùng thường tin tưởng nguồn chia sẻ cũ mà không kiểm tra lại đích đến.
- Tên thương hiệu, giao diện quen thuộc và quy trình xác minh giả có thể làm giảm cảnh giác.

**Góc nhìn analyst:** Không đánh giá độ an toàn của URL chỉ dựa trên việc nó xuất hiện trên website có uy tín. Cần xác minh redirect và destination tại thời điểm người dùng truy cập.

### 2. Fake verification và OAuth/social engineering

Trong mô tả chiến dịch, người dùng được đưa tới server Discord giả mạo có giao diện và quy trình xác minh trông hợp pháp. Sau đó, một bot hướng người dùng sang website bên ngoài.

Các điểm cần quan sát khi điều tra:

- Invite URL ban đầu và redirect chain.
- Tên server, channel, bot và nội dung hướng dẫn.
- Website được mở sau thao tác verify.
- Quyền OAuth hoặc thông tin profile mà ứng dụng yêu cầu.
- Các script, URL hoặc hành động được tạo ra từ trang phishing.

Không nên tin một quy trình xác minh chỉ vì giao diện có logo hoặc cách trình bày giống dịch vụ chính thức.

### 3. ClickFix – Social engineering yêu cầu người dùng tự thực thi lệnh

**ClickFix** là kỹ thuật social engineering trong đó website giả vờ có lỗi hoặc bước kiểm tra không hoạt động, sau đó hướng dẫn người dùng tự thực hiện thao tác “sửa lỗi”.

Trong kiểu tấn công này:

1. Website hiển thị CAPTCHA hoặc bước xác minh giả.
2. Người dùng được hướng dẫn mở hộp thoại hệ điều hành hoặc terminal.
3. Nội dung độc hại có thể được copy vào clipboard mà người dùng không nhận ra.
4. Người dùng paste và thực thi nội dung theo hướng dẫn của website.
5. Script/command có thể tải và chạy payload tiếp theo.

MITRE ATT&CK mô tả ClickFix trong kỹ thuật **T1204.004 – User Execution: Malicious Copy and Paste**.

**Detection ideas:**

- Browser hoặc process liên quan đến website khởi chạy command interpreter bất thường.
- PowerShell được gọi ngay sau thao tác copy/paste hoặc truy cập website đáng ngờ.
- Command line có biểu hiện download-and-execute.
- Process con phát sinh từ hành vi người dùng không phù hợp với hoạt động bình thường.

### 4. Multi-stage payload delivery

Báo cáo mô tả một chuỗi nhiều giai đoạn, kết hợp website phishing, Pastebin, GitHub và Bitbucket để phân phối các thành phần khác nhau.

Mô hình tổng quát:

```text
Trusted-looking invite / community link
                 |
                 v
     Redirect to malicious Discord server
                 |
                 v
       Fake verification / phishing page
                 |
                 v
       ClickFix social engineering
                 |
                 v
       User runs malicious command
                 |
                 v
        Script / first-stage downloader
                 |
                 v
        Additional loaders / payloads
                 |
          +------+------+
          |             |
          v             v
     Remote access   Information / credential
        payload          stealing payload
          |             |
          +------+------+
                 |
                 v
        C2 / data exfiltration
```

Các nền tảng cloud hoặc dịch vụ chia sẻ nội dung hợp pháp có thể bị lạm dụng làm nơi lưu trữ và phân phối payload. Do đó, phân loại một domain theo thương hiệu dịch vụ không đủ để kết luận hành vi an toàn.

### 5. Một số năng lực malware được báo cáo

Báo cáo nghiên cứu đề cập đến nhiều thành phần, trong đó có:

- **AsyncRAT:** Remote Access Trojan có thể cung cấp khả năng điều khiển từ xa đối với máy bị xâm nhập.
- **Skuld Stealer:** Malware đánh cắp thông tin, trong đó có dữ liệu trình duyệt, Discord và dữ liệu ví tiền mã hóa theo phạm vi mẫu được nghiên cứu.
- **ChromeKatz:** Công cụ được điều chỉnh để truy xuất browser cookies từ các trình duyệt Chromium trong bối cảnh các cơ chế bảo vệ cookie mới hơn.

Các tên trên là bối cảnh của báo cáo chiến dịch, không nên mặc định mọi sample trong cùng một room hoặc mọi incident có Discord đều chứa các thành phần này.

### 6. C2 và exfiltration

Báo cáo cho thấy kẻ tấn công có thể lạm dụng dịch vụ phổ biến như Discord webhook để gửi dữ liệu ra ngoài. Điều này minh họa một vấn đề quan trọng trong network monitoring: traffic tới một dịch vụ hợp pháp vẫn có thể mang nội dung độc hại.

Khi phân tích:

- Xác định process nào tạo kết nối.
- Ghi nhận domain, URL, IP, protocol và timestamp.
- Kiểm tra request pattern và dữ liệu truyền nếu log cho phép.
- Đối chiếu với hành vi của process và các artefact khác.
- Phân biệt kết nối dịch vụ hợp pháp của ứng dụng bình thường với kết nối được tạo ra bởi process đáng ngờ.

---

## Quy trình điều tra tổng hợp cho Invite Only

### 1. Pivoting checklist

| Bước | Câu hỏi phân tích | Dữ liệu cần ghi |
|---|---|---|
| 1. Initial hash | Hash đại diện cho file nào? | Filename, file type, SHA-256, metadata, reputation. |
| 2. File context | File đến từ đâu và xuất hiện khi nào? | Source, timestamp, filepath, signature. |
| 3. Process lineage | Process nào khởi chạy file? Có process cha/con nào bất thường? | Parent/child process, command line, execution time. |
| 4. Dropped files | File nào được tạo/tải thêm? | Filename, hash, path, creator process. |
| 5. Network activity | Process kết nối đến hạ tầng nào? | IP, domain, URL, protocol, timestamp. |
| 6. IP/domain context | Hạ tầng thuộc network/provider nào? Có reputation hoặc campaign link không? | ASN, geolocation, hosting, passive DNS, reputation. |
| 7. Malware family | Mẫu có liên hệ đến family nào? | Labels, source, behavior match, confidence. |
| 8. Threat report | Có báo cáo gốc nào giải thích chiến dịch? | Report title, vendor, date, attack chain, TTP. |
| 9. ATT&CK mapping | Hành vi nào được quan sát và kỹ thuật nào phù hợp? | Technique ID, evidence và thời điểm. |
| 10. Assessment | Những kết luận nào có đủ bằng chứng? | Timeline, confidence, impact, recommendation. |

### 2. Correlation matrix

Có thể dùng bảng quan hệ sau để tránh ghi nhận artefact rời rạc:

| From | Relation | To | Evidence |
|---|---|---|---|
| Hash A | Identifies | File A | Threat-intelligence lookup / file metadata. |
| Process A | Creates / launches | Process B | Process tree hoặc EDR telemetry. |
| Process B | Drops | File B | Filesystem event / sandbox report. |
| File B | Connects to | Domain/IP | Sandbox network log hoặc endpoint telemetry. |
| Domain/IP | Associated with | Infrastructure / campaign | Reputation, passive DNS, vendor report. |
| Behavior | Maps to | ATT&CK technique | Command line, process event, network event hoặc forensic evidence. |

### 3. Mẫu threat intelligence report

**Executive summary**  
Tóm tắt một đến ba câu về sự kiện, phạm vi điều tra và đánh giá hiện tại.

**Initial indicators**  
Liệt kê loại indicator nhận được, nguồn phát hiện và thời điểm ghi nhận. Có thể defang IP/domain/URL trong báo cáo chia sẻ.

**Technical findings**

- File identity và hash.
- Process ancestry và command line.
- Dropped files và payload stages.
- Network infrastructure và các mối quan hệ.
- Malware family/campaign attribution.
- ATT&CK techniques, kèm bằng chứng cụ thể.

**Assessment**  
Nêu mức confidence, bằng chứng hỗ trợ, dữ liệu còn thiếu và các giả thuyết chưa xác minh.

**Impact / risk**  
Đánh giá khả năng truy cập từ xa, đánh cắp dữ liệu, đánh cắp session/cookie hoặc các tác động liên quan dựa trên hành vi đã quan sát.

**Recommended actions**

- Hunt các hash, domain, URL và process liên quan trong telemetry nội bộ.
- Kiểm tra process ancestry, scheduled tasks, persistence và log đăng nhập.
- Block/quarantine khi bằng chứng và chính sách cho phép.
- Reset/revoke session hoặc credential khi có căn cứ bị đánh cắp.
- Theo dõi các domain/IP/payload liên quan và cập nhật detection.

**Sources and handling**  
Ghi rõ nguồn, ngày tra cứu và nhãn TLP nếu được cung cấp.

---

## Ghi nhớ và giá trị ứng dụng

- Pivoting là kỹ năng cốt lõi: một hash có thể dẫn đến file, parent process, dropped file, IP, malware family và campaign.
- Process tree giúp hiểu cách file được thực thi và tạo ra hoạt động tiếp theo.
- Dropped files cần được phân tích độc lập bằng hash/reputation riêng.
- IP enrichment phải kết hợp ASN, reputation, network context và local evidence.
- Threat reports cung cấp bối cảnh về mục tiêu, delivery, payload, C2 và exfiltration.
- ClickFix cho thấy người dùng có thể bị lừa tự thực thi lệnh; detection nên quan sát chuỗi browser-to-command-interpreter.
- Một dịch vụ phổ biến như Discord, GitHub, Bitbucket hoặc Pastebin có thể bị lạm dụng; cần đánh giá hành vi và quan hệ, không chỉ nhìn thương hiệu dịch vụ.
- Báo cáo analyst cần trình bày chuỗi bằng chứng, confidence, giới hạn và hành động đề xuất; không chỉ liệt kê đáp án của challenge.

**Năng lực có thể thể hiện trong portfolio:** Điều tra theo hướng pivoting, xây dựng process/file/network relationship, đối chiếu malware family với threat report, ánh xạ hành vi sang ATT&CK và viết threat intelligence report có căn cứ.

---

## Tài liệu tham khảo

1. [TryHackMe – Threat Analysis Tools module](https://tryhackme.com/module/threat-analysis-tools)
2. [TryHackMe – Invite Only (được liệt kê trong module Threat Analysis Tools)](https://tryhackme.com/module/threat-analysis-tools)
3. [Check Point Research – From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery (12 June 2025)](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
4. [MITRE ATT&CK – T1204.004: Malicious Copy and Paste (ClickFix)](https://attack.mitre.org/techniques/T1204/004/)
5. [MITRE ATT&CK – Enterprise Techniques](https://attack.mitre.org/techniques/)
6. [FIRST – Traffic Light Protocol (TLP)](https://www.first.org/tlp/)

---

## Ghi chú về độ bao phủ

Room *Invite Only* được TryHackMe giới thiệu công khai ở cấp module là challenge phân tích artefact để tạo threat intelligence. Các nội dung chi tiết của lab và dữ liệu trong TryDetectThis 2.0 cần được xác minh trực tiếp trong tài khoản/lab của người học. Phần mô tả chiến dịch Discord/ClickFix/malware trong tài liệu này được đối chiếu với báo cáo công khai của Check Point Research; đây là kiến thức nền liên quan, không khẳng định mọi chi tiết của báo cáo đều là đáp án hoặc dữ liệu xuất hiện nguyên văn trong room.
