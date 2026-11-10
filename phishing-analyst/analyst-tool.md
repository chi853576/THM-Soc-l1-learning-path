# Phishing Analysis Tools


## Task 1: Introduction

### Mục tiêu
Học cách sử dụng các công cụ hỗ trợ điều tra email đáng ngờ, bao gồm:
- Phân tích email headers.
- Trích xuất và kiểm tra hyperlinks.
- Kiểm tra reputation của IP, domain và URL.
- Tính hash và kiểm tra file đính kèm.
- Sử dụng malware sandbox để quan sát hành vi.
- Phân tích các case phishing thực tế.

**Cảnh báo:** Các mẫu trong room có thể chứa IP, domain và file độc hại. Không nhấp vào link hoặc chạy attachment trên máy cá nhân.

---

## Task 2: Identifying Artifacts

### 1. Thu thập thông tin từ email header

| Artifact | Thông tin cần thu thập |
|---|---|
| Sender email | Địa chỉ người gửi thực tế. |
| Sender IP | IP nguồn hoặc IP liên quan đến máy chủ gửi. |
| Reverse lookup | Hostname hoặc thông tin DNS liên quan đến IP. |
| Subject | Tiêu đề email. |
| Recipient | Địa chỉ người nhận, kể cả CC/BCC. |
| Reply-To | Địa chỉ nhận phản hồi nếu có. |
| Date/Time | Thời gian được ghi nhận trong email. |

### 2. Thu thập thông tin từ email body và attachment

- Hyperlinks và URL đích thực tế.
- URL gốc nếu email sử dụng URL shortener.
- Tên file đính kèm.
- Hash của file, ưu tiên SHA-256.
- Các domain, IP hoặc indicators liên quan đến hành vi đáng ngờ.

**Ghi nhớ:** Artifact là dữ liệu có thể thu thập và sử dụng làm bằng chứng trong quá trình điều tra.

---

## Task 3: Email Header Analysis

### 1. Công cụ phân tích header

| Công cụ | Công dụng |
|---|---|
| [Google Admin Toolbox – Messageheader](https://toolbox.googleapps.com/apps/messageheader/analyzeheader) | Phân tích SMTP headers, đường đi của email và độ trễ. |
| [Message Header Analyzer](https://mha.azurewebsites.net/) | Trình bày header theo cấu trúc dễ đọc. |
| [Mailheader.org](https://mailheader.org/) | Trích xuất và phân tích thông tin từ raw headers. |

**MTA (Message Transfer Agent):** Hệ thống chuyển email giữa các mail server.

**MUA (Mail User Agent):** Ứng dụng người dùng dùng để đọc và gửi email, ví dụ Outlook hoặc Thunderbird.

### 2. Phân tích sender IP

Công cụ: [IPinfo](https://ipinfo.io/)

Có thể dùng để kiểm tra:
- Thông tin đăng ký và tổ chức sở hữu IP.
- Vị trí địa lý ước tính.
- Thông tin mạng liên quan.

Không nên xem địa chỉ địa lý của IP là vị trí chính xác của attacker. IP có thể thuộc VPN, proxy, cloud hosting hoặc mail server hợp pháp.

### 3. Kiểm tra URL

**[URLScan.io](https://urlscan.io/)** có thể ghi nhận:
- Domain và IP được website yêu cầu.
- Scripts và resources được tải.
- DOM content và cookies.
- Screenshot của trang web.
- Dấu hiệu giả mạo thương hiệu.

**[Cisco Talos Reputation Center](https://talosintelligence.com/reputation)** hỗ trợ kiểm tra reputation của IP, domain và URL.

### 4. Ví dụ: `capitai-one.com`

Domain `capitai-one.com` được tạo để giống với website của ngân hàng Capital One.

- Domain chính thức: `capitalone.com`
- Domain đáng ngờ: `capitai-one.com`

Khác biệt nhỏ giữa các ký tự có thể khiến người dùng nhầm lẫn. Đây là một ví dụ về **typosquatting**.

---

## Task 4: Email Body Analysis

### 1. Trích xuất hyperlinks

Có thể lấy URL bằng cách:
- Nhấp chuột phải vào hyperlink và chọn **Copy Link Location**.
- Kiểm tra raw email source, tìm thuộc tính `href`.
- Sử dụng công cụ tự động trích xuất URL.

Công cụ:
- [URL Extractor](https://www.convertcsv.com/url-extractor.htm)
- [CyberChef](https://gchq.github.io/CyberChef/), thao tác `Extract URLs`.

Sau khi trích xuất, cần kiểm tra cả URL đầy đủ lẫn root domain. Không nên chỉ tin vào phần chữ hiển thị trên nút bấm.

### 2. Kiểm tra file đính kèm

Quy trình an toàn:
1. Lưu file mà không mở hoặc thực thi.
2. Ghi lại tên file và loại file.
3. Tính SHA-256.
4. Kiểm tra hash bằng dịch vụ reputation.
5. Nếu cần, phân tích file trong sandbox.

Ví dụ trên Linux:

```bash
sha256sum "filename.pdf"
```

Kết quả sẽ chứa hash SHA-256 và tên file.

### 3. Công cụ kiểm tra file

| Công cụ | Công dụng |
|---|---|
| [Cisco Talos File Reputation](https://talosintelligence.com/talos_file_reputation) | Tra cứu reputation của file bằng hash. |
| [VirusTotal](https://www.virustotal.com/gui/) | Tổng hợp kết quả từ nhiều antivirus engines và nguồn phân tích. |
| [ReversingLabs](https://register.reversinglabs.com/) | Tra cứu file reputation và threat intelligence. |

### Câu hỏi thực hành
Để lấy vị trí của hyperlink theo cách thủ công:

**Đáp án:** `Copy Link Location`

---

## Task 5: Malware Sandboxes

### 1. Sandbox là gì?

Malware sandbox là môi trường cô lập dùng để quan sát hành vi của file hoặc URL đáng ngờ mà không trực tiếp phơi nhiễm hệ thống làm việc thông thường.

Sandbox có thể ghi nhận:
- Domain và IP mà file cố gắng kết nối.
- Payload bổ sung được tải xuống.
- Process được tạo.
- File được ghi hoặc thay đổi.
- Registry modifications.
- Persistence mechanisms.
- Indicators of Compromise (IOCs).

### 2. Các công cụ sandbox

| Công cụ | Đặc điểm |
|---|---|
| [ANY.RUN](https://app.any.run/) | Sandbox tương tác, cho phép quan sát hành vi trong thời gian thực. |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | Phân tích file và hành vi đáng ngờ. |
| [Joe Sandbox](https://www.joesecurity.org/) | Phân tích hành vi chuyên sâu, hỗ trợ mapping và threat hunting. |

**Ghi nhớ:** Sandbox cung cấp bằng chứng về hành vi của mẫu trong một môi trường cụ thể. Một file không thể hiện hành vi độc hại trong lần chạy đó chưa chắc đã an toàn.

---

## Task 6: Using PhishTool

### 1. PhishTool là gì?

**PhishTool** là nền tảng hỗ trợ điều tra và phân loại phishing, kết hợp email metadata, OSINT, threat intelligence và các bước phân tích tự động.

### 2. Những thông tin có thể trích xuất

- Sender và recipient.
- Timestamp.
- Originating IP và reverse DNS.
- SMTP relay chain.
- X-headers.
- IP/domain intelligence.
- Email body dạng text và HTML.
- URL và attachment.
- SHA-256 hash và kết quả reputation nếu có tích hợp.

### 3. Phân tích attachment

PhishTool có thể hiển thị:
- Tên file.
- SHA-256.
- Metadata.
- Kết quả VirusTotal khi được tích hợp.
- Strings và thông tin phục vụ phân tích sâu hơn.

### 4. Phân loại và xử lý case

Sau khi phân tích, analyst có thể:
1. Đưa ra verdict.
2. Đánh dấu email là malicious hoặc theo phân loại phù hợp.
3. Thêm tags.
4. Ghi analyst notes.
5. Lưu lại kết quả xử lý.

**Đáp án câu hỏi Strings trong walkthrough:** `454326_PDF.exe`

---

## Task 7: Phishing Case 1

### Kịch bản
Phân tích email giả mạo Netflix, tập trung vào sender, originating IP, domain đáng ngờ và URL rút gọn.

### Quy trình
1. Mở `Phish3Case1.eml` trên máy lab.
2. Kiểm tra nội dung và thương hiệu bị giả mạo.
3. Sao chép raw email source vào công cụ phân tích header.
4. Xác định sender và originating IP.
5. Tìm các domain liên quan trong header.
6. Lấy URL đích bằng `Copy Link Location`.
7. Defang các indicators trước khi ghi vào báo cáo.

### Đáp án tham khảo

| Câu hỏi | Kết quả |
|---|---|
| Thương hiệu bị giả mạo | Netflix |
| From email | `JGQ47wazXe1xYVBrkeDg-JOg7ODDQwWdR@JOg7ODDQwWdR-yVkCaBkTNp.gogolecloud.com` |
| Originating IP đã defang | `209[.]85[.]167[.]226` |
| Domain đáng chú ý đã defang | `etekno[.]xyz` |
| URL rút gọn đã defang | `hxxps[://]t[.]co/yuxfZm8KPg?amp=1` |

Nguồn đối chiếu: [Walkthrough Phishing Analysis Tools](https://www.jalblas.com/blog/tryhackme-phishing-analysis-tools-soc-level-1/).

---

## Task 8: Update Payment Details — Phishing Case 2

### Kịch bản
Điều tra mẫu PDF đáng ngờ bằng ANY.RUN. Cần xác định phân loại, tên file, hash, các IP độc hại và process đáng ngờ.

### Quy trình
1. Mở [ANY.RUN analysis](https://app.any.run/tasks/8bfd4c58-ec0d-4371-bfeb-52a334b69f59).
2. Kiểm tra verdict trên phần summary.
3. Ghi tên file PDF.
4. Mở Text Report để lấy SHA-256.
5. Tìm phần Connections để kiểm tra các IP.
6. Tìm phần Threats để xác định process bị đánh dấu.

### Đáp án tham khảo

| Câu hỏi | Kết quả |
|---|---|
| ANY.RUN classification | `Suspicious activity` |
| PDF filename | `Payment-updateid.pdf` |
| SHA-256 | `CC6F1A04B10BCB168AEEC8D870B97BD7C20FC161E8310B5BCE1AF8ED420E2C24` |
| Hai IP độc hại đã defang | `2[.]16[.]107[.]24,2[.]16[.]107[.]83` |
| Process bị đánh dấu Potentially Bad Traffic | `svchost.exe` |

**Lưu ý:** `svchost.exe` là process Windows hợp pháp. Việc process bị gắn cờ trong một phân tích cần được xem xét theo hành vi và ngữ cảnh, không có nghĩa mọi `svchost.exe` đều độc hại.

---

## Task 9: Excel Executable — Phishing Case 3

### Kịch bản
Phân tích file Excel độc hại bằng ANY.RUN để thu thập verdict, hash, domain, IP và vulnerability mà attachment cố khai thác.

### Quy trình
1. Mở [ANY.RUN analysis](https://app.any.run/tasks/82d8adc9-38a0-4f0e-a160-48a5e09a6e83).
2. Kiểm tra summary.
3. Ghi tên file Excel.
4. Mở Text Report để lấy SHA-256.
5. Kiểm tra DNS Requests và HTTP Connections.
6. Defang domain và IP, sắp xếp đúng thứ tự đề yêu cầu.
7. Xác định CVE được ghi trong báo cáo.

### Đáp án tham khảo

| Câu hỏi | Kết quả |
|---|---|
| Analysis classification | `Malicious Activity` |
| Excel filename | `CBJ200620039539.xlsx` |
| SHA-256 | `5F94A66E0CE78D17AFC2DD27FC17B44B3FFC13AC5F42D3AD6A5DCFB36715F3EB` |
| Domains đã defang, theo thứ tự alphabet | `biz9holdings[.]com,findresults[.]site,ww38[.]findresults[.]site` |
| IPs đã defang, từ thấp đến cao | `75[.]2[.]11[.]242,103[.]224[.]182[.]251,204[.]11[.]56[.]48` |
| Vulnerability | `CVE-2017-11882` |

### CVE-2017-11882

Đây là lỗ hổng thực thi mã từ xa trong Microsoft Office Equation Editor. File Office độc hại có thể khai thác lỗ hổng này khi được mở trên hệ thống chưa được vá.

**Ghi nhớ:** File Excel không chỉ có thể chứa macro; nó cũng có thể chứa nội dung hoặc đối tượng khai thác lỗ hổng của phần mềm liên quan.

