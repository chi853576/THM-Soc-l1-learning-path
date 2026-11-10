# Intro to Cyber Threat Intel

**Nguồn học chính:** [TryHackMe – Intro to Cyber Threat Intel](https://tryhackme.com/room/cyberthreatintel)  
**Module:** [Threat Analysis Tools](https://tryhackme.com/module/threat-analysis-tools)  
**Chủ đề:** Nền tảng Cyber Threat Intelligence (CTI), quy trình xử lý threat intelligence, chuẩn chia sẻ dữ liệu và framework phân tích hành vi đối phương.

> **Mục tiêu ghi chú:** Tập trung vào kiến thức và tư duy phân tích có thể áp dụng trong môi trường SOC. Không ghi lại đáp án, flag hoặc giá trị cần điền của room.

---

## Task 1: Introduction

### 1. Cyber Threat Intelligence là gì?

**Cyber Threat Intelligence (CTI)** là quá trình thu thập, xử lý, phân tích và chia sẻ thông tin về mối đe dọa an ninh mạng nhằm giúp tổ chức hiểu rõ đối phương, đánh giá rủi ro và đưa ra hành động phòng thủ phù hợp.

CTI không đơn thuần là một danh sách IP, domain hoặc hash độc hại. Giá trị của CTI nằm ở việc bổ sung bối cảnh cho các artefact và giải thích được:

- **Who/What:** Indicator có liên quan đến cá nhân, hạ tầng, malware hoặc nhóm đe dọa nào?
- **What happened / What may happen:** Indicator từng được sử dụng như thế nào? Có hành vi hoặc chiến dịch nào liên quan?
- **So what / What next:** Mối đe dọa ảnh hưởng đến tổ chức ra sao và cần phản ứng như thế nào?

Trong SOC, CTI giúp analyst chuyển từ việc nhìn thấy một alert sang đánh giá alert đó có ý nghĩa gì đối với hệ thống đang bảo vệ.

### 2. Từ Data đến Information và Intelligence

Ba khái niệm này có liên quan nhưng không giống nhau.

| Cấp độ | Ý nghĩa | Ví dụ minh họa | Công việc của analyst |
|---|---|---|---|
| **Data** | Dữ liệu thô, chưa có bối cảnh. | Một địa chỉ IP xuất hiện trong log. | Ghi nhận artefact chính xác. |
| **Information** | Dữ liệu đã được bổ sung thuộc tính. | IP thuộc ASN của một hosting provider, có lịch sử hoạt động nhất định. | Tra cứu và ghi lại nguồn, thời gian, thuộc tính. |
| **Intelligence** | Thông tin đã được phân tích để tạo ra nhận định có thể hành động. | IP có liên hệ với hạ tầng C2 trong một chiến dịch đang nhắm đến tổ chức. | Đánh giá mức độ liên quan, đề xuất block/monitor/escalate. |

**Ghi nhớ:** Một IOC được tìm thấy trên threat-intelligence platform chưa tự động trở thành intelligence hữu dụng. Analyst vẫn phải kiểm tra độ tin cậy, thời điểm, bối cảnh và mức độ liên quan đến môi trường nội bộ.

### 3. IOC, IOA và TTP

| Khái niệm | Viết đầy đủ | Ý nghĩa | Ví dụ |
|---|---|---|---|
| **IOC** | Indicator of Compromise | Dấu hiệu có thể cho thấy hệ thống đã hoặc đang bị xâm nhập. | Hash của malware, domain C2, IP độc hại, registry key bất thường. |
| **IOA** | Indicator of Attack | Dấu hiệu về hành động hoặc chuỗi hành vi tấn công đang diễn ra. | PowerShell bất thường tạo tiến trình con, trình duyệt kết nối đến URL đáng ngờ. |
| **TTP** | Tactics, Techniques and Procedures | Cách thức và phương pháp mà đối phương sử dụng để đạt mục tiêu. | Phishing, thực thi script, duy trì persistence, đánh cắp thông tin xác thực. |

**Phân biệt nhanh:** IOC thường mô tả *dấu vết cụ thể*; IOA mô tả *hành động đáng ngờ*; TTP mô tả *phương pháp hoạt động của đối phương*.

### 4. Các nhóm indicator thường gặp trong SOC L1

| Loại indicator | Ví dụ | Hướng enrichment phù hợp |
|---|---|---|
| IPv4 / IPv6 | IP xuất hiện trong firewall hoặc proxy log. | WHOIS/RDAP, ASN, geolocation, reputation, Shodan, Censys, passive DNS. |
| Domain / FQDN | Domain mới xuất hiện trong DNS log. | WHOIS age, DNS records, passive DNS, certificate transparency, reputation. |
| URL | Link được truy cập từ email hoặc trình duyệt. | URLhaus, VirusTotal, urlscan.io, phân tích redirect và nội dung trang. |
| File hash | SHA-256 của file được EDR phát hiện. | VirusTotal, MalwareBazaar, Hybrid Analysis, Joe Sandbox. |
| Email address | Địa chỉ gửi email đáng ngờ. | Kiểm tra domain, DNS/MX, email authentication, nguồn OSINT phù hợp. |
| Local artefact | Registry key, process, service, scheduled task. | EDR/SIEM, log hệ điều hành, Sigma rules, baseline nội bộ. |

Không nên sử dụng một công cụ cho mọi loại indicator. Cần chọn nguồn tra cứu theo bản chất của artefact.

### 5. Các loại Cyber Threat Intelligence

| Phân loại | Nội dung | Đối tượng sử dụng / mục đích |
|---|---|---|
| **Strategic Intelligence** | Xu hướng đe dọa, bối cảnh ngành, rủi ro và mục tiêu ở cấp tổ chức. | Ban lãnh đạo, quản lý rủi ro, hoạch định bảo mật. |
| **Operational Intelligence** | Thông tin về chiến dịch, động cơ, mục tiêu, thời gian và hạ tầng của đối phương. | Threat analysts, incident responders, threat hunters. |
| **Tactical Intelligence** | TTP và cách thức hoạt động của đối phương. | SOC, detection engineering, blue team. |
| **Technical Intelligence** | Các indicator kỹ thuật cụ thể như IP, domain, URL, hash, email, artefact. | SOC L1, firewall, EDR, SIEM và hệ thống phát hiện. |

Một analyst L1 thường xử lý nhiều technical indicators, quan sát IOA, ghi nhận TTP và chuyển những mẫu hình quan trọng cho cấp phân tích sâu hơn.

### 6. Nguồn thu thập threat intelligence

- **Internal telemetry:** SIEM logs, EDR alerts, firewall/proxy/DNS logs, email được người dùng báo cáo. Đây là nguồn giúp xác định indicator có thực sự xuất hiện trong tổ chức hay không.
- **Commercial intelligence:** Threat feeds, sandbox hoặc dịch vụ phân tích có trả phí. Cần kiểm tra phạm vi giấy phép và quyền chia sẻ dữ liệu.
- **Open-source intelligence (OSINT):** AbuseIPDB, URLhaus, MalwareBazaar, VirusTotal, báo cáo nghiên cứu, blog kỹ thuật và dữ liệu công khai. Kết quả cần được đối chiếu vì chất lượng có thể khác nhau.
- **Communities / ISACs:** Cộng đồng chia sẻ thông tin và các tổ chức chia sẻ theo ngành, thường cung cấp bối cảnh chuyên sâu hơn cho lĩnh vực cụ thể.

### 7. Threat Feed và Threat Intelligence Platform

| Thành phần | Vai trò | Ví dụ |
|---|---|---|
| **Feed** | Luồng dữ liệu indicator được cập nhật theo lịch hoặc khi có thông tin mới; có thể ở dạng CSV, JSON, STIX hoặc được phân phối qua TAXII. | Feed chứa IP, domain, URL hoặc hash. |
| **Platform** | Kho quản lý indicator, enrichment, mối quan hệ giữa các artefact, lịch sử và chính sách chia sẻ. | MISP, OpenCTI. |

Không nên nhập mọi feed vào hệ thống mà không đánh giá. Feed kém chất lượng hoặc không phù hợp với threat model có thể tạo false positive, làm analyst mất thời gian và giảm niềm tin vào hệ thống.

---

## Task 2: CTI Lifecycle

### 1. Tổng quan

CTI Lifecycle là quy trình sáu giai đoạn giúp chuyển dữ liệu thô thành intelligence có thể sử dụng, sau đó đánh giá hiệu quả và cải tiến liên tục.

| Giai đoạn | Mục tiêu | Công việc điển hình |
|---|---|---|
| **1. Direction** | Xác định điều cần biết và lý do cần biết. | Xác định tài sản cần bảo vệ, rủi ro kinh doanh, phạm vi và câu hỏi intelligence. |
| **2. Collection** | Thu thập dữ liệu phù hợp. | Lấy dữ liệu từ SIEM/EDR, threat feeds, OSINT, báo cáo và nền tảng chia sẻ. |
| **3. Processing** | Chuẩn hóa dữ liệu để có thể so sánh và phân tích. | Chuẩn hóa IP/domain/hash, loại trùng, gắn nguồn, thời điểm và TLP. |
| **4. Analysis** | Đánh giá dữ liệu và hình thành nhận định. | Correlate nguồn, kiểm tra sự hiện diện nội bộ, đánh giá confidence và relevance. |
| **5. Dissemination** | Chuyển kết quả đến đúng người hoặc hệ thống. | Gửi IOC cho firewall/EDR, báo cáo cho SOC/IR và bản tóm tắt cho quản lý. |
| **6. Feedback** | Đo lường và cải tiến chu trình. | Theo dõi hiệu quả chặn, false positive, thời gian xử lý và cập nhật yêu cầu intelligence. |

### 2. Direction – Xác định yêu cầu intelligence

Không bắt đầu bằng việc thu thập thật nhiều IOC. Trước tiên cần đặt câu hỏi gắn với tài sản và rủi ro thực tế.

Ví dụ về intelligence requirements:

- Những IP/domain nào đang được sử dụng để tấn công dịch vụ mà tổ chức đang vận hành?
- Những malware family nào đang nhắm đến hệ thống hoặc phần mềm mà tổ chức sử dụng?
- Các hash/domain quan sát được có xuất hiện trong log nội bộ không?
- Hệ thống phòng thủ hiện có có thể xử lý indicator theo cách nào: block, alert, hunt hay monitor?

Yêu cầu tốt nên có phạm vi, khoảng thời gian, đối tượng và tiêu chí đánh giá kết quả rõ ràng.

### 3. Collection – Thu thập dữ liệu

Nguồn dữ liệu nên được chọn theo câu hỏi đã đặt ra, thay vì thu thập không có mục tiêu.

Ví dụ:

- Vendor threat feed: indicator mới liên quan đến sản phẩm bảo mật đang triển khai.
- AbuseIPDB hoặc nguồn reputation: thông tin cộng đồng về IP đáng ngờ.
- MISP/OpenCTI nội bộ: lịch sử indicator từng xuất hiện trong tổ chức.
- Báo cáo threat research: bối cảnh chiến dịch, malware family và TTP.

Nên lưu bản dữ liệu theo thời điểm thu thập để có thể tái kiểm tra và giải thích vì sao kết luận được đưa ra tại thời điểm đó.

### 4. Processing – Chuẩn hóa và tương quan

Dữ liệu từ nhiều nguồn có thể khác định dạng hoặc cách viết. Những bước xử lý thường gặp:

1. Chuẩn hóa địa chỉ IP, domain, URL và hash.
2. Loại bỏ bản ghi trùng nhưng vẫn giữ thông tin nguồn gốc.
3. Gắn thời gian first seen/last seen nếu nguồn cung cấp.
4. Ghi rõ nguồn, độ tin cậy và nhãn chia sẻ TLP.
5. Liên kết indicator có quan hệ với nhau, ví dụ hash → file → process → domain → IP.
6. Ghi nhận cả dữ liệu mâu thuẫn thay vì tự động loại bỏ kết quả trái chiều.

**Lưu ý:** Không được xóa mất provenance. Mỗi indicator cần biết lấy từ đâu, được quan sát khi nào và đã được xác minh ở mức nào.

### 5. Analysis – Đánh giá intelligence

Các câu hỏi cần đặt ra:

- Có bao nhiêu nguồn độc lập ghi nhận indicator này?
- Nguồn đó có uy tín, cập nhật và phù hợp với ngữ cảnh không?
- Indicator có xuất hiện trong hệ thống nội bộ không?
- Indicator có liên hệ với malware/campaign/TTP đã biết không?
- Hành động nào tương xứng với bằng chứng hiện có?

Có thể tham khảo cách phân loại đơn giản:

| Mức tin cậy | Bằng chứng minh họa | Hướng xử lý tham khảo |
|---|---|---|
| **High** | Nhiều nguồn đáng tin cậy đồng thuận và có telemetry nội bộ phù hợp. | Ưu tiên xác minh và áp dụng biện pháp phòng thủ phù hợp. |
| **Medium** | Một nguồn tin cậy hoặc có dấu hiệu đáng ngờ nhưng chưa có local hit. | Alert, theo dõi hoặc điều tra bổ sung. |
| **Low** | Chỉ có nguồn OSINT đơn lẻ, thiếu bối cảnh hoặc dữ liệu cũ. | Chưa nên block tự động; tiếp tục kiểm tra. |

Đây là mô hình tham khảo trong bài học, không phải ngưỡng bắt buộc cho mọi SOC. Mức confidence cần được điều chỉnh theo nguồn dữ liệu, rủi ro và chính sách tổ chức.

### 6. Dissemination – Chia sẻ kết quả

Thông tin cần được trình bày phù hợp với người nhận:

- **Firewall / Network team:** IP, domain, hành động đề xuất, thời hạn và lý do.
- **Endpoint / EDR team:** hash, file metadata, YARA rule hoặc hành vi cần phát hiện.
- **SOC / IR team:** timeline, IOC, IOA, TTP, phạm vi ảnh hưởng và mức confidence.
- **Management:** tóm tắt tác động, rủi ro và biện pháp giảm thiểu.

Một báo cáo tốt không chỉ chứa danh sách IOC mà cần giải thích vì sao các IOC đó có ý nghĩa và người nhận cần làm gì.

### 7. Feedback – Đo lường hiệu quả

Một số chỉ số có thể theo dõi:

- Thời gian từ khi indicator được công bố đến khi tổ chức xử lý.
- Thời gian tồn tại của một hoạt động tấn công trong mạng nội bộ.
- Số lượng false positive sau khi áp dụng block/detection rule.
- Số alert được enrichment thành công.
- Tỷ lệ indicator thực sự liên quan đến tài sản của tổ chức.

Feedback giúp điều chỉnh nguồn feed, tiêu chí confidence và phạm vi collection trong chu kỳ tiếp theo.

---

## Task 3: CTI Standards & Frameworks

### 1. Traffic Light Protocol (TLP)

**TLP** là hệ thống nhãn quy định phạm vi được phép chia sẻ thông tin. Theo FIRST TLP 2.0, có bốn nhãn:

| Nhãn | Phạm vi chia sẻ | Cách ghi nhớ |
|---|---|---|
| **TLP:RED** | Chỉ người nhận được chỉ định trong cuộc trao đổi. | Không chia sẻ ra ngoài nhóm/người nhận cụ thể. |
| **TLP:AMBER** | Chia sẻ trong phạm vi tổ chức và các bên có nhu cầu cần biết theo quy định. | Hạn chế, theo nguyên tắc need-to-know. |
| **TLP:GREEN** | Có thể chia sẻ trong cộng đồng/nhóm đối tác phù hợp, không công khai rộng rãi. | Chia sẻ trong cộng đồng tin cậy. |
| **TLP:CLEAR** | Có thể chia sẻ công khai, không có hạn chế theo TLP. | Có thể công bố rộng rãi. |

**Điểm cần nhớ:** TLP mô tả phạm vi chia sẻ, không phải mức độ nguy hiểm hoặc độ tin cậy của indicator. Không được tự ý nâng phạm vi chia sẻ; phải giữ nhãn TLP đi cùng dữ liệu trong quá trình lưu trữ và chuyển tiếp.

### 2. STIX và TAXII

| Chuẩn | Vai trò | Ghi nhớ |
|---|---|---|
| **STIX** – Structured Threat Information Expression | Mô hình biểu diễn threat intelligence có cấu trúc, thường ở dạng JSON, mô tả indicator, malware, threat actor, campaign và mối quan hệ. | STIX = mô tả intelligence. |
| **TAXII** – Trusted Automated eXchange of Indicator Information | Giao thức/API để trao đổi threat intelligence tự động giữa các hệ thống. | TAXII = vận chuyển/chia sẻ intelligence. |

TAXII có thể tổ chức chia sẻ theo các mô hình như Collection và Channel. Việc trao đổi tự động giúp giảm độ trễ nhưng vẫn phải tuân thủ TLP, quyền truy cập, giấy phép và chính sách dữ liệu.

### 3. MITRE ATT&CK

**MITRE ATT&CK** là knowledge base mô tả hành vi và kỹ thuật mà adversary sử dụng. Analyst có thể dùng ATT&CK để:

1. Đối chiếu hành vi quan sát được với tactic/technique phù hợp.
2. Ghi ID và mô tả kỹ thuật vào triage note hoặc incident report.
3. Giúp các nhóm SOC, IR và detection engineering sử dụng chung thuật ngữ.
4. Xây dựng detection, hunting query và biện pháp giảm thiểu.

Không gán technique chỉ dựa trên tên file hoặc một dấu hiệu riêng lẻ. Cần dựa trên hành vi được quan sát và mô tả bằng chứng.

### 4. MITRE D3FEND

Nếu ATT&CK mô tả cách đối phương thực hiện hành vi tấn công, **D3FEND** tập trung vào các kỹ thuật phòng thủ có thể được sử dụng để đối phó.

Ví dụ về tư duy áp dụng:

- ATT&CK chỉ ra hành vi truy vấn DNS bất thường.
- Analyst tham khảo D3FEND để tìm các phương pháp giám sát, phân tích hoặc hạn chế hành vi DNS đó.
- Đưa biện pháp phù hợp vào trường `recommended action` của báo cáo.

### 5. Cyber Kill Chain

Cyber Kill Chain mô tả chuỗi giai đoạn của một cuộc tấn công, giúp analyst xác định sự kiện đã diễn ra ở đâu trong tiến trình xâm nhập.

| Giai đoạn | Ý nghĩa tổng quát |
|---|---|
| Reconnaissance | Thu thập thông tin về mục tiêu. |
| Weaponization | Chuẩn bị payload hoặc phương tiện tấn công. |
| Delivery | Đưa phương tiện tấn công đến nạn nhân. |
| Exploitation | Khai thác điểm yếu hoặc kích hoạt hành vi thực thi. |
| Installation | Cài đặt thành phần độc hại hoặc thiết lập quyền truy cập. |
| Command and Control | Thiết lập kênh điều khiển với hệ thống bị xâm nhập. |
| Actions on Objectives | Thực hiện mục tiêu như đánh cắp dữ liệu, phá hoại hoặc gian lận. |

Kill Chain cung cấp góc nhìn theo trình tự; ATT&CK mô tả kỹ thuật chi tiết hơn. Có thể dùng hai framework kết hợp khi phân tích incident.

### 6. CVE, CVSS và NVD

- **CVE (Common Vulnerabilities and Exposures):** Mã định danh công khai cho một lỗ hổng đã được ghi nhận.
- **CVSS (Common Vulnerability Scoring System):** Hệ thống chấm điểm mức độ nghiêm trọng của lỗ hổng, thông thường theo thang 0–10.
- **NVD (National Vulnerability Database):** Cơ sở dữ liệu cung cấp thông tin về CVE, điểm CVSS, sản phẩm bị ảnh hưởng và các tham chiếu liên quan.

CVE là mã định danh, CVSS là cách đánh giá mức độ nghiêm trọng; hai khái niệm này không đồng nghĩa.

---

## Task 4: Practical Analysis

Bài thực hành yêu cầu xây dựng threat profile từ các dấu vết như email, file và hoạt động liên quan. Thay vì chỉ thu thập một giá trị riêng lẻ, cần kết nối các artefact thành một câu chuyện có bằng chứng.

### Quy trình phân tích đề xuất

1. Ghi nhận nguồn phát hiện và thời điểm phát hiện.
2. Trích xuất các indicator có thể quan sát: email, domain, URL, file name, file hash, IP và process.
3. Enrich từng indicator bằng nguồn phù hợp.
4. Xác định mối quan hệ giữa email, file được tải xuống, hạ tầng mạng và hành vi thực thi.
5. Tìm các TTP tương ứng trên MITRE ATT&CK khi có đủ bằng chứng.
6. Tóm tắt threat profile: delivery, execution, persistence, C2, impact và mức độ tin cậy.
7. Đề xuất hành động phòng thủ có thể thực hiện và nêu rõ giới hạn của kết luận.

### Mẫu ghi chép một indicator

| Trường | Nội dung cần ghi |
|---|---|
| Indicator | IP / domain / URL / hash / email / artefact. |
| First seen / Last seen | Thời điểm quan sát được theo nguồn dữ liệu. |
| Source | SIEM, EDR, OSINT, commercial feed hoặc threat report. |
| Enrichment | Kết quả tra cứu và mối liên hệ tìm được. |
| Confidence | High / Medium / Low, kèm lý do. |
| Internal relevance | Có xuất hiện trong hệ thống của tổ chức hay không. |
| Recommended action | Block, alert, hunt, monitor hoặc escalate. |
| TLP | Nhãn chia sẻ nếu có. |

---

## Ghi nhớ và giá trị ứng dụng

Sau room này, các kiến thức quan trọng cần nắm được gồm:

- Phân biệt data, information và intelligence.
- Phân biệt IOC, IOA, TTP; hiểu bốn nhóm CTI strategic, operational, tactical và technical.
- Biết lựa chọn nguồn enrichment phù hợp với loại indicator.
- Hiểu sáu giai đoạn của CTI Lifecycle và cách đo lường hiệu quả.
- Phân biệt feed với intelligence platform; hiểu vai trò của STIX, TAXII và TLP.
- Sử dụng ATT&CK, D3FEND và Cyber Kill Chain để mô tả hành vi và hỗ trợ đề xuất phòng thủ.
- Viết triage note có nguồn, thời gian, confidence, bối cảnh và hành động đề xuất.

**Lưu ý khi đưa vào CV/portfolio:** Chỉ mô tả những công cụ và thao tác đã trực tiếp thực hành. Có thể lưu lại một báo cáo mẫu đã loại bỏ IOC nhạy cảm để chứng minh khả năng enrichment và phân tích.

---

## Tài liệu tham khảo

1. [TryHackMe – Intro to Cyber Threat Intel](https://tryhackme.com/room/cyberthreatintel)
2. [TryHackMe – Threat Analysis Tools module](https://tryhackme.com/module/threat-analysis-tools)
3. [FIRST – Traffic Light Protocol (TLP) v2.0](https://www.first.org/tlp/)
4. [OASIS – Cyber Threat Intelligence (CTI) Documentation](https://oasis-open.github.io/cti-documentation/)
5. [MITRE ATT&CK](https://attack.mitre.org/)
6. [MITRE D3FEND](https://d3fend.mitre.org/)
7. [NIST – National Vulnerability Database](https://nvd.nist.gov/)
