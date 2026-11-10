# File and Hash Threat Intel

**Nguồn học chính:** [TryHackMe – File and Hash Threat Intel](https://tryhackme.com/room/fileandhashthreatintel)  
**Module:** [Threat Analysis Tools](https://tryhackme.com/module/threat-analysis-tools)  
**Chủ đề:** Phân tích dấu hiệu từ tên file và đường dẫn, fingerprint bằng hash, tra cứu malware intelligence và đọc kết quả sandbox.

> **Mục tiêu ghi chú:** Ghi lại phương pháp phân tích file theo góc nhìn SOC L1. Không ghi lại đáp án, flag hoặc dữ liệu cụ thể phải tìm trong các file của lab.

---

## Task 1: Introduction

### 1. Vai trò của File and Hash Threat Intelligence

Trong quá trình triage, EDR có thể phát hiện một file đáng ngờ trên nhiều máy. Tên file hoặc đường dẫn chỉ là dấu hiệu ban đầu; analyst cần xác minh file, tạo hash, enrich bằng threat-intelligence platform và tìm bằng chứng về hành vi thực tế.

Quy trình cơ bản:

`Verify → Enrich → Decide`

- **Verify:** Xác định đúng file, nguồn thu thập, đường dẫn và hash.
- **Enrich:** Tra cứu thông tin về file, malware family, lịch sử phát hiện, chữ ký, quan hệ mạng và hành vi.
- **Decide:** Đưa ra nhận định có cơ sở: benign, suspicious hoặc malicious; đề xuất xử lý phù hợp.

### 2. Mục tiêu kỹ năng

- Đọc và đánh giá các dấu hiệu đáng ngờ từ filepath và filename.
- Tạo, xác minh và sử dụng file hash để tra cứu.
- Sử dụng VirusTotal, MalwareBazaar và threat-intelligence platform để bổ sung bối cảnh.
- Đọc báo cáo sandbox và nhận diện process, file được tạo, network connection, persistence và hành vi khác.
- Liên hệ hành vi quan sát được với MITRE ATT&CK.

---

## Task 2: Filenames and Paths

### 1. Phân tích đường dẫn file (Filepath Analysis)

Đường dẫn có thể cho biết file được lưu ở đâu, user hoặc process nào có thể truy cập, và attacker có thể đang cố gắng giảm khả năng bị phát hiện hay không.

| Vị trí | Lý do cần chú ý |
|---|---|
| `C:\` | Vị trí gốc của ổ hệ thống; cần kiểm tra file lạ được đặt trực tiếp tại đây và mục đích sử dụng. |
| `C:\Users\Public\` | Thư mục dùng chung, có thể cho phép nhiều tài khoản truy cập. |
| `C:\Users\Public\Public Downloads\` | Vị trí có thể được lợi dụng để lưu file tải xuống hoặc staging payload. |
| `C:\Windows\Temp\` | Thư mục tạm, có thể chứa payload hoặc file trung gian trong quá trình thực thi. |
| `C:\ProgramData\` | Vị trí có thể được ứng dụng hợp pháp sử dụng; cũng có thể bị lợi dụng để lưu thành phần độc hại hoặc duy trì hoạt động. |

**Nguyên tắc phân tích:** Không kết luận một file độc hại chỉ vì nó nằm trong thư mục đáng ngờ. Cần so sánh với baseline của hệ thống, quyền truy cập, thời gian tạo file, process tạo file và nội dung thực tế.

### 2. Filename Heuristics – Dấu hiệu bất thường trong tên file

| Dấu hiệu | Ví dụ minh họa | Vì sao cần kiểm tra |
|---|---|---|
| **Double extension** | `invoice.pdf.exe` | Người dùng có thể nhìn thấy phần mở rộng đầu tiên và tưởng đây là tài liệu PDF. |
| **System binary impersonation** | `scvhost.exe` gần giống tên một tiến trình Windows quen thuộc | Kẻ tấn công có thể dùng ký tự thay thế để giả dạng file hệ thống. |
| **High-entropy / tên ngẫu nhiên** | `jh8F21.exe` | Có thể liên quan đến payload được tạo tự động, packer hoặc polymorphism; vẫn cần đối chiếu thêm. |
| **Masquerading** | `backup-2300.exe` | Tên file được đặt để hòa lẫn với file thông thường hoặc phần mềm hợp pháp. |

Ngoài tên file, cần kiểm tra:

- Phần mở rộng thật và loại file thực tế (file signature/magic bytes).
- Đường dẫn đầy đủ thay vì chỉ tên file.
- Digital signature, publisher và trạng thái chứng thư.
- Thời gian tạo, sửa đổi, compile timestamp nếu có.
- Kích thước, entropy và metadata.
- Process cha tạo hoặc tải file xuống.

### 3. Cách tiếp cận khi thấy file đáng ngờ

1. Ghi lại tên file và filepath đầy đủ.
2. Không mở hoặc thực thi file trên máy cá nhân.
3. Xác định loại file thực tế, không chỉ dựa vào extension.
4. Kiểm tra chữ ký số và metadata.
5. Tạo hash của file gốc và các file liên quan.
6. Tra cứu hash để tìm thông tin đã được cộng đồng hoặc vendor ghi nhận.
7. Chỉ thực hiện dynamic analysis trong lab/sandbox được cô lập.

---

## Task 3: File Hash Lookup

### 1. Hash là gì?

Hash là giá trị fingerprint được tạo từ nội dung file bằng một hàm băm. Với cùng thuật toán, cùng nội dung file sẽ tạo ra cùng hash; thay đổi dù chỉ một byte có thể tạo ra hash hoàn toàn khác.

Hash hữu ích vì tên file có thể bị đổi nhưng hash vẫn nhận diện được nội dung file chưa thay đổi.

### 2. Các thuật toán hash thường gặp

| Thuật toán | Đặc điểm | Ứng dụng trong triage |
|---|---|---|
| **MD5** | Hash 128-bit; không còn phù hợp cho mục tiêu bảo mật chống va chạm. | Có thể gặp trong dữ liệu legacy hoặc hệ thống reputation cũ. |
| **SHA-1** | Hash 160-bit; đã có vấn đề va chạm thực tế. | Có thể gặp trong báo cáo cũ, nên ưu tiên đối chiếu SHA-256. |
| **SHA-256** | Hash 256-bit thuộc SHA-2. | Thường được ưu tiên để nhận diện file và chia sẻ IOC. |

### 3. Tạo hash trên Windows và Linux

**Windows – Command Prompt:**

```powershell
certutil -hashfile suspicious.exe SHA256
```

**Windows – PowerShell:**

```powershell
Get-FileHash -Algorithm SHA256 .\suspicious.exe
```

**Linux:**

```bash
sha256sum suspicious.exe
```

**Lưu ý khi ghi nhận hash:**

- Dùng định dạng nhất quán, thường lưu chữ thường để dễ đối chiếu.
- Ghi rõ thuật toán, filename, filepath, nguồn và thời điểm lấy mẫu.
- Nếu file nằm trong archive, nên ghi hash của archive và hash của file sau khi giải nén.
- Không coi hash là thuộc tính nhận dạng tên file; hash nhận diện nội dung byte của file.
- Khi file được đóng gói/giải nén hoặc chỉnh sửa, hash có thể thay đổi.

### 4. Enrichment bằng VirusTotal

VirusTotal tổng hợp kết quả phân tích từ nhiều antivirus engine và một số nguồn thông tin liên quan. Khi tra cứu hash, không nên chỉ nhìn detection ratio.

| Thành phần | Cần xem gì? | Câu hỏi analyst cần đặt ra |
|---|---|---|
| **Detection score** | Số engine đánh dấu file là độc hại hoặc đáng ngờ. | Có sự đồng thuận giữa nhiều vendor không? Có engine nào phân loại khác biệt không? |
| **Threat labels** | Tên malware family hoặc loại mối đe dọa. | Các nhãn có nhất quán và có ý nghĩa kỹ thuật không? |
| **Detection details / rules** | Signature, heuristic hoặc YARA rule. | File bị phát hiện bởi chữ ký cụ thể hay hành vi tổng quát? |
| **First submission / upload time** | Lần đầu file xuất hiện trong nền tảng. | File mới xuất hiện hay đã được lưu hành từ trước? Dữ liệu có cập nhật không? |
| **Digital signature** | Publisher, trạng thái ký và certificate chain. | Chứng thư có hợp lệ và có phù hợp với nhà phát hành không? |
| **File properties** | File type, size, timestamp, entropy, section và metadata. | Có gì bất thường khi so với bản hợp pháp? |
| **Relations** | Domain, IP, URL, file liên quan hoặc file được tạo. | File có kết nối đến hạ tầng đáng ngờ nào không? |
| **Behavior** | Registry modification, process injection, process creation, network activity. | Những hành vi đó có phù hợp với chức năng dự kiến của file không? |

**Một số dấu hiệu cần xem xét:**

- Nhiều vendor uy tín cùng phát hiện một file.
- Phân loại malware family nhất quán giữa các nguồn.
- File có chữ ký số không hợp lệ hoặc publisher không liên quan.
- Compile timestamp, entropy hoặc metadata bất thường.
- File có quan hệ với IP/domain đã biết là độc hại.
- Hành vi như process injection, tạo scheduled task hoặc sửa registry không phù hợp với vai trò phần mềm.

**Cảnh báo về false positive/false negative:**

- File mới có thể chưa được nhiều vendor nhận diện.
- Một số phần mềm hợp pháp hoặc packer có thể có entropy cao.
- Chứng thư hợp lệ không đảm bảo file vô hại; chứng thư có thể bị lạm dụng hoặc đánh cắp.
- Một dịch vụ CDN/hosting hợp pháp có thể được sử dụng để phân phối payload.
- Detection ratio chỉ là một phần của bằng chứng, không phải kết luận cuối cùng.

### 5. Cross-reference với MalwareBazaar

**MalwareBazaar** là nguồn dữ liệu cộng đồng phục vụ chia sẻ và nghiên cứu malware samples.

Những thông tin có thể khai thác:

- Malware family labels và tags.
- Thông tin về mẫu malware đã được thu thập.
- YARA rules hoặc thông tin phát hiện liên quan.
- Campaign hoặc threat-actor tags nếu nguồn cung cấp.
- Liên hệ đến mẫu tương tự và dữ liệu phân tích bổ sung.

Có thể tìm kiếm theo SHA-256 bằng cú pháp:

```text
sha256:<file_hash>
```

MalwareBazaar hữu ích khi dữ liệu từ một nguồn khác còn ít phát hiện. Tuy nhiên, tag cộng đồng vẫn cần được đối chiếu với nguồn và bằng chứng khác.

---

## Task 4: Sandbox Analysis

### 1. Static Analysis và Dynamic Analysis

| Phương pháp | Nội dung | Ví dụ dữ liệu thu thập |
|---|---|---|
| **Static Analysis** | Phân tích file mà không thực thi nó. | Hash, strings, file type, PE sections, imports, signature, metadata. |
| **Dynamic Analysis** | Quan sát file khi chạy trong môi trường kiểm soát. | Process tree, registry writes, files dropped, network connections, mutex và runtime behavior. |

Static analysis giúp nhận diện đặc điểm của file; dynamic analysis giúp hiểu file thực sự làm gì khi chạy.

### 2. Mục đích của sandbox

Sandbox là môi trường thực thi có kiểm soát, thường sử dụng VM hoặc hệ thống phân tích chuyên dụng để hạn chế rủi ro đối với máy thật.

SOC analyst dùng sandbox nhằm:

- **Confirm execution:** Quan sát file có thực sự tạo hoạt động đáng chú ý hay không.
- **Extract runtime IOCs:** Thu thập domain, IP, URL, mutex, dropped files và dấu vết mạng.
- **Understand behavior:** Theo dõi process tree, registry, file system và thao tác khác.
- **Map to ATT&CK:** Đối chiếu các hành vi quan sát được với kỹ thuật của đối phương.

### 3. Công cụ sandbox được đề cập

| Công cụ | Điểm nổi bật trong ngữ cảnh học tập |
|---|---|
| **Hybrid Analysis** | Thường cung cấp bản tóm tắt, behavior tree và góc nhìn MITRE ATT&CK thuận tiện cho triage nhanh. |
| **Joe Sandbox** | Cung cấp nhiều chi tiết kỹ thuật như system calls, strings, memory và hành vi sâu hơn, hữu ích cho phân tích chuyên sâu. |

Tùy dữ liệu có sẵn, analyst cần đọc cả phần summary lẫn chi tiết hành vi; không dừng lại ở threat score.

### 4. Những mục cần đọc trong sandbox report

| Thành phần | Nội dung cần tìm |
|---|---|
| Verdict / Threat score | Nhận định tự động của sandbox và cơ sở của nhận định. |
| Tags / Risk behavior | Nhãn hành vi, đặc điểm rủi ro và lý do bị cảnh báo. |
| Process tree | Process nào tạo ra file hoặc process con; command line được sử dụng. |
| Filesystem | File được tạo, sửa, tải xuống hoặc xóa. |
| Registry | Key/value bị thêm hoặc thay đổi, đặc biệt các vị trí có thể liên quan đến persistence. |
| Network | DNS query, IP, domain, URL, HTTP request và kết nối ra ngoài. |
| Strings / Imports | Chuỗi đáng chú ý và API có thể gợi ý chức năng của file. |
| MITRE ATT&CK | Kỹ thuật được sandbox ánh xạ từ hành vi quan sát. |

### 5. Giới hạn của sandbox

Sandbox rất hữu ích nhưng kết quả không đại diện cho toàn bộ khả năng của malware.

1. **Sandbox evasion:** Malware có thể phát hiện VM, debugger, cấu hình phần cứng hoặc dấu hiệu môi trường phân tích.
2. **Execution time:** Thời gian chạy ngắn có thể bỏ lỡ payload nhiều giai đoạn hoặc hành vi kích hoạt trễ.
3. **Encrypted / obfuscated traffic:** HTTPS/TLS hoặc DNS tunneling có thể khiến analyst không đọc được nội dung trao đổi.
4. **Fileless malware / Living off the Land:** Một số hoạt động lợi dụng PowerShell, WMI hoặc công cụ hợp pháp của hệ điều hành mà không tạo file độc hại rõ ràng trên disk.
5. **Environment dependency:** Malware có thể chỉ thực thi khi có user interaction, domain join, thời gian hoặc điều kiện cụ thể.

**Kết luận:** Không thấy hành vi trong sandbox không đồng nghĩa file an toàn. Cần kết hợp static analysis, threat intelligence, log nội bộ và các nguồn khác.

---

## Quy trình triage một file đáng ngờ

```text
EDR alert / suspicious file
          |
          v
Verify filename, path, source and timestamp
          |
          v
Identify file type + inspect metadata/signature
          |
          v
Calculate SHA-256 hash
          |
          v
Enrich hash with VirusTotal / MalwareBazaar
          |
          v
Review relations and existing threat reports
          |
          v
Sandbox analysis (isolated environment only)
          |
          v
Extract runtime IOCs + map observed behavior to ATT&CK
          |
          v
Correlate with internal EDR/SIEM telemetry
          |
          v
Document confidence, impact and recommended actions
```

### Mẫu báo cáo phân tích file

| Trường | Nội dung cần ghi |
|---|---|
| File name / path | Tên file và đường dẫn đầy đủ. |
| File type | Loại file thực tế. |
| SHA-256 | Hash của mẫu được phân tích. |
| Signature | Publisher, trạng thái chữ ký và certificate chain. |
| Source | EDR, email, download, user report hoặc nguồn khác. |
| Reputation | Kết quả từ VirusTotal/MalwareBazaar và thời điểm tra cứu. |
| Sandbox findings | Process tree, file/registry changes và network behavior. |
| Related IOCs | Hash, IP, domain, URL, mutex hoặc file liên quan. |
| ATT&CK mapping | Technique được hỗ trợ bởi hành vi quan sát. |
| Assessment | Benign / Suspicious / Malicious cùng confidence. |
| Recommendation | Quarantine, block, hunt, isolate, monitor hoặc escalate. |

---

## Ghi nhớ và giá trị ứng dụng

- Filename và filepath là heuristic ban đầu, không phải bằng chứng kết luận.
- SHA-256 giúp nhận diện file theo nội dung và hỗ trợ pivot sang các nguồn threat intelligence.
- VirusTotal cần được đọc theo nhiều chiều: detections, labels, properties, signatures, relations và behavior.
- MalwareBazaar hỗ trợ tìm malware family, tags và YARA-related intelligence.
- Sandbox giúp hiểu hành vi runtime nhưng có thể bị né tránh hoặc bỏ lỡ hoạt động.
- Cần kết hợp static analysis, dynamic analysis và telemetry nội bộ trước khi đưa ra kết luận.

**Năng lực có thể thể hiện trong portfolio:** Phân tích dấu hiệu filename/path; tạo hash; thực hiện hash enrichment; đọc sandbox report; trích xuất IOC và lập báo cáo ngắn có bằng chứng. Chỉ liệt kê công cụ đã trực tiếp sử dụng trong lab.

---

## Tài liệu tham khảo

1. [TryHackMe – File and Hash Threat Intel](https://tryhackme.com/room/fileandhashthreatintel)
2. [VirusTotal](https://www.virustotal.com/)
3. [MalwareBazaar – abuse.ch](https://bazaar.abuse.ch/)
4. [Hybrid Analysis](https://www.hybrid-analysis.com/)
5. [Joe Sandbox](https://www.joesandbox.com/)
6. [MITRE ATT&CK](https://attack.mitre.org/)
