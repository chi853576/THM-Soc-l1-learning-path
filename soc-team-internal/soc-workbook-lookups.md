> room này giúp tôi: hiểu các khái niệm, ngữ cảnh xung quanh những cảnh báo.


Kiểm kê danh tính: tra cứu danh tính, vai trò, quyền hạn của người dùng.

Tra cứu tài sản: danh sách tất cả các tài nguyên máy tính trong môi trường CNTT của một tổ chức.

Sơ đồ mạng: một sơ đồ trực quan thể hiện các vị trí hiện có, mạng con và các kết nối của chúng

SOC workbook, playbook, runbook hoặc workflow: tài liệu hướng dẫn các bước điều tra các mối đe dọa đã biết.

Tôi đã luyện tập xây dựng workbook cho các mối de dọa:
Cụ thể những gì tôi đã làm:
Đối với email analysis:
Mục đích: Xác định email là sạch (Clean), rác (Spam), hay độc hại (Malicious) và chứa mối đe dọa gì.
Bước 1: Thu thập thông tin ban đầu (Initial Collection)
Lấy Email Header đầy đủ (Full Header), file .eml gốc.
Ghi lại: Người gửi (From), Người nhận (To), Tiêu đề (Subject), Thời gian gửi.
Lấy URL và file đính kèm (nếu có) ra, không click trực tiếp.
Bước 2: Phân tích Header (Header Analysis) - Quan trọng nhất
Kiểm tra Return-Path và From có khớp nhau không? Nếu khác nhau -> có dấu hiệu giả mạo.
Kiểm tra xác thực: SPF, DKIM, DMARC - Nếu cả 3 đều FAIL thì 99% là giả mạo.
Kiểm tra IP gửi: Tra cứu IP trong header trên AbuseIPDB / Talos Intelligence xem có phải IP spam không.
Kiểm tra Reply-To: Nếu Reply-To là một email lạ khác với From -> lừa đảo.
Bước 3: Phân tích nội dung (Body Analysis)
Kiểm tra ngôn ngữ: Có tạo cảm giác khẩn cấp không? (Ví dụ: "Tài khoản của bạn sẽ bị khóa trong 24h")
Kiểm tra lỗi chính tả, tên miền sai (ví dụ: micros0ft.com thay vì microsoft.com)
Kiểm tra xem có yêu cầu cung cấp thông tin nhạy cảm (password, OTP) không.
Bước 4: Phân tích URL / Link
TUYỆT ĐỐI KHÔNG CLICK TRỰC TIẾP.
Dùng tool: VirusTotal, URLScan.io, Any.run để quét URL.
Kiểm tra kỹ thuật rút gọn link: bit.ly, tinyurl có che giấu link thật không.
Hover chuột để xem link thật là gì.
Bước 5: Phân tích file đính kèm (Attachment Analysis)
Lấy hash của file (MD5, SHA256) và tra trên VirusTotal.
Kiểm tra đuôi file nguy hiểm: .exe, .js, .vbs, .scr, .iso, .lnk, file Excel có Macro (.xlsm).
Nếu là file an toàn, cho vào sandbox (Any.Run, Hybrid Analysis) để xem nó làm gì.
Bước 6: Làm giàu thông tin (Enrichment & Correlation)
Tra cứu địa chỉ email người gửi trên HaveIBeenPwned, VirusTotal.
Kiểm tra trong SIEM: Có user nào khác trong công ty cũng nhận được email giống vậy không? Có ai đã click vào link chưa?
Kiểm tra logs: Có kết nối nào từ máy user tới IP / domain độc hại đó không?
Bước 7: Kết luận và Hành động (Conclusion & Action)
Kết luận:
Malicious - Độc hại (Chứa link/file độc)
Phishing - Lừa đảo (Giả mạo để lấy thông tin)
Spam / Benign - Rác / Sạch
Hành động của L1:
Nếu Malicious/Phishing: Chặn IP/domain trên firewall, xóa email khỏi tất cả mailbox, cô lập (isolate) máy của user đã click, reset mật khẩu, và Escalate lên L2.
Nếu Benign: Đóng alert với lý do False Positive.

powershell analysis:
Mục đích: Xác định câu lệnh PowerShell là hoạt động bình thường của admin hay là hành vi của hacker (Living off the Land).
Bước 1: Thu thập lệnh gốc (Initial Collection)
Lấy toàn bộ command line đầy đủ từ alert. Ví dụ trong Windows Event Log ID 4688 hoặc Sysmon Event ID 1.
Ghi lại: User nào chạy? Process cha (Parent Process) là gì? Thời gian chạy?
Lưu ý quan trọng: PowerShell bình thường sẽ do explorer.exe hoặc vscode gọi. Nếu PowerShell được gọi bởi outlook.exe, winword.exe, excel.exe -> 99% là mã độc.
Bước 2: Nhận diện dấu hiệu đáng ngờ (Obfuscation & Red Flags)
Chỉ cần thấy 1 trong những cái này là phải nghi ngờ ngay:
Tham số mã hóa / che giấu:
-EncodedCommand, -enc, -e (lệnh bị mã hóa Base64)
-WindowStyle Hidden, -w hidden (chạy ẩn cửa sổ)
-NoProfile, -nop (không tải profile để tránh bị phát hiện)
Ký tự lạ: Lệnh chứa nhiều ký tự ^, , +, %, $` chèn lung tung để làm rối (obfuscation).
Tải file từ xa:
IEX (Invoke-Expression), Invoke-WebRequest, wget, curl, DownloadString, DownloadFile
Ví dụ: IEX (New-Object Net.WebClient).DownloadString('http://...')
Tắt bảo mật:
Set-MpPreference -DisableRealtimeMonitoring $true (tắt Windows Defender)
Set-ExecutionPolicy Bypass
Bước 3: Giải mã (Decoding / Deobfuscation) - Bước quan trọng nhất
Nếu gặp -EncodedCommand:
Copy đoạn mã sau -enc
Giải mã Base64: Dùng CyberChef hoặc lệnh PowerShell: [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('đoạn mã'))
Nếu nó giải mã ra thêm một lớp mã hóa nữa, tiếp tục giải mã cho tới khi ra được lệnh cuối cùng.
Bước 4: Phân tích hành vi (Behavioral Analysis)
Sau khi giải mã, xem nó định làm gì:
Nó có kết nối ra ngoài không? Kiểm tra IP / Domain nó kết nối tới trên VirusTotal / AbuseIPDB. (Thường là IP của C2 server)
Nó có tải thêm file gì không? .../mimikatz.exe, .../cobaltstrike.ps1
Nó có cố gắng đánh cắp thông tin không? Tìm từ khóa password, credential, lsass, SAM
Nó có tạo ra tính bền vững không? (Persistence) Tìm schtasks, New-ItemProperty ... Run, Startup folder
Bước 5: Tương quan với log khác (Correlation)
Kiểm tra Sysmon Event ID 3 (Network Connection): Máy đó có kết nối tới IP lạ ngay sau khi chạy PowerShell không?
Kiểm tra Windows Event ID 11 (File Created): Nó có tạo ra file .exe lạ trong thư mục Temp không?
Kiểm tra xem user đó có hay dùng PowerShell không? Nếu user là nhân viên kế toán mà tự nhiên chạy PowerShell mã hóa -> rất bất thường.
Bước 6: Kết luận và Hành động
Kết luận:
Malicious: Có hành vi tải file, tắt AV, kết nối C2, mã hóa.
Benign: Lệnh rõ ràng, do admin chạy, không có obfuscation (ví dụ: Get-Service, Get-Process)
Hành động của L1:
Nếu Malicious: Cô lập máy ngay (Isolate Host), lấy mẫu file PowerShell, chặn IP C2 trên firewall, và Escalate lên L2 kèm theo bản giải mã.
Nếu Benign: Đóng alert là False Positive và note lại user này là IT admin.

NETWORK ANALYSIS
Mục đích: Xác định lưu lượng mạng (network traffic) là bình thường hay là hành vi tấn công / liên lạc với máy chủ điều khiển (C2).
Bước 1: Thu thập thông tin cơ bản (The 5-Tuple)
Mỗi khi có alert mạng, phải lấy ngay 5 thông tin này:
Source IP: IP nguồn (máy trong công ty)
Destination IP: IP đích (máy ngoài internet)
Source Port: Cổng nguồn
Destination Port: Cổng đích (ví dụ: 80, 443, 445, 3389)
Protocol: Giao thức (TCP, UDP, HTTP, DNS, ICMP)
Thêm: Thời gian, số lượng byte gửi/nhận, User-Agent (nếu là HTTP)
Bước 2: Làm giàu thông tin IP và Domain (IP Enrichment)
Đây là việc đầu tiên phải làm.
IP nội bộ: Tra trong Asset Inventory xem IP đó là máy của ai, phòng ban nào, có phải là server quan trọng không.
IP bên ngoài: Tra ngay trên VirusTotal, AbuseIPDB, Talos Intelligence, GreyNoise.
Nếu AbuseIPDB báo > 50% abuse score -> IP xấu.
Nếu GreyNoise báo là malicious -> đang bị botnet quét.
Domain: Tra trên VirusTotal, URLScan, Whois. Domain mới tạo gần đây (vài ngày) + tên ngẫu nhiên (ví dụ: xj9f2s...com) -> rất đáng ngờ (DGA).
Bước 3: Phân tích giao thức và hành vi (Protocol & Behavior Analysis)
Đây là bước để phát hiện bất thường.
HTTP/HTTPS (Port 80/443):
Kiểm tra User-Agent lạ không? (Ví dụ: Python-requests, curl, PowerShell)
URL có chứa .exe, .ps1, .bat không? Có tham số dài bất thường không?
Máy nội bộ gửi rất nhiều dữ liệu ra ngoài (Upload lớn) -> có thể đang rò rỉ dữ liệu (Data Exfiltration).
DNS (Port 53):
Kiểm tra DNS Query Length: Hacker hay dùng DNS để tuồn dữ liệu ra, nên tên miền sẽ rất dài và ngẫu nhiên.
Tần suất: Một máy mà query hàng ngàn tên miền lạ trong 1 phút -> nhiễm mã độc DGA.
NXDOMAIN nhiều: Máy liên tục hỏi những tên miền không tồn tại.
SMB / Lateral Movement (Port 445, 135):
Một máy trạm (workstation) bình thường không bao giờ kết nối tới hàng chục máy khác qua port 445. Nếu thấy -> đang có hành vi di chuyển ngang (Lateral Movement).
Beaconing / C2 Communication:
Dấu hiệu kinh điển: Một máy trong công ty cứ 5 phút lại kết nối tới 1 IP ngoài internet 1 lần, đều đặn, lượng byte nhỏ và bằng nhau. Đây là nhịp tim (heartbeat) của mã độc gọi về máy chủ điều khiển.
Bước 4: Phân tích gói tin (Packet Analysis - Nếu có PCAP)
Nếu được cung cấp file .pcap thì dùng Wireshark.
Dùng bộ lọc: ip.addr == [IP đáng ngờ]
Vào Statistics -> Conversations để xem ai nói chuyện với ai nhiều nhất.
Click chuột phải -> Follow -> TCP Stream / HTTP Stream để xem nội dung trao đổi.
Kiểm tra trong stream có chứa username, password, api key dạng plain-text không.
Bước 5: Tương quan (Correlation)
Máy có lưu lượng mạng đáng ngờ đó, trước đó có chạy PowerShell mã hóa không?
Có cảnh báo nào khác từ Endpoint (CrowdStrike, Defender) trên cùng máy đó không?
Có nhiều máy khác trong công ty cũng kết nối tới cùng 1 IP xấu đó không?
Bước 6: Kết luận và Hành động
Kết luận: True Positive (Tấn công thật / C2), Benign (Ứng dụng bình thường nhưng cấu hình sai), False Positive (Ví dụ: phần mềm update).
Hành động L1:
Nếu True Positive: Chặn IP / Domain độc hại trên Firewall ngay, cô lập máy nguồn, và Escalate lên L2 kèm bằng chứng PCAP và kết quả VirusTotal.
Nếu False Positive: Đóng alert và tạo rule exception nếu cần.


