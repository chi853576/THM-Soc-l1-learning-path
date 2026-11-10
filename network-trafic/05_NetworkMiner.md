# NetworkMiner

**Nguồn học:** [TryHackMe – NetworkMiner](https://tryhackme.com/room/networkminer)

## 1. NetworkMiner là gì?

**NetworkMiner** là công cụ mã nguồn mở thuộc nhóm **Network Forensic Analysis Tool (NFAT)**, được phát triển bởi Netresec. Công cụ hỗ trợ điều tra traffic đã ghi lại, nhận diện host và session, phân tích giao thức, đồng thời trích xuất một số artifacts như file và certificate từ PCAP.

NetworkMiner có thể được sử dụng theo hai cách:
- **Passive sniffing:** quan sát traffic trên interface và lập hồ sơ host/session mà không chủ động gửi traffic thăm dò.
- **PCAP parsing:** mở file capture để phân tích offline.

Đây là công cụ bổ trợ cho Wireshark. NetworkMiner thiên về việc tổng hợp host và trích xuất artifacts; Wireshark mạnh trong việc xem chi tiết từng packet và diễn giải protocol tree.

## 2. Network forensics là gì?

**Network forensics** là quá trình thu thập, bảo toàn, kiểm tra và diễn giải dữ liệu mạng để tái dựng sự kiện, xác định hệ thống liên quan và tìm bằng chứng phục vụ incident response.

Câu hỏi thường gặp:
- Host nào đã giao tiếp?
- Host nào liên hệ với domain/IP bên ngoài?
- Giao thức và dịch vụ nào được sử dụng?
- Có file nào được truyền qua mạng không?
- Có certificate hoặc thông tin định danh nào hỗ trợ điều tra?
- Dữ liệu có cho thấy hoạt động đáng ngờ hoặc dấu hiệu xâm nhập không?

PCAP có thể cung cấp bằng chứng ở mức packet, nhưng phạm vi kết luận phụ thuộc điểm capture, thời lượng, packet loss, giao thức mã hóa và dữ liệu có sẵn.

## 3. Khi nào dùng NetworkMiner?

NetworkMiner hữu ích khi cần:
- Tóm tắt nhanh các host xuất hiện trong capture.
- Xem địa chỉ IP/MAC, hostname hoặc thông tin host được suy ra từ traffic.
- Tổng hợp session và các giao tiếp quan sát được.
- Liệt kê DNS names, web requests hoặc artifacts theo những protocol được hỗ trợ.
- Trích xuất file được truyền qua giao thức mà công cụ có thể tái dựng.
- Thu thập certificate hoặc các artifacts phục vụ điều tra offline.

Không phải mọi PCAP đều chứa đủ dữ liệu để NetworkMiner khôi phục file hoặc hostname. Traffic mã hóa, capture một chiều hoặc thiếu packet có thể hạn chế kết quả.

## 4. Mở PCAP và bắt đầu phân tích

Quy trình cơ bản:
1. Khởi động NetworkMiner trong môi trường phân tích.
2. Chọn **File → Open** (hoặc chức năng mở PCAP tương đương theo phiên bản).
3. Chọn file `.pcap` / `.pcapng`.
4. Chờ công cụ xử lý toàn bộ capture; file lớn có thể cần thêm thời gian.
5. Xem các tab kết quả để hiểu host, session và artifacts.
6. Ghi nhận các thông tin liên quan, rồi quay lại Wireshark để xác minh packet cụ thể.

Trong lab TryHackMe, phiên bản NetworkMiner được cài sẵn trong máy ảo. Cần dùng phiên bản mà hướng dẫn của lab yêu cầu vì giao diện hoặc chức năng có thể khác nhau giữa các bản.

Nếu dữ liệu dường như thiếu, hãy kiểm tra lại file đầu vào, chờ xử lý hoàn tất và thử tải PCAP lại. Công cụ có thể hiển thị hoặc nhóm thông tin khác cách Wireshark làm.

## 5. Các tab và loại dữ liệu thường gặp

Tên tab và trường cụ thể có thể khác giữa phiên bản, nhưng các nhóm dữ liệu thường gồm:

| Nhóm / tab | Nội dung có thể cung cấp | Giá trị điều tra |
|---|---|---|
| **Hosts** | Host được nhận diện, IP/MAC, hostname và metadata có sẵn | Lập danh sách hệ thống xuất hiện trong capture |
| **Sessions** | Các cuộc giao tiếp/session giữa endpoint | Tìm cặp host và giao tiếp đáng chú ý |
| **DNS** | Tên miền và truy vấn DNS được nhận diện | Xây dựng mối liên hệ host–domain |
| **Files** | File được tái dựng từ traffic khi có đủ dữ liệu | Tìm file được tải lên/tải xuống |
| **Images** | Hình ảnh trích xuất được từ các giao thức hỗ trợ | Artifact bổ sung cho điều tra web |
| **Messages / Credentials** | Một số thông điệp hoặc thông tin được nhận diện từ protocol hỗ trợ | Kiểm tra phơi lộ dữ liệu; cần xử lý bí mật cẩn trọng |
| **Parameters / Keywords** | Các trường hoặc chuỗi được trích xuất theo chức năng của phiên bản | Tìm dữ liệu có thể liên quan đến sự kiện |
| **Certificates** | Certificate quan sát được trong traffic | Hỗ trợ nhận diện dịch vụ và điều tra TLS |

Không phải phiên bản nào cũng có cùng các tab. Không nên coi danh sách tab là bảo đảm rằng công cụ có thể giải mã mọi giao thức hoặc tìm thấy mọi artifact.

## 6. Hosts và fingerprinting

NetworkMiner có thể tổng hợp thông tin về các host được nhìn thấy trong PCAP. Tùy dữ liệu, có thể thu thập:
- IP và MAC address.
- Hostname hoặc tên máy được quảng bá qua giao thức.
- Thông tin về hệ điều hành hoặc thiết bị được suy ra từ dấu vết mạng.
- Các port, service hoặc session liên quan.

**Fingerprinting** là suy luận đặc điểm của host từ các dấu hiệu quan sát được. Đây không phải lúc nào cũng là nhận diện chắc chắn: hostname có thể bị giả mạo, IP có thể được cấp lại, và fingerprint có thể sai nếu dữ liệu không đầy đủ.

### Cách dùng thông tin host
1. Xác định host nội bộ liên quan đến alert.
2. Xem host đó giao tiếp với endpoint nào.
3. Ghi lại hostname/IP/MAC cùng thời gian capture.
4. Đối chiếu với DHCP, EDR, asset inventory hoặc log mạng.
5. Dùng Wireshark kiểm tra các packet hỗ trợ kết luận.

## 7. Sessions và giao tiếp mạng

Session view giúp gom nhóm các cuộc giao tiếp được công cụ nhận diện. Đây là điểm bắt đầu để trả lời:
- Host nào nói chuyện với host nào?
- Giao tiếp có liên quan đến domain/IP đáng ngờ không?
- Có nhiều session lặp lại hoặc bất thường không?
- Session có liên quan tới file được trích xuất hay DNS request không?

### Quy trình phân tích session
1. Xác định source và destination.
2. Kiểm tra protocol, port và thời gian nếu được cung cấp.
3. So sánh với baseline hoặc hoạt động hợp pháp đã biết.
4. Chọn conversation đáng chú ý.
5. Mở PCAP trong Wireshark và lọc theo endpoint/protocol.
6. Xem packet, stream và payload để xác nhận ý nghĩa.

Một session lạ không tự động là độc hại. Cần xem ứng dụng, thời gian, người dùng và bằng chứng liên quan.

## 8. File extraction và artifacts

NetworkMiner có thể tái dựng file từ một số giao thức khi PCAP chứa đủ dữ liệu. Kết quả phụ thuộc protocol, hướng traffic, packet completeness và khả năng hỗ trợ của phiên bản.

### Quy trình xử lý file được trích xuất
1. Ghi lại tên file, kích thước, nguồn/đích và thời gian nếu có.
2. Không mở hoặc thực thi file trên máy cá nhân.
3. Tính hash (ví dụ SHA-256) để định danh artifact.
4. Kiểm tra loại file thực tế bằng công cụ phù hợp; không tin hoàn toàn vào extension.
5. Dùng sandbox và quy trình malware triage được phê duyệt.
6. Tương quan artifact với HTTP/FTP/session trong PCAP.
7. Ghi kết quả và giới hạn của việc trích xuất.

Không phải file xuất hiện trong tab Files nào cũng độc hại. Tương tự, không thấy file không có nghĩa là không có truyền file; traffic có thể mã hóa hoặc capture thiếu.

## 9. Certificates và traffic mã hóa

Certificate có thể cung cấp thông tin như subject, issuer, validity period và các tên miền được liệt kê, tùy certificate và giao thức.

Có thể dùng certificate để:
- So sánh danh tính dịch vụ với hostname kết nối.
- Phát hiện certificate tự ký hoặc bất thường cần kiểm tra thêm.
- Bổ sung ngữ cảnh khi điều tra kết nối TLS.

Certificate hợp lệ không chứng minh website an toàn, và certificate bất thường không tự động chứng minh tấn công. HTTPS thường mã hóa payload; NetworkMiner không thể khôi phục nội dung plaintext nếu dữ liệu/khóa cần thiết không có sẵn.

## 10. NetworkMiner và Wireshark: dùng kết hợp

| Nhu cầu | NetworkMiner | Wireshark |
|---|---|---|
| Tổng hợp host và artifacts nhanh | Thường thuận tiện | Có thể làm nhưng thường cần nhiều thao tác |
| Xem từng packet và trường protocol | Có giới hạn theo giao diện | Rất phù hợp |
| Lọc packet theo biểu thức phức tạp | Khả năng tùy phiên bản | Display filters mạnh và linh hoạt |
| Follow TCP stream | Không phải điểm mạnh chính | Tính năng quan trọng |
| Trích xuất file từ PCAP | Hỗ trợ các protocol phù hợp | Có Export Objects cho một số protocol |
| Điều tra sâu một dấu hiệu cụ thể | Dùng để tìm điểm bắt đầu | Dùng để xác minh bằng packet-level evidence |

Workflow đề xuất: **NetworkMiner để tổng hợp host/artifact → Wireshark để xác minh packet/stream → các nguồn log khác để tương quan.**

## 11. Giới hạn và lưu ý

- **Capture không đầy đủ:** thiếu packet có thể làm session hoặc file không được tái dựng chính xác.
- **Mã hóa:** TLS/VPN có thể che payload và hạn chế việc trích xuất.
- **False positives:** fingerprint hoặc chuỗi được nhận diện có thể không chính xác trong mọi trường hợp.
- **Phiên bản khác nhau:** giao diện và các tab có thể thay đổi.
- **Dữ liệu nhạy cảm:** PCAP và file trích xuất có thể chứa credentials, cookies, dữ liệu cá nhân hoặc tài liệu nội bộ.
- **Chain of custody:** trong điều tra chính thức, giữ bản gốc, ghi hash, ghi công cụ/phiên bản và lưu lại các bước xử lý.
- **Không chủ động tương tác:** không truy cập domain/IP đáng ngờ hoặc chạy artifact chỉ vì chúng xuất hiện trong capture.

## 12. Mẫu ghi chú khi dùng NetworkMiner

```text
Case / Alert:
PCAP filename and SHA-256:
Capture time range:
Tool and version:
Hosts of interest:
Sessions of interest:
Domains / IPs:
Files or certificates extracted:
Related packet evidence in Wireshark:
Assessment:
Limitations:
Recommended next steps:
```

## 13. Kỹ năng đạt được
- Giải thích vai trò của NetworkMiner trong network forensics.
- Mở PCAP và điều hướng các nhóm dữ liệu host/session/artifact.
- Dùng thông tin host để hỗ trợ dựng timeline và tìm giao tiếp liên quan.
- Hiểu quy trình an toàn khi xử lý file được trích xuất.
- Kết hợp NetworkMiner với Wireshark và log khác để tạo kết luận có bằng chứng.

## Tài liệu tham khảo
- [TryHackMe – NetworkMiner](https://tryhackme.com/room/networkminer)
- [Netresec – NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
