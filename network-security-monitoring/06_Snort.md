# Snort

**Nguồn học:** [TryHackMe – Snort](https://tryhackme.com/room/snort)  
**Chủ đề:** Sử dụng Snort để sniff traffic, ghi packet, đọc PCAP, chạy IDS/IPS mode và viết custom detection rules.

> **Lưu ý phiên bản:** Nội dung lab này sử dụng cú pháp và cấu trúc **Snort 2** (trang room minh họa môi trường Snort 2.9.x, trong đó có ví dụ build 2.9.7.0). Không nên áp dụng nguyên xi cấu hình/rule của Snort 2 cho Snort 3. Hãy kiểm tra phiên bản thực tế bằng `snort -V` trước khi làm việc.

> **Phạm vi ghi chú:** Tập trung vào kỹ năng sử dụng công cụ và nguyên lý viết rule. Không bao gồm đáp án, flag, số lượng alert hoặc kết quả riêng từ các file PCAP của room.

## 1. Snort là gì?

**Snort** là công cụ open-source Network Intrusion Detection System / Network Intrusion Prevention System (NIDS/NIPS), sử dụng rules để xác định các packet hoặc traffic pattern đáng chú ý.

Các khả năng quan trọng:

- Phân tích traffic trực tiếp trên network interface.
- Phân tích packet capture (PCAP) đã lưu.
- Phát hiện attack pattern và reconnaissance activity dựa trên rules.
- Ghi log packet để điều tra.
- Tạo alert theo rule match.
- Hỗ trợ preprocessors và output plugins.

Snort là công cụ dựa trên rules: chất lượng detection phụ thuộc vào rule, cấu hình, vị trí sensor và dữ liệu traffic mà nó quan sát được.

## 2. IDS và IPS trong bối cảnh Snort

| Khái niệm | Cách hoạt động |
|---|---|
| NIDS | Giám sát traffic tại một segment hoặc nhiều vùng mạng; tạo alert khi rule match. |
| HIDS | Giám sát hoạt động trên một host cụ thể. Đây là nhóm theo vị trí triển khai, không phải mode mặc định của Snort network sensor. |
| NIPS | Được triển khai inline để có khả năng chặn/drop/reject traffic phù hợp với rule. |
| HIPS | Ngăn chặn hành vi trực tiếp trên host. |

Snort thường hoạt động ở chế độ quan sát/IDS khi không được cấu hình inline. Để dùng như IPS, cần triển khai inline và cấu hình DAQ/network path phù hợp. Không thử chế độ chặn trên mạng production khi chưa được phê duyệt và kiểm thử.

## 3. Chuẩn bị môi trường và kiểm tra cấu hình

Trong lab, các file thực hành được tổ chức theo thư mục task; file cấu hình mẫu và rule có thể nằm riêng với cấu hình đang chạy.

Một số đường dẫn thường gặp trong môi trường Snort 2:

| Đường dẫn | Vai trò |
|---|---|
| `/etc/snort/snort.conf` | File cấu hình chính. |
| `/etc/snort/rules/` | Thư mục chứa ruleset. |
| `/etc/snort/rules/local.rules` | Nơi đặt custom local rules. |
| `/var/log/snort/` | Thư mục log mặc định trong nhiều cấu hình. |

Đường dẫn có thể khác theo bản cài đặt. Luôn kiểm tra cấu hình thực tế trước khi chạy lệnh.

### 3.1. Kiểm tra phiên bản

```bash
snort -V
```

Xác định Snort version/build và những dependency được hiển thị. Phiên bản quan trọng vì Snort 2 và Snort 3 có khác biệt về cấu hình và rule options.

### 3.2. Kiểm tra file cấu hình

```bash
sudo snort -c /etc/snort/snort.conf -T
```

- `-c`: chỉ định configuration file.
- `-T`: kiểm tra cấu hình và phát hiện lỗi trước khi chạy.

Nên kiểm tra config sau khi chỉnh rule hoặc thay đổi cấu hình. Không nên đưa cấu hình chưa validate vào vận hành.

### 3.3. Quiet mode

```bash
sudo snort -q -c /etc/snort/snort.conf -T
```

`-q` giảm output banner/thông tin khởi tạo không cần thiết. Tùy mục đích debug, có thể bỏ `-q` để xem đầy đủ quá trình khởi động.

## 4. Sniffer Mode

Sniffer mode tương tự cách quan sát packet bằng tcpdump: Snort đọc traffic từ interface và hiển thị thông tin ra terminal.

### 4.1. Các tham số thường dùng

| Parameter | Ý nghĩa |
|---|---|
| `-i` | Chọn network interface. |
| `-v` | Verbose; hiển thị thông tin header/packet. |
| `-d` | Hiển thị packet payload ở dạng dữ liệu. |
| `-e` | Hiển thị Ethernet header. |
| `-X` | Hiển thị packet data ở dạng hex và ASCII. |

### 4.2. Ví dụ lệnh

Sniff traffic trên interface `eth0`:

```bash
sudo snort -v -i eth0
```

Hiển thị thêm payload:

```bash
sudo snort -vd -i eth0
```

Hiển thị Ethernet header:

```bash
sudo snort -vde -i eth0
```

Hiển thị packet payload dạng hex/ASCII:

```bash
sudo snort -X -i eth0
```

Các lệnh này chỉ quan sát traffic; chúng không tự động chứng minh một packet là malicious. Analyst cần đọc source/destination, protocol, port, flags và payload trong ngữ cảnh.

## 5. Packet Logger Mode

Packet logger mode dùng để lưu traffic vào file để phân tích sau, thay vì chỉ xem trực tiếp trên console.

### 5.1. Tham số liên quan

| Parameter | Ý nghĩa |
|---|---|
| `-l` | Chỉ định thư mục ghi log. |
| `-K ASCII` | Ghi packet theo dạng ASCII thay vì chỉ binary dump. |
| `-r` | Đọc packet capture/log đã có. |
| `-n` | Giới hạn số packet được xử lý. |

### 5.2. Ghi traffic vào thư mục log

Tạo thư mục trước nếu chưa tồn tại:

```bash
mkdir -p ./snort-logs
sudo snort -dev -i eth0 -l ./snort-logs
```

`-d`, `-e`, `-v` giúp quan sát thêm thông tin packet; `-l` chỉ định nơi ghi log.

Ghi log ở dạng ASCII:

```bash
sudo snort -dev -K ASCII -i eth0 -l ./snort-logs
```

### 5.3. Đọc PCAP bằng Snort

```bash
sudo snort -r capture.pcap
```

Đọc PCAP cùng cấu hình IDS và xuất alert chi tiết:

```bash
sudo snort -c /etc/snort/snort.conf -A full -l ./snort-logs -r capture.pcap
```

- `-r`: đọc file capture thay vì sniff interface trực tiếp.
- `-A full`: chọn alert format chi tiết.
- `-l`: chỉ định nơi ghi output/log.

Khi phân tích PCAP, cần biết file có bao nhiêu traffic, time range, interface/network context và rule set nào đang được sử dụng. Kết quả có thể thay đổi khi chạy cùng PCAP với ruleset hoặc cấu hình khác nhau.

## 6. IDS/IPS Mode

IDS/IPS mode sử dụng rules và cấu hình để quyết định packet nào cần tạo alert hoặc xử lý.

### 6.1. Các tham số thường dùng trong room

| Parameter | Ý nghĩa |
|---|---|
| `-c` | Chọn file cấu hình. |
| `-T` | Kiểm tra cấu hình. |
| `-N` | Tắt packet logging. |
| `-D` | Chạy ở background/daemon mode. |
| `-A` | Chọn alert mode. |

### 6.2. Ví dụ chạy IDS và hiển thị alert trên console

```bash
sudo snort -c /etc/snort/snort.conf -i eth0 -A console
```

Trong đó, Snort đọc traffic trên interface, nạp cấu hình/rules và hiển thị alert theo chế độ console khi rule match.

### 6.3. Alert mode

| Mode | Đặc điểm |
|---|---|
| `console` | Hiển thị alert nhanh trên terminal. |
| `fast` | Hiển thị thông tin ngắn như thời gian, message, source/destination và port. |
| `full` | Cung cấp nhiều chi tiết hơn về alert. |
| `cmg` | Hiển thị header cùng payload ở dạng hex/text. |
| `none` | Tắt alert output; không có nghĩa traffic không được xử lý. |

Ví dụ:

```bash
sudo snort -c /etc/snort/snort.conf -A fast -i eth0
```

### 6.4. Background mode

```bash
sudo snort -c /etc/snort/snort.conf -D
```

Kiểm tra process:

```bash
ps -ef | grep snort
```

Trong môi trường thực tế, nên quản lý service bằng cơ chế init/service manager phù hợp thay vì tự xử lý process thủ công. Chỉ dùng background mode khi cấu hình đã được kiểm thử và logging/monitoring hoạt động đúng.

## 7. Cấu trúc Snort 2 Rule

Trong rule syntax của Snort 2 ở room, các protocol filter cơ bản thường dùng là `ip`, `tcp`, `udp` và `icmp`. Một Snort 2 rule cơ bản có hai phần:

1. **Rule header:** action, protocol, source IP/port, direction, destination IP/port.
2. **Rule options:** message, SID, revision và điều kiện kiểm tra packet/payload.

Cấu trúc tổng quát:

```text
action protocol source_ip source_port direction destination_ip destination_port (options;)
```

### 7.1. Ví dụ custom ICMP alert rule

```text
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
```

Giải thích:

| Thành phần | Ý nghĩa |
|---|---|
| `alert` | Tạo alert khi packet khớp rule. |
| `icmp` | Chỉ áp dụng cho ICMP traffic. |
| `any any` | Bất kỳ source IP và source port. |
| `->` | Traffic theo hướng source tới destination. |
| `any any` | Bất kỳ destination IP và destination port. |
| `msg` | Nội dung thông báo của rule. |
| `sid` | Signature ID; cần duy nhất trong ruleset. |
| `rev` | Revision/version của rule. |

### 7.2. Direction operator

| Operator | Ý nghĩa |
|---|---|
| `->` | Source tới destination. |
| `<>` | Hai chiều. |

Snort 2 không dùng operator `<-` trong rule header.

### 7.3. Action thường gặp

| Action | Ý nghĩa tổng quát |
|---|---|
| `alert` | Tạo alert và ghi nhận packet theo cấu hình. |
| `log` | Ghi packet mà không nhất thiết tạo alert. |
| `pass` | Bỏ qua packet phù hợp với rule. |
| `drop` | Drop packet trong môi trường inline phù hợp. |
| `reject` | Chặn và gửi phản hồi/đóng kết nối theo protocol và cấu hình hỗ trợ. |

Khả năng thực thi action phụ thuộc mode triển khai. Một rule `drop`/`reject` không tự biến sensor thụ động thành IPS; cần inline mode và DAQ/network configuration tương ứng.

## 8. Rule Options quan trọng

### 8.1. General rule options

| Option | Chức năng |
|---|---|
| `msg` | Message hiển thị khi rule match. |
| `sid` | Signature ID để phân biệt rule. |
| `rev` | Revision number của rule. |
| `reference` | Tham chiếu tài liệu hoặc ID liên quan nếu được cấu hình. |

### 8.2. Payload detection options

| Option | Chức năng |
|---|---|
| `content` | Tìm chuỗi/byte pattern trong payload. |
| `nocase` | Không phân biệt chữ hoa/chữ thường cho phép so khớp content liên quan. |

Ví dụ rule tìm chuỗi cụ thể trong TCP packet:

```text
alert tcp any any -> any any (msg:"Example string detected"; content:"suspicious-pattern"; sid:1000002; rev:1;)
```

`content` phải được lựa chọn cẩn thận. Pattern quá rộng có thể tạo nhiều false positive; pattern quá hẹp có thể bỏ sót biến thể.

### 8.3. Non-payload options

| Option | Chức năng |
|---|---|
| `flags` | Lọc theo TCP flags như SYN, ACK, FIN, RST, PSH hoặc URG. |
| `dsize` | Lọc theo kích thước payload. |
| `sameip` | Kiểm tra trường hợp source IP và destination IP giống nhau. |
| `flow` | Lọc theo trạng thái/hướng flow trong những rule hỗ trợ option này. |

Ví dụ rule tìm TCP SYN packet:

```text
alert tcp any any -> any any (msg:"TCP SYN observed"; flags:S; sid:1000003; rev:1;)
```

Ví dụ lọc packet có payload size lớn hơn một ngưỡng:

```text
alert ip any any -> any any (msg:"Large IP payload"; dsize:>1000; sid:1000004; rev:1;)
```

Ngưỡng payload trong ví dụ chỉ minh họa cú pháp, không phải ngưỡng phát hiện áp dụng cho mọi môi trường.

## 9. Local rules và cấu hình Snort 2

### 9.1. Local rules

Trong môi trường room, local rules thường được đặt tại:

```text
/etc/snort/rules/local.rules
```

Có thể mở file bằng editor có sẵn trên hệ thống, ví dụ:

```bash
sudo nano /etc/snort/rules/local.rules
```

Sau khi thêm rule, kiểm tra xem file cấu hình chính có include local rules hay không. Không nên giả định mọi bản cài Snort đều bật cùng một dòng include.

### 9.2. Các biến cấu hình thường gặp

| Variable | Ý nghĩa |
|---|---|
| `HOME_NET` | Mạng nội bộ đang được bảo vệ. |
| `EXTERNAL_NET` | Mạng bên ngoài; thường được định nghĩa tương quan với `HOME_NET`. |
| `RULE_PATH` | Đường dẫn chứa rules. |
| `SO_RULE_PATH` | Đường dẫn rule liên quan shared object nếu được sử dụng. |
| `PREPROC_RULE_PATH` | Đường dẫn rules liên quan preprocessors nếu có. |

Cấu hình `HOME_NET` sai có thể khiến rule không khớp như dự kiến hoặc tạo nhiều alert nhiễu.

## 10. Snort processing pipeline

Các thành phần chính thường được mô tả trong Snort 2:

1. **Packet Decoder:** nhận packet và chuẩn bị dữ liệu đầu vào.
2. **Preprocessors:** xử lý/chuẩn hóa traffic trước khi detection engine phân tích; ví dụ hỗ trợ protocol normalization hoặc tái lắp ghép tùy module.
3. **Detection Engine:** áp dụng rule và đánh giá điều kiện match.
4. **Logging and Alerting:** tạo alert và lưu packet/event theo cấu hình.
5. **Output plugins:** chuyển output tới các kênh logging/integration được cấu hình.

Hiểu pipeline giúp analyst biết alert xuất hiện từ giai đoạn nào và cần kiểm tra cấu hình nào khi rule không hoạt động như mong đợi.

## 11. Quy trình tạo và kiểm thử custom rule

1. Xác định hành vi cần phát hiện và nguồn packet/PCAP phù hợp.
2. Xác định protocol, source/destination, port và hướng traffic.
3. Chọn action phù hợp với mode triển khai; khi mới kiểm thử, ưu tiên `alert`.
4. Xác định điều kiện trong rule options: content, flags, payload size hoặc flow.
5. Viết `msg`, `sid` duy nhất và `rev`.
6. Lưu rule trong `local.rules` hoặc file rule được cấu hình.
7. Kiểm tra cấu hình:

```bash
sudo snort -c /etc/snort/snort.conf -T
```

8. Chạy rule trên PCAP:

```bash
sudo snort -c /etc/snort/snort.conf -A full -l ./snort-logs -r sample.pcap
```

9. Kiểm tra alert, packet và lý do match.
10. Điều chỉnh điều kiện để giảm false positive và tăng tính đặc hiệu.
11. Ghi chú mục tiêu, điều kiện, giới hạn và test case của rule.

## 12. Những lỗi thường gặp khi làm việc với Snort

- Chỉnh rule nhưng quên kiểm tra `snort.conf` có include file đó không.
- `HOME_NET`/`EXTERNAL_NET` đặt sai.
- `sid` bị trùng hoặc `rev` không được cập nhật khi thay đổi rule.
- Content match quá chung, dẫn đến nhiều alert không liên quan.
- Dùng alert count làm kết luận mà không đọc packet.
- Chạy PCAP bằng ruleset khác nhau rồi so sánh kết quả mà không ghi lại config.
- Dùng cú pháp Snort 3 trong môi trường Snort 2 hoặc ngược lại.
- Bật drop/reject trên mạng thật khi chưa kiểm thử inline mode và tác động tới traffic.

## 13. Snort 2 và Snort 3: điểm cần lưu ý

Room này mô tả Snort 2, với file cấu hình kiểu `snort.conf` và rule syntax như ví dụ ở trên. Snort 3 có kiến trúc và cách cấu hình khác; tài liệu Snort 3 hiện hành sử dụng rule guide riêng và có khác biệt về một số option/cú pháp.

Trước khi sao chép một rule từ Internet:

1. Xác định Snort version bằng `snort -V`.
2. Chọn đúng manual/rule guide theo version.
3. Kiểm tra rule syntax bằng test config.
4. Test trên PCAP hoặc lab an toàn trước khi đưa vào production.

## 14. Kiến thức và kỹ năng có thể thể hiện trong portfolio

- Kiểm tra Snort version và validate configuration.
- Dùng sniffer mode để quan sát live packet.
- Ghi packet và đọc capture/PCAP bằng Snort.
- Phân biệt sniffer, packet logger và IDS/IPS mode.
- Giải thích Snort 2 rule header, direction operator và rule options.
- Viết custom rule có `msg`, `sid`, `rev` và điều kiện phát hiện.
- Kiểm thử rule, đọc alert và điều chỉnh để giảm false positive.
- Nhận biết sự khác biệt giữa triển khai IDS thụ động và IPS inline.

## 15. Tài liệu tham khảo

- [TryHackMe – Snort](https://tryhackme.com/room/snort)
- [TryHackMe – IDS Fundamentals](https://tryhackme.com/room/idsfundamentals)
- [Snort 3 – Rule Writing Guide](https://docs.snort.org/rules/) (tham khảo cho Snort 3; không dùng để thay thế tài liệu cú pháp Snort 2 của room)
- [Snort – Official Website](https://www.snort.org/)
