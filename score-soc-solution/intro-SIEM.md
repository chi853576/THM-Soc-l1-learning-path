
## 1. SIEM là gì?

**SIEM (Security Information and Event Management)** là giải pháp bảo mật giúp thu thập log từ nhiều nguồn, chuẩn hóa dữ liệu, tương quan sự kiện và phát hiện hoạt động đáng ngờ thông qua các quy tắc phát hiện.

### Quy trình hoạt động cơ bản

```text
Log Sources
    ↓
Log Ingestion
    ↓
Parsing & Normalization
    ↓
Correlation & Detection Rules
    ↓
Alerts
    ↓
SOC Analyst điều tra
```

## 2. Log Sources — Nguồn log

Log ghi lại các sự kiện xảy ra trong hệ thống, giúp giám sát, điều tra sự cố và phát hiện hành vi đáng ngờ.

### Hai loại nguồn log chính

| Loại | Nội dung | Ví dụ nguồn |
|---|---|---|
| **Host-Centric** | Hoạt động trên máy tính hoặc máy chủ | Windows, Linux, Server |
| **Network-Centric** | Hoạt động giao tiếp mạng | Firewall, Router, IDS/IPS, VPN |

Ví dụ:

- Host-Centric: đăng nhập, thực thi tiến trình, truy cập tệp, chạy PowerShell, sửa Registry.
- Network-Centric: kết nối SSH, truy cập web, VPN, truyền tệp qua FTP.

### Vị trí log cần nhớ

| Hệ thống | Công cụ / Đường dẫn | Công dụng |
|---|---|---|
| Windows | Event Viewer | Xem log sự kiện Windows |
| Linux | `/var/log/auth.log` | Log xác thực trên Debian/Ubuntu |
| Linux | `/var/log/secure` | Log xác thực trên một số hệ thống RHEL |
| Linux | `/var/log/cron` | Log liên quan đến cron job trên một số hệ thống |
| Apache Web Server | `/var/log/apache2/` hoặc `/var/log/httpd/` | Thường chứa access log và error log |

Đường dẫn thực tế có thể thay đổi tùy hệ điều hành và cấu hình.

**Phân biệt log web server:**
- **Access log:** Ghi nhận các yêu cầu truy cập.
- **Error log:** Ghi nhận lỗi của web server.

## 3. Hạn chế của việc phân tích log riêng lẻ

| Hạn chế | Ý nghĩa |
|---|---|
| Numerous Log Sources | Quá nhiều nguồn và sự kiện cần phân tích |
| No Centralization | Log phân tán trên nhiều thiết bị |
| Limited Context | Một sự kiện riêng lẻ không đủ để hiểu toàn bộ hoạt động |
| Limited Analysis | Khó kiểm tra thủ công toàn bộ log |
| Format Issues | Các nguồn sử dụng định dạng log khác nhau |

**Giải pháp:** SIEM tập trung log, chuẩn hóa dữ liệu và liên kết các sự kiện để phát hiện những hành vi mà khi xem riêng lẻ có thể không đáng ngờ.

## 4. Các tính năng chính của SIEM

| Tính năng | Chức năng |
|---|---|
| Centralized Log Collection | Thu thập log từ nhiều nguồn về một nơi |
| Parsing | Tách log thành các trường dữ liệu |
| Normalization | Chuẩn hóa dữ liệu về cấu trúc thống nhất |
| Correlation | Liên kết các sự kiện để tìm ra mối quan hệ |
| Detection Rules | Xác định điều kiện cần phát hiện |
| Alerting | Tạo cảnh báo khi điều kiện phát hiện được thỏa mãn |
| Dashboards & Reporting | Hiển thị cảnh báo, thống kê và thông tin hệ thống |

SIEM còn có thể hỗ trợ tích hợp Threat Intelligence, lưu giữ log và tìm kiếm dữ liệu.

### Ví dụ về Correlation

Một người dùng:
1. Đăng nhập VPN từ IP lạ.
2. Truy cập tài liệu dùng chung.
3. Chạy PowerShell.
4. Tạo kết nối mạng ra bên ngoài.

Từng hành động có thể hợp lệ, nhưng kết hợp chúng có thể cho thấy dấu hiệu tài khoản bị xâm phạm hoặc dữ liệu bị đưa ra ngoài.

**Lưu ý:** Đây là dấu hiệu cần điều tra, chưa phải bằng chứng chắc chắn về một cuộc tấn công.

## 5. Log Ingestion — Đưa log vào SIEM

Bốn phương thức được giới thiệu trong room:

| Phương thức | Cách hoạt động |
|---|---|
| Agent / Forwarder | Phần mềm trên máy nguồn thu thập và gửi log đến SIEM |
| Syslog | Truyền thông điệp log đến hệ thống tiếp nhận tập trung |
| Manual Upload | Tải tệp log có sẵn lên để phân tích |
| Listening Port | Nguồn gửi log đến địa chỉ và cổng tiếp nhận đã cấu hình |

- **Agent / Forwarder:** Thường phù hợp với việc thu thập log liên tục từ endpoint.
- **Syslog:** Phổ biến với thiết bị mạng và máy chủ hỗ trợ Syslog.
- **Manual Upload:** Phù hợp với phân tích dữ liệu ngoại tuyến.
- **Listening Port:** Cho phép hệ thống nhận log qua mạng theo cấu hình.

## 6. Detection Rules — Quy tắc phát hiện

Detection Rule là tập hợp điều kiện logic dùng để phát hiện sự kiện hoặc hành vi đáng ngờ. Khi điều kiện được thỏa mãn, SIEM có thể tạo alert.

### Ví dụ 1: Nhiều lần đăng nhập thất bại

```text
IF failed login attempts >= 5
WITHIN 10 seconds
THEN ALERT "Multiple Failed Login Attempts"
```

### Ví dụ 2: Phát hiện tạo tiến trình `whoami`

```text
IF EventCode = 4688
AND NewProcessName CONTAINS "whoami"
THEN ALERT "WHOAMI command Execution DETECTED"
```

Trong Windows, Event ID 4688 liên quan đến việc tạo tiến trình mới, khi auditing phù hợp được bật.

### Ví dụ 3: Phát hiện xóa Event Log

Room sử dụng Event ID 104 để minh họa việc tạo cảnh báo xóa log. Khi áp dụng thực tế, cần xác minh provider và channel cụ thể; Security Event ID 1102 thường được dùng để ghi nhận việc xóa Security audit log.

### Các trường thường dùng trong Detection Rules

- `Log Source`: Nguồn tạo log.
- `Event ID` / `EventCode`: Mã sự kiện.
- `NewProcessName`: Tên hoặc đường dẫn tiến trình.
- `Source IP`: Địa chỉ IP nguồn.
- Thời gian và số lần sự kiện xảy ra.

**Normalization rất quan trọng** vì detection rule cần truy vấn đúng trường dữ liệu và giá trị tương ứng.

## 7. Alert Investigation — Điều tra cảnh báo

Khi SIEM tạo alert, analyst cần kiểm tra nguyên nhân kích hoạt và xác minh hoạt động thực tế.

### Quy trình cơ bản

1. Xem alert, thời gian, host và tài khoản liên quan.
2. Kiểm tra các điều kiện của detection rule.
3. Phân tích log liên quan trước và sau sự kiện.
4. Đối chiếu ngữ cảnh và xác minh hoạt động.
5. Phân loại kết quả và thực hiện hành động phù hợp.

### True Positive và False Positive

| Thuật ngữ | Ý nghĩa | Hành động |
|---|---|---|
| **True Positive (TP)** | Cảnh báo phát hiện đúng hoạt động độc hại hoặc hành vi mục tiêu | Điều tra sâu hơn và xử lý nếu xác nhận có sự cố |
| **False Positive (FP)** | Cảnh báo được kích hoạt nhưng hoạt động thực tế không phải mối đe dọa mục tiêu | Xem xét tinh chỉnh rule để giảm cảnh báo sai |

Các hành động khác có thể bao gồm liên hệ chủ sở hữu tài sản, cách ly host bị xâm nhập hoặc chặn IP đáng ngờ theo quy trình ứng phó sự cố.

**Cần nhớ:** Alert không đồng nghĩa với một cuộc tấn công đã được xác nhận.

## 8. Những khái niệm dễ nhầm lẫn

| Khái niệm | Phân biệt |
|---|---|
| Log source vs. Log | Nguồn tạo log vs. bản ghi sự kiện |
| Parsing vs. Normalization | Tách trường dữ liệu vs. chuẩn hóa cấu trúc |
| Normalization vs. Correlation | Thống nhất dữ liệu vs. liên kết sự kiện |
| Detection Rule vs. Alert | Điều kiện phát hiện vs. cảnh báo được tạo |
| TP vs. FP | Phát hiện đúng vs. cảnh báo sai so với mục tiêu phát hiện |
