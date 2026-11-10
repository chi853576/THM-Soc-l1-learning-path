# Linux Threat Detection 1

**Nguồn học:** [TryHackMe – Linux Threat Detection 1](https://tryhackme.com/room/linuxthreatdetection1)  
**Trọng tâm:** Phát hiện Initial Access vào Linux server, đặc biệt qua SSH và các dịch vụ public-facing; sử dụng authentication logs, application logs và process tree analysis.

---

## Task 1: Introduction

### 1. Mục tiêu học tập

- Hiểu rủi ro khi SSH được expose ra Internet.
- Nhận diện các dấu hiệu SSH brute force và credential compromise.
- Hiểu cách public-facing services có thể trở thành điểm xâm nhập.
- Phân tích application logs để tìm dấu hiệu khai thác.
- Dùng auditd và process tree để xác định nguồn gốc process đáng ngờ.

### 2. Initial Access là gì?

Initial Access là giai đoạn threat actor tìm cách có được quyền truy cập ban đầu vào hệ thống hoặc môi trường. Trên Linux server, các đường xâm nhập có thể bao gồm:
- SSH password bị đoán hoặc bị lộ.
- SSH private key bị đánh cắp.
- Public-facing application bị khai thác.
- Dịch vụ hoặc phần mềm có lỗ hổng.
- Supply chain compromise thông qua phần mềm/phụ thuộc đáng tin cậy.

---

## Task 2: Initial Access via SSH

### 1. SSH trong môi trường Linux

SSH (Secure Shell) là giao thức quản trị/truy cập từ xa phổ biến. SSH có thể xác thực bằng:
- **Password authentication:** dùng username và password.
- **Public-key authentication:** server xác minh private key của client thông qua public key đã được cấu hình.

SSH thuận tiện cho quản trị, automation và deployment, nhưng cũng là bề mặt tấn công khi mở công khai hoặc cấu hình yếu.

### 2. Các rủi ro thường gặp

**Password-based authentication**
- Password yếu hoặc dùng lại giữa các dịch vụ.
- Tài khoản thử nghiệm/contractor không được đổi mật khẩu.
- SSH được mở ra Internet mà không có kiểm soát bổ sung.
- Không có giới hạn tốc độ hoặc giám sát login failure phù hợp.

**Key-based authentication**
- Private key bị lưu trong source code, repository hoặc automation server không an toàn.
- Máy quản trị bị nhiễm infostealer làm lộ SSH private key.
- Key cũ không được thu hồi sau khi nhân sự/nhà cung cấp kết thúc quyền truy cập.
- File `authorized_keys` bị thêm key không được phê duyệt.

### 3. Xem SSH logs

Trên Debian/Ubuntu thường dùng:

```bash
grep "sshd" /var/log/auth.log
```

Trên RHEL-based thường kiểm tra:

```bash
grep "sshd" /var/log/secure
```

Một số mẫu thông điệp:
- `Accepted password`: đăng nhập SSH bằng password thành công.
- `Accepted publickey`: đăng nhập bằng public key thành công.
- `Failed password`: xác thực password thất bại.
- `Invalid user`: username không tồn tại hoặc không được nhận diện.

### 4. Dấu hiệu SSH attack

| Dấu hiệu | Ý nghĩa cần đánh giá |
|---|---|
| Nhiều `Failed password` | Có thể là brute force hoặc lỗi cấu hình/client |
| Một IP thử nhiều username | Có thể là password spraying hoặc user enumeration |
| Một username bị thử nhiều lần | Có thể là brute force nhắm mục tiêu |
| Failed logins nối tiếp bằng `Accepted` | Có thể cho thấy credential đã bị đoán/trộm |
| Login ngoài giờ hoặc từ nguồn lạ | Cần kiểm tra lịch làm việc và nguồn IP |
| Service account có interactive login | Có thể lệch khỏi hành vi automation bình thường |

### 5. Quy trình phân tích SSH login

1. Lọc các event `Failed`, `Invalid user` và `Accepted`.
2. Nhóm theo source IP, username và khoảng thời gian.
3. Xác định phương thức xác thực: password hay public key.
4. So sánh với baseline đăng nhập và danh sách IP quản trị/automation được tin cậy.
5. Tìm chuỗi successful login sau các lần thất bại.
6. Kiểm tra activity sau login bằng sudo logs, auditd và process telemetry.
7. Đánh giá xem đây là hoạt động hợp lệ, false positive hay dấu hiệu compromise.

Không nên xem việc sử dụng password hoặc IP bên ngoài là bằng chứng kết luận độc lập. Cần xác minh với owner của tài khoản, lịch vận hành và nguồn tài sản.

---

## Task 3: Detecting SSH Attacks

### 1. Brute force và password spraying

**Brute force**
- Attacker lặp lại việc thử mật khẩu cho một hoặc một số tài khoản.
- Log có thể thể hiện nhiều authentication failures liên tiếp.
- Tần suất và số lần thử là các yếu tố cần phân tích.

**Password spraying**
- Attacker thử một số lượng nhỏ mật khẩu phổ biến trên nhiều tài khoản.
- Có thể làm phân tán số lần thất bại theo từng user.
- Phân tích theo source IP và nhiều username giúp nhìn ra pattern.

### 2. Xác minh successful login

Khi phát hiện login thành công đáng ngờ, cần kiểm tra:
- Username và chủ sở hữu account.
- IP nguồn, ASN/asset context và reputation nếu có.
- Thời điểm login và vị trí/giờ làm việc thông thường.
- Authentication method.
- Những lần thất bại trước đó.
- Các lệnh hoặc file được truy cập sau login.

### 3. Phân tích hành vi sau SSH login

Dùng authentication logs và auditd để tìm:
- Session opened/closed.
- Sử dụng `sudo` hoặc `su`.
- Process discovery hoặc download.
- Tạo user, thay đổi group/SSH config.
- File hoặc scheduled task mới được tạo.
- Network connections bất thường.

Mục tiêu là nối hoạt động sau đăng nhập với đúng user/session, không chỉ đánh giá login event riêng lẻ.

---

## Task 4: Initial Access via Services

### 1. Public-facing services

Linux server có thể chạy nhiều dịch vụ public-facing:
- Web server và web applications.
- Email server.
- Database.
- VPN/firewall software.
- Container management hoặc orchestration API.
- Công cụ quản trị/development được expose ra mạng.

Khi một dịch vụ bị khai thác, attacker có thể thực thi lệnh dưới quyền của service account hoặc khai thác tiếp để chiếm quyền host.

### 2. Application logs

Application logs có thể cung cấp bằng chứng về request hoặc hành vi cụ thể:
- Web access logs: client IP, URI, HTTP method, status, timestamp.
- Web error logs: lỗi xử lý request hoặc ứng dụng.
- Database logs: authentication/query events.
- VPN logs: remote access/session.
- Mail logs: kết nối và xử lý email.

Application logs thường không mô tả đầy đủ việc một lệnh hệ điều hành có được thực thi hay không. Cần đối chiếu với process/runtime logs.

### 3. Command injection

Command injection xảy ra khi ứng dụng đưa input của người dùng vào câu lệnh hệ điều hành mà không kiểm soát phù hợp.

Dấu hiệu trong web logs:
- Tham số vốn cần một giá trị hợp lệ nhưng lại chứa cú pháp/lệnh shell.
- Request bất thường lặp lại theo từng bước kiểm tra.
- Các request bắt đầu bằng input lỗi rồi chuyển sang biểu thức có thể thực thi lệnh.
- Một client thực hiện nhiều request discovery bất thường.

Ví dụ về ngữ cảnh cần xem xét:
- Endpoint nhận hostname/IP nhưng query parameter chứa từ khóa command hoặc shell metacharacters.
- Request đến endpoint quản trị không phù hợp với hành vi người dùng thông thường.
- Request có status khác nhau khi attacker thử nhiều biến thể input.

**Lưu ý:** HTTP status hoặc query string đơn lẻ không chứng minh command đã chạy. Phải tìm process execution logs và kiểm tra output/effect nếu có.

### 4. Phân tích Nginx access logs

```bash
# Đọc web access log
cat /var/log/nginx/access.log

# Tìm request đến endpoint cụ thể
grep "/ping" /var/log/nginx/access.log

# Lọc client IP
grep "CLIENT_IP" /var/log/nginx/access.log
```

Các trường hữu ích:
- Client IP.
- Timestamp.
- HTTP method.
- Request URI và query string.
- HTTP status.
- Response size.

Cần chú ý URL-encoded input, request sequence và các request từ cùng IP. Khi đưa URI độc hại vào báo cáo, nên defang hoặc escape để tránh vô tình kích hoạt liên kết.

---

## Task 5: Detecting Service Breach

### 1. Vì sao cần process tree analysis?

Application logs có thể cho thấy attacker gửi request gì, nhưng không nhất thiết cho biết:
- Ứng dụng có tạo process mới hay không.
- Process nào thực thi lệnh.
- Lệnh chạy dưới account nào.
- Process được tạo bởi user session hay bởi web/database/service process.

Process tree analysis giúp lần ngược từ command đáng ngờ đến chương trình hoặc service đã khởi chạy nó.

### 2. Tìm process execution với auditd

Ví dụ lọc theo command:

```bash
ausearch -i -x whoami
```

Một audit event có thể cung cấp:
- `pid`: process ID.
- `ppid`: parent process ID.
- `auid`: audit user ID.
- `uid`: user ID đang thực thi.
- `exe`: đường dẫn executable.
- `proctitle`: command/process title.
- `tty`: terminal context nếu có.

### 3. Dựng process tree

Quy trình tổng quát:

1. Tìm process đáng ngờ bằng tên lệnh hoặc executable.
2. Ghi nhận PID và PPID.
3. Tra cứu parent bằng PPID.
4. Lặp lại đến khi xác định được nguồn khởi chạy, thường đi lên các ancestor process cao hơn.
5. Liệt kê các child process của parent đáng chú ý.
6. Đối chiếu timestamp, account, working directory và application logs.

Ví dụ cấu trúc chuỗi cần nhận diện:

```text
service manager
└── web application runtime
    └── shell
        └── unexpected command
            └── downloader or other child process
```

Nếu web application khởi chạy shell/process không thuộc chức năng bình thường của ứng dụng, cần điều tra khả năng application compromise hoặc command injection.

### 4. Lần theo parent và child process

```bash
# Tìm command execution
ausearch -i -x COMMAND

# Xem event của process cha
ausearch -i --pid PARENT_PID

# Xem process được một PID khởi chạy
ausearch -i --ppid PARENT_PID
```

Thay `COMMAND` và PID placeholder bằng giá trị điều tra thực tế trong lab/môi trường được phép.

### 5. Các dấu hiệu process tree bất thường

- Web server hoặc database process sinh ra shell.
- Service account chạy lệnh quản trị không phù hợp chức năng.
- Process chain có downloader/interpreter bất thường.
- Process chạy từ thư mục tạm hoặc đường dẫn không tin cậy.
- Process có `auid` không rõ/không có interactive TTY trong khi hoạt động có vẻ do con người thực hiện.
- Một parent process tạo nhiều child process có liên quan đến discovery hoặc tải file.

Cần xác minh với application owner trước khi kết luận; một số ứng dụng hợp pháp cũng có thể tạo subprocess.

---

## Task 6: Advanced Initial Access

### 1. Supply chain compromise

Supply chain compromise là việc attacker xâm nhập nhà cung cấp, package, dependency hoặc quy trình phân phối phần mềm để tác động đến hệ thống sử dụng sản phẩm đó.

Ví dụ rủi ro:
- Package/update bị thay thế hoặc chèn mã độc.
- Dependency bị compromise.
- CI/CD pipeline hoặc automation credential bị lộ.
- Binary đáng tin cậy nhưng nội dung hoặc nguồn phân phối không còn đáng tin cậy.

### 2. Dấu hiệu cần quan sát

- Package mới hoặc phiên bản thay đổi bất thường.
- Process được tạo ngay sau quá trình update.
- File executable xuất hiện ở vị trí bất thường.
- Hash/chữ ký khác với baseline.
- Kết nối mạng hoặc hành vi process lạ sau khi cài đặt package.
- Tác động đồng thời trên nhiều host sử dụng cùng package.

### 3. Kết hợp nhiều nguồn log

Một cuộc điều tra Initial Access nên tương quan:
- SSH authentication logs.
- Web/application logs.
- `auditd` process execution.
- File/package manager logs.
- Network/DNS telemetry.
- Account và privilege changes.

---

## Quy trình phân tích Initial Access trên Linux

1. **Xác định alert:** SSH login bất thường, web request đáng ngờ hoặc process không quen thuộc.
2. **Xác định điểm xâm nhập:** SSH, public-facing service, package/dependency hay nguồn khác.
3. **Xác minh authentication:** account, IP, phương thức và session.
4. **Kiểm tra application evidence:** endpoint, request sequence và input.
5. **Dựng process tree:** bắt đầu từ process đáng ngờ và lần ngược parent.
6. **Kiểm tra hành động tiếp theo:** discovery, download, account changes, persistence hoặc network activity.
7. **Dựng timeline:** liên kết timestamp từ các nguồn log.
8. **Kết luận có căn cứ:** nêu evidence, giả thuyết, mức độ tin cậy và điểm cần xác minh.

## Ghi nhớ

- SSH là dịch vụ quản trị hữu ích nhưng có thể là Initial Access vector nếu lộ credential hoặc cấu hình yếu.
- Phải phân tích cả login failure lẫn successful login và activity sau login.
- Public-facing applications có thể bị khai thác để thực thi lệnh hệ điều hành.
- Web logs cho biết request; auditd/process logs giúp xác định command có được thực thi và process nào tạo ra nó.
- Process tree là kỹ năng cốt lõi để truy nguyên nguồn gốc Initial Access.
- Supply chain compromise cần phân tích package, file, process và network telemetry cùng nhau.

## Nguồn tham khảo

- [TryHackMe – Linux Threat Detection 1](https://tryhackme.com/room/linuxthreatdetection1)
- [MITRE ATT&CK – External Remote Services](https://attack.mitre.org/techniques/T1133/)
- [MITRE ATT&CK – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
