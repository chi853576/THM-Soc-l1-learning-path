# Linux Logging for SOC

**Nguồn học:** [TryHackMe – Linux Logging for SOC](https://tryhackme.com/room/linuxloggingforsoc)  
**Trọng tâm:** Tìm kiếm, lọc và diễn giải log Linux để phục vụ SOC triage; hiểu authentication logs, system/application logs và runtime monitoring bằng auditd.

---

## Task 1: Introduction

### 1. Mục tiêu của Linux logging trong SOC

Linux được sử dụng rộng rãi trên server, cloud workload, container và thiết bị hạ tầng. SOC Analyst cần hiểu các log trên Linux để:
- Xác định ai đã truy cập hệ thống và truy cập bằng phương thức nào.
- Theo dõi thay đổi tài khoản, quyền và cấu hình.
- Phát hiện lệnh hoặc process bất thường.
- Liên kết log hệ thống, ứng dụng và runtime để dựng timeline.
- Cung cấp evidence cho incident response và threat hunting.

### 2. Phạm vi nền tảng

Room tập trung vào Linux server không có giao diện đồ họa, ví dụ Debian, Ubuntu, CentOS và RHEL. Vị trí và định dạng log có thể khác theo distribution, phiên bản và cấu hình.

---

## Task 2: Working With Text Logs

### 1. Vị trí log phổ biến

Phần lớn text logs truyền thống nằm trong:

```bash
/var/log/
```

Một số file/thư mục thường gặp:

| Log source | Nội dung |
|---|---|
| `/var/log/syslog` | Log hệ thống tổng hợp thường gặp trên Debian/Ubuntu |
| `/var/log/messages` | Log hệ thống tổng hợp thường gặp trên RHEL-based |
| `/var/log/auth.log` | Authentication, session, sudo và user management trên Debian/Ubuntu |
| `/var/log/secure` | Authentication và security-related messages trên RHEL-based |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/audit/audit.log` | Audit events nếu auditd được cài đặt và cấu hình |
| `/var/log/dpkg.log` | Package operations trên Debian-based |
| `/var/log/apt/` | APT package-management logs |
| `/var/log/dnf.log`, `/var/log/yum.log` | Package-management logs trên RHEL-based |
| `/var/log/nginx/access.log` | HTTP requests được web server ghi nhận |
| `/var/log/nginx/error.log` | Nginx errors và operational messages |

Không phải hệ thống nào cũng có đầy đủ các file trên. Một số hệ thống dùng `journald` làm nguồn log chính hoặc chuyển log đến SIEM/remote syslog.

### 2. Đọc và lọc log

Các lệnh cơ bản:

```bash
# Liệt kê nguồn log
ls -lah /var/log/

# Đọc phần đầu/cuối file
head /var/log/syslog
tail -n 50 /var/log/syslog

# Theo dõi log phát sinh theo thời gian thực
tail -f /var/log/auth.log

# Tìm keyword
grep -i "error" /var/log/syslog

# Lọc các dòng có CRON
grep "CRON" /var/log/syslog

# Loại bỏ các dòng có CRON
grep -v "CRON" /var/log/syslog

# Tìm kiếm đệ quy trong thư mục log
grep -R -E -i "auth|login|session" /var/log
```

### 3. Cách tiếp cận khi log quá lớn

1. Xác định loại sự kiện cần tìm: login, process, package, network hay service.
2. Chọn đúng log source trước khi tìm kiếm.
3. Thu hẹp theo keyword, username, IP, process hoặc khoảng thời gian.
4. Đọc các dòng trước/sau event để hiểu ngữ cảnh.
5. Liên kết với log khác để xác minh.

### 4. Những điểm cần lưu ý

- Linux distributions có thể khác nhau về tên file, format, timezone và mức độ verbosity.
- Log có thể được rotate, nén hoặc lưu trong journal thay vì file text hiện tại.
- Không tìm thấy event trong một file không đồng nghĩa hành động đó không xảy ra; có thể audit chưa bật hoặc log nằm ở nguồn khác.
- Cần kiểm tra thời gian hệ thống, timezone và độ lệch đồng hồ trước khi dựng timeline.

---

## Task 3: Authentication Logs

### 1. Authentication log là gì?

Authentication logs là nguồn quan trọng để theo dõi hoạt động truy cập. Vị trí thường gặp:

- Debian/Ubuntu: `/var/log/auth.log`
- RHEL/CentOS: `/var/log/secure`

Các sự kiện có thể bao gồm:
- Local login và remote login.
- SSH authentication success/failure.
- Session opened/session closed.
- `sudo` và `su` activity.
- Tạo, xóa hoặc thay đổi user.
- Các hành động PAM liên quan authentication/session.

### 2. Login và logout events

Tìm session mở/đóng:

```bash
grep -E "session opened|session closed" /var/log/auth.log
```

Cần chú ý:
- Tên user và UID.
- Service tạo session, ví dụ `login`, `sshd`, `sudo`, `su`, `CRON`.
- Timestamp.
- Session có bắt nguồn từ login tương tác, remote access hay scheduled job.

Không phải tất cả session đều là người dùng ngồi trực tiếp trước máy. Cron hoặc service cũng có thể tạo session dưới một account.

### 3. Phân tích SSH login

Lọc SSH authentication:

```bash
# Xem log sshd
grep "sshd" /var/log/auth.log

# SSH login thành công
grep -E "Accepted" /var/log/auth.log

# SSH login thất bại
grep -E "Failed|Invalid user" /var/log/auth.log
```

Một dòng SSH thường cung cấp:
- Kết quả: `Accepted` hoặc `Failed`.
- Authentication method: `password` hoặc `publickey`.
- Username.
- Source IP và source port.
- SSH protocol/version context.

### 4. Dấu hiệu SSH cần điều tra

- Nhiều lần đăng nhập thất bại trong thời gian ngắn.
- Một IP thử nhiều username.
- Một username bị thử từ nhiều nguồn không quen thuộc.
- Successful login đến sau chuỗi thất bại.
- Đăng nhập từ IP, vị trí, thời gian hoặc phương thức không phù hợp baseline.
- Service account hoặc tài khoản ít dùng có phiên đăng nhập tương tác.

Một lần đăng nhập bằng password không tự động là malicious; cần xác minh owner, nguồn IP, lịch làm việc và hành động sau đăng nhập.

### 5. User management và sudo activity

```bash
# Tìm sự kiện tạo/sửa/xóa tài khoản
grep -E "(passwd|useradd|usermod|userdel)\[" /var/log/auth.log

# Tìm các lệnh được chạy qua sudo
grep "COMMAND=" /var/log/auth.log
```

Theo dõi:
- Password change.
- Tạo hoặc xóa tài khoản.
- Thêm user vào group đặc quyền như `sudo` hoặc `wheel`.
- Thay đổi shell hoặc UID/GID.
- Các lệnh sudo bất thường, ví dụ thay đổi firewall, dừng security agent hoặc chỉnh sửa SSH configuration.

### 6. Phân biệt user gốc và effective user

Khi dùng `sudo` hoặc `su`, user ban đầu và user thực thi lệnh có thể khác nhau. Đây là lý do cần kết hợp authentication logs với audit records để xác định:
- Ai bắt đầu phiên.
- Ai thực sự chạy lệnh.
- Lệnh chạy trên terminal hay từ service/background process.

---

## Task 4: Common Linux Logs

### 1. Generic system logs

| Log | Nội dung và giá trị điều tra |
|---|---|
| `syslog` / `messages` | Event tổng hợp từ hệ thống và service |
| `kern.log` | Kernel messages, lỗi driver/module và hoạt động kernel |
| `dpkg.log` / `apt` | Cài đặt, nâng cấp, gỡ package trên Debian-based |
| `dnf.log` / `yum.log` | Package activity trên RHEL-based |
| `journal/` | Persistent journal data nếu journald được cấu hình lưu trên disk |

Package logs hữu ích khi cần xác định phần mềm mới được cài đặt, nâng cấp hoặc gỡ bỏ gần thời điểm xảy ra sự cố.

### 2. Application-specific logs

Mỗi ứng dụng thường có log riêng, ví dụ:
- Web server: access log và error log.
- Database: connection, authentication và query logs.
- Mail server: message delivery và authentication events.
- VPN: remote access và session logs.
- Container platform: container lifecycle và application stdout/stderr.

Ví dụ Nginx access log:

```text
CLIENT_IP - - [timestamp] "GET /login HTTP/1.1" 200 1056
CLIENT_IP - - [timestamp] "POST /login HTTP/1.1" 302 112
```

Những trường cần quan tâm:
- Client IP.
- Request timestamp.
- HTTP method và URI.
- HTTP status code.
- Response size.
- User-agent/referrer nếu format được cấu hình để ghi nhận.

Status `200`, `302`, `403` hoặc `500` cần được hiểu theo endpoint và ứng dụng; không thể chỉ dựa vào status code để kết luận có tấn công.

### 3. Bash history

Bash thường ghi lịch sử lệnh của từng user tại:

```bash
~/.bash_history
```

Có thể xem bằng:

```bash
history
cat ~/.bash_history
```

Bash history có thể cung cấp manh mối về:
- Các lệnh người dùng đã nhập.
- File/config được chỉnh sửa.
- Hành động quản trị hoặc discovery.
- Các lệnh tải và chạy file.

**Giới hạn của Bash history:**
- Lệnh của session hiện tại có thể chưa được ghi xuống file cho đến khi shell kết thúc.
- Không ghi lại command chạy non-interactive qua cron/service hoặc script theo cách đầy đủ.
- Cấu hình shell có thể bỏ qua một số lệnh, ví dụ lệnh bắt đầu bằng dấu cách khi `HISTCONTROL` cho phép.
- Người dùng có thể xóa hoặc chỉnh sửa history.
- Shell khác như `sh` có thể không ghi vào Bash history.
- Lệnh chạy trong script chỉ có thể để lại dấu vết gọi script, không nhất thiết lưu từng lệnh bên trong.

Do đó, Bash history chỉ nên được xem là nguồn tham khảo bổ sung, không phải nguồn audit đáng tin cậy duy nhất.

---

## Task 5: Runtime Monitoring

### 1. Runtime events là gì?

Runtime events là những hoạt động phát sinh trong quá trình hệ điều hành đang chạy, ví dụ:
- Tạo process và thực thi chương trình.
- Mở, đọc, ghi hoặc xóa file.
- Thay đổi cấu hình quan trọng.
- Thực hiện các system calls.
- Một số hoạt động network tùy giải pháp giám sát.

Linux mặc định không nhất thiết ghi đầy đủ các sự kiện này vào syslog/auth log. Muốn có visibility cần cấu hình audit hoặc triển khai công cụ giám sát endpoint.

### 2. System calls

System call là giao diện để chương trình yêu cầu kernel thực hiện dịch vụ như tạo process, mở file hoặc truy cập tài nguyên hệ thống.

Một số khái niệm:
- `execve`: thực thi một chương trình.
- `openat`: mở file tương đối hoặc tuyệt đối theo directory context.
- `connect`: yêu cầu thiết lập kết nối socket.
- `unlink` / `unlinkat`: xóa liên kết file.

EDR và audit tools có thể theo dõi các system calls được chọn để chuyển hoạt động mức thấp thành telemetry có thể điều tra.

---

## Task 6: Using Auditd

### 1. Auditd là gì?

`auditd` (Audit Daemon) là thành phần user-space của Linux Audit framework, nhận audit events và ghi chúng ra log.

Các thành phần quan trọng:

| Thành phần | Vai trò |
|---|---|
| `auditd` | Ghi audit records |
| `auditctl` | Quản lý hoặc nạp audit rules |
| `/etc/audit/rules.d/` | Nơi lưu rule files thường dùng |
| `/var/log/audit/audit.log` | File audit log phổ biến |
| `ausearch` | Tìm kiếm và lọc audit events |
| `aureport` | Tạo summary/report từ audit data |

### 2. Audit rules

Audit rules xác định sự kiện nào cần theo dõi và điều kiện lọc. Ví dụ rule có thể giám sát:
- Process execution.
- Truy cập hoặc thay đổi file quan trọng.
- Thay đổi cấu hình SSH.
- Hoạt động trên tài khoản và quyền.
- Các system calls có rủi ro cao.

Không nên bật ghi log mọi thứ một cách thiếu chọn lọc. Khối lượng log lớn tạo noise, tăng storage/ingestion cost và khiến event quan trọng khó được phát hiện.

### 3. Đọc audit logs

Log thô thường nằm tại:

```bash
/var/log/audit/audit.log
```

Dùng `ausearch` để lọc và diễn giải:

```bash
# Tìm event theo key được gán trong rule
ausearch -i -k proc_wget

# Tìm event theo executable/command name
ausearch -i -x whoami

# Tìm process theo PID
ausearch -i --pid 1234

# Tìm các process được một process cha khởi chạy
ausearch -i --ppid 1234
```

Ví dụ một event thực thi chương trình có thể chứa nhiều record cùng một event serial:
- `PROCTITLE`: command line/process title.
- `EXECVE`: argument được truyền vào chương trình.
- `CWD`: current working directory.
- `SYSCALL`: system call, kết quả và process metadata.
- `PATH`: file path liên quan đến syscall.

### 4. Trường quan trọng khi phân tích auditd

| Field | Ý nghĩa |
|---|---|
| `pid` | Process ID |
| `ppid` | Parent Process ID |
| `auid` | Audit user ID, thường phản ánh user ban đầu của login session |
| `uid` | User ID hiện tại thực hiện thao tác |
| `euid` | Effective UID, quyền hiệu lực của process |
| `tty` | Terminal/session nếu có |
| `exe` | Đường dẫn executable |
| `proctitle` | Tên/command line của process |
| `key` | Nhãn do rule cấu hình để hỗ trợ lọc |
| `success` / `exit` | Trạng thái và kết quả syscall |

`auid` và `uid` có thể khác nhau khi user đăng nhập bằng tài khoản thường rồi dùng `sudo` để thực thi lệnh dưới quyền root.

### 5. Liên kết event để dựng process tree

1. Tìm command/process đáng chú ý bằng `ausearch`.
2. Ghi nhận `pid`, `ppid`, `auid`, `uid`, `exe` và timestamp.
3. Tìm process cha bằng `ppid`.
4. Lặp lại việc tra cứu parent process để lần ngược nguồn khởi chạy.
5. Tìm các child process khác của cùng parent để nhận diện chuỗi hành vi.
6. Đối chiếu với authentication, application và network logs.

### 6. Các giải pháp runtime monitoring khác

| Công cụ | Vai trò khái quát |
|---|---|
| Sysmon for Linux | Process, network và các event endpoint theo cấu hình |
| Falco | Runtime threat detection, thường dùng trong container/cloud-native environments |
| osquery | Truy vấn trạng thái endpoint và thu thập telemetry |
| EDR | Theo dõi process, file, network và hành vi endpoint theo năng lực sản phẩm |

Các công cụ có cách triển khai và data model khác nhau, nhưng thường cần thu thập thông tin runtime đủ để liên kết hành vi với process/user context.

---

## Quy trình phân tích log Linux trong SOC

1. **Xác định host và thời gian:** hostname, timezone, nguồn alert và phạm vi điều tra.
2. **Xác định user/session:** bắt đầu từ `auth.log` hoặc `secure`.
3. **Xác định hoạt động hệ thống:** xem `syslog`, `messages`, kernel và application logs.
4. **Kiểm tra process/runtime:** tìm auditd hoặc EDR telemetry.
5. **Tương quan:** kết nối user, `auid`, `uid`, PID/PPID, timestamp, file path và network evidence.
6. **Dựng timeline:** sắp xếp event theo thời gian và xác định trình tự hành động.
7. **Đánh giá:** so sánh với baseline, thay đổi được phê duyệt và hoạt động thường lệ.
8. **Ghi nhận:** lưu evidence, nguồn log, thời gian, mức độ tin cậy và bước xác minh tiếp theo.

## Ghi nhớ

- Linux logs thường nằm trong `/var/log/`, nhưng vị trí và format tùy distribution/configuration.
- `auth.log`/`secure` quan trọng cho login, SSH, sudo và user management.
- Application logs cung cấp ngữ cảnh theo dịch vụ; Bash history chỉ có giá trị tham khảo.
- Muốn theo dõi process/file runtime cần auditd hoặc giải pháp endpoint monitoring.
- `pid`/`ppid` dùng để dựng process tree; `auid` và `uid` giúp xác định user context.
- Một event đơn lẻ hiếm khi đủ để kết luận; cần liên kết nhiều nguồn log.

## Nguồn tham khảo

- [TryHackMe – Linux Logging for SOC](https://tryhackme.com/room/linuxloggingforsoc)
- [Linux Audit Documentation – ausearch manual](https://man7.org/linux/man-pages/man8/ausearch.8.html)
