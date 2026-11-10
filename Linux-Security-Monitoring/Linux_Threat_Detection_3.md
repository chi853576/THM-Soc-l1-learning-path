# Linux Threat Detection 3

**Nguồn học:** [TryHackMe – Linux Threat Detection 3](https://tryhackme.com/room/linuxthreatdetection3)  
**Trọng tâm:** Phát hiện các giai đoạn sau của một cuộc tấn công Linux: Reverse Shells, Privilege Escalation, Startup Persistence và Account Persistence; phân tích các hành vi targeted intrusion qua system logs.

> **Phạm vi ghi chú:** Trang TryHackMe công khai các chủ đề và tên task, trong khi phần lab chi tiết cần đăng nhập/truy cập room. Nội dung dưới đây là ghi chú kiến thức và quy trình điều tra phòng thủ theo các chủ đề đó, không phải transcript từng bước hoặc đáp án của lab.

---

## Task 1: Introduction

### 1. Mục tiêu học tập

- Hiểu cách reverse shell được sử dụng trong Linux intrusion.
- Nhận diện hoạt động privilege escalation.
- Kiểm tra các cơ chế persistence phổ biến trên Linux.
- Dùng system logs và runtime telemetry để phát hiện hành vi.
- Kết nối các event thành attack timeline thay vì phân tích từng dấu vết riêng lẻ.

### 2. Các giai đoạn tấn công cần nhận diện

| Giai đoạn | Mục đích của attacker |
|---|---|
| Reverse shell | Tạo kênh shell từ host bị xâm nhập về phía attacker |
| Privilege escalation | Tăng quyền từ account hạn chế lên quyền cao hơn |
| Startup persistence | Tự chạy lại khi máy khởi động hoặc service được khởi động |
| Account persistence | Duy trì quyền truy cập thông qua account, SSH key hoặc credential |
| Targeted activity | Kết hợp nhiều kỹ thuật có chủ đích để duy trì và mở rộng quyền kiểm soát |

---

## Task 2: Reverse Shells

### 1. Reverse shell là gì?

Reverse shell là mô hình trong đó host bị xâm nhập khởi tạo kết nối mạng ra một hệ thống bên ngoài, sau đó cung cấp shell tương tác thông qua kết nối đó.

Mô hình này thường được dùng khi:
- Host nạn nhân có thể tạo outbound connection.
- Kết nối inbound trực tiếp đến host khó thực hiện do firewall/NAT.
- Attacker muốn thực thi lệnh từ xa trong context của một user hoặc service account.

Reverse shell không đồng nghĩa mọi outbound connection đều độc hại. Cần xem process, destination, account và hành vi đi kèm.

### 2. Dấu hiệu reverse shell

**Process telemetry**
- Shell process như `sh` hoặc `bash` được khởi chạy từ web server, database hoặc service không thường xuyên tạo shell.
- Command interpreter có parent process bất thường.
- Shell chạy dưới service account và không có TTY tương ứng với hoạt động tương tác.
- Chuỗi shell tạo child process thực hiện discovery hoặc tải file.

**Network telemetry**
- Process shell hoặc process con tạo outbound connection không thường lệ.
- Kết nối đến IP/domain không thuộc hệ thống tin cậy.
- Kết nối tồn tại lâu hoặc lặp lại bất thường.
- Thời gian network event khớp với thời gian shell/process được tạo.

**Audit data**
- `execve` events cho biết shell/program được khởi chạy.
- `pid`, `ppid`, `uid`, `auid`, `exe`, `proctitle` giúp xác định nguồn process.
- Auditd có thể không cung cấp đầy đủ network context nếu ruleset chỉ theo dõi process; cần EDR/network telemetry bổ sung.

### 3. Quy trình điều tra

1. Xác định outbound connection hoặc shell process đáng ngờ.
2. Tìm process ID và user context.
3. Dựng process tree để tìm parent/ancestor.
4. Kiểm tra có web application, SSH session hoặc service nào đứng trước không.
5. Liên kết timestamp với DNS/network events.
6. Tìm child process liên quan discovery, file transfer hoặc privilege escalation.
7. Xác định thời điểm đầu tiên attacker có khả năng điều khiển host.

### 4. Câu hỏi SOC cần trả lời

- Process nào tạo kết nối?
- Kết nối được tạo bởi user hay service account nào?
- Parent process là gì?
- Tại sao service đó cần shell?
- Destination có thuộc hạ tầng hợp lệ không?
- Những lệnh nào được chạy sau khi shell xuất hiện?

---

## Task 3: Privilege Escalation

### 1. Privilege escalation là gì?

Privilege escalation là việc nâng quyền thực thi từ mức thấp lên mức cao hơn, ví dụ từ local user lên root. Attacker có thể tìm kiếm:
- Cấu hình `sudo` quá rộng.
- Binary có SUID/SGID không an toàn.
- File/script hoặc directory có quyền ghi không phù hợp.
- Service chạy với quyền cao nhưng sử dụng file có thể bị sửa.
- Credential hoặc secret có thể truy cập.
- Lỗi cấu hình hoặc lỗ hổng kernel/phần mềm.

### 2. Các khu vực cần kiểm tra

| Khu vực | Điểm điều tra |
|---|---|
| `sudo` | Quyền được cấp, command được chạy và account thực thi |
| SUID/SGID | Binary có special permission và nguồn gốc của chúng |
| File permissions | File cấu hình/script có thể bị user không phù hợp chỉnh sửa |
| Capabilities | Linux capabilities được gán cho executable |
| Services | Service chạy quyền cao nhưng executable/config không được bảo vệ |
| Accounts/groups | User được thêm vào group đặc quyền hoặc UID/GID thay đổi |
| Kernel/software | Phiên bản và lỗ hổng đã biết, cần xác minh khả năng bị khai thác |

### 3. Theo dõi sudo và account context

Authentication logs:

```bash
# Debian/Ubuntu
grep "sudo" /var/log/auth.log

# RHEL-based
grep "sudo" /var/log/secure
```

Cần xem:
- User khởi tạo thao tác.
- Command được chạy.
- Thời điểm và terminal/session.
- Có chuyển sang root bằng `su` hay không.
- Sau đó có process/file/registry-like system configuration change nào xuất hiện không.

### 4. Tìm dấu vết quyền đặc biệt

Các thông tin cần kiểm tra trong điều tra:
- SUID/SGID executable mới xuất hiện hoặc thay đổi.
- File capability được thêm hoặc chỉnh sửa.
- Thay đổi `/etc/sudoers` hoặc `/etc/sudoers.d/`.
- Service/process chạy với quyền root bất thường.
- File script hoặc binary mà service root sử dụng có quyền ghi quá rộng.

Các thay đổi này cần được đối chiếu với baseline và quy trình quản trị; nhiều hệ thống hợp pháp sử dụng SUID, capabilities và sudo.

### 5. Auditd và privilege changes

Kết hợp:
- `execve` để theo dõi command execution.
- File/path events để phát hiện thay đổi file nhạy cảm.
- Authentication logs để liên kết sudo/su sessions.
- Process metadata để so sánh user ban đầu và effective user.

Các field `auid`, `uid` và `euid` đặc biệt hữu ích khi một phiên ban đầu của user thường được nâng quyền sang root.

---

## Task 4: Startup Persistence

### 1. Startup persistence là gì?

Startup persistence là cơ chế giúp chương trình hoặc script được thực thi lại khi hệ thống khởi động, service khởi động hoặc một trigger tự động xảy ra.

Mục tiêu của attacker là giữ khả năng thực thi sau reboot hoặc sau khi process ban đầu đã kết thúc.

### 2. Các cơ chế cần kiểm tra

**Systemd services**
- Unit files thường nằm trong `/etc/systemd/system/` hoặc các thư mục unit của hệ thống.
- Kiểm tra service mới, service vừa thay đổi và service có tên giả dạng.
- Kiểm tra `ExecStart`, `User`, `WantedBy` và các dependency.
- Đối chiếu executable path, hash, owner và file permissions.

**Cron jobs**
- Kiểm tra system cron và user crontabs.
- Các vị trí có thể liên quan: `/etc/crontab`, `/etc/cron.d/`, `/etc/cron.hourly/`, `/etc/cron.daily/` và user crontabs.
- Tìm command/script mới, lịch chạy bất thường và file được gọi từ thư mục không tin cậy.

**Startup/initialization scripts**
- Kiểm tra các script khởi tạo hệ thống như RC scripts hoặc `rc.local` nếu distribution còn hỗ trợ.
- Xác minh nội dung thay đổi và quyền file.
- Đối chiếu với package baseline và change management.

**Shell initialization files**
- Kiểm tra `~/.bashrc`, `~/.profile`, `~/.bash_profile`, `/etc/profile` và `/etc/profile.d/`.
- Xem các command được thêm vào có tạo process, tải file hoặc thiết lập kết nối hay không.
- Phân biệt customization hợp pháp với nội dung được chèn không rõ nguồn gốc.

### 3. Dấu hiệu bất thường

- Service/cron job mới không có change request.
- Tên unit/task gần giống thành phần hệ thống.
- Executable nằm trong `/tmp`, `/var/tmp`, `/dev/shm` hoặc thư mục user.
- Script khởi chạy từ URL hoặc binary không có nguồn gốc rõ ràng.
- File thời gian sửa trùng với incident timeline.
- Process tự xuất hiện sau reboot hoặc login mà không có lý do vận hành.

### 4. Nguồn log hỗ trợ

- `syslog`/`journal`: service start/stop và cron activity.
- `auth.log`/`secure`: thao tác sudo và thay đổi account.
- `auditd`: file write, `execve` và process tree.
- Package manager logs: xác minh service/package được cài hợp lệ hay không.
- EDR/file integrity monitoring: thay đổi file và process runtime.

---

## Task 5: Account Persistence

### 1. Account persistence là gì?

Account persistence là việc duy trì truy cập bằng cách thêm hoặc thay đổi tài khoản, credential hay cơ chế xác thực trên hệ thống.

Các tình huống thường cần điều tra:
- Tạo local user mới.
- Thêm user vào `sudo`, `wheel` hoặc group đặc quyền.
- Thay đổi password hoặc account attributes.
- Thêm SSH public key vào `authorized_keys`.
- Thay đổi SSH server configuration để mở rộng phương thức đăng nhập.
- Thay đổi shell, home directory hoặc UID/GID.

### 2. Các file nhạy cảm

| File/path | Nội dung cần quan tâm |
|---|---|
| `/etc/passwd` | Account metadata, UID/GID, home directory và login shell |
| `/etc/shadow` | Password hashes và password aging data; quyền truy cập rất hạn chế |
| `/etc/group` | Group membership |
| `/etc/gshadow` | Group security information |
| `/etc/sudoers` | Quyền sudo |
| `/etc/sudoers.d/` | Các file cấu hình sudo bổ sung |
| `~/.ssh/authorized_keys` | Public keys được phép xác thực vào account |
| `/etc/ssh/sshd_config` | Chính sách/cấu hình SSH server |

Không nên đọc hoặc sao chép nội dung nhạy cảm không cần thiết; trong điều tra hãy ưu tiên metadata, event records và xác minh đúng quyền truy cập.

### 3. Phân tích SSH authorized keys

SSH `authorized_keys` thường nằm trong thư mục `.ssh` của user. Việc thêm public key không được phê duyệt có thể tạo khả năng truy cập lâu dài mà không cần password.

Điểm cần kiểm tra:
- File có được tạo mới hoặc sửa gần thời điểm incident không?
- Owner và permissions của file/directory có hợp lý không?
- Có key mới không gắn với user/automation đã biết không?
- Có thay đổi `sshd_config` cùng thời điểm không?
- Sau thay đổi có successful SSH login sử dụng public-key authentication không?

### 4. Phân tích account và group changes

Kết hợp các nguồn:
- Authentication logs: `useradd`, `usermod`, `userdel`, password change và sudo.
- Auditd: file write vào `/etc/passwd`, `/etc/shadow`, `/etc/group`, sudoers và authorized_keys.
- SSH logs: successful login, authentication method và source IP.
- Process tree: command/process nào đã thực hiện thay đổi.

### 5. Câu hỏi điều tra

- Ai tạo hoặc sửa account?
- Account có được yêu cầu bởi IT/change management không?
- User mới có quyền gì?
- Có SSH key nào được thêm không?
- Thay đổi có diễn ra trong một session đáng ngờ không?
- Account/key có được sử dụng sau đó để đăng nhập không?

---

## Task 6: Targeted Attacks and Recap

### 1. Targeted attack là gì?

Targeted attack là cuộc tấn công có chủ đích vào một tổ chức, hệ thống hoặc tài sản cụ thể. Khác với hoạt động scan/brute force hàng loạt, attacker có thể thực hiện nhiều bước thủ công, lựa chọn công cụ và thay đổi hành vi dựa trên môi trường.

Các giai đoạn có thể liên kết:
1. Initial Access.
2. Discovery.
3. Reverse shell hoặc remote execution.
4. Privilege escalation.
5. Startup/account persistence.
6. Các hành động tiếp theo trên hệ thống.

### 2. Dựng attack timeline

| Giai đoạn | Evidence có thể cần |
|---|---|
| Initial access | SSH auth logs, public service/application logs |
| Remote control | Process execution, shell process, network connections |
| Discovery | Command history trong auditd/EDR và process tree |
| Privilege escalation | sudo/su events, UID/EUID changes, file permission changes |
| Startup persistence | Cron, systemd, startup script changes |
| Account persistence | User/group changes, authorized_keys, SSH configuration |
| Follow-on activity | File, network, service và system logs |

### 3. Phân tích theo process tree và identity

- Dùng PID/PPID để xác định nguồn process.
- Dùng `auid` để hiểu login identity ban đầu.
- Dùng `uid`/`euid` để xác định quyền đang thực thi.
- Dùng timestamp để liên kết process với network/file events.
- Tìm những process con được tạo trong cùng attack sequence.
- Kiểm tra liệu process có được chạy lại sau reboot hoặc login không.

### 4. Phân biệt persistence hợp pháp và độc hại

| Thay đổi hợp pháp có thể gặp | Câu hỏi xác minh |
|---|---|
| Service mới sau khi cài phần mềm | Package và change request có hợp lệ không? |
| Cron job phục vụ backup/maintenance | Owner, command và lịch chạy có đúng không? |
| SSH key của automation | Key owner và phạm vi sử dụng đã được xác minh chưa? |
| User mới cho ứng dụng | Account có đúng owner, group và quyền tối thiểu không? |
| Shell profile được cập nhật | Nội dung có khớp chuẩn cấu hình của tổ chức không? |

Không có tên file, service hoặc command nào tự nó chứng minh maliciousness. Baseline và provenance rất quan trọng.

---

## Quy trình điều tra Linux post-compromise

1. **Xác định hoạt động đáng ngờ:** shell, network connection, sudo event hoặc file/config change.
2. **Tìm nguồn process:** sử dụng auditd/EDR và dựng process tree.
3. **Xác định identity:** so sánh `auid`, `uid`, `euid`, TTY và authentication session.
4. **Điều tra privilege escalation:** kiểm tra sudo, group, SUID/SGID, capabilities và file permissions.
5. **Kiểm tra startup persistence:** systemd, cron, RC/startup scripts và shell initialization.
6. **Kiểm tra account persistence:** local users, groups, SSH keys và SSH server configuration.
7. **Tương quan network:** xác định outbound connections liên quan reverse shell hoặc remote control.
8. **Dựng timeline:** nối Initial Access với remote shell, privilege changes và persistence.
9. **Ghi nhận kết quả:** evidence, affected accounts/files/processes, mức độ tin cậy và hành động khắc phục đề xuất.

## Ghi nhớ

- Reverse shell thường cần được phân tích bằng cả process telemetry và network telemetry.
- Privilege escalation có thể để lại dấu vết ở sudo logs, account context, permissions và file changes.
- Startup persistence thường liên quan systemd, cron hoặc initialization scripts.
- Account persistence có thể thông qua user/group changes hoặc SSH authorized keys.
- Process tree, `auid`/`uid`/`euid` và timeline giúp nối các hoạt động thành attack chain.
- Cần xác minh các thay đổi với baseline/change management; công cụ quản trị hợp pháp cũng có thể tạo dấu vết tương tự.

## Nguồn tham khảo

- [TryHackMe – Linux Threat Detection 3](https://tryhackme.com/room/linuxthreatdetection3)
- [MITRE ATT&CK – Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
- [MITRE ATT&CK – Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [MITRE ATT&CK – SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)
- [MITRE ATT&CK – Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
