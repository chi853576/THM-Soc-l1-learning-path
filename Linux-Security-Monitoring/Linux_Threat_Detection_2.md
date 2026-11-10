# Linux Threat Detection 2

**Nguồn học:** [TryHackMe – Linux Threat Detection 2](https://tryhackme.com/room/linuxthreatdetection2)  
**Trọng tâm:** Phát hiện các hành động đầu tiên của attacker sau khi xâm nhập Linux server: Discovery, tìm kiếm tài nguyên, tải công cụ/malware và hoạt động cryptomining.

> **Phạm vi ghi chú:** Trang room công khai xác nhận các chủ đề Discovery, Motivation for Attacks và case study Dota3 (First Actions, Miner Setup). Một phần nội dung chi tiết của task yêu cầu đăng nhập/truy cập lab. Ghi chú này tập trung vào các khái niệm và workflow phòng thủ có thể xác thực; không chứa đáp án, flag hoặc dữ liệu riêng của máy lab.

---

## Task 1: Introduction

### 1. Mục tiêu học tập

- Nhận diện các lệnh Discovery trong Linux logs.
- Hiểu động cơ của các cuộc tấn công Linux server.
- Phát hiện cách attacker tải công cụ hoặc malware lên host.
- Phân tích một tình huống cryptominer infection từ các dấu vết trên hệ thống.
- Liên kết process execution, file và network events để dựng timeline.

### 2. Vị trí trong attack lifecycle

Sau Initial Access, attacker thường cần hiểu môi trường trước khi quyết định bước tiếp theo. Những hoạt động thường thấy:
- Xác định user, quyền và hostname.
- Tìm hiểu OS/kernel, CPU, memory và tài nguyên host.
- Kiểm tra network interfaces, routes và dịch vụ đang mở.
- Tìm process, software, container và thư mục có thể truy cập.
- Tải công cụ hoặc payload phục vụ mục tiêu tiếp theo.

---

## Task 2: Discovery Overview

### 1. Discovery là gì?

Discovery là hoạt động thu thập thông tin về hệ thống hoặc môi trường sau khi attacker có quyền truy cập. Mục tiêu có thể là:
- Hiểu hệ điều hành và cấu hình host.
- Xác định account và quyền hiện tại.
- Tìm các dịch vụ, process và ứng dụng đang chạy.
- Khám phá network và các server liên quan.
- Xác định tài nguyên hoặc dữ liệu có giá trị.
- Đánh giá khả năng triển khai malware hoặc công cụ bổ sung.

### 2. Các nhóm thông tin attacker có thể tìm

| Nhóm | Ví dụ thông tin |
|---|---|
| Identity | User hiện tại, UID/GID, group membership |
| Host | Hostname, kernel, distribution, OS version |
| Hardware/resources | CPU, memory, disk, số core |
| Process/service | Process đang chạy, service, listening ports |
| Network | Interface, route, DNS, remote connections |
| Filesystem | Home directories, temporary folders, shared data |
| Software | Installed packages, runtime, container tooling |

### 3. Một số lệnh hệ thống có thể xuất hiện trong telemetry

Các lệnh dưới đây cũng là công cụ quản trị Linux hợp pháp. Việc chúng xuất hiện không tự động chứng minh có tấn công.

| Lệnh | Loại thông tin |
|---|---|
| `whoami`, `id` | User và identity context |
| `hostname`, `uname` | Hostname và kernel |
| `cat /etc/os-release` | Distribution/version |
| `ps` | Process đang chạy |
| `ip`, `ss` | Network configuration và socket |
| `df`, `free`, `lscpu` | Disk, memory và CPU |
| `find`, `ls` | Khám phá filesystem |
| `systemctl` | Service status/configuration |

### 4. Phân tích Discovery trong log

- Tìm process execution events qua auditd/EDR.
- Ghi lại executable, arguments, PID, PPID, `auid`, `uid` và timestamp.
- Kiểm tra user nào thực hiện chuỗi lệnh.
- So sánh với baseline và vai trò của host.
- Tìm các lệnh liên tiếp có cùng parent process hoặc cùng session.
- Kiểm tra discovery có tiếp nối bằng download, archive, network connection hoặc privilege changes không.

### 5. Phân biệt hoạt động quản trị hợp pháp và đáng ngờ

| Hoạt động hợp pháp có thể có | Dấu hiệu cần xác minh thêm |
|---|---|
| Admin kiểm tra CPU/disk khi xử lý sự cố | Một user hiếm dùng lệnh discovery trên server không thuộc phạm vi quản trị |
| Monitoring agent truy vấn service | Shell được khởi chạy bởi web/database process |
| Automation chạy theo lịch | Chuỗi lệnh phát sinh đột ngột sau SSH login lạ |
| Deployment tool kiểm tra OS/package | Discovery đi kèm download payload và outbound connection bất thường |

Ngữ cảnh quan trọng hơn tên lệnh đơn lẻ.

---

## Task 3: Detecting Discovery

### 1. Detection workflow

1. Bắt đầu từ alert hoặc chuỗi process bất thường.
2. Lọc audit events theo executable/command name.
3. Lấy PID/PPID để xác định parent process.
4. Xem `auid`, `uid` và TTY để xác định user context.
5. Nhóm event theo timeline.
6. Xác định các nhóm Discovery được thực hiện.
7. Đối chiếu với file/network events để tìm bước tiếp theo.

### 2. Dùng auditd

Các câu lệnh tìm kiếm thường hữu ích:

```bash
# Tìm execution của một command cụ thể
ausearch -i -x COMMAND

# Tìm theo audit rule key
ausearch -i -k RULE_KEY

# Xem event của một process
ausearch -i --pid PID

# Tìm các child process
ausearch -i --ppid PID
```

### 3. Các field nên ghi lại

- `pid`, `ppid`: xác định process tree.
- `auid`: identity ban đầu của login session.
- `uid`/`euid`: quyền đang được sử dụng.
- `exe`: binary được thực thi.
- `proctitle`/`EXECVE`: command line và arguments.
- `cwd`: working directory.
- Timestamp: thời gian thực hiện.

### 4. Chuyển từ Discovery sang hành động khác

Discovery có thể là bước chuẩn bị cho:
- Lựa chọn dữ liệu cần truy cập.
- Chọn nơi lưu payload.
- Xác định khả năng khai thác tài nguyên CPU/GPU.
- Tìm dịch vụ hoặc cấu hình yếu.
- Tải và chạy công cụ tiếp theo.

Vì vậy nên theo dõi process/file/network events sau Discovery, thay vì dừng phân tích ở các command reconnaissance.

---

## Task 4: Motivation for Attacks

### 1. Vì sao attacker nhắm Linux servers?

Một Linux server bị xâm nhập có thể cung cấp:
- Năng lực tính toán và tài nguyên cloud.
- Kết nối đến các hệ thống nội bộ.
- Dữ liệu ứng dụng hoặc database.
- Credential và secret được lưu trong môi trường.
- Khả năng làm điểm trung gian để tiếp tục tấn công.
- Cơ hội khai thác tài nguyên để kiếm lợi tài chính.

### 2. Cryptomining và cryptojacking

**Cryptomining** là hoạt động dùng năng lực tính toán để tham gia xử lý các tác vụ liên quan đến cryptocurrency mining. **Cryptojacking** là việc attacker chiếm dụng tài nguyên của nạn nhân để thực hiện mining mà không được phép.

Đặc điểm có thể gặp:
- CPU utilization tăng cao kéo dài.
- Process lạ tiêu thụ CPU bất thường.
- Process hoặc binary chạy dưới user/service account không phù hợp.
- Outbound connections đến mining pool hoặc hạ tầng đáng ngờ.
- File thực thi mới được tải từ Internet.
- Cấu hình tự khởi chạy để miner hoạt động lâu dài.

### 3. Tác động với tổ chức

- Tăng chi phí compute/cloud.
- Làm chậm service và ảnh hưởng availability.
- Tăng nhiệt độ, tải CPU và mức tiêu thụ năng lượng.
- Tạo outbound traffic không mong muốn.
- Cho thấy host có thể đã bị compromise và attacker có thể tiếp tục thực hiện hành động khác.

Không nên chỉ xem cryptomining là vấn đề hiệu năng; nó là dấu hiệu cần điều tra như một security incident.

---

## Task 5: Dota3 — First Actions

### 1. Mục tiêu điều tra

Case study này tập trung vào việc xác định attacker đã thực hiện hành động nào sau khi có mặt trên Linux host. Từ góc độ SOC, nên dựng lại các nhóm hành vi:
- Discovery và xác định tài nguyên host.
- Xác định process/service và môi trường thực thi.
- Kiểm tra network và khả năng tải file.
- Xác định thư mục/file được tạo.
- Tìm process tiếp theo được khởi chạy từ file mới.

### 2. Tìm dấu vết process

Nguồn log cần kiểm tra:
- `/var/log/audit/audit.log` nếu auditd được cấu hình.
- Authentication log để biết account/session.
- Syslog/journal để kiểm tra service và scheduled activity.
- EDR/Sysmon for Linux/osquery/Falco nếu được triển khai.

Các trường nên ghi nhận:
- Command/executable.
- Arguments và current working directory.
- PID/PPID.
- `auid`, `uid`, `euid`.
- Timestamp.
- Parent/child process relationship.

### 3. Xác định file được đưa vào host

Những dấu hiệu cần điều tra:
- File mới xuất hiện trong `/tmp`, `/var/tmp`, `/dev/shm`, home directory hoặc thư mục ứng dụng.
- File executable hoặc có tên giả dạng thành phần hệ thống.
- Process thực hiện download hoặc truy xuất remote URL.
- File được tạo ngay sau một lệnh discovery hoặc một kết nối từ xa.
- File mới được thực thi bởi shell hoặc service account.

Tương quan với:
- File metadata và timestamp.
- Hash để kiểm tra tính toàn vẹn/reputation.
- Parent process và command line.
- DNS/network telemetry tương ứng.

### 4. Phân tích nguồn tải

Các chương trình tải file phổ biến trong môi trường Linux có thể bao gồm `curl` hoặc `wget`. Để điều tra:
- Xác định process khởi chạy downloader.
- Xem command line/URL nếu log thu thập đủ.
- Kiểm tra destination path.
- Tìm network connection và DNS query theo cùng thời điểm.
- Xác định file được tạo có được chạy tiếp hay không.

Không mở hoặc thực thi payload đáng ngờ trên workstation; dùng sandbox/môi trường phân tích cô lập theo quy trình của tổ chức.

---

## Task 6: Dota3 — Miner Setup

### 1. Các giai đoạn cần tái dựng

Khi điều tra một cryptominer infection, có thể phân chia timeline thành:
1. **Initial access:** attacker có quyền truy cập host.
2. **Discovery:** kiểm tra tài nguyên và môi trường.
3. **Payload transfer:** tải hoặc đưa miner vào hệ thống.
4. **Execution:** miner được thực thi.
5. **Resource abuse:** CPU/network activity bất thường xuất hiện.
6. **Maintain access:** có thể tồn tại cơ chế tự khởi động hoặc user/key bổ sung; cần kiểm tra nếu evidence cho thấy.

Các giai đoạn trên là khung điều tra, không phải giả định rằng mọi biến thể malware đều thực hiện đủ các bước.

### 2. Dấu hiệu miner execution

| Dữ liệu | Điều cần kiểm tra |
|---|---|
| Process | Tên, binary path, user, command line, CPU usage |
| File | File mới, hash, permission, timestamp, vị trí |
| Network | Kết nối outbound liên tục, domain/IP/port và process sở hữu kết nối |
| System load | CPU tăng bất thường, load average và resource consumption |
| Authentication | Tài khoản/phiên có trước thời điểm tải và chạy miner |
| Persistence artifacts | Cron, systemd service hoặc account/SSH key thay đổi nếu có |

### 3. Process context

Process đáng ngờ cần được đánh giá dựa trên:
- Parent process là shell, SSH session hay service.
- User thực thi có phù hợp với ứng dụng hay không.
- Binary path có nằm trong thư mục đáng tin cậy không.
- Process có được tạo sau lệnh download không.
- Process có outbound connection liên tục không.

Tên process có thể bị giả mạo; nên dựa vào full path, hash, parent process và hành vi.

### 4. Network context

Các kết nối có thể cần kiểm tra:
- Outbound destination IP/domain.
- DNS query trước khi kết nối.
- Port/protocol và tần suất kết nối.
- Process mở socket.
- Đích kết nối có thuộc dịch vụ doanh nghiệp đã phê duyệt không.

Một port hoặc domain đơn lẻ không đủ để chứng minh mining. Cần tương quan với process, tải CPU và threat intelligence.

### 5. Tạo timeline

Một bảng timeline nên có cấu trúc:

| Thời gian | Nguồn | Event | Diễn giải |
|---|---|---|---|
| T0 | auth log | Login/session | Xác định account và nguồn truy cập |
| T1 | auditd | Discovery commands | Xác định hoạt động sau login |
| T2 | auditd/file log | Download/process/file creation | Tìm nguồn và vị trí payload |
| T3 | process telemetry | Miner execution | Xác định process và user |
| T4 | network telemetry | Outbound connection | Xác định hạ tầng liên lạc |
| T5 | system telemetry | Resource usage | Xác minh dấu hiệu cryptomining |

## Quy trình điều tra Discovery và Cryptominer

1. Xác định alert và khoảng thời gian CPU/network bất thường.
2. Xác định process tiêu thụ tài nguyên.
3. Lần ngược process tree để tìm nguồn khởi chạy.
4. Xác định account và session liên quan.
5. Tìm file/payload mới được tạo hoặc tải về.
6. Đối chiếu outbound network/DNS activity.
7. Kiểm tra persistence artifacts nếu có dấu hiệu duy trì hoạt động.
8. Dựng timeline và ghi lại evidence có thể xác minh.

## Ghi nhớ

- Discovery cho biết attacker đang tìm hiểu host, account, process, service và network.
- Các lệnh quản trị thông thường có thể bị lạm dụng; cần xét user, parent process, thời điểm và chuỗi hành vi.
- Cryptojacking có thể gây CPU load và outbound network traffic bất thường.
- Process, file, network và resource telemetry cần được liên kết để xác định miner.
- Một tên process lạ hoặc CPU cao chưa đủ kết luận; cần xác minh binary, hành vi và nguồn khởi chạy.

## Nguồn tham khảo

- [TryHackMe – Linux Threat Detection 2](https://tryhackme.com/room/linuxthreatdetection2)
- [TryHackMe – Linux Security Monitoring module](https://tryhackme.com/module/linux-security-monitoring)
- [MITRE ATT&CK – Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
