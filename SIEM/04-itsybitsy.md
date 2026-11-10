# ItsyBitsy

**Nguồn học:** [TryHackMe – ItsyBitsy](https://tryhackme.com/room/itsybitsy)  
**Module:** [SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)

## Task 1: Introduction

### 1. Mục tiêu của challenge

ItsyBitsy là challenge yêu cầu vận dụng kiến thức ELK/Elastic để điều tra một alert từ IDS về khả năng có **Command and Control (C2) communication**.

Trọng tâm của bài thực hành:

- Đọc một cảnh báo IDS và xác định phạm vi điều tra.
- Sử dụng Kibana Discover để truy vấn log.
- Phân tích network indicators và xác định các kết nối đáng chú ý.
- Liên kết dữ liệu mạng với host/process để hiểu nguồn phát sinh traffic.
- Xây dựng timeline và đánh giá khả năng có hoạt động C2.

### 2. C2 là gì?

**Command and Control (C2)** là cơ chế cho phép attacker giao tiếp với hệ thống đã bị xâm nhập để gửi lệnh, nhận trạng thái hoặc điều khiển hoạt động tiếp theo.

Một thiết bị bị xâm nhập có thể liên lạc với C2 server thông qua HTTP/HTTPS, DNS hoặc các giao thức mạng khác. Kênh C2 có thể được thiết kế để trông giống traffic thông thường, vì vậy analyst cần dựa trên nhiều dấu hiệu thay vì chỉ một IP hay port.

### 3. Phân biệt IDS alert và bằng chứng compromise

IDS alert thể hiện rằng một rule hoặc signature đã nhận diện traffic có đặc điểm đáng chú ý. Alert không nhất thiết chứng minh endpoint đã bị xâm nhập.

Cần kiểm tra:

- Alert dựa trên signature, anomaly hay rule nào?
- Source/destination IP có vai trò gì trong kết nối?
- Kết nối thành công, bị chặn hay chỉ là attempt?
- Có endpoint telemetry cho thấy process tạo traffic không?
- Có nhiều lần kết nối lặp lại hoặc DNS query liên quan không?

---

## Task 2: Chuẩn bị Elastic và dữ liệu điều tra

### 1. Truy cập log trong Kibana

Room sử dụng Kibana Discover để xem log. Quy trình tổng quát:

1. Khởi động Lab Machine và AttackBox hoặc kết nối qua VPN theo hướng dẫn của TryHackMe.
2. Mở Kibana được cấp cho lab.
3. Vào **Discover**.
4. Chọn Data View chứa dữ liệu liên quan.
5. Đặt time range đủ rộng để bao gồm thời điểm cảnh báo.
6. Kiểm tra field list và mở document để đọc chi tiết.

Tên index/data view và field phụ thuộc dataset của lab. Không nên giả định mọi log dùng chung một schema.

### 2. Các field cần chú ý

| Field | Mục đích |
|---|---|
| `@timestamp` | Xác định thời gian event. |
| `source.ip` | IP phát sinh kết nối. |
| `source.port` | Port phía nguồn. |
| `destination.ip` | IP đích. |
| `destination.port` | Port dịch vụ đích. |
| `network.transport` | TCP hoặc UDP nếu được ghi nhận. |
| `network.protocol` | Giao thức cấp ứng dụng nếu có. |
| `network.direction` | Hướng kết nối nếu được chuẩn hóa. |
| `host.name` | Tên thiết bị ghi nhận event. |
| `process.name` | Process liên quan đến traffic, nếu endpoint telemetry cung cấp. |
| `user.name` | User liên quan. |
| `event.action` / `event.category` | Loại hành động hoặc nhóm event. |

Nếu field không xuất hiện, kiểm tra raw event hoặc field tương đương trong dataset.

---

## Task 3: Investigate a Potential C2 Communication Alert

### 1. Bắt đầu từ alert

Không nên bắt đầu bằng việc tìm kiếm ngẫu nhiên toàn bộ log. Hãy sử dụng thông tin từ IDS alert để tạo phạm vi ban đầu.

Ghi nhận:

- Timestamp và timezone.
- Source IP và destination IP.
- Source/destination port.
- Protocol/transport.
- Tên IDS rule hoặc signature.
- Sensor hoặc thiết bị tạo alert.
- Trạng thái kết nối nếu có.

### 2. Pivot theo IP và port

Khi có IP từ alert, dùng nó làm pivot để tìm các event liên quan trước và sau thời điểm đó.

Ví dụ KQL theo IP đích:

```text
destination.ip: "<suspected_ip>"
```

Theo IP nguồn:

```text
source.ip: "<internal_host_ip>"
```

Theo cặp source/destination:

```text
source.ip: "<internal_host_ip>" AND destination.ip: "<suspected_ip>"
```

Theo port đích:

```text
destination.port: <port_number>
```

Các truy vấn trên là mẫu; thay giá trị bằng dữ liệu quan sát được trong lab và xác nhận kiểu dữ liệu của field.

### 3. Xác định host nội bộ và external endpoint

Cần hiểu địa chỉ nào thuộc mạng nội bộ, địa chỉ nào là external. Đối chiếu:

- Inventory/asset data của tổ chức.
- Dải RFC1918 hoặc IPv6 ULA khi phù hợp.
- NAT, proxy hoặc gateway có thể làm thay đổi địa chỉ nguồn quan sát được.
- Network logs từ firewall/IDS và endpoint logs.

Không suy luận danh tính host chỉ bằng địa chỉ IP nếu chưa đối chiếu asset context hoặc DHCP/network inventory.

### 4. Phân tích dấu hiệu C2

Một số hành vi có thể quan sát:

**Periodic beaconing**

- Kết nối lặp lại theo chu kỳ tương đối đều.
- Số lượng dữ liệu mỗi lần kết nối tương tự nhau.
- Một host liên tục giao tiếp với cùng đích dù không có lý do nghiệp vụ rõ ràng.

**Unusual destination**

- Domain/IP không quen thuộc với môi trường.
- Đích có reputation xấu hoặc liên quan threat intelligence.
- Port/protocol không phù hợp với vai trò của host.

**Suspicious DNS behavior**

- Domain có tên ngẫu nhiên hoặc cấu trúc bất thường.
- Nhiều subdomain khác nhau được truy vấn liên tục.
- DNS query của process lạ ngay trước network connection.

**Unexpected process network activity**

- Ứng dụng không có nhu cầu mạng nhưng tạo outbound connection.
- Script engine hoặc process chạy từ thư mục tạm kết nối đến Internet.
- Process không rõ nguồn gốc giao tiếp với endpoint không quen thuộc.

Không có dấu hiệu đơn lẻ nào luôn chứng minh C2. Các phần mềm hợp pháp như agent quản trị, updater và monitoring agent cũng thường tạo kết nối định kỳ.

### 5. Tìm endpoint telemetry

Nếu có Sysmon hoặc EDR logs, hãy tìm event process/network ở cùng host và khoảng thời gian.

Một số Sysmon event đáng chú ý:

| Event ID | Ý nghĩa | Câu hỏi |
|---|---|---|
| 1 | Process creation | Process nào được chạy, bởi user nào, parent là gì? |
| 3 | Network connection | Process nào tạo kết nối đến IP/port? |
| 22 | DNS query | Process nào truy vấn domain nào? |
| 11 | File create | Có file nào được ghi ngay trước/sau kết nối không? |

KQL ví dụ:

```text
host.name: "<host_name>" AND event.category: process
```

```text
host.name: "<host_name>" AND process.name: *
```

```text
host.name: "<host_name>" AND destination.ip: "<suspected_ip>"
```

Field `event.category` chỉ hoạt động như mong đợi nếu log đã được map theo schema tương ứng. Nếu dữ liệu dùng field riêng, cần điều chỉnh query.

### 6. Enrichment và đánh giá reputation

Sau khi thu thập IP/domain:

- Kiểm tra WHOIS/RDAP để tìm nhà đăng ký hoặc thông tin mạng liên quan khi cần.
- Kiểm tra ASN và thông tin nhà cung cấp mạng.
- Sử dụng threat intelligence phù hợp để kiểm tra reputation.
- So sánh nhiều nguồn độc lập và ghi lại thời điểm kiểm tra.
- Phân biệt dữ liệu reputation, phán đoán của vendor và bằng chứng trực tiếp từ môi trường.

Một IP có reputation xấu không tự động chứng minh host nội bộ đã bị compromise. Ngược lại, một IP chưa có cảnh báo cũng không đảm bảo an toàn.

---

## Task 4: Xây dựng timeline sự cố

### 1. Mục tiêu timeline

Timeline giúp nối các hành động thành một chuỗi có thể giải thích:

1. IDS ghi nhận kết nối hoặc pattern bất thường.
2. Host nội bộ có DNS query hoặc network activity liên quan.
3. Một process cụ thể tạo kết nối.
4. Process đó có thể được khởi chạy bởi một process cha đáng chú ý.
5. File hoặc hành động khác xảy ra trước/sau kết nối.

Không nên khẳng định thứ tự nhân quả chỉ vì các event gần nhau. Cần xem timestamp, process ID/GUID và các định danh liên quan.

### 2. Mẫu timeline

| Thời gian (kèm timezone) | Nguồn log | Host/User/Process | Hành động | Nhận định |
|---|---|---|---|---|
| T0 | IDS | Source → Destination | Alert về network traffic | Điểm bắt đầu điều tra |
| T1 | DNS | Host / Process | Truy vấn domain | Kiểm tra mối liên quan |
| T2 | Sysmon/EDR | Process | Tạo network connection | Xác định process chịu trách nhiệm |
| T3 | Endpoint | Process/File | File hoặc process activity khác | Kiểm tra chuỗi hành động |

Các mốc T0–T3 là cấu trúc minh họa để ghi chú, không phải timestamp hay kết quả của room.

---

## Task 5: Đánh giá và xử lý

### 1. Khi nào nên đánh giá là suspicious?

Có thể xếp hoạt động vào nhóm cần điều tra sâu khi:

- Destination IP/domain không rõ lý do nghiệp vụ.
- Kết nối lặp lại có pattern giống beaconing.
- Process tạo kết nối không phù hợp với chức năng của host.
- Hash/domain/IP có thêm bằng chứng threat intelligence.
- Có process execution, file creation hoặc persistence liên quan.

### 2. Các bước tiếp theo trong quy trình SOC

- Kiểm tra các host khác có kết nối đến cùng destination hay không.
- Xác định phạm vi và thời điểm đầu tiên indicator xuất hiện.
- Lưu bằng chứng và query đã sử dụng.
- Escalate nếu có dấu hiệu compromise hoặc C2 rõ ràng.
- Việc cô lập host hoặc chặn IP cần tuân theo quy trình ứng phó sự cố và phê duyệt của tổ chức.

### 3. Mẫu báo cáo C2 alert

```text
Alert source / IDS rule:
Alert timestamp and timezone:
Internal source host:
Source IP / port:
Destination IP / port:
Protocol:
Related DNS query/domain:
Process and user context:
First observed / last observed:
Connection pattern:
Threat intelligence enrichment:
Supporting endpoint/network events:
Alternative benign explanations:
Assessment and confidence:
Affected scope:
Recommended next action:
```

**Kết luận kiến thức:** Điều tra C2 cần đi từ alert mạng đến thiết bị, process, DNS và timeline. Mục tiêu không chỉ là tìm destination IP mà còn xác định process nào tạo traffic, hành động đó có phù hợp với host hay không và bằng chứng nào hỗ trợ giả thuyết C2.

---

## Tài liệu tham khảo

- [TryHackMe – ItsyBitsy](https://tryhackme.com/room/itsybitsy)
- [TryHackMe – SIEM Triage for SOC Training](https://tryhackme.com/module/siem-triage-for-soc)
- [Elastic – KQL syntax reference](https://www.elastic.co/docs/reference/query-languages/kql)
- [Elastic – Elastic Common Schema: Event fields](https://www.elastic.co/docs/reference/ecs/ecs-event)
- [Microsoft Learn – Understanding Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
