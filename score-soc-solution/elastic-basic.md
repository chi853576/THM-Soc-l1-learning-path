# TryHackMe — Elastic Basics: Kiến thức cần nhớ

## 1. Elastic Stack (ELK) là gì?

**Elastic Stack (ELK)** là tập hợp các thành phần mã nguồn mở dùng để thu thập, lưu trữ, tìm kiếm, phân tích và trực quan hóa dữ liệu.

ELK không phải SIEM truyền thống, nhưng nhiều đội SOC sử dụng nó tương tự SIEM nhờ khả năng tìm kiếm log, điều tra sự kiện và xây dựng dashboard.

**Mục đích trong SOC:**
- Phân tích và điều tra log.
- Tìm kiếm, lọc dữ liệu.
- Phát hiện các hoạt động bất thường.
- Tạo biểu đồ và dashboard để giám sát hệ thống.

## 2. Bốn thành phần chính của Elastic Stack

| Thành phần | Chức năng |
|---|---|
| **Beats** | Thu thập và chuyển dữ liệu từ endpoint đến hệ thống xử lý. |
| **Logstash** | Tiếp nhận, lọc, phân tích và chuẩn hóa dữ liệu trước khi chuyển tiếp. |
| **Elasticsearch** | Lưu trữ, tìm kiếm, phân tích và tương quan dữ liệu. |
| **Kibana** | Giao diện web để tìm kiếm, điều tra, trực quan hóa dữ liệu và tạo dashboard. |

### Vai trò của từng thành phần

- **Beats:** Các agent chuyên dụng để thu thập dữ liệu. Ví dụ, Winlogbeat thu thập Windows Event Logs; Packetbeat thu thập dữ liệu lưu lượng mạng.
- **Logstash:** Có ba phần cấu hình chính:
  - `Input`: Nguồn dữ liệu đầu vào.
  - `Filter`: Lọc, phân tích và chuẩn hóa dữ liệu.
  - `Output`: Nơi gửi dữ liệu sau xử lý.
- **Elasticsearch:** Lưu trữ dữ liệu dưới dạng tài liệu JSON và cung cấp khả năng tìm kiếm, phân tích.
- **Kibana:** Cho phép SOC analyst truy vấn dữ liệu, áp dụng bộ lọc và tạo biểu đồ, dashboard.

### Luồng dữ liệu tổng quát

`Beats → Logstash → Elasticsearch → Kibana`

Đây là luồng minh họa phổ biến. Tùy cấu hình, Beats cũng có thể gửi dữ liệu trực tiếp đến Elasticsearch mà không cần Logstash.

## 3. Kibana Discover — Tìm kiếm và điều tra log

**Discover** là khu vực SOC analyst thường sử dụng để khám phá, tìm kiếm và phân tích log.

| Thành phần | Chức năng |
|---|---|
| **Logs** | Hiển thị các event và thông tin trường dữ liệu của từng log. |
| **Fields Pane** | Hiển thị các trường dữ liệu được phân tích từ log. |
| **Index Pattern / Data View** | Xác định tập dữ liệu mà Kibana sẽ truy vấn. |
| **Search Bar** | Nhập truy vấn để tìm kiếm và thu hẹp kết quả. |
| **Time Filter** | Lọc log theo khoảng thời gian. |
| **Timeline** | Hiển thị số lượng event theo thời gian, hỗ trợ phát hiện đột biến. |
| **Add Filter** | Thêm bộ lọc theo trường dữ liệu mà không cần tự viết toàn bộ truy vấn. |
| **Create Table** | Chọn các trường quan trọng để tạo bảng, giảm thông tin dư thừa. |

### Index Pattern / Data View

Dùng để xác định những index chứa dữ liệu cần truy vấn. Một Data View có thể trỏ đến một hoặc nhiều index.

Trong room này, Data View dùng để phân tích VPN logs là `vpn_connections`.

### Fields Pane

- Nhấp vào một trường để xem các giá trị phổ biến và tần suất xuất hiện.
- Nút `+` có thể thêm bộ lọc để chỉ hiển thị log chứa giá trị đã chọn.
- Nút `-` có thể thêm bộ lọc để loại trừ giá trị đó.

### Timeline

Biểu đồ số lượng event theo thời gian giúp nhận biết các đợt tăng đột biến bất thường (*log spike*). Đây có thể là dấu hiệu cần điều tra thêm.

## 4. KQL — Kibana Query Language

**KQL** là ngôn ngữ truy vấn dùng trong Kibana để tìm kiếm và lọc dữ liệu trong Elasticsearch.

### 4.1. Free-text search

Tìm một từ hoặc cụm từ trong dữ liệu mà không chỉ định trường cụ thể.

Ví dụ:

```text
security
```

Tìm kiếm có thể không trả về kết quả nếu cụm từ không khớp với cách dữ liệu được lập chỉ mục. Có thể dùng wildcard để tìm các từ bắt đầu bằng một chuỗi.

```text
United*
```

Wildcard `*` đại diện cho không hoặc nhiều ký tự, tùy vị trí sử dụng.

### 4.2. Toán tử logic

| Toán tử | Ý nghĩa | Ví dụ |
|---|---|---|
| `AND` | Các điều kiện đều phải thỏa mãn. | `"United States" AND "Virginia"` |
| `OR` | Chỉ cần thỏa mãn một trong các điều kiện. | `"United States" OR "England"` |
| `NOT` | Loại trừ điều kiện được chỉ định. | `"United States" AND NOT "Florida"` |

### 4.3. Field-based search

Tìm kiếm dựa trên tên trường và giá trị cần tìm theo cú pháp:

`field: value`

Ví dụ:

```text
Source_ip: 238.163.231.224 AND UserName: Suleman
```

Ý nghĩa: Tìm các log có `Source_ip` bằng `238.163.231.224` và `UserName` bằng `Suleman`.

**Lưu ý:** Tên trường phải khớp với trường thực tế trong dữ liệu. KQL dùng để lọc dữ liệu, không phải ngôn ngữ truy vấn để thay đổi hay xóa dữ liệu.

## 5. Visualizations — Trực quan hóa dữ liệu

Kibana hỗ trợ trình bày dữ liệu bằng bảng, biểu đồ tròn, biểu đồ cột và nhiều dạng trực quan hóa khác.

### Tạo và lưu visualization

1. Mở **Discover** và chọn trường dữ liệu cần phân tích.
2. Chọn tùy chọn tạo visualization hoặc mở khu vực Visualize.
3. Chọn loại biểu đồ hoặc bảng phù hợp.
4. Có thể kết hợp nhiều trường để so sánh hoặc thể hiện mối liên hệ giữa chúng.
5. Nhấn **Save**, nhập tiêu đề và mô tả.
6. Chọn **Save and add to library** để lưu vào thư viện.

### Thực hành: VPN connection thất bại

Mục tiêu: Tạo bảng hiển thị người dùng và địa chỉ IP liên quan đến các lần kết nối VPN thất bại.

1. Chọn Data View `vpn_connections`.
2. Đặt Time Filter bao gồm tháng 1/2022.
3. Lọc các event bằng truy vấn:

```text
action: failed
```

4. Chọn hai trường để hiển thị trong bảng:
   - `UserName`
   - `Source_ip`
5. Lưu visualization để sử dụng lại.

Bảng này giúp xác định người dùng và IP nguồn liên quan đến các lần đăng nhập VPN thất bại, từ đó hỗ trợ điều tra các hoạt động đáng ngờ.

## 6. Dashboards — Tổng hợp dữ liệu giám sát

**Dashboard** là giao diện tổng hợp nhiều visualization và saved searches trên cùng một màn hình, giúp theo dõi hoạt động hệ thống dễ dàng hơn.

### Tạo custom dashboard

1. Mở tab **Dashboard**.
2. Chọn **Create dashboard**.
3. Nhấn **Add from Library**.
4. Chọn các visualization và saved searches đã lưu.
5. Sắp xếp, điều chỉnh bố cục các thành phần.
6. Lưu dashboard.

### Ý nghĩa trong SOC

Dashboard VPN có thể kết hợp:
- Bảng các lần kết nối thất bại.
- Biểu đồ số lượng kết nối theo thời gian.
- Thống kê theo người dùng hoặc IP nguồn.

Nhờ đó, analyst có thể nhanh chóng nhận ra các đợt đăng nhập thất bại tăng bất thường hoặc những nguồn truy cập cần điều tra.
