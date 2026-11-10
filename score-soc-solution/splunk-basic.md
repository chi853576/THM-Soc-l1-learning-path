# TryHackMe — Splunk Basics: Kiến thức cần nhớ

## 1. Splunk là gì?

**Splunk** là một giải pháp SIEM giúp thu thập, phân tích và tương quan dữ liệu log từ hệ thống và mạng theo thời gian thực. Splunk hỗ trợ giám sát hoạt động, phát hiện sự kiện bất thường và đẩy nhanh quá trình điều tra bảo mật.

**Learning Objectives:**
- Hiểu các thành phần của Splunk.
- Khám phá giao diện và các chức năng của Splunk.
- Hiểu cách đưa dữ liệu log vào Splunk (Log Ingestion).
- Thực hành nhập log và phân tích dữ liệu.

## 2. Ba thành phần chính của Splunk

| Thành phần | Chức năng |
|---|---|
| **Forwarder** | Thu thập log từ các máy hoặc nguồn dữ liệu và gửi đến Indexer. |
| **Indexer** | Xử lý, phân tích cấu trúc, chuẩn hóa và lưu trữ dữ liệu dưới dạng các event để có thể tìm kiếm. |
| **Search Head** | Cung cấp giao diện để người dùng tìm kiếm và phân tích dữ liệu đã được index bằng SPL. |

### Luồng hoạt động

`Log Sources → Forwarder → Indexer → Search Head`

- **Forwarder:** Thu thập log từ Windows Event Logs, PowerShell, Sysmon, Linux, web server, database...
- **Indexer:** Xử lý dữ liệu và tổ chức thông tin thành các cặp `field=value`, giúp việc tìm kiếm dễ dàng hơn.
- **Search Head:** Gửi truy vấn đến Indexer và hiển thị các event phù hợp với kết quả tìm kiếm.

**SPL (Search Processing Language):** Ngôn ngữ truy vấn được Splunk sử dụng để tìm kiếm và phân tích dữ liệu đã index.

## 3. Các khu vực chính trên giao diện Splunk

- **Splunk Bar:** Chứa các tùy chọn như Messages, Settings, Activity, Help và Find; hỗ trợ chuyển đổi giữa các ứng dụng Splunk đã cài đặt.
- **Apps Panel:** Hiển thị các ứng dụng đã cài đặt. Ứng dụng mặc định là **Search & Reporting**.
- **Explore Splunk:** Cung cấp liên kết nhanh để thêm dữ liệu, cài đặt ứng dụng và truy cập tài liệu hướng dẫn.
- **Home Dashboard:** Hiển thị dashboard được chọn làm trang chủ. Người dùng có thể chọn dashboard có sẵn hoặc tạo dashboard riêng. Tab **Yours** hiển thị các dashboard do người dùng tạo.

## 4. Data Ingestion — Đưa dữ liệu vào Splunk

**Data Ingestion** là quá trình đưa dữ liệu từ các nguồn bên ngoài vào Splunk để xử lý, lưu trữ và phân tích.

Splunk có thể tiếp nhận nhiều loại dữ liệu, chẳng hạn:
- Event logs từ hệ điều hành.
- Web server logs.
- Firewall logs.
- VPN logs.

Khi dữ liệu được đưa vào Splunk, hệ thống xử lý và chuyển đổi dữ liệu thành các **event** riêng lẻ.

### Thực hành trong room

1. Tại trang chủ Splunk, chọn **Add Data**.
2. Chọn **Upload** để tải dữ liệu log từ máy tính lên Splunk.
3. Trong bài thực hành, dữ liệu được sử dụng là **VPN logs**.

## 5. Những điểm cần nhớ

- **Forwarder = Thu thập và gửi log.**
- **Indexer = Xử lý và lưu trữ log.**
- **Search Head = Tìm kiếm và phân tích log.**
- **SPL = Ngôn ngữ truy vấn của Splunk.**
- **Add Data → Upload = Tải log từ máy tính vào Splunk.**
- **Event = Đơn vị dữ liệu được Splunk tạo ra sau khi xử lý dữ liệu đầu vào.**
- **Search & Reporting = Ứng dụng mặc định của Splunk.**

