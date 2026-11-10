# The Greenholt Phish

**Chủ đề:** Phân tích email phishing\
**Mục tiêu:** Kiểm tra email header, xác minh danh tính người gửi, tra
cứu SPF/DMARC và phân tích tệp đính kèm đáng ngờ.

> **Lưu ý:** Đây là ghi chú tham khảo dựa trên các walkthrough công
> khai. Nếu dữ liệu hoặc phiên bản lab thay đổi, hãy đối chiếu với
> `challenge.eml` trong máy của TryHackMe. Không mở tệp đính kèm đáng
> ngờ trên máy thật.

## Task 1 --- A Message That Doesn't Add Up

### Bối cảnh

Một nhân viên kinh doanh của Greenholt PLC nhận được email bất thường từ
một khách hàng. Email dùng lời chào chung chung, đề cập đến một khoản
tiền chuyển vào tài khoản và đính kèm tệp mà người nhận không yêu cầu.
Email được chuyển đến SOC để điều tra.

### Mở email mẫu

Trong máy lab, tìm `challenge.eml`. Có thể mở bằng Thunderbird:

1.  Nhấp chuột phải vào `challenge.eml`.
2.  Chọn **Open With Other Application**.
3.  Chọn **Thunderbird Mail**.
4.  Xem nội dung email và phần header/source để tìm thông tin người gửi,
    địa chỉ Reply-To, IP nguồn và tệp đính kèm.


## Phân tích các dấu hiệu đáng ngờ

### 1. From và Reply-To khác nhau

-   **From:** `info@mutawamarine.com`
-   **Reply-To:** `info.mutawamarine@mail.com`

Khi nhấn Reply, email phản hồi sẽ được gửi đến địa chỉ Reply-To, không
nhất thiết là địa chỉ hiển thị trong From. Sự khác biệt này cần được xác
minh, đặc biệt khi email liên quan đến giao dịch tài chính.

### 2. Kiểm tra Originating IP

IP nguồn được xác định trong mẫu là `192.119.71.157`.

Có thể tra cứu thông tin chủ sở hữu bằng WHOIS:

``` bash
whois 192.119.71.157
```

Kết quả tham khảo: `Hostwinds LLC`.

Khi đọc header, các dòng `Received:` thường được thêm theo từng chặng
máy chủ. Đọc chuỗi header để xác định máy chủ đã gửi email vào hệ thống
nhận; không nên chỉ dựa vào tên hiển thị của người gửi.

### 3. SPF

Bản ghi SPF của domain Return-Path:

``` text
v=spf1 include:spf.protection.outlook.com -all
```

-   `include:spf.protection.outlook.com`: cho phép áp dụng chính sách
    SPF được chỉ định bởi domain này.
-   `-all`: các máy chủ không được cho phép sẽ nhận kết quả **Fail**.

Nếu kết quả SPF của email là `fail`, IP gửi không được bản ghi SPF của
domain cho phép. Đây là dấu hiệu đáng ngờ, nhưng nên kết hợp với các
bằng chứng khác.

### 4. DMARC

Bản ghi DMARC:

``` text
v=DMARC1; p=quarantine; fo=1
```

-   `v=DMARC1`: phiên bản DMARC.
-   `p=quarantine`: yêu cầu bên nhận xử lý thư không vượt qua DMARC theo
    chính sách quarantine, thường là đưa vào spam/quarantine.
-   `fo=1`: yêu cầu tạo báo cáo lỗi khi SPF hoặc DKIM không vượt qua
    theo điều kiện được quy định.

DMARC dựa trên sự căn chỉnh (alignment) giữa domain trong thông tin
người gửi và kết quả xác thực SPF/DKIM. Bản ghi DMARC tồn tại không đồng
nghĩa email cụ thể đó là hợp lệ.

### 5. Tên tệp và phần mở rộng thực tế

Tên tệp hiển thị:

``` text
SWT_#09674321____PDF__.CAB
```

Phần mở rộng trong tên là `.CAB`, nhưng phân tích nhận dạng tệp cho thấy
định dạng thực tế là **RAR**. Không nên tin hoàn toàn vào phần mở rộng
do người gửi đặt; hãy kiểm tra loại tệp thực tế bằng công cụ phân tích
an toàn.

### 6. Tính SHA-256

Nếu tệp đã được trích xuất trong môi trường lab an toàn, có thể tính
hash bằng:

``` bash
sha256sum "SWT_#09674321____PDF__.CAB"
```

SHA-256 tham khảo:

``` text
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f
```

Nếu muốn tránh trích xuất tệp đáng ngờ ra khỏi email, có thể phân tích
nội dung `.eml` và trích riêng khối Base64 trong môi trường cách ly. Chỉ
thực hiện khi hiểu rõ cấu trúc MIME và bảo đảm lấy đúng khối dữ liệu của
tệp đính kèm.

Tra cứu hash trên VirusTotal có thể cung cấp loại tệp, kích thước và
thông tin phát hiện từ các công cụ bảo mật. Kết quả tham khảo của lab:

-   **Kích thước:** `400.26 KB`
-   **Loại tệp thực tế:** `RAR`

Không tải hoặc chạy tệp đáng ngờ trên máy cá nhân chỉ để kiểm tra hash.
