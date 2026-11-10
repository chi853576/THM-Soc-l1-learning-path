# TryHackMe --- Snapped Phish-ing Line

**Chủ đề:** Điều tra chiến dịch phishing, phân tích email và URL, kiểm
tra phishing kit, trích xuất IOC và sử dụng Cyber Threat Intelligence
(CTI).

**Bối cảnh:** Nhiều nhân viên của SwiftSpend Financial nhận được email
đáng ngờ; một số người đã nhập thông tin đăng nhập vào trang giả mạo.
Nhiệm vụ của nhà phân tích là xác định cách chiến dịch hoạt động, dữ
liệu nào bị lộ và những dấu vết nào có thể dùng để phát hiện hoặc ngăn
chặn cuộc tấn công.

> **Phạm vi tài liệu:** Tài liệu này tổng hợp kiến thức và quy trình
> điều tra, không phải danh sách đáp án cho từng câu hỏi của room. Chỉ
> phân tích URL, email và tệp trong máy lab cô lập. Không truy cập lại
> hạ tầng độc hại từ máy cá nhân hoặc gửi thông tin thật vào trang thử
> nghiệm.

## 1. Mô hình điều tra tổng quát

Một chiến dịch phishing có thể được điều tra theo chuỗi:

1.  **Email mẫu** --- xác định người gửi, người nhận, chủ đề, tệp đính
    kèm và dấu hiệu social engineering.
2.  **URL và nội dung HTML** --- trích xuất liên kết, tham số, domain,
    đường dẫn và hành vi chuyển hướng.
3.  **Hạ tầng tấn công** --- xác định domain/IP, trang giả mạo và tài
    nguyên được máy chủ công khai.
4.  **Phishing kit** --- kiểm tra mã nguồn để hiểu cách thu thập thông
    tin đăng nhập và nơi dữ liệu được gửi.
5.  **Dấu vết người dùng** --- kiểm tra log để xác định tài khoản nào đã
    tương tác hoặc gửi thông tin.
6.  **Threat intelligence** --- tra cứu hash, domain, URL và các IOC
    liên quan.
7.  **Báo cáo và ứng phó** --- xác định phạm vi ảnh hưởng, lưu bằng
    chứng và đề xuất hành động.

Điều tra tốt không chỉ xác định một email là độc hại; nó giải thích
**cách cuộc tấn công diễn ra, ai có thể bị ảnh hưởng và cần làm gì tiếp
theo**.

## 2. Phân tích email mẫu (`.eml`)

Tệp `.eml` thường lưu nội dung email cùng header và MIME parts. Có thể
mở bằng trình đọc mail hoặc kiểm tra dưới dạng văn bản trong máy lab.

### Các trường cần chú ý

  -----------------------------------------------------------------------
  Trường                  Ý nghĩa                 Câu hỏi điều tra
  ----------------------- ----------------------- -----------------------
  `From`                  Địa chỉ người gửi được  Tên hiển thị có khớp
                          thể hiện trong email    địa chỉ không? Domain
                                                  có hợp lý không?

  `To`                    Người nhận              Ai là mục tiêu của
                                                  email?

  `Reply-To`              Địa chỉ nhận phản hồi   Có khác `From` không?

  `Return-Path`           Địa chỉ liên quan đến   Domain này có liên quan
                          đường trả thư           đến domain hiển thị
                                                  không?

  `Received`              Các chặng máy chủ xử lý Email đi qua những máy
                          email                   chủ nào?

  `Subject`               Chủ đề                  Có tạo cảm giác khẩn
                                                  cấp, thanh toán hoặc
                                                  yêu cầu hành động
                                                  không?

  `Content-Type`          Kiểu nội dung/MIME      Email có HTML hoặc tệp
                                                  đính kèm không?

  `Content-Disposition`   Cách phần MIME được     Có tệp đính kèm không,
                          trình bày               tên tệp là gì?
  -----------------------------------------------------------------------

**Lưu ý:** Không nên kết luận chỉ dựa vào tên hiển thị, một địa chỉ
email hoặc một dòng `Received`. Header có thể chứa dữ liệu giả mạo; cần
xem xét chuỗi chuyển tiếp và kết hợp nhiều bằng chứng.

### Tìm nhanh trong nhiều email

Mở terminal trong thư mục chứa email mẫu:

``` bash
# Tìm các tệp có nhắc tới PDF trong header MIME
grep -il 'pdf' *.eml

# Tìm trường From trong các email
grep -h -i '^From:' *.eml

# Tìm các trường người gửi, người nhận và tiêu đề
grep -h -i -E '^(From|To|Reply-To|Return-Path|Subject):' *.eml
```

Các lệnh trên chỉ là bước sàng lọc. Kết quả cần được xác minh trong đúng
email vì từ khóa `pdf` có thể xuất hiện ở nội dung khác hoặc trong tên
tệp.

### Xem các dòng lân cận

``` bash
grep -in -A 3 -B 2 'Reply-To' sample.eml
```

-   `-i`: không phân biệt chữ hoa/chữ thường.
-   `-n`: hiển thị số dòng.
-   `-A 3`: hiển thị 3 dòng sau kết quả.
-   `-B 2`: hiển thị 2 dòng trước kết quả.

## 3. Phân tích tệp HTML đính kèm

Tệp HTML có thể chứa trang đăng nhập giả mạo hoặc chuyển hướng đến một
URL khác. **Không mở trực tiếp tệp đáng ngờ trong trình duyệt máy
thật.** Hãy kiểm tra mã nguồn bằng trình soạn thảo văn bản trong môi
trường lab.

### Những gì cần tìm

-   URL đầy đủ và domain gốc.
-   Tham số truy vấn như `?email=...`.
-   Đường dẫn cụ thể và mã định danh nạn nhân.
-   JavaScript hoặc HTML dùng để chuyển hướng.
-   Tên thương hiệu bị giả mạo, logo và biểu mẫu đăng nhập.
-   Các endpoint xử lý dữ liệu như `submit.php`, `login.php` hoặc tên
    tương tự.
-   Các URL khác được nhúng trong mã nguồn.

Tìm URL trong tệp:

``` bash
grep -Eoi 'https?://[^" <>]+' suspicious.html
```

Tìm những dòng có thể chứa chuyển hướng hoặc biểu mẫu:

``` bash
grep -in -E 'https?://|window.location|location.href|action=|form|submit' suspicious.html
```

Các biểu thức tìm kiếm không thay thế việc đọc mã nguồn. URL có thể bị
mã hóa, chia nhỏ hoặc tạo động bằng JavaScript.

### Domain, URL và tham số

Một URL có thể gồm:

``` text
scheme://host/path?query#fragment
```

-   `scheme`: ví dụ `http` hoặc `https`.
-   `host`: hostname/domain và có thể có port.
-   `path`: tài nguyên hoặc endpoint trên máy chủ.
-   `query`: tham số có thể chứa mã chiến dịch hoặc địa chỉ email nạn
    nhân.
-   `fragment`: phần sau `#`, thường được xử lý phía trình duyệt.

Khi ghi IOC, phân biệt **domain**, **URL đầy đủ** và **URL riêng cho
từng nạn nhân**. Tham số cá nhân có thể chứa dữ liệu nhạy cảm, vì vậy
cần che/redact khi chia sẻ báo cáo.

### Defang URL

Defanging giúp giảm khả năng người đọc vô tình nhấp vào URL độc hại. Ví
dụ:

``` text
https://example.com/path
hxxps[://]example[.]com/path
```

Defanging chỉ là biện pháp trình bày an toàn, **không làm URL trở nên vô
hại**. Khi đưa IOC vào hệ thống bảo mật, phải dùng định dạng mà hệ thống
đó yêu cầu.

## 4. Phishing kit: cấu trúc và cách điều tra

**Phishing kit** là bộ tệp giúp kẻ tấn công triển khai trang giả mạo và
thu thập dữ liệu. Kit có thể chứa:

-   HTML/CSS/JavaScript mô phỏng trang đăng nhập.
-   PHP hoặc mã server-side xử lý biểu mẫu.
-   Hình ảnh, logo và tài nguyên của thương hiệu bị giả mạo.
-   Cấu hình nhận dữ liệu hoặc chuyển tiếp dữ liệu.
-   Tệp log lưu các lần gửi biểu mẫu.
-   Tệp nén hoặc tài nguyên được công khai trên máy chủ.

### Liệt kê và tìm kiếm tệp

Chỉ thực hiện trong thư mục lab đã chuẩn bị:

``` bash
# Liệt kê tệp
find . -maxdepth 3 -type f -print

# Tìm email trong mã nguồn
grep -RniE '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}' .

# Tìm các endpoint hoặc thao tác gửi dữ liệu
grep -RniE 'mail\(|sendmail|smtp|POST|password|passwd|submit' .
```

Mục tiêu là **hiểu luồng dữ liệu**, không chạy mã trong kit.

### Đọc mã xử lý biểu mẫu

Khi thấy tệp như `submit.php`, hãy kiểm tra:

1.  Dữ liệu nào được lấy từ request?
2.  Có thu thập tên người dùng, email hoặc mật khẩu không?
3.  Dữ liệu được lưu vào tệp, cơ sở dữ liệu hay gửi qua email?
4.  Có địa chỉ email, máy chủ SMTP, URL hoặc webhook được mã hóa cứng
    không?
5.  Có kiểm tra, mã hóa hoặc xóa log không?
6.  Có mã nào tải thêm nội dung hoặc chuyển tiếp người dùng không?

Địa chỉ email được nhúng trong mã nguồn có thể là hạ tầng nhận dữ liệu
của kẻ tấn công. Tuy nhiên, cần xác minh vai trò của nó: một email xuất
hiện trong kit không tự động chứng minh nó đã nhận thông tin bị đánh
cắp.

### Tệp nén và hash

Kiểm tra thông tin tệp trước khi giải nén:

``` bash
file phishing-kit.zip
sha256sum phishing-kit.zip
unzip -l phishing-kit.zip
```

-   `file`: nhận diện loại tệp dựa trên nội dung.
-   `sha256sum`: tạo hash để định danh và tra cứu mẫu.
-   `unzip -l`: liệt kê nội dung archive mà không giải nén.

Nếu cần giải nén, dùng thư mục làm việc riêng trong máy lab và kiểm tra
tên đường dẫn trong archive trước. Không chạy các script trong bộ kit.

**Hash không chứng minh tệp độc hại hay lành tính.** Nó là định danh để
so sánh mẫu và tra cứu threat intelligence.

## 5. Phân tích log thu thập thông tin đăng nhập

Log của phishing kit có thể ghi nhận các lần người dùng gửi biểu mẫu.
Khi điều tra, tìm:

-   Email hoặc username được nhập.
-   Thời điểm gửi.
-   Số lần thử và các lần gửi lặp lại.
-   IP nguồn hoặc user-agent, nếu có.
-   Trạng thái chuyển hướng sau khi gửi biểu mẫu.
-   Thông tin nào được ghi lại rõ ràng trong log.

Ví dụ tìm email trong tệp log:

``` bash
grep -ni '@' log.txt
```

Đếm số dòng chứa một địa chỉ cụ thể:

``` bash
grep -ic 'user@example.com' log.txt
```

Đây là các ví dụ minh họa; cần điều chỉnh theo định dạng log thực tế.
Một địa chỉ xuất hiện nhiều lần có thể là nhiều lần thử, nhưng không
nhất thiết là nhiều tài khoản bị xâm phạm.

### Khi thông tin đăng nhập có thể đã bị lộ

-   Xác định tài khoản và người dùng bị ảnh hưởng.
-   Thực hiện quy trình đổi mật khẩu và thu hồi phiên đăng nhập/token.
-   Kiểm tra đăng nhập bất thường và hoạt động sau thời điểm lộ thông
    tin.
-   Kiểm tra việc tái sử dụng mật khẩu ở các dịch vụ khác theo quy trình
    của tổ chức.
-   Bảo toàn email, URL, log và hash làm bằng chứng.
-   Báo cáo sự cố qua kênh SOC/IR được phê duyệt.

Không sao chép mật khẩu thật vào báo cáo hoặc chia sẻ rộng rãi log có
chứa thông tin xác thực.

## 6. Threat Intelligence và VirusTotal

Threat intelligence giúp bổ sung bối cảnh cho các IOC như:

-   **File hash:** nhận diện mẫu tệp cụ thể.
-   **Domain:** hạ tầng lưu trữ trang phishing hoặc chuyển hướng.
-   **URL:** đường dẫn cụ thể, đôi khi gắn với từng nạn nhân.
-   **IP address:** máy chủ hoặc hạ tầng liên quan.
-   **Email address:** địa chỉ gửi hoặc nhận dữ liệu được phát hiện
    trong chiến dịch.

### Quy trình tra cứu

1.  Tính SHA-256 của mẫu trong môi trường an toàn.
2.  Tra cứu hash trên dịch vụ CTI phù hợp, chẳng hạn VirusTotal.
3.  Kiểm tra loại tệp, thời điểm nộp mẫu, các phát hiện và mối quan hệ
    với domain/URL.
4.  Đối chiếu với bằng chứng từ email và mã nguồn.
5.  Ghi nguồn, thời gian tra cứu và mức độ tin cậy.

### Đọc kết quả cẩn thận

-   Không có phát hiện không có nghĩa là tệp an toàn.
-   Kết quả từ nhiều engine có thể khác nhau.
-   Một domain có thể được chia sẻ bởi nhiều dịch vụ hoặc bị chiếm
    quyền.
-   Dữ liệu CTI có thể cũ hoặc thiếu ngữ cảnh.
-   Không tải mẫu độc hại lên dịch vụ công cộng nếu dữ liệu có chứa
    thông tin riêng tư hoặc chính sách tổ chức không cho phép.

## 7. IOC và cách ghi nhận bằng chứng

Một bảng IOC hữu ích nên có các trường:

  Trường       Nội dung
  ------------ -----------------------------------------------------
  Loại IOC     Hash, domain, URL, IP, email
  Giá trị      Giá trị đã xác minh; defang khi chia sẻ
  Vai trò      Sender, redirect, hosting, credential collection...
  Bằng chứng   Tên tệp, dòng log, header hoặc đoạn mã
  Thời gian    Thời gian phát hiện/quan sát và múi giờ
  Nguồn        Email mẫu, log, CTI hoặc mã nguồn
  Độ tin cậy   Cao / trung bình / thấp, kèm lý do
  Hành động    Chặn, giám sát, truy tìm thêm hoặc cần xác minh

Không gộp tất cả IOC thành một danh sách thiếu ngữ cảnh. Ghi rõ IOC được
quan sát trực tiếp hay chỉ được suy ra từ nguồn CTI.

## 8. Quy trình phân tích mẫu cho SOC

`<list marker="number" gap={1}>`{=html} `<list-item>`{=html}**Triage:**
ghi nhận người báo cáo, thời gian, người nhận, tiêu đề và mức độ khẩn
cấp.`</list-item>`{=html} `<list-item>`{=html}**Preserve:** lưu email
gốc và các tệp liên quan; tránh chỉnh sửa mẫu gốc.`</list-item>`{=html}
`<list-item>`{=html}**Analyze:** đọc header, body, URL, HTML và
attachment trong môi trường cô lập.`</list-item>`{=html}
`<list-item>`{=html}**Correlate:** nối các bằng chứng như domain, hash,
địa chỉ thu thập dữ liệu và log.`</list-item>`{=html}
`<list-item>`{=html}**Scope:** xác định người dùng đã nhận email, nhấp
link hoặc gửi thông tin đăng nhập.`</list-item>`{=html}
`<list-item>`{=html}**Contain:** phối hợp chặn IOC, vô hiệu hóa
trang/URL qua quy trình được phép, đổi thông tin xác thực và thu hồi
phiên nếu cần.`</list-item>`{=html} `<list-item>`{=html}**Report:** nêu
tóm tắt, bằng chứng, phạm vi ảnh hưởng, độ tin cậy, hành động đã thực
hiện và việc cần theo dõi.`</list-item>`{=html} `</list>`{=html}

## 9. Checklist ôn tập

-   [ ] Phân biệt `From`, `Reply-To`, `Return-Path` và `Received`.
-   [ ] Tìm được email mẫu và các trường header quan trọng bằng `grep`.
-   [ ] Trích xuất URL từ HTML và phân tích domain/path/query.
-   [ ] Giải thích defanging và biết khi nào cần dùng.
-   [ ] Nhận biết cấu trúc cơ bản của phishing kit.
-   [ ] Đọc mã xử lý biểu mẫu mà không chạy mã độc.
-   [ ] Tính hash, xác định loại tệp và liệt kê archive an toàn.
-   [ ] Đọc log để tìm hoạt động gửi biểu mẫu và các tài khoản liên
    quan.
-   [ ] Tra cứu IOC bằng CTI và đánh giá giới hạn của kết quả.
-   [ ] Viết báo cáo nêu rõ bằng chứng, phạm vi ảnh hưởng và hành động
    ứng phó.

## Nguồn tham khảo

-   [TryHackMe --- Phishing Analysis
    module](https://tryhackme.com/module/phishing) --- mô tả mục tiêu
    của challenge *Snapped Phish-ing Line*.
-   [TryHackMe SOC Level 1
    path](https://tryhackme.com/path/outline/soclevel1) --- bối cảnh học
    tập và kỹ năng SOC.
-   [Snapped Phish-ing Line walkthrough --- Uphill
    Push](https://uphillpush.github.io/THM/Walkthroughs/Snapped-Phish-ing-Line.html)
    --- tham khảo các kỹ thuật tìm kiếm email, URL và phân tích phishing
    kit.
-   [Snapped Phish-ing Line walkthrough ---
    StumbleSec](https://stumblesec.com/posts/tryhackme-snapped-phish-ing-line-challenge-walkthrough/)
    --- tham khảo quy trình triage email, URL và CTI.

Các nguồn walkthrough được dùng để xác định kỹ thuật và quy trình liên
quan; tài liệu này không chép danh sách đáp án của room.
