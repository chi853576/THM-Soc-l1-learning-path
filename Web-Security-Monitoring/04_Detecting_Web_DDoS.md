# Detecting Web DDoS

**Nguồn học:** [TryHackMe – Detecting Web DDoS](https://tryhackme.com/room/detectingwebddos)

## 1. Denial of Service (DoS) và Distributed Denial of Service (DDoS)

**Denial of Service (DoS)** là hành vi làm suy giảm hoặc gián đoạn khả năng cung cấp dịch vụ, khiến người dùng hợp pháp không thể truy cập hoặc sử dụng dịch vụ bình thường.

**Distributed Denial of Service (DDoS)** là DoS được tạo ra từ nhiều hệ thống/nguồn khác nhau. Attacker thường sử dụng botnet hoặc hạ tầng phân tán để tạo lượng traffic lớn hoặc nhiều request tới mục tiêu.

Mục tiêu trực tiếp của DoS/DDoS là ảnh hưởng đến **Availability** trong CIA Triad.

### Khác biệt cơ bản

| Tiêu chí | DoS | DDoS |
|---|---|---|
| Nguồn phát sinh | Một nguồn hoặc số lượng rất ít | Nhiều nguồn phân tán |
| Khả năng mở rộng | Thường hạn chế hơn | Có thể tạo traffic lớn từ nhiều mạng/địa lý |
| Attribution | Có thể dễ khoanh vùng hơn nhưng vẫn không chắc chắn | Khó xác định nguồn điều khiển thực tế |
| Mitigation | Có thể lọc/giới hạn nguồn nếu nguồn rõ | Cần lọc phân tán, edge/CDN/scrubbing và phối hợp ISP/provider |

Một địa chỉ IP không đồng nghĩa một attacker. IP có thể thuộc NAT, proxy, VPN, cloud host hoặc bot đã bị kiểm soát.

## 2. Các lớp DoS/DDoS

### 2.1 Network-layer attacks (L3/L4)

Nhắm vào bandwidth, network protocol hoặc trạng thái kết nối.

| Kiểu | Khái niệm |
|---|---|
| UDP flood | Lượng lớn UDP traffic làm tiêu hao bandwidth hoặc tài nguyên xử lý |
| ICMP flood | Lượng lớn ICMP packet gây tiêu hao tài nguyên |
| SYN flood | Tạo nhiều TCP SYN để làm cạn tài nguyên quản lý kết nối |
| Reflection/amplification | Lợi dụng server bên thứ ba phản hồi lượng dữ liệu lớn về phía nạn nhân |

Dấu hiệu thường thấy:
- Băng thông inbound tăng đột ngột.
- Packet per second (PPS) tăng mạnh.
- Nhiều packet cùng protocol/port.
- Connection table hoặc SYN backlog tăng.
- Service/network device quá tải.

### 2.2 Application-layer attacks (L7)

Nhắm vào HTTP/HTTPS hoặc logic ứng dụng. Request có thể trông giống traffic hợp lệ, nhưng tổng số request hoặc chi phí xử lý khiến application/backend quá tải.

Các ví dụ:
- **HTTP GET flood:** nhiều GET request đến page/resource/API.
- **HTTP POST flood:** nhiều POST request, có thể kích hoạt xử lý tốn tài nguyên.
- **Slow HTTP attacks:** giữ connection hoặc gửi request chậm để chiếm connection/resource.
- **Cache-bypass/cache-busting:** tạo request khiến nội dung không được phục vụ từ cache và origin phải xử lý lại.
- **API/resource exhaustion:** tập trung vào endpoint tốn CPU, database query hoặc backend calls.

L7 DDoS có thể gây ảnh hưởng lớn dù bandwidth không quá cao, vì một request nhỏ có thể khiến server thực hiện nhiều truy vấn hoặc thao tác tốn tài nguyên.

## 3. Động cơ của Attacker

Một cuộc DDoS có thể được thực hiện vì nhiều mục đích:
- **Hacktivism:** gây gián đoạn để thể hiện quan điểm hoặc phản đối.
- **Extortion:** yêu cầu tiền để dừng tấn công.
- **Disruption/sabotage:** làm gián đoạn hoạt động của tổ chức.
- **Distraction:** tạo nhiễu để che giấu một hoạt động tấn công khác.
- **Competition:** gây ảnh hưởng đến dịch vụ của đối thủ.
- **Retaliation:** trả đũa cá nhân hoặc tổ chức.

SOC không nên mặc định động cơ chỉ từ loại traffic. Cần phối hợp threat intelligence, thông tin từ business và incident context.

## 4. Indicators of DDoS

### 4.1 Network indicators
- Inbound bandwidth hoặc packets per second tăng bất thường.
- Kết nối đến một IP/port/service tăng đột biến.
- Nhiều nguồn IP gửi cùng loại traffic.
- Tỷ lệ TCP handshake thành công giảm.
- Connection backlog hoặc số lượng concurrent connections tăng.
- Nhiều packet có pattern giống nhau hoặc protocol bất thường.

### 4.2 Web/application indicators
- Requests per second (RPS) tăng mạnh so với baseline.
- Một số URI/API bị truy cập với tần suất rất cao.
- Nhiều request lặp lại, query hoặc header gần giống nhau.
- Response time/latency tăng.
- Tỷ lệ 5xx tăng, đặc biệt 502, 503, 504.
- Tỷ lệ timeout và failed request tăng.
- Origin CPU, memory, database connections hoặc thread pool đạt ngưỡng.
- Người dùng hợp pháp không thể đăng nhập hoặc tải nội dung.

### 4.3 Log indicators
| Field | Dấu hiệu đáng chú ý |
|---|---|
| Timestamp | Burst request trong thời gian ngắn |
| Client IP | Một IP hoặc nhiều IP gửi request với pattern tương tự |
| URI/path | Một endpoint bị nhắm liên tục |
| Method | GET/POST tăng không cân xứng |
| Status | Tăng 429, 5xx hoặc status pattern bất thường |
| Bytes sent/received | Request/response size lệch baseline |
| User-Agent | Nhiều request dùng cùng UA lạ hoặc UA bất thường |
| Time taken | Latency tăng và kéo dài |
| Referrer | Không khớp hành vi truy cập thông thường |

Các field này chỉ là tín hiệu ban đầu. DDoS hiện đại có thể dùng User-Agent phổ biến, nhiều IP thật và request gần giống người dùng.

## 5. Phân biệt DDoS với Flash Crowd hoặc lỗi hệ thống

Traffic tăng không phải lúc nào cũng là DDoS. Ví dụ một chiến dịch marketing, livestream hoặc sự kiện bán hàng có thể tạo flash crowd.

| Tình huống | Đặc điểm cần kiểm tra |
|---|---|
| Flash crowd | Tăng traffic trùng sự kiện, nhiều người dùng hợp lệ, hành vi và session có tính đa dạng |
| DDoS | Request pattern lặp lại, nguồn phân tán hoặc bất thường, endpoint/resource bị nhắm có chủ đích |
| Application bug | Traffic có thể bình thường nhưng CPU/latency/5xx tăng do code hoặc dependency lỗi |
| Infrastructure failure | Disk, network, database, DNS hoặc upstream service gặp sự cố |
| Scheduled batch | Tăng request theo lịch vận hành hoặc job nội bộ đã biết |

Cần kết hợp lịch business, deployment, metrics, source distribution và application telemetry trước khi kết luận.

## 6. Log Analysis

### 6.1 Các nguồn log nên thu thập
- Web access logs: Apache, Nginx, IIS.
- Web error logs.
- Application/API logs.
- WAF/CDN logs.
- Load balancer and reverse proxy logs.
- Firewall/network flow logs.
- DNS logs.
- Host/EDR telemetry.
- Metrics từ web server, application, database và cloud infrastructure.

### 6.2 Quy trình phân tích access log
1. Xác định thời điểm dịch vụ bắt đầu chậm hoặc không truy cập được.
2. So sánh request volume với baseline cùng giờ/ngày.
3. Nhóm theo source IP, URI, method, User-Agent và status code.
4. Tìm endpoint bị truy cập lặp lại hoặc có response latency cao.
5. So sánh số request với số session/người dùng hợp lệ nếu có dữ liệu.
6. Tương quan với CPU, memory, network bandwidth, database connections và upstream errors.
7. Kiểm tra CDN/WAF đã chặn hay origin vẫn nhận phần lớn traffic.
8. Ghi rõ phạm vi ảnh hưởng và giới hạn của log.

### 6.3 Vì sao không nên chỉ đếm IP?

- Botnet có thể phân tán traffic qua hàng nghìn IP.
- Một IP có thể đại diện cho nhiều người dùng sau NAT.
- Reverse proxy/CDN có thể làm log origin ghi IP của proxy nếu không cấu hình forwarded client IP an toàn.
- Source IP có thể bị spoof trong một số dạng network attack.
- IP reputation có thể lỗi thời hoặc tạo false positive.

Do đó nên phân tích cả rate, URI, method, request pattern, ASN/geo (nếu được phép), session, latency và backend metrics.

## 7. SIEM-Based Detection

SIEM giúp tập trung log từ web server, WAF, CDN, firewall và hệ thống backend để phát hiện pattern theo thời gian.

### Các analytic/use case có thể xây dựng
- RPS theo source IP vượt baseline.
- Nhiều source cùng truy cập một URI với pattern tương tự.
- 5xx/429 tăng mạnh trong một cửa sổ thời gian.
- Một endpoint có response time hoặc request rate bất thường.
- Số lượng concurrent connections tăng nhanh.
- WAF block/challenge events tăng đột biến.
- Origin CPU/memory tăng đồng thời với HTTP request volume.

### Ví dụ truy vấn Splunk (mẫu cần điều chỉnh field/index)

**Đếm request theo IP trong khoảng thời gian:**
```spl
index=web sourcetype=access_combined
| bin _time span=1m
| stats count as requests by _time clientip
| sort - requests
```

**Tìm endpoint có nhiều request:**
```spl
index=web sourcetype=access_combined
| stats count as requests by uri_path, http_method
| sort - requests
```

**Theo dõi tỷ lệ status code 5xx:**
```spl
index=web sourcetype=access_combined
| bin _time span=1m
| stats count as total
        count(eval(status>=500 AND status<600)) as errors_5xx
  by _time
| eval error_rate=round(errors_5xx/total*100,2)
```

**Lưu ý khi dùng SPL:**
- `index`, `sourcetype`, `clientip`, `uri_path`, `http_method` và `status` là field mẫu; cần thay theo dữ liệu thực tế.
- Nên có time range và baseline rõ ràng.
- Cần loại trừ health checks, monitoring systems, crawler hoặc batch jobs hợp lệ.
- Một truy vấn có kết quả lớn chưa đủ chứng minh DDoS; cần correlation với service health và network metrics.

## 8. Defense and Mitigation

### 8.1 CDN và DDoS protection provider
- Đặt CDN/reverse proxy trước origin.
- Sử dụng dịch vụ DDoS mitigation có năng lực lọc traffic ở edge.
- Giới hạn origin chỉ chấp nhận traffic từ CDN/proxy được phép.
- Chuẩn bị quy trình phối hợp ISP/cloud provider khi attack vượt khả năng xử lý tại chỗ.

### 8.2 WAF và rate limiting
- Dùng managed rules để phát hiện các pattern tấn công đã biết.
- Rate-limit các endpoint nhạy cảm hoặc tốn tài nguyên.
- Challenge traffic đáng ngờ khi việc block có nguy cơ ảnh hưởng người dùng hợp pháp.
- Tách chính sách theo URI, method, identity/session và risk score.
- Điều chỉnh rule dựa trên telemetry và false-positive rate.

### 8.3 Application resilience
- Cache nội dung tĩnh và response phù hợp.
- Hạn chế query tốn tài nguyên và đặt timeout.
- Dùng queue, concurrency limits và circuit breakers cho dependency.
- Tối ưu database connection pool.
- Thiết kế graceful degradation khi backend bị quá tải.
- Autoscaling có thể hỗ trợ nhưng không thay thế DDoS filtering; autoscale không giới hạn có thể làm chi phí tăng mạnh.

### 8.4 Network/Host controls
- Lọc traffic ở upstream/network edge.
- Dùng SYN cookies hoặc cơ chế bảo vệ TCP phù hợp khi cần.
- Tối ưu connection/backlog limits theo capacity và môi trường.
- Theo dõi CPU, memory, file descriptors và network saturation.
- Không block diện rộng chỉ dựa trên geo/IP nếu chưa hiểu tác động business.

## 9. Incident Response Workflow cho DDoS

### Bước 1 – Detect và xác nhận
- Xác định dịch vụ bị ảnh hưởng.
- Ghi nhận start time, peak time và trạng thái hiện tại.
- So sánh traffic với baseline.
- Xác minh người dùng hợp pháp có bị ảnh hưởng không.

### Bước 2 – Classify
- Network-layer hay application-layer?
- Một nguồn hay nhiều nguồn?
- Protocol/port/URI nào bị nhắm?
- Bandwidth saturation hay application resource exhaustion?

### Bước 3 – Scope and impact
- Các hostname/API/region bị ảnh hưởng.
- RPS, bandwidth, PPS, concurrency và error rate.
- CPU, memory, database và upstream dependency.
- Khả năng ảnh hưởng sang dịch vụ khác.

### Bước 4 – Mitigate
- Phối hợp CDN/WAF/DDoS provider hoặc ISP.
- Áp dụng rate limit/challenge/block rule theo bằng chứng.
- Cache và giảm tải origin nếu phù hợp.
- Điều chỉnh capacity và bảo vệ backend.
- Thông báo các bộ phận business/communications theo incident plan.

### Bước 5 – Monitor
- Theo dõi traffic đã giảm hay chưa.
- Kiểm tra người dùng hợp pháp có truy cập được không.
- Theo dõi false positives và tác động của rule.
- Tiếp tục quan sát các endpoint/asset khác để phát hiện diversion attack.

### Bước 6 – Post-incident
- Lưu log, metrics, WAF events và PCAP nếu có.
- Ghi lại timeline, attack pattern và mitigation đã áp dụng.
- Xác định điểm nghẽn và cải thiện runbook/capacity.
- Cập nhật detection threshold theo baseline mới.

## 10. Mẫu báo cáo DDoS

```text
Incident ID:
Affected service / hostname:
Start time and timezone:
End time / current status:
Attack category (L3/L4/L7):
Target IP / port / URI:
Observed source distribution:
Peak bandwidth / PPS / RPS:
Concurrent connections:
HTTP status / latency / error trends:
Host and application resource impact:
CDN/WAF/ISP observations:
Mitigation actions:
Impact on legitimate users:
Evidence and log sources:
Current assessment:
Follow-up actions:
```

## 11. Lỗi thường gặp khi phân tích DDoS

- Gọi mọi traffic spike là DDoS mà không kiểm tra flash crowd hoặc deployment.
- Chỉ nhìn số lượng IP và bỏ qua request rate/URI/backend metrics.
- Block IP ngay lập tức mà không xác định proxy, NAT hoặc shared infrastructure.
- Chỉ tăng server capacity mà không xử lý traffic độc hại.
- Dùng rule WAF quá rộng gây chặn người dùng hợp pháp.
- Không ghi lại thời điểm, baseline và hiệu quả của từng biện pháp mitigation.
- Bỏ qua khả năng DDoS được dùng làm distraction cho intrusion khác.

## 12. Kỹ năng đạt được

- Phân biệt DoS và DDoS, network-layer và application-layer attacks.
- Hiểu các động cơ thường gặp phía sau DDoS.
- Phân tích access logs, request rates, URI patterns, status codes và latency.
- Sử dụng SIEM để tổng hợp và phát hiện traffic spike.
- Tương quan web logs với network/server/application metrics.
- Hiểu vai trò của CDN, WAF, rate limiting và DDoS mitigation provider.
- Trình bày được quy trình triage, mitigation và post-incident review.

## Tài liệu tham khảo

- [TryHackMe – Detecting Web DDoS](https://tryhackme.com/room/detectingwebddos)
- [MITRE ATT&CK – T1499 Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/)
- [MITRE ATT&CK – T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498/)
- [Cloudflare – Application Layer DDoS Attack](https://www.cloudflare.com/learning/ddos/application-layer-ddos-attack/)
- [Cloudflare – DDoS Protection Documentation](https://developers.cloudflare.com/learning-paths/application-security/default-traffic-security/ddos/)
- [CISA – Understanding and Responding to DDoS Attacks](https://www.cisa.gov/sites/default/files/publications/understanding-and-responding-to-ddos-attacks_508c.pdf)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
