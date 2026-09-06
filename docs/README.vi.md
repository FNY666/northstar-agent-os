# Northstar Agent OS

**Các thành phần runtime mở, đáng tin cậy và có quản trị cho đồng nghiệp AI tự chủ.**

[English](../README.md) · [简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · [日本語](README.ja.md) · [Español](README.es.md) · [한국어](README.ko.md) · [Français](README.fr.md) · [Deutsch](README.de.md) · [Português (Brasil)](README.pt-BR.md) · [Italiano](README.it.md) · [Türkçe](README.tr.md) · [Tiếng Việt](README.vi.md)

**Tóm tắt trong một câu:** Northstar là dự án được duy trì độc lập để xây dựng các đồng nghiệp AI có quản trị bằng định tuyến mô hình rõ ràng, ranh giới công cụ cục bộ, khả năng kiểm toán và thực thi có thể khôi phục. **Thành phần được phát hành hôm nay là Northstar Codex Sidecar, một bộ điều hợp worker cục bộ bị giới hạn — không phải nền tảng agent tự chủ hoàn chỉnh.**

> English is the canonical project entry. Translations mirror its scope and security claims; update them when the canonical README changes.

## Đây là gì?

Northstar là dự án runtime theo thành phần dành cho các nhà phát triển muốn đồng nghiệp AI hoạt động trong những ranh giới có thể nhìn thấy, thay vì một vòng lặp prompt và công cụ không bị giới hạn. Dự án tập trung vào các khối nhỏ, có thể kiểm thử: hợp đồng hiển thị cho bên gọi, thực thi bị giới hạn, kết quả có cấu trúc và khả năng khôi phục vận hành.

Dự án được xây dựng từng bước. Một thành phần có thể hữu ích độc lập, nhưng việc các bài kiểm thử của thành phần đó vượt qua không chứng minh nền tảng agent hoàn chỉnh an toàn hoặc sẵn sàng cho production.

## Hiện đang phát hành gì?

- `../components/northstar-codex-sidecar/` — dịch vụ Unix socket cục bộ xác thực request, chạy Codex ở chế độ read-only, giới hạn input và output, che lỗi, dọn dẹp nhóm tiến trình hết timeout và trả về trạng thái có cấu trúc.
- `../components/northstar-run-contract/` — hợp đồng Run Request/Receipt có phiên bản, Run Binding HMAC có thời hạn và ranh giới adapter nghiêm ngặt để chuyển một lượt chạy đã xác minh cho Sidecar.
- `../components/northstar-agent-runtime/` — vòng lặp agent được kiểm soát: luồng sự kiện, mười hook vòng đời, cổng phân quyền ba lớp, các giới hạn độc lập về số lượt / số lời gọi công cụ / USD, agent con, phiên chỉ ghi thêm, nén chỉ tại ranh giới an toàn và theo dõi theo span. Thành phần này không giữ thông tin đăng nhập mô hình và không khởi chạy CLI mô hình: việc chạy Codex được ủy quyền cho Sidecar qua Unix socket.
- Bộ kiểm thử xác định, mẫu hardening cho systemd, script cài đặt thận trọng và script rollback.

## Sidecar hoạt động như thế nào?

Mỗi kết nối Unix socket nhận một request JSON:

```json
{"request_id":"demo-1","prompt":"Reply with OK","timeout_ms":10000}
```

Response là một đối tượng JSON có giới hạn:

```json
{"request_id":"demo-1","status":"ok","text":"OK"}
```

Các thuộc tính quan trọng:

- Chỉ dùng Unix socket; không có TCP listener.
- Allowlist request nghiêm ngặt: `request_id`, `prompt`, `timeout_ms`.
- Giới hạn prompt và timeout.
- Codex chạy với `--sandbox read-only` và `--ephemeral`.
- Nhóm tiến trình riêng, được dọn bằng TERM rồi KILL khi timeout.
- Read deadline cho từng kết nối và worker pool có giới hạn.
- Phân loại lỗi có cấu trúc và redaction bí mật.
- Service user riêng và mẫu systemd hardening.
- Codex bị tắt cho đến khi quản trị viên cài đặt và bật dịch vụ một cách rõ ràng.

## Bắt đầu nhanh

Yêu cầu: Linux, Python 3.10 trở lên, executable `codex` được cài riêng và service user có thể sử dụng, systemd, cùng service user/workspace riêng không có đặc quyền.

```sh
cd components/northstar-codex-sidecar
python3 -m py_compile sidecar.py transport.py service.py sidecar_socket.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
sh -n install.sh rollback.sh
```

Hãy xem xét các script và service account trước khi bật vòng đời thận trọng:

```sh
sudo ./install.sh
sudo systemctl enable --now northstar-codex-sidecar.service
```

Executable Codex mặc định được tìm trong `PATH`; đặt `CODEX_BIN` nếu dùng đường dẫn không chuẩn.

## Dành cho ai?

Northstar dành cho nhà phát triển và vận hành viên xây dựng runtime đồng nghiệp AI cục bộ hoặc self-hosted, cần một thành phần thực thi hẹp có thể kiểm thử, kiểm toán, tắt và rollback. Đây không phải sản phẩm AI hosted, bảo đảm an toàn tự động hay sự thay thế cho kiến trúc identity, policy, workspace và observability đầy đủ.

## Đây không phải là gì?

- Chưa phải hệ điều hành multi-agent hoàn chỉnh.
- Không phải dịch vụ hosted hay lời hứa sẵn sàng production.
- Không phải API thực thi shell tổng quát.
- Không tự ủy quyền cho caller, cô lập mọi run hay truyền cancellation từ parent.
- Không chứa thông tin xác thực Codex và không cung cấp tài khoản Codex.

**Not a complete autonomous-agent platform.**

## Quan hệ với OpenBot

Northstar là dự án độc lập hướng tới các tích hợp tương thích OpenBot. Dự án không liên kết hoặc được OpenBot, CopilotKit hay maintainer của họ xác nhận. Sidecar được thiết kế để tích hợp với runtime kiểu OpenBot nhưng không tuyên bố là một phần của repository OpenBot upstream.

Tương thích là mục tiêu tích hợp, không phải quyền sở hữu, bảo trợ hay tương đương về bảo mật.

## Ranh giới bảo mật

Sidecar chỉ xác thực caller bằng quyền Unix. Tích hợp production còn phải cung cấp authorization và identity binding của caller, cô lập workspace theo run hoặc actor, truyền cancellation từ parent, observability không ghi prompt nhạy cảm, health check và rollback, kiểm thử concurrency/process tree trên Linux native, cùng việc xem xét cấu hình tài khoản, network và tool của Codex.

Không expose Unix socket qua TCP proxy. Không commit API key, OAuth token, Codex login state, private key, file `.env` production hay transcript người dùng.

## Trạng thái dự án

Đây là thành phần Northstar công khai đầu tiên. Runtime Northstar Agent OS rộng hơn đang được xây dựng từng bước. Identity binding runtime, authorization workspace theo run, truyền cancellation, kiểm thử end-to-end trên Linux native và tích hợp triển khai production vẫn là trách nhiệm của host hoặc công việc tương lai. **Repository này không phải nền tảng agent tự chủ hoàn chỉnh.**

Việc dọn nhóm tiến trình phải được xác nhận trên bản phân phối Linux native mục tiêu; hành vi signal và thu hồi PID trên Linux di động có thể không đại diện.

## Đóng góp và bảo trì

Xem [CONTRIBUTING.md](../CONTRIBUTING.md) về yêu cầu bằng chứng, kiểm thử, bảo mật, tương thích và rollback. Xem [SECURITY.md](../SECURITY.md) để báo cáo bảo mật. English is the canonical source for project scope; translations should be updated when it changes.

## Giấy phép

MIT. Xem [LICENSE](../LICENSE).
