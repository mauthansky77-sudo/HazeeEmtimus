# Hazee Key 1.0

Ứng dụng Android riêng để nhập và kiểm tra key trên https://hazee-key-trial.onrender.com.

- Package: `vn.hazee.keycheck`. Android 6.0 trở lên (API 23).
- Quyền duy nhất: Internet. Kết nối HTTPS với kiểm tra chứng thư mặc định.
- Không nhúng mã quản trị. Không lưu key đã nhập. Chỉ lưu UUID cài đặt ngẫu nhiên.
- Gửi JSON `key` và `device_id` đến `/api/v1/licenses/verify`.
- Thành công hiển thị ngày hết hạn. Báo riêng lỗi giới hạn thiết bị, key không hợp lệ, lỗi mạng và quá nhiều yêu cầu.
- Chỉ kết luận key hợp lệ khi máy chủ trả HTTP 200 và `valid: true`. Không lưu kết quả hợp lệ để dùng ngoại tuyến.
- Key hợp lệ sẽ ghi nhận UUID hiện tại vào danh sách thiết bị. Gỡ/cài lại hoặc xóa dữ liệu tạo UUID mới và có thể chiếm thêm một thiết bị.
- Render Free có thể cần khoảng một phút để thức dậy; dữ liệu key có thể mất khi dịch vụ khởi động lại/ngủ/triển khai lại.

## Cách sử dụng

1. Trong trang quản trị backend, tạo key với số ngày và giới hạn thiết bị mong muốn.
2. Cài APK Hazee Key trên điện thoại, mở ứng dụng và dán key.
3. Bấm **Kiểm tra key**. Key đã thu hồi hoặc hết hạn sẽ không được xác nhận ở lần kiểm tra tiếp theo.

Ứng dụng này chưa mở menu NTJR, không chứa game và không thay đổi APK NTJR.

## Biên dịch

Cần Python 3, JDK trong PATH, Android SDK build-tools 36.0.0 và platform android-37.0. Đặt `ANDROID_HOME` nếu SDK không ở vị trí mặc định Windows. Chạy `python build.py`.

APK được tạo tại `build/Hazee-Key-1.0.apk`. Khóa ký và mật khẩu nằm trong `.signing/`, được loại khỏi Git. Giữ nguyên khóa ký này để phát hành bản cập nhật cài đè. Không đưa `.signing/` lên GitHub.
