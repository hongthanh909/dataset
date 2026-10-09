# Workspace local cho phiên bản dataset tiếp theo

Tạo các thư mục `discovery`, `evidence`, `review`, `dataset`, `training`, `reports`
khi cần. Nội dung sinh ra được bỏ qua bởi Git để tránh vô tình công khai
mã nguồn bên thứ ba, secret trong mẫu, cache hoặc dữ liệu chưa duyệt.

Dataset sáu nhóm mới chưa được phát hành. Chỉ đưa mẫu vào bộ train sau khi
xác thực cơ chế lỗi, nhãn, ngữ cảnh, nguồn, bản sửa, giấy phép và chống rò rỉ split.

Khi nhóm quyết định phát hành dataset đã duyệt, dùng thư mục release riêng,
có manifest và thông tin giấy phép; không dùng `git add -f` để bỏ qua kiểm soát.
