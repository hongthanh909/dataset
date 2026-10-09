# Dataset cho CodeBERT: 6 nhóm lỗ hổng

## Phần đang làm

- `active/six-groups-v2/`: dữ liệu ứng viên, bằng chứng, review và báo cáo mới.
- `config/`: cấu hình nhóm và CWE.
- `scripts/`: công cụ thu thập, xác thực, xử lý và kiểm tra.
- `tests/`: kiểm thử các công cụ.
- `WORKING_SIX_GROUPS.md`: tiến độ và quy trình chi tiết.

Nhóm 6 là `HARDCODED_CREDENTIALS`, hiện đang bổ sung và xác thực mẫu.
Các mẫu trong `review/` chưa tự động được phép dùng để train.
Chưa có bộ dataset mới được duyệt hoàn chỉnh hoặc lần train mới.

## Kiểm tra nhanh

Chạy trong thư mục này:

```powershell
python -m unittest discover -s tests -v
python scripts/check_six_group_readiness.py
```

Kiểm tra readiness trả về mã 2 khi còn thiếu điều kiện; đây không phải lệnh train.

## Thành viên mới clone repository

```powershell
git clone https://github.com/hongthanh909/dataset.git
cd dataset
python -m unittest discover -s tests -v
python scripts/check_six_group_readiness.py
```

Bản public chia sẻ **mã, cấu hình và hướng dẫn**, chưa chứa dataset train hoặc
checkpoint. Trên máy mới, readiness sẽ báo `HOLD_LOCAL_BASELINE_NOT_AVAILABLE`
thay vì kết luận đủ điều kiện train. Thư mục archive chỉ có trên máy đang làm.
Các helper `prepare_six_group_workspace`, `build_hardcoded_review_queue`,
`prime_hardcoded_source_cache` cần dữ liệu lịch sử local để đối chiếu.

Có thể tìm ứng viên nhóm 6 độc lập ngay sau khi clone:

```powershell
python scripts/collect_python_advisories.py --cwe-file config/hardcoded_discovery_allowlist.csv --output-dir active/six-groups-v2/discovery/github
```

Đây chỉ là tìm ứng viên, không xác nhận mẫu train. Collector dùng `GITHUB_TOKEN`
từ môi trường nếu có; không ghi token vào file hoặc commit.

Để dùng tokenizer, tạo môi trường riêng và cài các dependency:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-curation.txt
.\.venv\Scripts\python.exe -c "from transformers import AutoTokenizer; AutoTokenizer.from_pretrained('microsoft/codebert-base')"
```

Collection và unit tests không cần PyTorch. Full-context retrieval dùng
`curl.exe` trên Windows. Repo hiện chưa cung cấp lệnh huấn luyện model;
dependency trên chỉ phục vụ tokenizer/curation, không phải môi trường train.

Quy trình nhóm: tạo branch cá nhân → tìm và kiểm tra mẫu → review thay đổi
→ cập nhật phiên bản dataset được duyệt → train và ghi kết quả. Không dùng
tập test để điều chỉnh mô hình. Mã nguồn mẫu phải có provenance, giấy phép
và attribution trước khi phát hành. Chưa gán giấy phép mới cho mã dự án.

## Phần cũ đã gom lại

- `archive/legacy-data/`: toàn bộ dữ liệu, cache và bằng chứng cũ.
- `archive/legacy-runners/`: 10 file PowerShell chạy quy trình cũ.
- `archive/legacy-readme.md`: hướng dẫn cũ, giữ nguyên nội dung.
- `archive/phase5c-v1/`: snapshot dataset nền được kiểm tra SHA-256.

Không có dữ liệu bị xóa vĩnh viễn. Các helper đang dùng đã được cập nhật
để đọc dữ liệu lịch sử từ vị trí mới. Snapshot vẫn giữ nguyên manifest gốc.
Đường dẫn tuyệt đối trong báo cáo cũ là thông tin lịch sử, không phải đường dẫn
hiện tại. Các runner lưu trữ không phải lệnh chạy cho workspace mới; cần sửa
đường dẫn trước nếu muốn tái chạy quy trình cũ.

Khi dùng các script thu thập gốc, truyền rõ các tham số input/output vào
`active/six-groups-v2/`; không dùng mặc định `data/` của quy trình cũ.

Việc dọn thư mục không bổ sung mẫu được duyệt, không thay đổi nhãn và không train.
Repository public chỉ chứa các file được chọn để chia sẻ. `.gitignore` giữ
`archive/`, kết quả ứng viên, cache và checkpoint ngoài Git. Việc push mã
không đồng nghĩa đã phát hành dataset hoặc đã train model sáu nhóm.
