"""PHẦN LÀM BÀI CỦA NHÓM.

Quy tắc:
  * Tự giải mã mọi cấu trúc từ byte (dùng binio.AnhDia). Cấm thư viện phân tích hệ thống tập tin
    (pytsk3, dfvfs, pyfatfs, libntfs, libext2fs...) và cấm gọi công cụ ngoài (subprocess, os.system).
  * Không cố định offset / số cluster / giá trị của ảnh nhóm: chương trình sẽ chạy trên ảnh ẩn.
  * Không ghi lên ảnh đầu vào; muốn sửa thì img.sao_chep(...).
  * Ghi nhật ký mọi bước quan trọng: self.log.buoc(...), self.log.quyet_dinh(...).
  * Có thể tách mã ra nhiều tệp (vd. ntfs.py, runlist.py) và import vào đây.
"""
from binio import AnhDia
from tienich import NhatKy, ThuMucKetQua
from volume_info import FAT32Reader


class BaiLam:
    def __init__(self, log: NhatKy):
        self.log = log

    # ------------------------------------------------------------------ --info
    def info(self, img: AnhDia) -> dict:
        """Đọc ảnh NGUYÊN VẸN, trả về dict:
            {"fs": "fat32|exfat|ntfs|ext4",
             "cluster_size": 4096,                # kích thước cluster/block (byte)
             ...                                  # các tham số khác tuỳ hệ thống (không chấm)
             "files": [{"path": "DATA/A12.JPG", "size": 123456}, ...]}   # chỉ tập tin, không thư mục
        """
        reader = FAT32Reader(img, self.log)
        return reader.get_volume_info()

    # ------------------------------------------------------------- tình huống
    def case1(self, img, out):
        """Tình huống 1 — sai tham số boot sector / superblock.
        Suy ra giá trị đúng, rồi trích xuất MỌI tập tin: out.luu("DATA/A12.JPG", data)."""
        raise NotImplementedError("case1")

    def case2(self, img, out):
        """Tình huống 2 — sai directory entry. Ghép đúng tên với dữ liệu, lưu các tập tin bị ảnh hưởng
        (lưu thêm cả tập tin không bị ảnh hưởng cũng được)."""
        raise NotImplementedError("case2")

    def case3(self, img: AnhDia, out: ThuMucKetQua):
        """Tình huống 3 — sai chuỗi vị trí. Ghép mảnh theo nội dung, lưu tập tin JPEG mục tiêu."""
        # raise NotImplementedError("case3")
        
        # read BPB
        byte_per_sec = img.u16(0x0b)
        sec_per_clus = img.u8(0x0d)
        rsvd_sec_cnt = img.u16(0x0e)
        num_fats = img.u8(0x10)
        fat_sz = img.u32(0x24)
        root_clus = img.u32(0x2c)

        byte_per_clus = byte_per_sec * sec_per_clus
        fat_offset = rsvd_sec_cnt * byte_per_sec
        

    def case_ext(self, img, out):
        """Tình huống mở rộng nhóm đã chọn (khai trong nhom.json)."""
        raise NotImplementedError("case_ext")

    # --------------------------------------------------------------- cộng điểm
    def repair(self, img, case, anh_moi):
        """--repair: sửa trên BẢN SAO và ghi ra anh_moi.
            ban_sua = img.sao_chep(anh_moi)
            ban_sua.ghi_u16(..., ...)
            ban_sua.dong()
        """
        raise NotImplementedError("repair")

    def corrupt(self, img, dac_ta, anh_hong):
        """--corrupt: từ ảnh sạch, tạo ảnh hỏng theo đặc tả JSON của nhóm.
        Trả về danh sách vùng đã sửa (giảng viên đối chiếu tự động):
            [{"offset": 1234, "length": 4, "cau_truc": "BPB_RootClus (sector 0)"}, ...]
        Mọi byte thay đổi phải nằm trong các vùng này và không được chạm vùng dữ liệu tập tin."""
        raise NotImplementedError("corrupt")
