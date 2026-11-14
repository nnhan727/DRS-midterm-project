import math

from binio import AnhDia
from tienich import NhatKy, ThuMucKetQua
from volume_info import FAT32Reader


class CorrectedFAT32Reader(FAT32Reader):
    """FAT32Reader với các tham số Boot Sector đã được suy luận và sửa đúng."""

    def __init__(self, img: AnhDia, log: NhatKy, sec_per_clus: int, rsvd_sec_cnt: int, fat_sz: int):
        self.img = img
        self.log = log

        # Đọc các thông số nguyên vẹn từ Boot Sector
        self.byte_per_sec = img.u16(0x0B)
        self.num_fats = img.u8(0x10)
        self.root_clus = img.u32(0x2C)

        # Tham số đã được sửa đúng
        self.sec_per_clus = sec_per_clus
        self.rsvd_sec_cnt = rsvd_sec_cnt
        self.fat_sz = fat_sz

        # Tính toán lại kích thước cluster và các offset vùng đĩa
        self.clus_size = self.byte_per_sec * self.sec_per_clus
        self.fat_off = self.rsvd_sec_cnt * self.byte_per_sec
        self.data_off = (self.rsvd_sec_cnt + self.num_fats * self.fat_sz) * self.byte_per_sec

        self.log.buoc("Khởi tạo reader với tham số đã sửa", gia_tri={
            "byte_per_sec": self.byte_per_sec,
            "sec_per_clus": self.sec_per_clus,
            "rsvd_sec_cnt": self.rsvd_sec_cnt,
            "fat_sz": self.fat_sz,
            "clus_size": self.clus_size,
            "fat_off": hex(self.fat_off),
            "data_off": hex(self.data_off),
        })


class Case1Recoverer:
    """Khôi phục dữ liệu FAT32 bị sai tham số Boot Sector (SecPerClus, RsvdSecCnt, FATSz32)."""

    def __init__(self, img: AnhDia, log: NhatKy):
        self.img = img
        self.log = log

        # Đọc các tham số cơ sở còn nguyên vẹn từ Boot Sector
        self.byte_per_sec = img.u16(0x0B)
        if self.byte_per_sec not in (512, 1024, 2048, 4096):
            self.byte_per_sec = 512

        self.num_fats = img.u8(0x10)
        if self.num_fats not in (1, 2):
            self.num_fats = 2

        self.media = img.u8(0x15)
        if self.media == 0:
            self.media = 0xF8

        self.root_clus = img.u32(0x2C)
        if self.root_clus < 2:
            self.root_clus = 2

        self.tot_sec = img.u32(0x20)
        if self.tot_sec == 0:
            self.tot_sec = img.kich_thuoc // self.byte_per_sec

        # Ghi nhận các giá trị sai ban đầu
        sai_spc = img.u8(0x0D)
        sai_rsvd = img.u16(0x0E)
        sai_fatsz = img.u32(0x24)

        self.log.canh_bao("Phát hiện tham số Boot Sector bị hỏng (Tình huống 1)", gia_tri={
            "BPB_SecPerClus": sai_spc,
            "BPB_RsvdSecCnt": sai_rsvd,
            "BPB_FATSz32": sai_fatsz,
        })

    def _is_fat_header(self, data: bytes) -> bool:
        # Kiểm tra chữ ký 8 byte đầu của bảng FAT32 (FAT[0] và FAT[1])
        if len(data) < 8:
            return False
        if data[1:3] != b"\xFF\xFF" or (data[3] & 0x0F) != 0x0F:
            return False
        if data[4:7] != b"\xFF\xFF\xFF" or (data[7] & 0x0F) != 0x0F:
            return False
        return True

    def _find_rsvd_sec_cnt(self) -> int:
        # Quét tìm sector đầu tiên của FAT1 (ngay sau vùng Reserved)
        gioi_han = min(65536, self.tot_sec)
        for s in range(1, gioi_han):
            off = s * self.byte_per_sec
            if off + 8 > self.img.kich_thuoc:
                break
            if self._is_fat_header(self.img.doc(off, 8)):
                self.log.quyet_dinh(
                    f"Xác định BPB_RsvdSecCnt = {s} dựa trên chữ ký FAT1 tại sector {s}",
                    rsvd_sec_cnt=s,
                    offset=off,
                )
                return s

        self.log.canh_bao("Không dò thấy chữ ký FAT1, sử dụng mặc định 32")
        return 32

    def _find_fat_sz(self, rsvd_sec_cnt: int) -> int:
        # Tìm khoảng cách giữa FAT1 và FAT2 (FAT2 là bản sao của FAT1)
        fat1_sec = rsvd_sec_cnt
        fat1_sec0 = self.img.doc(fat1_sec * self.byte_per_sec, self.byte_per_sec)

        for s in range(fat1_sec + 1, self.tot_sec):
            off = s * self.byte_per_sec
            if off + self.byte_per_sec > self.img.kich_thuoc:
                break
            # So sánh nhanh 8 byte đầu rồi so sánh toàn bộ sector
            if self.img.doc(off, 8) == fat1_sec0[:8]:
                if self.img.doc(off, self.byte_per_sec) == fat1_sec0:
                    fat_sz = s - fat1_sec
                    self.log.quyet_dinh(
                        f"Xác định BPB_FATSz32 = {fat_sz} dựa trên khoảng cách giữa FAT1 và FAT2",
                        fat_sz=fat_sz,
                        fat1_sec=fat1_sec,
                        fat2_sec=s,
                    )
                    return fat_sz

        # Dự phòng: dò vị trí thư mục gốc (Root Dir nằm ngay sau các bảng FAT)
        data_entry_pattern = b"DATA       \x10"
        pos = self.img.tim(data_entry_pattern, bat_dau=fat1_sec * self.byte_per_sec)
        if pos != -1:
            root_dir_sec = (pos - (pos % self.byte_per_sec)) // self.byte_per_sec
            fat_sz = (root_dir_sec - fat1_sec) // self.num_fats
            self.log.quyet_dinh(
                f"Xác định BPB_FATSz32 = {fat_sz} dựa trên vị trí thư mục gốc tại sector {root_dir_sec}",
                fat_sz=fat_sz,
            )
            return fat_sz

        raise ValueError("Không thể suy luận BPB_FATSz32 từ ảnh đĩa")

    def _find_sec_per_clus(self, rsvd_sec_cnt: int, fat_sz: int) -> int:
        # Vị trí Root Directory (cluster 2) tại data_off không phụ thuộc vào SecPerClus
        data_off = (rsvd_sec_cnt + self.num_fats * fat_sz) * self.byte_per_sec
        root_data = self.img.doc(data_off, min(self.byte_per_sec * 8, self.img.kich_thuoc - data_off))

        # Tìm cluster bắt đầu của thư mục con DATA trong Root Directory
        subdir_clus = None
        for i in range(0, len(root_data), 32):
            entry = root_data[i:i + 32]
            if entry[0] == 0x00:
                break
            if entry[0] == 0xE5 or entry[0x0B] == 0x0F:
                continue
            if entry[0x0B] & 0x10:
                clus = (int.from_bytes(entry[0x14:0x16], "little") << 16) | int.from_bytes(entry[0x1A:0x1C], "little")
                if clus >= 2:
                    subdir_clus = clus
                    break

        candidates = [1, 2, 4, 8, 16, 32, 64, 128]

        # Thư mục con luôn bắt đầu bằng 2 entry '.' và '..'
        if subdir_clus is not None:
            for s in candidates:
                cs = s * self.byte_per_sec
                target_off = data_off + (subdir_clus - 2) * cs
                if target_off + 64 <= self.img.kich_thuoc:
                    d1 = self.img.doc(target_off, 12)
                    d2 = self.img.doc(target_off + 32, 12)
                    if d1 == b".          \x10" and d2 == b"..         \x10":
                        self.log.quyet_dinh(
                            f"Xác định BPB_SecPerClus = {s} (cluster size = {cs} B) qua entry '.' và '..'",
                            sec_per_clus=s,
                            cluster_size=cs,
                        )
                        return s

        # Dự phòng: dò chữ ký file (JPEG, PNG, PDF) ở các cluster đầu
        for s in candidates:
            cs = s * self.byte_per_sec
            for test_clus in range(3, min(20, (self.img.kich_thuoc - data_off) // cs + 2)):
                off = data_off + (test_clus - 2) * cs
                if off + 8 <= self.img.kich_thuoc:
                    head = self.img.doc(off, 8)
                    if head[:3] == b"\xFF\xD8\xFF" or head[:4] == b"\x89PNG" or head[:4] == b"%PDF":
                        self.log.quyet_dinh(
                            f"Xác định BPB_SecPerClus = {s} dựa trên chữ ký file tại cluster {test_clus}",
                            sec_per_clus=s,
                            cluster_size=cs,
                        )
                        return s

        self.log.canh_bao("Không dò thấy qua thư mục, chọn mặc định SecPerClus = 8")
        return 8

    def recover(self, out: ThuMucKetQua):
        """Suy luận tham số và trích xuất mọi tập tin."""
        rsvd_sec_cnt = self._find_rsvd_sec_cnt()
        fat_sz = self._find_fat_sz(rsvd_sec_cnt)
        sec_per_clus = self._find_sec_per_clus(rsvd_sec_cnt, fat_sz)

        self.log.quyet_dinh(
            "Đã khôi phục các tham số Boot Sector",
            BPB_SecPerClus=sec_per_clus,
            BPB_RsvdSecCnt=rsvd_sec_cnt,
            BPB_FATSz32=fat_sz,
        )

        reader = CorrectedFAT32Reader(self.img, self.log, sec_per_clus, rsvd_sec_cnt, fat_sz)

        count = 0
        for entry in reader.walk(reader.root_clus):
            if entry["is_dir"]:
                continue

            path = entry["path"]
            size = entry["size"]
            first_clus = entry["first_clus"]

            # Lấy danh sách cluster từ bảng FAT
            clus_chain = reader.chain(first_clus)
            needed_clus = math.ceil(size / reader.clus_size) if size > 0 else 0

            # Nếu chuỗi FAT bị thiếu cluster, coi như cấp phát liên tục
            if len(clus_chain) < needed_clus:
                clus_chain = list(range(first_clus, first_clus + needed_clus))

            file_data = b"".join(
                self.img.doc(reader.data_off + (c - 2) * reader.clus_size, reader.clus_size)
                for c in clus_chain
            )[:size]

            out.luu(path, file_data)
            self.log.buoc("Đã trích xuất tập tin", gia_tri={"path": path, "size": len(file_data)})
            count += 1

        self.log.quyet_dinh(f"Hoàn tất Case 1: Đã lưu {count} tập tin.")
