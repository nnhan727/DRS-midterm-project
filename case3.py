import math

from binio import AnhDia
from tienich import NhatKy, ThuMucKetQua
from volume_info import FAT32Reader

MAX_GAP_CLUS = 64                 # mảnh 2 nằm trong vòng 64 cluster sau mảnh 1
JPEG_EXTENSIONS = (".jpg", ".jpeg")
JPEG_SOI = b"\xFF\xD8"
JPEG_EOI = b"\xFF\xD9"


def _is_valid_jpeg(jpeg_data):
    data_len = len(jpeg_data)

    # File JPEG phải bắt đầu bằng SOI (FF D8)
    if jpeg_data[:2] != JPEG_SOI:
        return False

    pos = 2
    # đọc các marker tiếp theo
    while pos < data_len:
        # marker bắt đầu bằng 0xFF, nếu ở đây không phải FF thì cấu trúc bị lệch
        if jpeg_data[pos] != 0xFF:
            return False
        # byte đệm FF, nhảy 1 byte để FF sau xét tiếp
        while pos < data_len and jpeg_data[pos] == 0xFF:
            pos += 1
        if pos >= data_len:
            return False
        marker = jpeg_data[pos]     # mã marker (DB, C0, DA, D9, ...)
        pos += 1

        # EOI phải là byte cuối cùng
        if marker == 0xD9:
            return pos == data_len
        # marker không có độ dài hay payload (standalone marker), chỉ cần đi tiếp sang marker kế
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        # marker SOI nằm ở giữa file, sai cấu trúc
        if marker == 0xD8:
            return False
        # FF 00 là 1 loại byte stuffing để báo cho trình đọc ảnh biết rằng byte 0xFF đó là dữ liệu điểm ảnh bình thường, nếu xuất hiện ở ngoài vùng dữ liệu ảnh nén (entropy) nghĩa là dữ liệu JPEG bị sai cấu trúc
        if marker == 0x00:
            return False

        # các marker còn lại có 2 byte độ dài payload ngay sau mã marker nên phải còn đủ 2 byte để đọc
        if pos + 2 > data_len:
            return False
        # 2 byte khai báo độ dài payload sau marker
        seg_len = int.from_bytes(jpeg_data[pos:pos + 2], "big")
        # độ dài payload sau marker có tính cả 2 byte khai báo độ dài, nên tối thiểu là 2
        if seg_len < 2:
            return False
        # nhảy qua để tới marker tiếp theo
        pos += seg_len

        # bắt đầu vùng dữ liệu ảnh nén, quét từng byte để kiểm tra các marker
        if marker == 0xDA:
            while pos < data_len:
                # byte dữ liệu thường
                if jpeg_data[pos] != 0xFF:
                    pos += 1
                    continue
                # byte FF ở cuối file, thiếu byte sau nên sai cấu trúc
                if pos + 1 >= data_len:
                    return False
                next_byte = jpeg_data[pos + 1]
                # FF D0-D7: RST (restart marker) nằm trong dữ liệu, bỏ qua cặp
                # FF FF: FF đệm, chỉ nhảy 1 byte để FF sau xét tiếp
                if next_byte == 0x00 or next_byte == 0xFF or 0xD0 <= next_byte <= 0xD7:
                    pos += 2 if next_byte != 0xFF else 1
                    continue
                break                                       # gặp marker thật
    return False


class Case3Recoverer:
    def __init__(self, img: AnhDia, log: NhatKy):
        self.img = img
        self.log = log
        self.reader = FAT32Reader(img, log)

        self.clus_size = self.reader.clus_size
        self.data_off = self.reader.data_off
        # cluster hợp lệ: 2 -> (total_clus - 1)
        self.total_clus = (img.kich_thuoc - self.data_off) // self.clus_size + 2

    def _read_clus(self, clus):
        return self.img.doc(self.data_off + (clus - 2) * self.clus_size, self.clus_size)    

    # chọn file JPEG bị phân mảnh
    def _pick_target(self, file_entries):
        jpeg_entries = [e for e in file_entries if e["path"].lower().endswith(JPEG_EXTENSIONS)]
        broken_entries = []
        for entry in jpeg_entries:
            needed_clus = math.ceil(entry["size"] / self.clus_size)
            fat_chain = self.reader.chain(entry["first_clus"])
            self.log.buoc("JPEG: so cluster can vs do dai chuoi FAT",
                          gia_tri={"path": entry["path"], "needed_clus": needed_clus,
                                   "fat_chain_len": len(fat_chain)})
            if len(fat_chain) < needed_clus:
                broken_entries.append(entry)

        candidates = broken_entries or jpeg_entries
        # just in case
        if not candidates:
            raise ValueError("không có file JPEG nào trong ảnh")
        target = max(candidates, key=lambda e: e["size"])
        reason = "chuỗi FAT không đủ cluster" if broken_entries else "file JPEG lớn nhất (theo đề)"
        self.log.quyet_dinh(f"Chọn file mục tiêu {target['path']} vì {reason}",
                            first_clus=target["first_clus"], size=target["size"])
        return target

    # cluster đã bị file khác chiếm
    def _occupied_clusters(self, file_entries, dir_clus_set, target):
        occupied_clus = set(dir_clus_set)
        for entry in file_entries:
            if entry is target:
                continue
            needed_clus = math.ceil(entry["size"] / self.clus_size)
            fat_chain = self.reader.chain(entry["first_clus"])
            if len(fat_chain) < needed_clus:    # chuỗi FAT không đủ -> coi như liên tục (theo đề)
                fat_chain = list(range(entry["first_clus"], entry["first_clus"] + needed_clus))
            occupied_clus.update(fat_chain)
        return occupied_clus

    # tìm mảnh thứ 2
    def _find_fragments(self, target, occupied_clus):
        first_clus = target["first_clus"]
        size = target["size"]
        needed_clus = math.ceil(size / self.clus_size)
        last_clus_bytes = size - (needed_clus - 1) * self.clus_size   # số byte thật ở cluster cuối

        self.log.buoc("Số cluster cần có (ceil(size / cluster_size))", gia_tri=needed_clus)

        if needed_clus < 2:
            return [first_clus]

        # số cluster liên tiếp còn trống tính từ first_clus -> chặn trên độ dài mảnh 1
        free_run_len = 0
        while (first_clus + free_run_len < self.total_clus
               and (first_clus + free_run_len) not in occupied_clus):
            free_run_len += 1

        tail_cache = {}

        def ends_with_eoi(clus):
            """Cluster cuối của file phải có FF D9 tại byte size-1."""
            if clus not in tail_cache:
                tail = self._read_clus(clus)[:last_clus_bytes]
                tail_cache[clus] = tail[-2:] == JPEG_EOI
            return tail_cache[clus]

        matches = []
        for frag1_clus_cnt in range(1, min(needed_clus - 1, free_run_len) + 1):
            frag2_clus_cnt = needed_clus - frag1_clus_cnt
            frag1_end_clus = first_clus + frag1_clus_cnt          # cluster ngay sau mảnh 1

            for frag2_start_clus in range(frag1_end_clus, frag1_end_clus + MAX_GAP_CLUS + 1):
                frag2_last_clus = frag2_start_clus + frag2_clus_cnt - 1
                if frag2_last_clus >= self.total_clus:
                    break
                if not ends_with_eoi(frag2_last_clus):             # lọc nhanh
                    continue

                frag2_clus_list = list(range(frag2_start_clus, frag2_last_clus + 1))
                if any(c in occupied_clus for c in frag2_clus_list):
                    continue
                if not any(self._read_clus(frag2_start_clus)):     # cluster toàn 0 -> không phải dữ liệu
                    continue

                clus_chain = list(range(first_clus, frag1_end_clus)) + frag2_clus_list
                jpeg_data = b"".join(self._read_clus(c) for c in clus_chain)[:size]
                if _is_valid_jpeg(jpeg_data):
                    gap_clus = frag2_start_clus - frag1_end_clus
                    matches.append((gap_clus, clus_chain))
                    self.log.buoc("Ứng viên hợp lệ",
                                  gia_tri={"frag1_clus_cnt": frag1_clus_cnt,
                                           "frag2_start_clus": frag2_start_clus,
                                           "gap_clus": gap_clus})

        if not matches:
            raise ValueError("không tìm được cách ghép mảnh hợp lệ")

        # nhiều ứng viên: chọn khoảng trống nhỏ nhất, ưu tiên mảnh 1 dài hơn
        matches.sort(key=lambda m: m[0])
        best_gap, best_chain = matches[0]
        self.log.quyet_dinh(f"Chọn chuỗi cluster cuối cùng ({len(matches)} ứng viên, gap={best_gap})",
                            clus_chain=best_chain)
        return best_chain

    # ------------------------------------------------------------ chính
    def recover(self, out: ThuMucKetQua):
        entries = list(self.reader.walk(self.reader.root_clus))
        file_entries = [e for e in entries if not e["is_dir"]]
        dir_clus_set = set(self.reader.chain(self.reader.root_clus))
        for e in entries:
            if e["is_dir"]:
                dir_clus_set.update(self.reader.chain(e["first_clus"]))
        self.log.buoc("Số file tìm thấy trong cây thư mục", gia_tri=len(file_entries))

        target = self._pick_target(file_entries)
        occupied_clus = self._occupied_clusters(file_entries, dir_clus_set, target)
        clus_chain = self._find_fragments(target, occupied_clus)

        jpeg_data = b"".join(self._read_clus(c) for c in clus_chain)[:target["size"]]
        out.luu(target["path"], jpeg_data)
        self.log.buoc("Đã lưu file JPEG phục hồi", gia_tri={"path": target["path"], "size": len(jpeg_data)})