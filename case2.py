import math

# # 1. Chạy phục hồi case 2:
# python recover.py --image mau/fat32/case2.img --case 2 --out ket_qua_case2/ --log nhat_ky_case2.jsonl
# # 2. Chạy selftest tự động chấm điểm:
# python selftest.py --mau mau/fat32

from binio import AnhDia
from tienich import NhatKy, ThuMucKetQua


class Case2Recoverer:
    def __init__(self, img: AnhDia, log: NhatKy):
        self.img = img
        self.log = log

    def recover(self, out: ThuMucKetQua):
        return _recover_case2(self.img, out, self.log)


def _recover_case2(img: AnhDia, out: ThuMucKetQua, log: NhatKy):
    """Khôi phục các file trong FAT32 bị mất FirstCluster."""
    # Đọc thông số BPB để tính toán các vùng trên đĩa.
    byte_per_sec = img.u16(0x0B)
    sec_per_clus = img.u8(0x0D)
    rsvd_sec_cnt = img.u16(0x0E)
    num_fats = img.u8(0x10)
    fat_sz = img.u32(0x24)
    root_clus = img.u32(0x2C)

    clus_size = byte_per_sec * sec_per_clus
    fat_off = rsvd_sec_cnt * byte_per_sec
    data_off = (rsvd_sec_cnt + num_fats * fat_sz) * byte_per_sec

    log.buoc("Thông số BPB", gia_tri={
        "clus_size": clus_size,
        "fat_off": hex(fat_off),
        "data_off": hex(data_off),
        "root_clus": root_clus,
    })

    def doc_cluster(c_num):
        c_offset = data_off + (c_num - 2) * clus_size
        return img.doc(c_offset, clus_size)

    def lay_chuoi_fat(start_clus):
        chain = []
        cur = start_clus
        visited = set()
        while 2 <= cur < 0x0FFFFFF8 and cur not in visited:
            chain.append(cur)
            visited.add(cur)
            cur = img.u32(fat_off + 4 * cur) & 0x0FFFFFFF
        return chain

    # Tìm thư mục DATA từ thư mục gốc.
    data_dir_clus = None
    for c in lay_chuoi_fat(root_clus):
        raw = doc_cluster(c)
        for i in range(0, clus_size, 32):
            entry = raw[i:i + 32]
            if entry[0] == 0x00:
                break
            if entry[0] == 0xE5 or entry[0x0B] == 0x0F:
                continue
            name = entry[0:8].decode("ascii", "replace").strip()
            attr = entry[0x0B]
            if (attr & 0x10) and name.upper() == "DATA":
                data_dir_clus = (int.from_bytes(entry[0x14:0x16], "little") << 16) | \
                    int.from_bytes(entry[0x1A:0x1C], "little")
                break
        if data_dir_clus:
            break

    if not data_dir_clus:
        raise RuntimeError("Không tìm thấy thư mục /DATA trong Root Directory!")

    log.buoc("Tìm thấy thư mục DATA", gia_tri={"cluster": data_dir_clus})

    cac_file_hong = []
    cac_cluster_da_dung = set()
    cac_cluster_da_dung.update(lay_chuoi_fat(root_clus))
    cac_cluster_da_dung.update(lay_chuoi_fat(data_dir_clus))

    # Đọc file trong /DATA, đồng thời ghi nhận các file bị mất FirstCluster.
    for c in lay_chuoi_fat(data_dir_clus):
        raw = doc_cluster(c)
        for i in range(0, clus_size, 32):
            entry = raw[i:i + 32]
            if entry[0] == 0x00:
                break
            if entry[0] == 0xE5 or entry[0x0B] == 0x0F:
                continue
            attr = entry[0x0B]
            if attr & 0x18:
                continue

            base = entry[0:8].decode("ascii", "replace").strip()
            ext = entry[8:11].decode("ascii", "replace").strip()
            filename = f"{base}.{ext}" if ext else base
            rel_path = f"DATA/{filename}"
            first_clus = (int.from_bytes(entry[0x14:0x16], "little") << 16) | \
                int.from_bytes(entry[0x1A:0x1C], "little")
            file_size = int.from_bytes(entry[0x1C:0x20], "little")

            if first_clus > 0:
                chain = lay_chuoi_fat(first_clus)
                cac_cluster_da_dung.update(chain)
                file_bytes = bytearray()
                for clus in chain:
                    file_bytes.extend(doc_cluster(clus))
                out.luu(rel_path, bytes(file_bytes[:file_size]))
                log.buoc(
                    f"Đã lưu file nguyên vẹn: {rel_path}",
                    gia_tri={"size": file_size, "chain": chain},
                )
            elif file_size > 0:
                cac_file_hong.append({
                    "path": rel_path,
                    "name": filename,
                    "ext": ext.upper(),
                    "size": file_size,
                    "expected_clusters": math.ceil(file_size / clus_size),
                })
                log.canh_bao(
                    f"Phát hiện file bị đứt liên kết: {rel_path}",
                    size=file_size,
                )

    # Tìm các chuỗi FAT đã cấp phát nhưng không còn được file nào trỏ tới.
    so_cluster_max = fat_sz * byte_per_sec // 4
    fat_table = [
        img.u32(fat_off + 4 * idx) & 0x0FFFFFFF
        for idx in range(so_cluster_max)
    ]

    cac_cluster_duoc_tro_toi = set()
    for idx in range(2, so_cluster_max):
        nxt = fat_table[idx]
        if 2 <= nxt < 0x0FFFFFF8:
            cac_cluster_duoc_tro_toi.add(nxt)

    orphan_chains = []
    for idx in range(2, so_cluster_max):
        val = fat_table[idx]
        if val != 0 and val != 0x0FFFFFF7:
            if idx not in cac_cluster_duoc_tro_toi and idx not in cac_cluster_da_dung:
                chain = lay_chuoi_fat(idx)
                orphan_chains.append({
                    "head": idx,
                    "chain": chain,
                    "length": len(chain),
                })

    log.buoc(
        "Tìm thấy các chuỗi mồ côi (Orphan Chains)",
        gia_tri=[
            {"head": orphan["head"], "length": orphan["length"]}
            for orphan in orphan_chains
        ],
    )

    def kiem_tra_chu_ky(data_head, ext):
        if ext in ("JPG", "JPEG"):
            return data_head.startswith(b"\xFF\xD8\xFF")
        if ext == "PNG":
            return data_head.startswith(b"\x89PNG\r\n\x1a\n")
        if ext == "PDF":
            return data_head.startswith(b"%PDF-")
        if ext == "TXT":
            sample = data_head[:min(len(data_head), 200)]
            return all(b in (9, 10, 13) or 32 <= b <= 126 for b in sample)
        return True

    for file_info in cac_file_hong:
        matched_candidate = None
        for candidate in orphan_chains:
            data_head = doc_cluster(candidate["head"])
            sig_match = kiem_tra_chu_ky(data_head, file_info["ext"])
            len_match = candidate["length"] == file_info["expected_clusters"]
            if sig_match and len_match:
                matched_candidate = candidate
                break

        if matched_candidate:
            log.quyet_dinh(
                f"Khớp thành công file {file_info['path']}",
                first_cluster=matched_candidate["head"],
                so_cluster=matched_candidate["length"],
            )
            data_bytes = bytearray()
            for clus in matched_candidate["chain"]:
                data_bytes.extend(doc_cluster(clus))
            out.luu(file_info["path"], bytes(data_bytes[:file_info["size"]]))
            orphan_chains.remove(matched_candidate)
        else:
            log.canh_bao(
                f"Không tìm thấy chuỗi mồ côi phù hợp cho {file_info['path']}"
            )

    log.buoc("Hoàn tất Case 2!")
