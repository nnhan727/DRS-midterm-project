from binio import AnhDia
from tienich import NhatKy


class FAT32Reader:
    def __init__(self, img: AnhDia, log: NhatKy):
        self.img = img
        self.log = log

        self.byte_per_sec = img.u16(0x0B)
        self.sec_per_clus = img.u8(0x0D)
        self.rsvd_sec_cnt = img.u16(0x0E)
        self.num_fats = img.u8(0x10)
        self.fat_sz = img.u32(0x24)
        self.root_clus = img.u32(0x2C)

        self.log.buoc(
            "BPB: byte_per_sec/sec_per_clus/rsvd_sec_cnt/num_fats/fat_sz/root_clus",
            offset=0x0B,
            gia_tri=[
                self.byte_per_sec,
                self.sec_per_clus,
                self.rsvd_sec_cnt,
                self.num_fats,
                self.fat_sz,
                self.root_clus
            ]
        )
    
        self.clus_size = self.byte_per_sec * self.sec_per_clus
        self.fat_off = self.rsvd_sec_cnt * self.byte_per_sec
        self.data_off = (self.rsvd_sec_cnt + self.num_fats * self.fat_sz) * self.byte_per_sec
        
        self.log.buoc("Đầu FAT1", offset=self.fat_off)
        self.log.buoc("Đầu vùng dữ liệu (cluster 2)", offset=self.data_off)

    def _chain(self, start_clus):
        clus_chain = []
        visited_clus = set()
        clus = start_clus
        while 2 <= clus < 0x0FFFFFF8 and clus not in visited_clus:
            clus_chain.append(clus)
            visited_clus.add(clus)
            clus = self.img.u32(self.fat_off + 4 * clus) & 0x0FFFFFFF
        return clus_chain

    def _checksum_short(self, short_name):
        chk = 0
        for byte in short_name:
            chk = (((chk & 1) << 7) + (chk >> 1) + byte) & 0xFF
        return chk

    def _long_name(self, lfn, short_name):
        """Ghép các entry LFN (nếu checksum khớp short entry), trả None nếu không dùng được."""
        if not lfn or any(chk != self._checksum_short(short_name) for _, chk, _ in lfn):
            return None
        raw = b"".join(ch for _, _, ch in sorted(lfn, key=lambda x: x[0]))
        s = raw.decode("utf-16le", errors="replace")
        return s.split("\x00")[0].rstrip("\uffff")

    def _short_name(self, entry):
        base = entry[0:8].decode("ascii", "replace").rstrip()
        ext = entry[8:11].decode("ascii", "replace").rstrip()

        # cho windows NT và các phiên bản sau này 
        if entry[0x0C] & 0x08:          # flag tên thường
            base = base.lower()
        if entry[0x0C] & 0x10:          # flag đuôi thường
            ext = ext.lower()
        return base + ("." + ext if ext else "")

    def _traverse_dir(self, c, prefix):
        lfn = []
        for c_i in self._chain(c):
            data = self.img.doc(self.data_off + (c_i - 2) * self.clus_size, self.clus_size)
            for i in range(0, self.clus_size, 32):
                entry = data[i:i+32]

                # status byte
                if entry[0] == 0x00:    # no more entry
                    return
                if entry[0] == 0xE5:    # deleted entry
                    lfn = []
                    continue
                
                attr = entry[0x0B]
                if attr == 0x0F:        # entry tên dài
                    lfn.append((entry[0] & 0x1F, entry[0x0D], entry[1:11] + entry[14:26] + entry[28:32]))
                    continue
                if attr & 0x08:         # volume label ko có tên dài
                    lfn = []
                    continue

                name = self._long_name(lfn, entry[:11]) or self._short_name(entry)
                lfn = []
                if name in (".", ".."):
                    continue
                clus = (int.from_bytes(entry[0x14:0x16], "little") << 16) | int.from_bytes(entry[0x1A:0x1C], "little")
                size = int.from_bytes(entry[0x1C:0x20], "little")
                
                if attr & 0x10:
                    yield from self._traverse_dir(clus, prefix + name + "/")
                else:
                    yield {"path": prefix + name, "size": size}

    def get_volume_info(self):
        files = list(self._traverse_dir(self.root_clus, ""))
        for f in files:
            self.log.buoc("Tập tin", gia_tri=f)
    
        return {
            "fs": self.img.doc(0x52, 8).decode('ascii'),
            "cluster_size": self.clus_size,
            "byte_per_sec": self.byte_per_sec,
            "sec_per_clus": self.sec_per_clus,
            "rsvd_sec_cnt": self.rsvd_sec_cnt,
            "num_fats": self.num_fats,
            "fat_sz": self.fat_sz,
            "root_clus": self.root_clus,
            "files": files
        }