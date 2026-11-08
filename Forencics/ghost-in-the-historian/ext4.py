import argparse
import mmap
import stat
import struct
from pathlib import Path, PurePosixPath


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


class Ext4:
    def __init__(self, image):
        self.image = image
        sb = image[1024:2048]
        if u16(sb, 56) != 0xEF53:
            raise ValueError("No ext4 superblock")
        self.block_size = 1024 << u32(sb, 24)
        self.inodes_per_group = u32(sb, 40)
        self.inode_size = u16(sb, 88)
        self.descriptor_size = max(32, u16(sb, 254))
        self.descriptor_table = (u32(sb, 20) + 1) * self.block_size

    def inode(self, number):
        group, slot = divmod(number - 1, self.inodes_per_group)
        descriptor = self.descriptor_table + group * self.descriptor_size
        table = u32(self.image, descriptor + 8)
        if self.descriptor_size >= 64:
            table |= u32(self.image, descriptor + 40) << 32
        start = table * self.block_size + slot * self.inode_size
        return self.image[start : start + self.inode_size]

    def extents(self, node):
        magic, count, _, depth = struct.unpack_from("<4H", node)
        if magic != 0xF30A:
            raise ValueError("Invalid extent header")
        for offset in range(12, 12 * (count + 1), 12):
            logical = u32(node, offset)
            if depth:
                block = u32(node, offset + 4) | u16(node, offset + 8) << 32
                start = block * self.block_size
                yield from self.extents(self.image[start : start + self.block_size])
                continue
            length = u16(node, offset + 4)
            if length <= 0x8000:
                block = u32(node, offset + 8) | u16(node, offset + 6) << 32
                yield logical, block, length

    def content(self, inode):
        size = u32(inode, 4) | u32(inode, 108) << 32
        if not size:
            return b""
        if not u32(inode, 32) & 0x80000:
            raise ValueError("Expected an extent-backed file")
        result = bytearray(size)
        for logical, block, length in self.extents(inode[40:100]):
            start = logical * self.block_size
            stop = min(size, start + length * self.block_size)
            physical = block * self.block_size
            if stop > start:
                result[start:stop] = self.image[physical : physical + stop - start]
        return bytes(result)

    def directory(self, inode):
        entries = self.content(inode)
        offset = 0
        while offset + 8 <= len(entries):
            number, length, name_length = struct.unpack_from("<IHB", entries, offset)
            if length < 8 or name_length > length - 8:
                raise ValueError("Invalid ext4 directory entry")
            if number:
                name = entries[offset + 8 : offset + 8 + name_length].decode("utf-8")
                if name not in (".", ".."):
                    yield name, number
            offset += length

    def file(self, name):
        inode = self.inode(2)
        for part in PurePosixPath(name).parts:
            inode = self.inode(dict(self.directory(inode))[part])
        if not stat.S_ISREG(u16(inode, 0)):
            raise ValueError(f"Expected a regular file: {name}")
        return self.content(inode)

    def list_files(self, number=2, base=""):
        for name, child in self.directory(self.inode(number)):
            path = base + name
            mode = u16(self.inode(child), 0)
            if stat.S_ISDIR(mode):
                yield from self.list_files(child, path + "/")
            elif stat.S_ISREG(mode):
                yield path
