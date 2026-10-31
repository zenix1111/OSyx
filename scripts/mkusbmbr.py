#!/usr/bin/env python3
"""Wraps a file system image in an MBR disk image, like Windows partitions a USB stick.

usage: mkusbmbr.py <out.img> <volume.img> <type hex, e.g. 0c or 07> [none]

The volume starts at LBA 2048 (1 MiB). With `none` the volume is written at
sector 0 instead (a "superfloppy", no partition table).
"""
import struct
import sys


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    out, vol, kind = sys.argv[1], sys.argv[2], int(sys.argv[3], 16)
    data = open(vol, 'rb').read()
    sectors = (len(data) + 511) // 512
    if len(sys.argv) > 4 and sys.argv[4] == 'none':
        open(out, 'wb').write(data)
        return 0
    first = 2048
    disk = bytearray(first * 512)
    disk[446:462] = struct.pack('<B3sB3sII', 0x80, b'\xfe\xff\xff', kind, b'\xfe\xff\xff', first, sectors)
    disk[510:512] = b'\x55\xaa'
    with open(out, 'wb') as f:
        f.write(disk)
        f.write(data)
    return 0


if __name__ == '__main__':
    sys.exit(main())
