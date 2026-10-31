#!/usr/bin/env python3
"""Writes an SSDT that adds a HID over I2C touchpad to QEMU's q35 machine.

QEMU has no DesignWare I2C controller, so the controller named here (PCI
00:15.1, below \\_SB.PCI0) does not exist. That is the point: the table makes
the whole path run (i2chidd evaluates the AML, the kernel receives the
description) and the kernel has to refuse the missing controller instead of
claiming anything. Usage: gen-i2c-ssdt.py OUT.aml
"""
import struct
import sys


def seg(s):
    assert len(s) == 4
    return s.encode()


def pkg_len(body):
    if body < 0x3F:
        return bytes([body + 1])
    total = body + 2
    assert total < 0x1000
    return bytes([0x40 | (total & 0xF), total >> 4])


def integer(v):
    if v == 0:
        return b"\x00"
    if v == 1:
        return b"\x01"
    if v <= 0xFF:
        return bytes([0x0A, v])
    if v <= 0xFFFF:
        return b"\x0B" + struct.pack("<H", v)
    return b"\x0C" + struct.pack("<I", v)


def string(s):
    return b"\x0D" + s.encode() + b"\x00"


def name(n, value):
    return b"\x08" + seg(n) + value


def ret(v):
    return b"\xA4" + v


def method(n, args, body):
    inner = seg(n) + bytes([args]) + body
    return b"\x14" + pkg_len(len(inner)) + inner


def package(items):
    inner = bytes([len(items)]) + b"".join(items)
    return b"\x12" + pkg_len(len(inner)) + inner


def buffer(data):
    inner = integer(len(data)) + data
    return b"\x11" + pkg_len(len(inner)) + inner


def device(n, body):
    inner = seg(n) + body
    return b"\x5B\x82" + pkg_len(len(inner)) + inner


def if_(predicate, body):
    return b"\xA0" + pkg_len(len(predicate) + len(body)) + predicate + body


def large(tag, data):
    return bytes([tag]) + struct.pack("<H", len(data)) + data


def i2c_connection(address, speed, source):
    data = bytes([1, 0, 1]) + struct.pack("<HHBH", 0, 0, 1, 6) + struct.pack("<IH", speed, address)
    return large(0x8E, data + source.encode() + b"\x00")


def gpio_interrupt(pin, source):
    # Offsets count from the first byte of the descriptor (tag and length
    # included): the 20 bytes after the header start at 3.
    table = 23
    head = bytes([1, 0]) + struct.pack("<HHBHH", 0, 0x2, 0, 0, 0)
    head += struct.pack("<HBHHH", table, 0, table + 2, 0, 0)
    assert len(head) == table - 3
    return large(0x8C, head + struct.pack("<H", pin) + source.encode() + b"\x00")


UUID = bytes([0xF7, 0xF6, 0xDF, 0x3C, 0x67, 0x42, 0x55, 0x45, 0xAD, 0x05, 0xB3, 0x0A, 0x3D, 0x89, 0x38, 0xDE])


def dsm(register):
    f0 = if_(b"\x93\x6A" + integer(0), ret(buffer(b"\x03")))
    f1 = if_(b"\x93\x6A" + integer(1), ret(integer(register)))
    outer = if_(b"\x93\x68" + buffer(UUID), f0 + f1)
    return method("_DSM", 4, outer + ret(buffer(b"\x00")))


def main():
    crs = i2c_connection(0x15, 400000, "\\_SB.PCI0.I2C9") + gpio_interrupt(0x42, "\\_SB.GPI0") + b"\x79\x00"
    touchpad = device(
        "TPD0",
        name("_HID", string("ELAN0001")) + name("_CID", string("PNP0C50")) + name("_CRS", buffer(crs)) + dsm(1),
    )
    timing = lambda n, h, l, d: method(n, 0, ret(package([integer(h), integer(l), integer(d)])))
    controller = device(
        "I2C9",
        name("_ADR", integer(0x00150001)) + timing("SSCN", 0x1D0, 0x1F7, 0x1E) + timing("FMCN", 0x80, 0xA0, 0x1E) + touchpad,
    )
    scope_inner = b"\x5C\x2E" + seg("_SB_") + seg("PCI0") + controller
    aml = b"\x10" + pkg_len(len(scope_inner)) + scope_inner
    header_len = 36
    total = header_len + len(aml)
    header = b"SSDT" + struct.pack("<IBB", total, 2, 0) + b"OSYX  " + b"I2CHIDTP" + struct.pack("<I", 1) + b"OSYX" + struct.pack("<I", 1)
    table = bytearray(header + aml)
    table[9] = (-sum(table)) & 0xFF
    with open(sys.argv[1], "wb") as f:
        f.write(table)


if __name__ == "__main__":
    main()
