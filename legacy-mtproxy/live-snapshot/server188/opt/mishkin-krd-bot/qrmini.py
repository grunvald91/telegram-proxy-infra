"""Small dependency-free QR Code generator for short ASCII links.

The implementation deliberately supports one conservative profile only:
QR version 5, error correction level L, byte mode and mask 0.  That is enough
for the short Mishkin request links and keeps the deployed bot dependency-free.
"""

from __future__ import annotations

import binascii
import pathlib
import struct
import zlib


VERSION = 5
SIZE = VERSION * 4 + 17
DATA_CODEWORDS = 108
ECC_CODEWORDS = 26
MAX_BYTES = 106


def _append_bits(target: list[int], value: int, width: int) -> None:
    target.extend((value >> shift) & 1 for shift in range(width - 1, -1, -1))


def _encode_data(payload: str) -> list[int]:
    raw = payload.encode("ascii")
    if len(raw) > MAX_BYTES:
        raise ValueError(f"QR payload is too long: {len(raw)} bytes (max {MAX_BYTES})")
    bits: list[int] = []
    _append_bits(bits, 0b0100, 4)  # Byte mode.
    _append_bits(bits, len(raw), 8)
    for value in raw:
        _append_bits(bits, value, 8)
    capacity = DATA_CODEWORDS * 8
    bits.extend([0] * min(4, capacity - len(bits)))
    bits.extend([0] * ((-len(bits)) % 8))
    result = [sum(bits[index + bit] << (7 - bit) for bit in range(8)) for index in range(0, len(bits), 8)]
    pad = (0xEC, 0x11)
    while len(result) < DATA_CODEWORDS:
        result.append(pad[(len(result) - len(raw)) & 1])
    return result


def _gf_multiply(left: int, right: int) -> int:
    result = 0
    for index in range(8):
        result = (result << 1) ^ ((result >> 7) * 0x11D)
        result ^= ((right >> (7 - index)) & 1) * left
    return result & 0xFF


def _reed_solomon_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for index in range(degree):
            result[index] = _gf_multiply(result[index], root)
            if index + 1 < degree:
                result[index] ^= result[index + 1]
        root = _gf_multiply(root, 0x02)
    return result


def _reed_solomon_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for value in data:
        factor = value ^ result.pop(0)
        result.append(0)
        for index, coefficient in enumerate(divisor):
            result[index] ^= _gf_multiply(coefficient, factor)
    return result


class _Matrix:
    def __init__(self) -> None:
        self.modules = [[False] * SIZE for _ in range(SIZE)]
        self.function = [[False] * SIZE for _ in range(SIZE)]

    def set_function(self, x: int, y: int, dark: bool) -> None:
        self.modules[y][x] = dark
        self.function[y][x] = True

    def finder(self, center_x: int, center_y: int) -> None:
        for dy in range(-4, 5):
            for dx in range(-4, 5):
                x, y = center_x + dx, center_y + dy
                if 0 <= x < SIZE and 0 <= y < SIZE:
                    distance = max(abs(dx), abs(dy))
                    self.set_function(x, y, distance not in (2, 4))

    def alignment(self, center_x: int, center_y: int) -> None:
        for dy in range(-2, 3):
            for dx in range(-2, 3):
                self.set_function(center_x + dx, center_y + dy, max(abs(dx), abs(dy)) != 1)

    def format_bits(self) -> None:
        # Error correction level L is binary 01; mask pattern is 000.
        data = 0b01000
        remainder = data << 10
        for bit in range(14, 9, -1):
            if (remainder >> bit) & 1:
                remainder ^= 0x537 << (bit - 10)
        value = ((data << 10) | remainder) ^ 0x5412
        get = lambda index: bool((value >> index) & 1)
        for index in range(6):
            self.set_function(8, index, get(index))
        self.set_function(8, 7, get(6))
        self.set_function(8, 8, get(7))
        self.set_function(7, 8, get(8))
        for index in range(9, 15):
            self.set_function(14 - index, 8, get(index))
        for index in range(8):
            self.set_function(SIZE - 1 - index, 8, get(index))
        for index in range(8, 15):
            self.set_function(8, SIZE - 15 + index, get(index))
        self.set_function(8, SIZE - 8, True)

    def draw_functions(self) -> None:
        for index in range(SIZE):
            self.set_function(6, index, index % 2 == 0)
            self.set_function(index, 6, index % 2 == 0)
        self.finder(3, 3)
        self.finder(SIZE - 4, 3)
        self.finder(3, SIZE - 4)
        self.alignment(30, 30)
        self.format_bits()

    def draw_data(self, codewords: list[int]) -> None:
        bits = [(value >> shift) & 1 for value in codewords for shift in range(7, -1, -1)]
        bit_index = 0
        right = SIZE - 1
        while right >= 1:
            if right == 6:
                right = 5
            upward = ((right + 1) & 2) == 0
            for vertical in range(SIZE):
                y = SIZE - 1 - vertical if upward else vertical
                for column in range(2):
                    x = right - column
                    if self.function[y][x]:
                        continue
                    value = bool(bits[bit_index]) if bit_index < len(bits) else False
                    bit_index += 1
                    self.modules[y][x] = value ^ ((x + y) % 2 == 0)
            right -= 2


def make_matrix(payload: str) -> list[list[bool]]:
    data = _encode_data(payload)
    ecc = _reed_solomon_remainder(data, _reed_solomon_divisor(ECC_CODEWORDS))
    matrix = _Matrix()
    matrix.draw_functions()
    matrix.draw_data(data + ecc)
    matrix.format_bits()
    return matrix.modules


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)


def write_png(payload: str, path: pathlib.Path, scale: int = 8, border: int = 4) -> pathlib.Path:
    matrix = make_matrix(payload)
    width = (SIZE + border * 2) * scale
    rows = bytearray()
    for pixel_y in range(width):
        module_y = pixel_y // scale - border
        rows.append(0)  # PNG filter type: None.
        for pixel_x in range(width):
            module_x = pixel_x // scale - border
            dark = 0 <= module_x < SIZE and 0 <= module_y < SIZE and matrix[module_y][module_x]
            rows.append(0 if dark else 255)
    png = b"\x89PNG\r\n\x1a\n"
    png += _chunk(b"IHDR", struct.pack(">IIBBBBB", width, width, 8, 0, 0, 0, 0))
    png += _chunk(b"IDAT", zlib.compress(bytes(rows), 9))
    png += _chunk(b"IEND", b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)
    return path
