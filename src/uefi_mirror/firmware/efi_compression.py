"""Bounded EFI 1.1 standard decompression (PI compression type 1).

The bitstream is the EFI variant of the Tiano LZ/Huffman format (PBIT=4).
See edk2 BaseTools/Source/C/Common/Decompress.c. Malformed input returns None.
"""

import struct

_NC = 510
_NT = 19
_NP = 31


class _Bits:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read(self, count: int) -> int:
        if count < 0 or self.pos + count > len(self.data) * 8:
            raise ValueError("truncated EFI compression stream")
        value = 0
        for _ in range(count):
            value = (value << 1) | ((self.data[self.pos // 8] >> (7 - self.pos % 8)) & 1)
            self.pos += 1
        return value


class _Codes:
    def __init__(self, lengths: list[int], singleton: int | None = None) -> None:
        self.singleton = singleton
        self.codes: dict[tuple[int, int], int] = {}
        if singleton is not None:
            if not 0 <= singleton < len(lengths):
                raise ValueError("invalid EFI compression symbol")
            return
        counts = [lengths.count(size) for size in range(17)]
        counts[0] = 0
        if any(size > 16 or size < 0 for size in lengths):
            raise ValueError("invalid EFI compression code length")
        code = 0
        for size in range(1, 17):
            code = (code + counts[size - 1]) << 1
            if code + counts[size] > 1 << size:
                raise ValueError("oversubscribed EFI compression table")
            offset = 0
            for symbol, length in enumerate(lengths):
                if length == size:
                    self.codes[(size, code + offset)] = symbol
                    offset += 1
        if code + counts[16] != 1 << 16:
            raise ValueError("incomplete EFI compression table")

    def read(self, bits: _Bits) -> int:
        if self.singleton is not None:
            return self.singleton
        code = 0
        for size in range(1, 17):
            code = (code << 1) | bits.read(1)
            symbol = self.codes.get((size, code))
            if symbol is not None:
                return symbol
        raise ValueError("invalid EFI compression code")


def _pt_lengths(bits: _Bits, count: int, width: int, special: int = -1) -> _Codes:
    used = bits.read(width)
    lengths = [0] * count
    if used == 0:
        return _Codes(lengths, bits.read(width))
    if used > count:
        raise ValueError("invalid EFI compression table size")
    index = 0
    while index < used:
        length = bits.read(3)
        if length == 7:
            while bits.read(1):
                length += 1
                if length > 16:
                    raise ValueError("invalid EFI compression code length")
        lengths[index] = length
        index += 1
        if index == special:
            index += bits.read(2)
            if index > used:
                raise ValueError("invalid EFI compression zero run")
    return _Codes(lengths)


def _c_lengths(bits: _Bits, extra: _Codes) -> _Codes:
    used = bits.read(9)
    lengths = [0] * _NC
    if used == 0:
        return _Codes(lengths, bits.read(9))
    if used > _NC:
        raise ValueError("invalid EFI compression character count")
    index = 0
    while index < used:
        symbol = extra.read(bits)
        if symbol <= 2:
            run = (1 if symbol == 0 else
                   bits.read(4) + 3 if symbol == 1 else bits.read(9) + 20)
            index += run
            if index > used:
                raise ValueError("invalid EFI compression zero run")
        else:
            lengths[index] = symbol - 2
            index += 1
    return _Codes(lengths)


def decompress(blob: bytes, limit: int) -> bytes | None:
    """Return decoded section bytes only when the header and stream fit limit."""
    # ponytail: bit-at-a-time Python favors zero dependencies; use a vetted native
    # decoder if large standard-compressed sections make parsing too slow.
    if len(blob) < 8:
        return None
    compressed_size, output_size = struct.unpack_from("<II", blob)
    if compressed_size > len(blob) - 8 or output_size > limit:
        return None
    bits = _Bits(blob[8:8 + compressed_size])
    out = bytearray()
    block_left = 0
    try:
        while len(out) < output_size:
            if block_left == 0:
                block_left = bits.read(16)
                if block_left == 0:
                    raise ValueError("empty EFI compression block")
                extra = _pt_lengths(bits, _NT, 5, 3)
                chars = _c_lengths(bits, extra)
                positions = _pt_lengths(bits, _NP, 4)
            block_left -= 1
            symbol = chars.read(bits)
            if symbol < 256:
                out.append(symbol)
            else:
                length = symbol - 253
                slot = positions.read(bits)
                distance = (slot if slot <= 1 else
                            (1 << (slot - 1)) + bits.read(slot - 1)) + 1
                if distance > len(out) or length > output_size - len(out):
                    raise ValueError("invalid EFI compression back-reference")
                for _ in range(length):
                    out.append(out[-distance])
    except ValueError:
        return None
    return bytes(out)
