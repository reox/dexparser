from construct.lib import *
from construct.expr import *
from construct.version import *
from construct.core import *



@singleton
class LEB128sl(Construct):
    """
    Construct for signed LEB128 little endian.

    _build does not work!
    """
    def _parse(self, stream, context, path):
        acc = []
        while True:
            b = byte2int(stream_read(stream, 1))
            acc.append(b & 0b01111111)
            if not b & 0b10000000:
                break
        num = 0
        signbit = 0b01000000
        mask = 0b1111111
        for b in reversed(acc):
            num = (num << 7) | b
            signbit <<= 7
            mask = (mask << 7) | mask

        signbit >>= 7
        mask >>= 8

        if num & signbit == signbit:
            num = (num & mask) - signbit

        return num

    def _build(self, obj, stream, context, path):
        pass

    def _emitprimitivetype(self, ksy, bitwise):
        return "vlq_base128_le"


if __name__ == "__main__":
    print(624485, "-->", VarInt.parse(b"\xE5\x8E\x26"))

    print(-624485, "-->", LEB128sl.parse(b"\x9B\xF1\x59"))
    print(-128, "-->", LEB128sl.parse(b"\x80\x7F"))
    print(-1, "-->", LEB128sl.parse(b"\x7F"))
    print(1, "-->", LEB128sl.parse(b"\x01"))
    print(0, "-->", LEB128sl.parse(b"\x00"))
