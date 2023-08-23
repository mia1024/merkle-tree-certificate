import io
from typing import Self

from .parser import (Parser,
                     int_to_bytes,
                     bytes_to_int
                     )


class Integer(Parser):
    size_in_bytes: int

    def __init__(self, /, value: int) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return int_to_bytes(self.value, self.size_in_bytes)

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        return cls(bytes_to_int(stream.read(cls.size_in_bytes)))

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        stream.seek(cls.size_in_bytes, io.SEEK_CUR)

    def print(self) -> str:
        return f"{self.size_in_bytes} {self.__class__.__name__} {self.value}"

    def validate(self) -> None:
        if not 0 <= self.value <= 2 ** (8 * self.size_in_bytes) - 1:
            raise self.ValidationError(f"{self.value} cannot fit into a uint{self.size_in_bytes}")


class UInt8(Integer):
    size_in_bytes = 1


class UInt16(Integer):
    size_in_bytes = 2


class UInt32(Integer):
    size_in_bytes = 4


class UInt64(Integer):
    size_in_bytes = 8
