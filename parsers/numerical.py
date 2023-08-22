import io

from .base import (Parser,
                   int_to_bytes,
                   parse_success,
                   ParseResult,
                   bytes_to_int
                   )
from typing import Self

class Integer(Parser):
    size_in_bytes: int

    def __init__(self, /, value: int) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return int_to_bytes(self.value, self.size_in_bytes)

    @classmethod
    def parse(cls, stream: io.BytesIO) -> Self:
        return cls(bytes_to_int(stream.read(cls.size_in_bytes)))

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
