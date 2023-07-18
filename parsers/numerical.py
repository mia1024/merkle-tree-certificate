from .base import (Parser,
                   int_to_bytes,
                   parse_success,
                   ParseResult,
                   bytes_to_int
                   )


class Integer(Parser):
    size_in_bytes: int

    def __init__(self, /, value: int) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return int_to_bytes(self.value, self.size_in_bytes)

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        return parse_success(cls(bytes_to_int(data[:cls.size_in_bytes])), cls.size_in_bytes)

    def print(self) -> str:
        return f"{self.size_in_bytes} {self.__class__.__name__} {self.value}"

    def validate(self) -> None:
        if not 0 <= self.value <= 2 ** self.size_in_bytes - 1:
            raise self.ValidationError(f"{self.value} cannot fit into a uint{self.size_in_bytes}")


class UInt8(Integer):
    size_in_bytes = 1


class UInt16(Integer):
    size_in_bytes = 2


class UInt32(Integer):
    size_in_bytes = 4


class UInt64(Integer):
    size_in_bytes = 8
