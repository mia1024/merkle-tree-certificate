import textwrap
from typing import Self
from .base import (Parser,
                   int_to_bytes,
                   bytes_to_int,
                   printable_bytes_truncate,
                   parse_failure,
                   parse_success,
                   ParseResult,
                   propagate_failure_with_offset
                   )


class Vector(Parser):
    data_type: type[Parser]
    max_length: int
    min_length: int
    # marker size should always be bytes_needed(max_length), but this
    # cannot be computed without messing around with metaclasses
    marker_size: int

    def __init__(self, /, value: list[Parser]) -> None:
        self.value = value.copy()

    def to_bytes(self) -> bytes:
        # vector size marker then value
        b = b""
        for item in self.value:
            b += item.to_bytes()
        return int_to_bytes(len(b), self.marker_size) + b

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        size = bytes_to_int(data[:cls.marker_size])
        if not cls.min_length <= size <= cls.max_length:
            return parse_failure(0, cls.marker_size, f"Invalid vector size {size}")

        offset = cls.marker_size
        l = []
        while offset - cls.marker_size < size:
            result = cls.data_type.parse(data[offset:])
            if result.success:
                l.append(result.result)
                offset += result.length
            else:
                # propagate parse failure with correct offset
                return propagate_failure_with_offset(result, offset)

        if offset - cls.marker_size > size:
            return parse_failure(size, offset, "Extra data read")

        return parse_success(cls(l), size + cls.marker_size)

    def print(self) -> str:
        header = "-" * 20 + f"Vector {self.__class__.__name__} ({len(self)})" + "-" * 20 + "\n"
        footer = "-" * 18 + f"End vector {self.__class__.__name__}" + "-" * 18
        inner = ""
        for v in self.value:
            inner += v.print() + "\n"

        return header + textwrap.indent(inner, "\t") + footer


# a special type of vector that can probably be implemented as a Vector of chars
class OpaqueVector(Parser):
    min_length: int
    max_length: int
    # marker size should always be bytes_needed(max_length), but this
    # cannot be computed without messing around with metaclasses
    marker_size: int

    def __init__(self, /, value: bytes) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        # vector size marker then value
        return int_to_bytes(len(self.value), self.marker_size) + self.value

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        size = bytes_to_int(data[:cls.marker_size])
        if not cls.min_length <= size <= cls.max_length:
            return parse_failure(0, cls.marker_size, f"Invalid vector size {size}")

        return parse_success(cls(data[cls.marker_size:size + cls.marker_size]), size + cls.marker_size)

    def validate(self) -> None:
        if not self.min_length <= len(self.value) <= self.max_length:
            raise self.ValidationError(
                f"Invalid data size {len(self.value)}. Must be between {self.min_length} and {self.max_length}")

    def print(self) -> str:
        b = self.value
        return f"{len(b) + self.marker_size} {self.__class__.__name__} {printable_bytes_truncate(b, 80)}"


__all__ = ["OpaqueVector", "Vector"]
