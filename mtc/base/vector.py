import io
import textwrap
from typing import Self

from .parser import (Parser,
                     int_to_bytes,
                     bytes_to_int,
                     printable_bytes_truncate,
                     bytes_needed
                     )


class VectorMeta(type):
    def __new__(cls, name, bases, attrs, **kwargs):
        if not ("min_length" in attrs and "max_length" in attrs):
            raise AttributeError("Improperly defined vector class. min_length and max_length must both be present")
        if "marker_size" in attrs:
            raise AttributeError("Vector subclasses should not define marker_size")
        marker_size = bytes_needed(attrs["max_length"])
        return super().__new__(cls, name, bases, {"marker_size": marker_size, **attrs}, **kwargs)


class Vector(Parser, metaclass=VectorMeta):
    data_type: type[Parser]
    max_length: int = 1
    min_length: int = 1
    # this is computed in metaclass
    marker_size: int

    def __init__(self, /, *value: Parser) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        # using BytesIO because repeated byte concatenation is slow
        bio = io.BytesIO()
        for item in self.value:
            bio.write(item.to_bytes())

        b = bio.getvalue()

        return int_to_bytes(len(b), self.marker_size) + b

    @classmethod
    def parse(cls, data: io.BufferedIOBase) -> Self:
        size = bytes_to_int(data.read(cls.marker_size))
        if not cls.min_length <= size <= cls.max_length:
            raise cls.ParsingError(data.tell() - cls.marker_size, data.tell(),
                                   f"Invalid vector size {size} outside {cls.min_length}-{cls.max_length}")

        l = []
        offset_start = data.tell()
        while data.tell() - offset_start < size:
            result = cls.data_type.parse(data)
            l.append(result)

        if data.tell() - offset_start > size:
            raise cls.ParsingError(offset_start + size, data.tell(), "extra data read while processing vector")

        return cls(*l)

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        size = bytes_to_int(stream.read(cls.marker_size))
        stream.seek(size, io.SEEK_CUR)

    def print(self) -> str:
        header = "-" * 20 + f"Vector {self.__class__.__name__} ({len(self)})" + "-" * 20 + "\n"
        footer = "-" * 18 + f"End vector {self.__class__.__name__}" + "-" * 18
        inner = ""
        for v in self.value:
            inner += v.print() + "\n"

        return header + textwrap.indent(inner, "\t") + footer

    def validate(self) -> None:
        for i, v in enumerate(self.value):
            if not isinstance(v, self.data_type):
                raise ValueError(
                    f"Input item {i} to {self.__class__.__name__} is not of type {self.data_type.__name__}. Found {type(v).__name__}")


# a special type of vector that can probably be implemented as a Vector of chars
class OpaqueVector(Parser, metaclass=VectorMeta):
    min_length: int = 1
    max_length: int = 1
    # this is computed in metaclass
    marker_size: int

    def __init__(self, /, value: bytes) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        # vector size marker then value
        return int_to_bytes(len(self.value), self.marker_size) + self.value

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        size = bytes_to_int(stream.read(cls.marker_size))
        if not cls.min_length <= size <= cls.max_length:
            raise cls.ParsingError(stream.tell() - cls.marker_size, stream.tell(),
                                   f"Invalid vector size {size} outside {cls.min_length}-{cls.max_length}")

        return cls(stream.read(size))

    def validate(self) -> None:
        if not self.min_length <= len(self.value) <= self.max_length:
            raise self.ValidationError(
                f"Invalid data size {len(self.value)}. Must be between {self.min_length} and {self.max_length}")

    def print(self) -> str:
        b = self.value
        return f"{len(b) + self.marker_size} {self.__class__.__name__} {printable_bytes_truncate(b, 80)}"

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        size = bytes_to_int(stream.read(cls.marker_size))
        stream.seek(size, io.SEEK_CUR)


class Array(Parser):
    length: int

    def __init__(self, /, value: bytes) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return self.value

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        return cls(stream.read(cls.length))

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        stream.seek(cls.length, io.SEEK_CUR)

    def validate(self) -> None:
        if len(self.value) != self.length:
            raise self.ValidationError(
                f"Invalid data size {len(self.value)}. Must be of length {self.length}")

    def print(self) -> str:
        b = self.value
        return f"{self.length} Array {self.__class__.__name__} {printable_bytes_truncate(b, 80)}"


__all__ = ["OpaqueVector", "Vector", "Array"]
