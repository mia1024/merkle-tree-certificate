import enum
import io

from .base import Parser, int_to_bytes, bytes_to_int, parse_failure, parse_success, ParseResult
from typing import Self


class EnumMeta(type):
    def __new__(cls, name, bases, attrs, **kwargs):
        cls_ = super().__new__(cls, name, bases, attrs, **kwargs)
        if "EnumClass" in attrs:
            for k, v in attrs["EnumClass"].__members__.items():
                setattr(cls_, k, cls_(v))
        return cls_


class Enum(Parser, metaclass=EnumMeta):
    """We use this wrapper to implement the BinRep interface on top of IntEnum"""
    EnumClass: type[enum.IntEnum]
    size_in_bytes: int

    def __init__(self, /, value: int) -> None:
        self.value = self.EnumClass(value)

    def to_bytes(self) -> bytes:
        return int_to_bytes(self.value, self.size_in_bytes)

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        n = bytes_to_int(stream.read(cls.size_in_bytes))
        try:
            obj = cls(n)
        except ValueError:
            raise cls.ParsingError(stream.tell() - cls.size_in_bytes, stream.tell(), f"Invalid value {n}")

        return obj

    def print(self) -> str:
        return f"{self.size_in_bytes} {self.__class__.__name__} {self.value.name}({self.value})"


__all__ = ["Enum"]
