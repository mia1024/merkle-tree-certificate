import enum
from .base import Parser, int_to_bytes, bytes_to_int, parse_failure, parse_success, ParseResult


class EnumMeta(type):
    def __new__(cls, name, bases, dict, **kwargs):
        cls_ = super().__new__(cls, name, bases, dict, **kwargs)
        if "EnumClass" in dict:
            for k, v in dict["EnumClass"].__members__.items():
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
    def parse(cls, data: bytes) -> ParseResult:
        n = bytes_to_int(data[:cls.size_in_bytes])
        try:
            obj = cls(n)
        except ValueError:
            return parse_failure(0, cls.size_in_bytes, f"Invalid value {n}")

        return parse_success(obj, cls.size_in_bytes)

    def print(self) -> str:
        return f"{self.size_in_bytes} {self.__class__.__name__} {self.value.name}({self.value})"


__all__ = ["Enum"]
