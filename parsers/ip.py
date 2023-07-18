import ipaddress

from .base import Parser, parse_success, ParseResult
from typing import Self


class IPv4Address(Parser):
    def __init__(self, /, value: bytes | str) -> None:
        self.value = ipaddress.IPv4Address(value)

    def to_bytes(self) -> bytes:
        return self.value.packed

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        return parse_success(cls(data[:4]), 4)

    def print(self) -> str:
        return f"4 {self.__class__.__name__} {str(self.value)}"


class IPv6Address(Parser):
    def __init__(self, /, value: bytes | str) -> None:
        self.value = ipaddress.IPv6Address(value)

    def to_bytes(self) -> bytes:
        return self.value.packed

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        return parse_success(cls(data[:16]), 16)

    def print(self) -> str:
        return f"16 {self.__class__.__name__} {str(self.value)}"


__all__ = ["IPv4Address", "IPv6Address"]
