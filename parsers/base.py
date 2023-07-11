from dataclasses import dataclass
import math
from string import printable
from typing import Literal, Union, Any


def bytes_needed(n: int) -> int:
    return math.ceil(math.ceil(math.log2(n + 1)) / 8)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)


def int_to_bytes(n: int, size: int) -> bytes:
    return n.to_bytes(size, "big", signed=False)


def printable_bytes_truncate(b: bytes, limit: int) -> str:
    if len(b) > limit:
        b = b[:limit - 3] + b"..."

    s = ""
    for c in b:
        char = chr(c)
        if char not in printable:
            s += "_"
        else:
            s += char
    return s


@dataclass
class ParseResultFail:
    success: Literal[False]
    offset_begin: int
    offset_end: int
    reason: str


@dataclass
class ParseResultSuccess:
    success: Literal[True]
    result: "Parser"
    # if success is True, this is the length of bytestream consumed
    length: int


ParseResult = Union[ParseResultSuccess, ParseResultFail]


def parse_failure(offset_begin: int, offset_end: int, reason: str) -> ParseResultFail:
    return ParseResultFail(False, offset_begin, offset_end, reason)


def parse_success(obj: "Parser", length: int) -> ParseResultSuccess:
    return ParseResultSuccess(True, obj, length)


def propagate_failure_with_offset(failure: ParseResultFail, offset: int) -> ParseResultFail:
    return parse_failure(offset + failure.offset_begin, offset + failure.offset_end, failure.reason)


class Parser:
    """
    Provides an interface to serialize and deserialize an object to bytes. Do not use directly.
    """

    def __init__(self, /, value: Any) -> None:
        self.value = value
        raise NotImplementedError("Do not use this class directly")

    def to_bytes(self) -> bytes:
        raise NotImplementedError("Do not use this class directly")

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        raise NotImplementedError("Do not use this class directly")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.value}>"

    def __str__(self) -> str:
        return self.to_bytes().hex()

    def __eq__(self, other: object):
        if isinstance(other, Parser):
            return self.value == other.value
        return False

    def __len__(self) -> int:
        return len(self.to_bytes())

    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def print(self) -> str:
        b = self.to_bytes()
        return f"{len(b)} {self.__class__.__name__} {printable_bytes_truncate(b, 80)}"


__all__ = ["bytes_needed", "bytes_to_int", "int_to_bytes", "printable_bytes_truncate", "propagate_failure_with_offset",
           "Parser"]
