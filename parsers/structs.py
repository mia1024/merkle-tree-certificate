from typing import NamedTuple
from .base import Parser, parse_success, ParseResult, propagate_failure_with_offset
import textwrap


class Field(NamedTuple):
    name: str
    data_type: type[Parser]


class Struct(Parser):
    fields: list[Field] = []

    def __init__(self, /, value: list[Parser]) -> None:
        if len(value) != len(self.fields):
            raise ValueError("Input to a struct must have the same length as struct definition")
        for v in value:
            if not isinstance(v, Parser):
                raise ValueError(f"All members of the struct must be BinRep, got {repr(v)}")
        self.value = value.copy()

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        offset = 0
        parsed = []
        for f in cls.fields:
            res = f.data_type.parse(data[offset:])
            if not res.success:
                return propagate_failure_with_offset(res, offset)
            offset += res.length
            parsed.append(res.result)

        return parse_success(cls(parsed), offset)

    def to_bytes(self) -> bytes:
        b = b""
        for v in self.value:
            b += v.to_bytes()
        return b

    def print(self) -> str:
        header = "-" * 20 + f"Struct {self.__class__.__name__} ({len(self)})" + "-" * 20 + "\n"
        footer = "-" * 18 + f"End struct {self.__class__.__name__}" + "-" * 18
        inner = ""
        for v in self.value:
            inner += v.print() + "\n"

        return header + textwrap.indent(inner, "\t") + footer


__all__ = ["Struct"]
