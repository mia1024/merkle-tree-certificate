import io
import textwrap
from typing import Self

from .parser import Parser


class Variant(Parser):
    vary_on_type: type[Parser]
    mapping: dict[Parser, type[Parser]]

    def __init__(self, /, value: tuple[Parser, Parser]) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return self.value[0].to_bytes() + self.value[1].to_bytes()

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        vary_on = cls.vary_on_type.parse(stream)
        content = cls.mapping[vary_on].parse(stream)

        return cls((vary_on, content))

    def print(self) -> str:
        return self.value[0].print() + "\n" + textwrap.indent(self.value[1].print(), "\t")


__all__ = ["Variant"]
