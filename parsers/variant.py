from .base import Parser, parse_success, ParseResult, propagate_failure_with_offset
import textwrap


class Variant(Parser):
    vary_on_type: type[Parser]
    mapping: dict[Parser, type[Parser]]

    def __init__(self, /, value: tuple[Parser, Parser]) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return self.value[0].to_bytes() + self.value[1].to_bytes()

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        vary_on = cls.vary_on_type.parse(data)
        if not vary_on.success:
            # propagating with an offset of 0
            return vary_on

        content = cls.mapping[vary_on.result].parse(data[vary_on.length:])
        if not content.success:
            return propagate_failure_with_offset(content, vary_on.length)

        return parse_success(cls((vary_on.result, content.result)),
                             vary_on.length + content.length)

    def print(self) -> str:
        return self.value[0].print() + "\n" + textwrap.indent(self.value[1].print(), "\t")


__all__ = ["Variant"]
