from typing import NamedTuple, Self
from .base import Parser, parse_success, ParseResult, propagate_failure_with_offset
import textwrap


class Field(NamedTuple):
    name: str
    data_type: type[Parser]


class StructMeta(type):
    def __new__(cls, name, bases, attrs, **kwargs):

        annotations = attrs.get("__annotations__")
        if annotations is None:
            raise AttributeError("Struct is defined without any field")

        fields = []
        slots = []

        for field_name, data_type in annotations.items():
            if field_name == "_fields":
                continue
            if not isinstance(data_type, type):
                raise TypeError("Struct fields must be a class")
            if not issubclass(data_type, Parser):
                raise TypeError("Struct fields must be a subclass of parser")

            fields.append(Field(field_name, data_type))
            slots.append(field_name)

        # use slots to reduce memory footprint and slightly increase access speed
        cls_ = super().__new__(cls, name, bases, {**attrs, "__slots__": slots}, **kwargs)
        cls_._fields = fields # type: ignore[attr-defined]

        return cls_


class Struct(Parser, metaclass=StructMeta):
    _fields: list[Field] = []

    def __init__(self, /, *value: Parser) -> None:
        self.value = value

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        offset = 0
        parsed = []
        for f in cls._fields:
            res = f.data_type.parse(data[offset:])
            if not res.success:
                return propagate_failure_with_offset(res, offset)
            offset += res.length
            parsed.append(res.result)

        return parse_success(cls(*parsed), offset)

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

    def validate(self) -> None:
        if len(self.value) != len(self._fields):
            raise ValueError("Input to a struct must have the same length as struct definition")
        for i, v in enumerate(self.value):
            name, data_type = self._fields[i]
            if not isinstance(v, data_type):
                raise ValueError(
                    f"Item {i} of input to {self.__class__.__name__} is not of type {data_type.__name__} (found {v.__class__.__name__})")
            setattr(self, self._fields[i].name, v)


__all__ = ["Struct"]
