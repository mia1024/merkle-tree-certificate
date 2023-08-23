import io
import textwrap
import types
import typing
from typing import NamedTuple, Self

from .parser import Parser, ParserError


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
            if isinstance(data_type, types.UnionType):
                for t in typing.get_args(data_type):
                    if not issubclass(t, Parser):
                        raise TypeError("Member of union must be a subclass of parser")
            else:
                if not isinstance(data_type, type):
                    raise TypeError("Struct fields must be a class or a union")
                if not issubclass(data_type, Parser):
                    raise TypeError("Struct fields must be a subclass of parser")

            fields.append(Field(field_name, data_type))
            slots.append(field_name)

        # use slots to reduce memory footprint and slightly increase access speed
        cls_ = super().__new__(cls, name, bases, {**attrs, "__slots__": slots}, **kwargs)
        cls_._fields = fields  # type: ignore[attr-defined]

        return cls_


class Struct(Parser, metaclass=StructMeta):
    _fields: list[Field] = []

    def __init__(self, /, *value: Parser) -> None:
        self.value = list(value)

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        parsed = []
        for f in cls._fields:
            if isinstance(f.data_type, types.UnionType):
                for d_type in typing.get_args(f.data_type):
                    initial = stream.tell()
                    try:
                        res = d_type.parse(stream)
                    except ParserError:
                        # revert attempt
                        stream.seek(initial)
                    else:
                        parsed.append(res)
                        break
                else:
                    raise cls.ParsingError(initial, initial, "Cannot decode data as any datatype of the union")
            else:
                parsed.append(f.data_type.parse(stream))

        return cls(*parsed)

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        for f in cls._fields:
            if isinstance(f.data_type, types.UnionType):
                raise NotImplementedError("Skipping unions must be implemented in subclass")
            else:
                f.data_type.skip(stream)

    def to_bytes(self) -> bytes:
        # using BytesIO because repeated byte concatenation is slow
        bio = io.BytesIO()
        for v in self.value:
            bio.write(v.to_bytes())
        return bio.getvalue()

    def print(self) -> str:
        header = "-" * 20 + f"Struct {self.__class__.__name__} ({len(self)})" + "-" * 20 + "\n"
        footer = "-" * 18 + f"End struct {self.__class__.__name__}" + "-" * 18
        inner = ""
        for v in self.value:
            inner += v.print() + "\n"

        return header + textwrap.indent(inner, "\t") + footer

    def __getattr__(self, item: str):
        for i, f in enumerate(self._fields):
            if f.name == item:
                return self.value[i]
        else:
            raise AttributeError

    def __setattr__(self, key, value):
        for i, f in enumerate(self._fields):
            if f.name == key:
                self.value[i] = value
        super().__setattr__(key, value)

    def validate(self) -> None:
        if len(self.value) != len(self._fields):
            raise ValueError("Input to a struct must have the same length as struct definition")
        for i, v in enumerate(self.value):
            name, data_type = self._fields[i]
            if not isinstance(v, data_type):
                raise ValueError(
                    f"Item {i} of input to {self.__class__.__name__} is not of type {data_type.__name__} (found {v.__class__.__name__})")


__all__ = ["Struct"]
