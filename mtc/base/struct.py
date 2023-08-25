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
    """
    The metaclass for :class:`Struct`. This is what enables the dataclass-like behavior of :class:`Struct`, but from
    inheritance instead of a class decorator. It reads the class annotation and instantiates the fields accordingly, in
    the order defined. It also defines :attr:`__slots__` on the inherited  classes to reduce access time and memory usage.
    All the metadata processed here is stored in the :attr:`_fields` attribute. For example, if you define a class like

    .. code-block::

        class HashEmptyInput(Struct):
            hash_head: HashHead
            index: UInt64
            level: UInt8

    Then HashEmptyInput._fields will be

    .. code-block::

        HashEmptyInput._fields = [
            Field(name = 'hash_head', data_type = HashHead),
            Field(name = 'index', data_type = UInt64),
            Field(name = 'level', data_type = UInt8)
        ]

    where :class:`Field` is a named tuple.
    """
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
    """
    Implements a struct similar to how it works in C. With this class, you can define structs as simple as

    .. code-block::

        class Assertion(Struct):
            subject_type: SubjectType
            subject_info: SubjectInfo
            claims: ClaimList
    """
    _fields: list[Field] = []

    def __init__(self, /, *value: Parser) -> None:
        super().__setattr__("_bytes_cache", None)
        super().__setattr__("value", list(value))

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
                raise NotImplementedError(f"Skipping unions must be implemented in subclass (missing in {cls.__name__})")
            else:
                f.data_type.skip(stream)

    def to_bytes(self) -> bytes:
        if self._bytes_cache is None:
            # using BytesIO because repeated byte concatenation is very slow
            bio = io.BytesIO()
            for v in self.value:
                bio.write(v.to_bytes())
            super().__setattr__("_bytes_cache", bio.getvalue())

        return self._bytes_cache  # type:ignore[return-value]

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
        if self._bytes_cache is not None:
            raise AttributeError("Cannot set attrs after to_bytes() is called")

        for i, f in enumerate(self._fields):
            if f.name == key:
                self.value[i] = value
        super().__setattr__(key, value)

    def validate(self) -> None:
        """
        Checks if all fields passed into the struct initializer are of the correct type in the correct order
        """
        if len(self.value) != len(self._fields):
            raise ValueError("Input to a struct must have the same length as struct definition")
        for i, v in enumerate(self.value):
            name, data_type = self._fields[i]
            if not isinstance(v, data_type):
                raise ValueError(
                    f"Item {i} of input to {self.__class__.__name__} is not of type {data_type.__name__} (found {v.__class__.__name__})")


__all__ = ["Struct"]
