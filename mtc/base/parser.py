import io
from math import ceil
from typing import Any, Self


def bytes_needed(n: int) -> int:
    # avoid using log2 because it might cause floating-point errors when n is large
    return ceil(n.bit_length() / 8)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)


def int_to_bytes(n: int, size: int) -> bytes:
    return n.to_bytes(size, "big", signed=False)


def printable_bytes_truncate(b: bytes, limit: int) -> str:
    if len(b) > limit:
        b = b[:limit - 3] + b"..."

    s = ""
    for c in b:
        if not 33 <= c <= 126:
            s += "_"
        else:
            s += chr(c)

    return s


class ParserError(Exception): pass


class ParserValidationError(ParserError): pass


class ParserParsingError(ParserError): pass


class Parser:
    """
    Provides an interface to serialize and deserialize an object to bytes. Do not use directly.
    """

    class ValidationError(ParserValidationError): pass

    class ParsingError(ParserParsingError):
        def __init__(self, start: int, end: int, *args):
            super().__init__(*args)
            self.start = start
            self.end = end

        def __str__(self) -> str:
            return f"Error {self.start}:{self.end} " + super().__str__()

    def __new__(cls, *args, **kwargs):
        """perform validation right after object initialization so subclasses don't have to explicitly call it"""
        obj = super().__new__(cls)
        obj.__init__(*args, **kwargs)  # type: ignore
        obj.validate()
        return obj

    def __init__(self, /, value: Any) -> None:
        self.value = value
        raise NotImplementedError("Do not use this class directly")

    def to_bytes(self) -> bytes:
        raise NotImplementedError("Implemented in subclass only")

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        raise NotImplementedError("Do not use this class directly")

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        """
        skips the corresponding section in the stream while doing minimum processing possible
        """
        raise NotImplementedError("Implemented in subclass only")

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

    def validate(self) -> None:
        """Subclasses should overwrite this function and raise a ValidationError from the class"""
        pass


__all__ = ["bytes_needed", "bytes_to_int", "int_to_bytes", "printable_bytes_truncate",
           "Parser", "ParserError", "ParserParsingError", "ParserValidationError"]
