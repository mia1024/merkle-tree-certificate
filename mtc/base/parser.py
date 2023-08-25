import io
from typing import Any, Self
from .utils import printable_bytes_truncate




class ParserError(Exception): pass


class Parser:
    """
    The basic building block of the rest of the project. It provides a standard interface to serialize and deserialize
    an object to bytes (hence the name parser). Do not instantiate this class directly.
    """

    def __new__(cls, *args, **kwargs):
        """perform validation right after object initialization so subclasses don't have to explicitly call it"""
        obj = super().__new__(cls)
        obj.__init__(*args, **kwargs)  # type: ignore
        obj.validate()
        return obj

    class ValidationError(ParserError): pass

    class ParsingError(ParserError):
        def __init__(self, start: int, end: int, *args):
            super().__init__(*args)
            self.start = start
            self.end = end

        def __str__(self) -> str:
            return f"Error {self.start}:{self.end} " + super().__str__()

    def __init__(self, /, value: Any) -> None:
        """
        All subclasses initializers must have the same signature. This function must be idempotent due to how validation
        is handled.
        """
        self.value = value
        raise NotImplementedError("Do not use this class directly")

    def to_bytes(self) -> bytes:
        """Serialize the object to bytes"""
        raise NotImplementedError("Implemented in subclass only")

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        """
        Deserialize the first object found from the stream. Raises :class:`ParsingError` if the stream cannot be parsed.
        """
        raise NotImplementedError("Do not use this class directly")

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        """
        skips the corresponding section in the stream, while doing minimum processing possible. This is especially
        useful when a large quantity of objects are serialized into a file.
        """
        raise NotImplementedError("Implemented in subclass only")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.value}>"

    def __str__(self) -> str:
        """By default, returns the serialized bytes in hex format"""
        return self.to_bytes().hex()

    def __eq__(self, other: object) -> bool:
        """Compares two :class:`Parser` object. They are equal if and only if their serialized bytes are equal"""
        if isinstance(other, Parser):
            return self.value == other.value
        return False

    def __len__(self) -> int:
        """Returns the length of the serialized bytes"""
        return len(self.to_bytes())

    def __hash__(self) -> int:
        """Returns the hash of the serialized bytes"""
        return hash(self.to_bytes())

    def print(self) -> str:
        """
        Returns a string representation of the pretty-formatted byte structure of the object. Despite its name, this
        method does not write anything to stdout because it is sometimes recursively called in subclasses.

        For example, calling
        """
        b = self.to_bytes()
        return f"{len(b)} {self.__class__.__name__} {printable_bytes_truncate(b, 80)}"

    def validate(self) -> None:
        """
        Performs basic validation on the data contained in the class and raises :class:`ValidationError` if data is
        inconsistent. This function is a no-op on :class:`Parser` and should be implemented in subclasses if needed
        """
        pass

    @staticmethod
    def disable_validation() -> None:
        """
        Disable validation for all :class:`Parser` objects for the duration of the program. This operation cannot be reversed without
        restarting the program. Calling this method in subclasses is the same as calling it on :class:`Parser`
        """
        Parser.__new__ = lambda cls, *args, **kwargs: object.__new__(cls) # types:ignore


__all__ = ["Parser", "ParserError"]
