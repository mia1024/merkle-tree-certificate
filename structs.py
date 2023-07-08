import enum
import math
import ipaddress
from dataclasses import dataclass
from typing import TypeVar, Any, NamedTuple, Literal, Union
from string import printable
import textwrap


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
    result: "BinRep"
    # if success is True, this is the length of bytestream consumed
    length: int


ParseResult = Union[ParseResultSuccess, ParseResultFail]


def parse_failure(offset_begin: int, offset_end: int, reason: str) -> ParseResultFail:
    return ParseResultFail(False, offset_begin, offset_end, reason)


def parse_success(obj: "BinRep", length: int) -> ParseResultSuccess:
    return ParseResultSuccess(True, obj, length)


def propagate_failure_with_offset(failure: ParseResultFail, offset: int) -> ParseResultFail:
    return parse_failure(offset + failure.offset_begin, offset + failure.offset_end, failure.reason)


class BinRep:
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
        if isinstance(other, BinRep):
            return self.value == other.value
        return False

    def __len__(self) -> int:
        return len(self.to_bytes())

    def __hash__(self) -> int:
        return hash(self.to_bytes())

    def print(self) -> str:
        b = self.to_bytes()
        return f"{len(b)} {self.__class__.__name__} {printable_bytes_truncate(b, 80)}"


# SomeBinRep = TypeVar("SomeBinRep", bound=BinRep)
SomeBinRep = BinRep


class Enum(BinRep):
    """We use this wrapper to implement the BinRep interface on top of IntEnum"""
    EnumClass: type[enum.IntEnum]
    size_in_bytes: int

    def __init__(self, /, value: int) -> None:
        self.value = self.EnumClass(value)

    def to_bytes(self) -> bytes:
        return int_to_bytes(self.value, self.size_in_bytes)

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        n = bytes_to_int(data[:cls.size_in_bytes])
        try:
            obj = cls(n)
        except ValueError:
            return parse_failure(0, cls.size_in_bytes, f"Invalid value {n}")

        return parse_success(obj, cls.size_in_bytes)

    def print(self) -> str:
        return f"{self.size_in_bytes} {self.__class__.__name__} {self.value.name}({self.value})"


class SubjectTypeEnum(enum.IntEnum):
    tls = 0


class ClaimTypeEnum(enum.IntEnum):
    dns = 0
    dns_wildcard = 1
    ipv4 = 2
    ipv6 = 3


class SubjectType(Enum):
    EnumClass = SubjectTypeEnum
    size_in_bytes = 2


class ClaimType(Enum):
    EnumClass = ClaimTypeEnum
    size_in_bytes = 2


class Vector(BinRep):
    data_type: type[SomeBinRep]
    max_length: int
    min_length: int
    # marker size should always be bytes_needed(max_length), but this
    # cannot be computed without messing around with metaclasses
    marker_size: int

    def __init__(self, /, value: list[SomeBinRep]) -> None:
        self.value = value.copy()

    def to_bytes(self) -> bytes:
        # vector size marker then value
        b = b""
        for item in self.value:
            b += item.to_bytes()
        return int_to_bytes(len(b), self.marker_size) + b

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        size = bytes_to_int(data[:cls.marker_size])
        if not cls.min_length <= size <= cls.max_length:
            return parse_failure(0, cls.marker_size, f"Invalid vector size {size}")

        offset = cls.marker_size
        l = []
        while offset - cls.marker_size < size:
            result = cls.data_type.parse(data[offset:])
            if result.success:
                l.append(result.result)
                offset += result.length
            else:
                # propagate parse failure with correct offset
                return propagate_failure_with_offset(result, offset)

        if offset - cls.marker_size > size:
            return parse_failure(size, offset, "Extra data read")

        return parse_success(cls(l), size + cls.marker_size)

    def print(self) -> str:
        header = "-" * 20 + f"Vector {self.__class__.__name__} ({len(self)})" + "-" * 20 + "\n"
        footer = "-" * 18 + f"End vector {self.__class__.__name__}" + "-" * 18
        inner = ""
        for v in self.value:
            inner += v.print() + "\n"

        return header + textwrap.indent(inner, "\t") + footer


# a special type of vector that can probably be implemented as a Vector of chars
class OpaqueVector(BinRep):
    min_length: int
    max_length: int
    # marker size should always be bytes_needed(max_length), but this
    # cannot be computed without messing around with metaclasses
    marker_size: int

    def __init__(self, /, value: bytes) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        # vector size marker then value
        return int_to_bytes(len(self.value), self.marker_size) + self.value

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        size = bytes_to_int(data[:cls.marker_size])
        if not cls.min_length <= size <= cls.max_length:
            return parse_failure(0, cls.marker_size, f"Invalid vector size {size}")

        return parse_success(cls(data[cls.marker_size:size + cls.marker_size]), size + cls.marker_size)

    def print(self) -> str:
        b = self.value
        return f"{len(b) + self.marker_size} {self.__class__.__name__} {printable_bytes_truncate(b, 80)}"


class String(OpaqueVector):
    min_length = 1
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


class IPv4Address(BinRep):
    def __init__(self, /, value: bytes | str) -> None:
        self.value = ipaddress.IPv4Address(value)

    def to_bytes(self) -> bytes:
        return self.value.packed

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        return parse_success(cls(data[:4]), 4)

    def print(self) -> str:
        return f"4 {self.__class__.__name__} {str(self.value)}"


class IPv6Address(BinRep):
    def __init__(self, /, value: bytes | str) -> None:
        self.value = ipaddress.IPv6Address(value)

    def to_bytes(self) -> bytes:
        return self.value.packed

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        return parse_success(cls(data[:16]), 16)

    def print(self) -> str:
        return f"16 {self.__class__.__name__} {str(self.value)}"


class IPv4AddressList(Vector):
    data_type = IPv4Address
    min_length = 4
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


class IPv6AddressList(Vector):
    data_type = IPv6Address
    min_length = 16
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


class DNSNameList(Vector):
    data_type = String
    min_length = 1
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


# lack of better name
class DiscriminatedUnionInner(NamedTuple):
    discriminant: BinRep
    content: BinRep


# variant?
class DiscriminatedUnion(BinRep):
    discriminant_type: type[SomeBinRep]
    mapping: dict[SomeBinRep, type[BinRep]]

    def __init__(self, /, value: DiscriminatedUnionInner) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return self.value.discriminant.to_bytes() + self.value.content.to_bytes()

    @classmethod
    def parse(cls, data: bytes) -> ParseResult:
        discriminant = cls.discriminant_type.parse(data)
        if not discriminant.success:
            # propagating with an offset of 0
            return discriminant

        content = cls.mapping[discriminant.result].parse(data[discriminant.length:])
        if not content.success:
            return propagate_failure_with_offset(content, discriminant.length)

        return parse_success(cls(DiscriminatedUnionInner(discriminant.result, content.result)),
                             discriminant.length + content.length)

    def print(self) -> str:

        return self.value.discriminant.print() + "\n" + textwrap.indent(self.value.content.print(), "\t")


class ClaimUnion(DiscriminatedUnion):
    discriminant_type = ClaimType
    mapping = {
        ClaimType(ClaimTypeEnum.dns): DNSNameList,
        ClaimType(ClaimTypeEnum.dns_wildcard): DNSNameList,
        ClaimType(ClaimTypeEnum.ipv4): IPv4AddressList,
        ClaimType(ClaimTypeEnum.ipv6): IPv6AddressList
    }


class Field(NamedTuple):
    name: str
    data_type: type[BinRep]


class Struct(BinRep):
    fields: list[Field] = []

    def __init__(self, /, value: list[BinRep]) -> None:
        if len(value) != len(self.fields):
            raise ValueError("Input to a struct must have the same length as struct definition")
        for v in value:
            if not isinstance(v, BinRep):
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


class Claim(Struct):
    # because the way it's constructed there is currently no way to separate claim_type and claim_info
    fields = [
        Field("claim", ClaimUnion),
    ]


def create_claim(claim_type: ClaimTypeEnum, data: BinRep) -> Claim:
    return Claim([
        DiscriminatedUnion(
            DiscriminatedUnionInner(
                ClaimType(claim_type),
                data
            ))
    ])


class ClaimList(Vector):
    data_type = Claim
    min_length = 0
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(2 ** 16 - 1)


class Assertion(Struct):
    fields = [
        Field("subject_type", SubjectType),
        Field("subject_info", String),
        Field("claims", ClaimList)
    ]


a = Assertion([
    SubjectType(SubjectTypeEnum.tls),
    String(b'some subject info'),
    ClaimList(
        [
            create_claim(ClaimTypeEnum.ipv4, IPv4AddressList([
                IPv4Address("1.1.1.1"),
                IPv4Address("1.2.3.4")
            ])),
            create_claim(ClaimTypeEnum.dns, DNSNameList([
                String(b'cloudflare.com'),
                String(b'cloudflareresearch.com'),
            ])),
        ]
    )
]
)

b = Assertion.parse(a.to_bytes())
assert b.success
assert b.result == a
assert b.length == len(a)

print(a.print())
