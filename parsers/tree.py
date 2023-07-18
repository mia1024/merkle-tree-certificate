import enum
from .enums import Enum
from .structs import Struct, Field
from .vector import OpaqueVector
from .base import bytes_needed, parse_success, ParseResult, int_to_bytes, propagate_failure_with_offset
from .assertions import Assertion
from .numerical import UInt8, UInt32, UInt64
from .base import Parser
from hashlib import sha256
from typing import Sequence, Self
from math import log2, ceil


class DistinguisherEnum(enum.IntEnum):
    HashEmptyInput = 0
    HashNodeInput = 1
    HashAssertionInput = 2


class Distinguisher(Enum):
    size_in_bytes = 1
    EnumClass = DistinguisherEnum
    HashEmptyInput: "Distinguisher"
    HashNodeInput: "Distinguisher"
    HashAssertionInput: "Distinguisher"


class SHA256Hash(OpaqueVector):
    min_length = 32
    max_length = 32
    marker_size = bytes_needed(max_length)


class IssuerID(OpaqueVector):
    min_length = 0
    max_length = 32


class HashHead(Parser):
    def __init__(self, /, value: tuple[Distinguisher, IssuerID, UInt32]) -> None:
        # value is (distinguisher, issuer_id, batch_number)
        self.value = value

    def to_bytes(self) -> bytes:
        b = b"".join(map(lambda p: p.to_bytes(), self.value))
        # pad to the block size of sha256
        b += b"\0" * (64 - len(b))
        return b

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        offset = 0

        distinguisher = Distinguisher.parse(data)
        if not distinguisher.success:
            return distinguisher
        offset += distinguisher.length

        issuer_id = IssuerID.parse(data[offset:])
        if not issuer_id.success:
            return propagate_failure_with_offset(issuer_id, offset)
        offset += issuer_id.length

        batch_number = UInt32.parse(data[offset:])
        if not batch_number.success:
            return propagate_failure_with_offset(batch_number, offset)

        return parse_success(cls((distinguisher.result, issuer_id.result, batch_number.result)), 64)

    def print(self) -> str:
        s = f"----------{self.__class__.__name__}(64)-----------"
        s += "\t" + self.value[0].print() + "\n"
        s += "\t" + self.value[1].print() + "\n"
        s += "\t" + self.value[2].print() + "\n"
        s += f"--------End {self.__class__.__name__}(64)---------"
        return s


class HashEmptyInput(Struct):
    fields = [
        Field("hash_head", HashHead),
        Field("index", UInt64),
        Field("level", UInt8)
    ]


class HashNodeInput(Struct):
    fields = [
        Field("hash_head", HashHead),
        Field("index", UInt64),
        Field("level", UInt8),
        Field("left", SHA256Hash),
        Field("right", SHA256Hash)
    ]


class HashAssertionInput(Struct):
    fields = [
        Field("hash_head", HashHead),
        Field("index", UInt64),
        Field("assertion", Assertion)
    ]


def hash_empty(hasher, level: int, index: int) -> bytes:
    hasher = hasher.copy()
    hasher.update(int_to_bytes(index, 8))
    hasher.update(int_to_bytes(level, 1))
    return hasher.digest()


def hash_node(hasher, left: bytes, right: bytes, level: int, index: int) -> bytes:
    hasher = hasher.copy()
    hasher.update(int_to_bytes(index, 8))
    hasher.update(int_to_bytes(level, 1))
    hasher.update(left)
    hasher.update(right)
    return hasher.digest()


def hash_assertion(hasher, assertion: Assertion, index: int) -> bytes:
    hasher = hasher.copy()
    hasher.update(int_to_bytes(index, 8))
    hasher.update(assertion.to_bytes())
    return hasher.digest()


def create_merkle_tree(assertions: Sequence[Assertion], issuer_id: bytes, batch_number: int):
    """Build Merkle tree as section 5.4.1"""
    n = len(assertions)
    l = ceil(log2(n)) + 1

    assertion_hasher = sha256()
    assertion_head = HashHead((Distinguisher.HashAssertionInput, IssuerID(issuer_id), UInt32(batch_number)))
    assertion_hasher.update(assertion_head.to_bytes())

    empty_hasher = sha256()
    empty_head = HashHead((Distinguisher.HashEmptyInput, IssuerID(issuer_id), UInt32(batch_number)))
    empty_hasher.update(empty_head.to_bytes())

    node_hasher = sha256()
    node_head = HashHead((Distinguisher.HashNodeInput, IssuerID(issuer_id), UInt32(batch_number)))
    node_hasher.update(node_head.to_bytes())
