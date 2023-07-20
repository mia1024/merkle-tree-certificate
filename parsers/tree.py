import enum, hashlib
from .enums import Enum
from .structs import Struct, Field
from .vector import OpaqueVector, Array
from .base import bytes_needed, parse_success, ParseResult, propagate_failure_with_offset
from .assertions import Assertion
from .numerical import UInt8, UInt32, UInt64
from .base import Parser
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


class SHA256Hash(Array):
    length = 32


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
    hash_head: HashHead
    index: UInt64
    level: UInt8


class HashNodeInput(Struct):
    hash_head: HashHead
    index: UInt64
    level: UInt8
    left: SHA256Hash
    right: SHA256Hash


class HashAssertionInput(Struct):
    hash_head: HashHead
    index: UInt64
    assertion: Assertion


def sha256(node: Parser) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(node.to_bytes())
    return hasher.digest()


def create_merkle_tree(assertions: Sequence[Assertion], issuer_id: bytes, batch_number: int):
    """Build Merkle tree as section 5.4.1 of the specification"""
    n = len(assertions)
    l = ceil(log2(n)) + 1

    nodes: dict[tuple[int, int], Parser] = {}

    assertion_head = HashHead((Distinguisher.HashAssertionInput, IssuerID(issuer_id), UInt32(batch_number)))
    empty_head = HashHead((Distinguisher.HashEmptyInput, IssuerID(issuer_id), UInt32(batch_number)))
    node_head = HashHead((Distinguisher.HashNodeInput, IssuerID(issuer_id), UInt32(batch_number)))
