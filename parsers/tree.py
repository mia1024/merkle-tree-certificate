import enum, hashlib
from .enums import Enum
from .structs import Struct, Field
from .vector import OpaqueVector, Array
from .base import parse_success, ParseResult, propagate_failure_with_offset, bytes_needed
from .assertions import Assertion
from .numerical import UInt8, UInt32, UInt64
from .base import Parser
from typing import Sequence, Self

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
    marker_size = bytes_needed(max_length)


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


def sha256(node: Parser) -> SHA256Hash:
    hasher = hashlib.sha256()
    hasher.update(node.to_bytes())
    return SHA256Hash(hasher.digest())


TreeNodes = HashNodeInput | HashAssertionInput | HashEmptyInput
# (level, index) -> node
NodesDict = dict[tuple[int, int], TreeNodes]


def create_merkle_tree(assertions: Sequence[Assertion], issuer_id: bytes, batch_number: int) -> tuple[
    NodesDict, SHA256Hash]:
    """Build Merkle tree as section 5.4.1 of the specification"""

    assertion_head = HashHead((Distinguisher.HashAssertionInput, IssuerID(issuer_id), UInt32(batch_number)))
    empty_head = HashHead((Distinguisher.HashEmptyInput, IssuerID(issuer_id), UInt32(batch_number)))
    node_head = HashHead((Distinguisher.HashNodeInput, IssuerID(issuer_id), UInt32(batch_number)))

    n = len(assertions)
    if n == 0:
        empty_node = HashEmptyInput(empty_head, UInt64(0), UInt8(0))
        return {(0, 0): empty_node}, sha256(empty_node)

    if n == 1:
        assertion_node = HashAssertionInput(assertion_head, UInt64(0), assertions[0])
        return {(0, 0): assertion_node}, sha256(assertion_node)

    # avoid using log2 because it might cause floating-point errors when n is large
    l = n.bit_length() + 1

    nodes: NodesDict = {}

    for j in range(n):
        a = HashAssertionInput(assertion_head, UInt64(j), assertions[j])
        nodes[0, j] = a

    if n % 2 == 1:
        nodes[0, n] = HashEmptyInput(empty_head, UInt64(n), UInt8(0))
        prev_nodes = n + 1
    else:
        prev_nodes = n

    for i in range(1, l):
        current_nodes = prev_nodes // 2
        for j in range(current_nodes):
            nodes[i, j] = HashNodeInput(node_head, UInt64(j), UInt8(i), sha256(nodes[i - 1, j * 2]),
                                        sha256(nodes[i - 1, j * 2 + 1]))

        # append empty node if not at root
        if current_nodes % 2 == 1 and i != l - 1:
            nodes[i, current_nodes] = HashEmptyInput(empty_head, UInt64(current_nodes), UInt8(i))
            prev_nodes = current_nodes + 1
        else:
            prev_nodes = current_nodes

    return nodes, sha256(nodes[l - 1, 0])
