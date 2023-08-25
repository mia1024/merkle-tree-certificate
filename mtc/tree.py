import enum
import hashlib
import io
from typing import Sequence, Self

from .assertion import Assertion
from .base import Parser, Enum, Struct, OpaqueVector, Array, UInt8, UInt32, UInt64


class DistinguisherEnum(enum.IntEnum):
    HashEmptyInput = 0
    HashNodeInput = 1
    HashAssertionInput = 2


class Distinguisher(Enum):
    """Implemented according to section 5.4.1 of the specification"""
    size_in_bytes = 1
    EnumClass = DistinguisherEnum
    HashEmptyInput: "Distinguisher"
    HashNodeInput: "Distinguisher"
    HashAssertionInput: "Distinguisher"


class SHA256Hash(Array):
    """Implemented according to section 5.4.1 of the specification"""
    length = 32


class IssuerID(OpaqueVector):
    """Implemented according to section 5.4.2 of the specification"""
    min_length = 0
    max_length = 32


class HashHead(Parser):
    """Implemented according to section 5.4.1 of the specification"""
    def __init__(self, /, value: tuple[Distinguisher, IssuerID, UInt32]) -> None:
        # value is (distinguisher, issuer_id, batch_number)
        self.value = value

    def to_bytes(self) -> bytes:
        b = b"".join(map(lambda p: p.to_bytes(), self.value))

        # pad to the block size of sha256. this assertion is always true under current spec but if issuer_id
        # might become longer in future specs
        assert len(b) < 64
        b += b"\0" * (64 - len(b))
        return b

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        distinguisher = Distinguisher.parse(stream)
        issuer_id = IssuerID.parse(stream)
        batch_number = UInt32.parse(stream)

        return cls((distinguisher, issuer_id, batch_number))

    def print(self) -> str:
        s = f"----------{self.__class__.__name__}(64)-----------"
        s += "\t" + self.value[0].print() + "\n"
        s += "\t" + self.value[1].print() + "\n"
        s += "\t" + self.value[2].print() + "\n"
        s += f"--------End {self.__class__.__name__}(64)---------"
        return s


class HashEmptyInput(Struct):
    """Implemented according to section 5.4.1 of the specification"""
    hash_head: HashHead
    index: UInt64
    level: UInt8


class HashNodeInput(Struct):
    """Implemented according to section 5.4.1 of the specification"""
    hash_head: HashHead
    index: UInt64
    level: UInt8
    left: SHA256Hash
    right: SHA256Hash


class HashAssertionInput(Struct):
    """Implemented according to section 5.4.1 of the specification"""
    hash_head: HashHead
    index: UInt64
    assertion: Assertion


def sha256(node: HashEmptyInput | HashNodeInput | HashAssertionInput) -> SHA256Hash:
    hasher = hashlib.sha256()
    hasher.update(node.to_bytes())
    return SHA256Hash(hasher.digest())


# (level, index) -> node
NodesList = list[list[SHA256Hash]]


def create_merkle_tree(assertions: Sequence[Assertion], issuer_id: bytes, batch_number: int) -> NodesList:
    """
    Build Merkle tree as defined by section 5.4.1 of the specification

    :param assertions: a list of assertions to create merkle tree for
    :param issuer_id: the issuer id, in bytes
    :param batch_number: the batch number to create merkle tree for
    :return: A :class:`NodesList` that can be passed into other functions
    """

    assertion_head = HashHead((Distinguisher.HashAssertionInput, IssuerID(issuer_id), UInt32(batch_number)))
    empty_head = HashHead((Distinguisher.HashEmptyInput, IssuerID(issuer_id), UInt32(batch_number)))
    node_head = HashHead((Distinguisher.HashNodeInput, IssuerID(issuer_id), UInt32(batch_number)))

    n = len(assertions)
    if n == 0:
        empty_node = HashEmptyInput(empty_head, UInt64(0), UInt8(0))
        return [[sha256(empty_node)]]

    if n == 1:
        assertion_node = HashAssertionInput(assertion_head, UInt64(0), assertions[0])
        return [[sha256(assertion_node)]]

    # avoid using log2 because it might cause floating-point errors when n is large
    l = n.bit_length() + 1

    nodes: NodesList = [[]]

    for j in range(n):
        a = HashAssertionInput(assertion_head, UInt64(j), assertions[j])
        nodes[0].append(sha256(a))

    if n % 2 == 1:
        nodes[0].append(sha256(HashEmptyInput(empty_head, UInt64(n), UInt8(0))))
        prev_nodes = n + 1
    else:
        prev_nodes = n

    for i in range(1, l):
        current_nodes = prev_nodes // 2
        nodes.append([])
        for j in range(current_nodes):
            nodes[i].append(sha256(
                HashNodeInput(node_head, UInt64(j), UInt8(i), nodes[i - 1][j * 2],
                              nodes[i - 1][j * 2 + 1])
            ))

        # append empty node if not at root
        if current_nodes % 2 == 1 and i != l - 1:
            nodes[i].append(sha256(HashEmptyInput(empty_head, UInt64(current_nodes), UInt8(i))))
            prev_nodes = current_nodes + 1
        else:
            prev_nodes = current_nodes

    return nodes
