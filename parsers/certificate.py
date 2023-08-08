import enum, hashlib, math
from .enums import Enum
from .structs import Struct
from .vector import Array, Vector, OpaqueVector
from .base import parse_success, ParseResult, Parser, propagate_failure_with_offset, int_to_bytes
from .numerical import UInt32, UInt64, UInt8
from typing import Self
from .tree import IssuerID, SHA256Hash, NodesList
from .assertions import Assertion
from .tree import create_merkle_tree, sha256, HashAssertionInput, HashHead, Distinguisher, HashNodeInput

# CA parameter as defined in section 5.1 of the spec
batch_duration = 3600  # 1 hour
lifetime = 60 * 60 * 24 * 14  # 14 days
validity_window_size = math.floor(lifetime / batch_duration) + 1


class TreeHead(Array):
    # TODO: make this actually an array
    length = 32


class ValidityWindow(Struct):
    batch_number: UInt32
    tree_heads: TreeHead


class ValidityWindowLabel(Parser):
    def __init__(self, /, value: bytes = b"Merkle Tree Crts ValidityWindow\0") -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return self.value

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        return parse_success(cls(data[:32]), 32)

    def validate(self) -> None:
        if self.value != b"Merkle Tree Crts ValidityWindow\0":
            raise self.ValidationError("Validity window has the wrong label")


class LabeledValidityWindow(Struct):
    label: ValidityWindowLabel
    issuer_id: IssuerID
    window: ValidityWindow


class ProofTypeEnum(enum.IntEnum):
    merkle_tree_sha256 = 0


class ProofType(Enum):
    EnumClass = ProofTypeEnum
    size_in_bytes = 2
    merkle_tree_sha256: "ProofType"


class SHA256Vector(Vector):
    data_type = SHA256Hash
    min_length = 32
    max_length = 2 ** 16 - 1


class TrustAnchorData(OpaqueVector):
    min_length = 0
    max_length = 255


class ProofData(OpaqueVector):
    min_length = 0
    max_length = 2 ** 16 - 1


class MerkleTreeTrustAnchor(Struct):
    issuer_id: IssuerID
    batch_number: UInt32

    def to_bytes(self) -> bytes:
        b = super().to_bytes()
        # pad it into opaque vector format for TrustAnchorData
        return int_to_bytes(len(b), TrustAnchorData.marker_size) + b


class MerkleTreeProofSHA256(Struct):
    index: UInt64
    path: SHA256Vector

    def to_bytes(self) -> bytes:
        b = super().to_bytes()
        # pad it into opaque vector format for ProofData
        return int_to_bytes(len(b), ProofData.marker_size) + b


class TrustAnchor(Struct):
    proof_type: ProofType
    trust_anchor_data: TrustAnchorData | MerkleTreeTrustAnchor


class Proof(Struct):
    trust_anchor: TrustAnchor
    proof_data: ProofData | MerkleTreeProofSHA256

    @classmethod
    def parse(cls, data: bytes) -> ParseResult[Self]:
        result = super().parse(data)
        if not result.success:
            return result
        d = result.result
        if d.trust_anchor.proof_type == ProofType.merkle_tree_sha256:
            anchor = MerkleTreeTrustAnchor.parse(d.trust_anchor.trust_anchor_data.value)
            if not anchor.success:
                return propagate_failure_with_offset(anchor, 2)
            d.trust_anchor.trust_anchor_data = anchor.result
            proof = MerkleTreeProofSHA256.parse(d.proof_data.value)
            if not proof.success:
                return propagate_failure_with_offset(proof, anchor.length)

            d.proof_data = proof.result
        return parse_success(d, result.length)


class BikeshedCertificate(Struct):
    assertion: Assertion
    proof: Proof


def create_merkle_tree_proof(assertions: list[Assertion], issuer_id: bytes, batch_number: int) -> tuple[list[Proof],
LabeledValidityWindow]:
    nodes = create_merkle_tree(assertions, issuer_id, batch_number)
    n = len(assertions)
    l = len(nodes)

    p_issuer_id = IssuerID(issuer_id)
    p_batch_number = UInt32(batch_number)

    proofs: list[Proof] = []
    for i in range(n):
        path = []
        for j in range(l - 1):
            path.append(nodes[j][(i >> j) ^ 1])

        proof = Proof(TrustAnchor(ProofType.merkle_tree_sha256,
                                  MerkleTreeTrustAnchor(p_issuer_id, p_batch_number)),
                      MerkleTreeProofSHA256(UInt64(i), SHA256Vector(*path)))
        proofs.append(proof)

    validity_window = LabeledValidityWindow(ValidityWindowLabel(), p_issuer_id,
                                            ValidityWindow(p_batch_number, TreeHead(nodes[-1][0].value)))
    return proofs, validity_window


def verify_certificate(certificate: BikeshedCertificate, validity_window: LabeledValidityWindow):
    if certificate.proof.trust_anchor.proof_type != ProofType.merkle_tree_sha256:
        raise TypeError("Proof is not MerkleTreeProofSHA256 type")

    if certificate.proof.trust_anchor.trust_anchor_data.issuer_id != validity_window.issuer_id:
        raise ValueError("Unrecognized certificate issuer")
    issuer_id = certificate.proof.trust_anchor.trust_anchor_data.issuer_id

    if certificate.proof.trust_anchor.trust_anchor_data.batch_number != validity_window.window.batch_number:
        # TODO: change this to handle multiple batch numbers
        raise ValueError("Certificate is no longer valid")
    batch_number = certificate.proof.trust_anchor.trust_anchor_data.batch_number
    index = certificate.proof.proof_data.index

    h = sha256(HashAssertionInput(HashHead((Distinguisher.HashAssertionInput,
                                            issuer_id, batch_number
                                            )),
                                  index, certificate.assertion))
    remaining = index.value

    node_head = HashHead((Distinguisher.HashNodeInput, issuer_id, batch_number))
    for i, v in enumerate(certificate.proof.proof_data.path.value):
        if remaining % 2 == 1:
            node = HashNodeInput(node_head, UInt64(remaining >> 1), UInt8(i + 1), v, h)
        else:
            node = HashNodeInput(node_head, UInt64(remaining >> 1), UInt8(i + 1), h, v)
        h = sha256(node)
        remaining >>= 1

    if remaining != 0:
        raise ValueError("Cannot verify certificate. Incorrect path")

    # TODO: change this to handle multiple batch numbers
    if h != validity_window.window.tree_heads:
        raise ValueError("Cannot verify certificate. Mismatching hash")
