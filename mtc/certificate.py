import enum
import io
import math
from typing import Optional, cast
from typing import Self

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from .assertion import Assertion
from .base import Enum, Vector, OpaqueVector, Struct, Parser, int_to_bytes, UInt32, UInt64, UInt8
from .tree import create_merkle_tree, sha256, HashAssertionInput, HashHead, Distinguisher, HashNodeInput, IssuerID, \
    SHA256Hash, NodesList

# CA parameter as defined in section 5.1 of the spec
BATCH_DURATION = 3600  # 1 hour
LIFETIME = 60 * 60 * 24 * 14  # 14 days
VALIDITY_WINDOW_SIZE = math.floor(LIFETIME / BATCH_DURATION) + 1
SHA256_HASH_SIZE = 32


class TreeHeads(Parser):
    """Implemented according to section 5.4.2 of the specification"""
    def __init__(self, /, value: list[SHA256Hash]) -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return b"".join(map(SHA256Hash.to_bytes, self.value)) + b"\0" * (
                VALIDITY_WINDOW_SIZE - len(self.value)) * SHA256_HASH_SIZE

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        l: list[SHA256Hash] = []
        for i in range(VALIDITY_WINDOW_SIZE):
            h = SHA256Hash.parse(stream)
            l.append(h)
        return cls(l)

    def validate(self) -> None:
        if len(self.value) > VALIDITY_WINDOW_SIZE:
            raise self.ValidationError("Validity window too large")

    def __len__(self):
        return VALIDITY_WINDOW_SIZE * SHA256_HASH_SIZE


class ValidityWindow(Struct):
    """Implemented according to section 5.4.2 of the specification"""
    batch_number: UInt32
    tree_heads: TreeHeads


class ValidityWindowLabel(Parser):
    """Implemented according to section 5.4.2 of the specification"""
    def __init__(self, /, value: bytes = b"Merkle Tree Crts ValidityWindow\0") -> None:
        self.value = value

    def to_bytes(self) -> bytes:
        return self.value

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        return cls(stream.read(32))

    def validate(self) -> None:
        if self.value != b"Merkle Tree Crts ValidityWindow\0":
            raise self.ValidationError("Validity window has the wrong label")


class LabeledValidityWindow(Struct):
    """Implemented according to section 5.4.2 of the specification"""
    label: ValidityWindowLabel
    issuer_id: IssuerID
    window: ValidityWindow


class Signature(OpaqueVector):
    """Implemented according to section 5.4.2 of the specification"""
    min_length = 1
    max_length = 2 ** 16 - 1


class SignedValidityWindow(Struct):
    """Implemented according to section 5.4.2 of the specification"""
    window: ValidityWindow
    signature: Signature


class ProofTypeEnum(enum.IntEnum):
    merkle_tree_sha256 = 0


class ProofType(Enum):
    """Implemented according to section 5.4.3 of the specification"""
    EnumClass = ProofTypeEnum
    size_in_bytes = 2
    merkle_tree_sha256: "ProofType"


class SHA256Vector(Vector):
    """Implemented according to section 5.4.3 of the specification"""
    data_type = SHA256Hash
    min_length = 0
    max_length = 2 ** 16 - 1


class TrustAnchorData(OpaqueVector):
    """Implemented according to section 5.4.3 of the specification"""
    min_length = 0
    max_length = 255


class ProofData(OpaqueVector):
    """Implemented according to section 5.4.3 of the specification"""
    min_length = 0
    max_length = 2 ** 16 - 1


class MerkleTreeTrustAnchor(Struct):
    """Implemented according to section 5.4.3 of the specification"""
    issuer_id: IssuerID
    batch_number: UInt32

    def to_bytes(self) -> bytes:
        b = super().to_bytes()
        # pad it into opaque vector format for TrustAnchorData
        return int_to_bytes(len(b), TrustAnchorData.marker_size) + b


class MerkleTreeProofSHA256(Struct):
    """Implemented according to section 5.4.3 of the specification"""
    index: UInt64
    path: SHA256Vector

    def to_bytes(self) -> bytes:
        b = super().to_bytes()
        # pad it into opaque vector format for ProofData
        return int_to_bytes(len(b), ProofData.marker_size) + b


class TrustAnchor(Struct):
    """Implemented according to section 5.4.3 of the specification"""
    proof_type: ProofType
    trust_anchor_data: TrustAnchorData | MerkleTreeTrustAnchor

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        ProofType.skip(stream)
        TrustAnchorData.skip(stream)


class Proof(Struct):
    """Implemented according to section 5.4.3 of the specification"""
    trust_anchor: TrustAnchor
    proof_data: ProofData | MerkleTreeProofSHA256

    @classmethod
    def parse(cls, stream: io.BufferedIOBase) -> Self:
        offset_start = stream.tell()
        proof = super().parse(stream)
        offset_end = stream.tell()
        if proof.trust_anchor.proof_type == ProofType.merkle_tree_sha256:
            try:
                anchor = MerkleTreeTrustAnchor.parse(io.BytesIO(proof.trust_anchor.trust_anchor_data.value))
                proof.trust_anchor.trust_anchor_data = anchor
                proof.proof_data = MerkleTreeProofSHA256.parse(io.BytesIO(proof.proof_data.value))
            except Parser.ParsingError:
                raise cls.ParsingError(offset_start, offset_end, "data cannot be interpreted as a MerkleTreeProof")

        return proof

    @classmethod
    def skip(cls, stream: io.BufferedIOBase) -> None:
        TrustAnchor.skip(stream)
        ProofData.skip(stream)


class BikeshedCertificate(Struct):
    """Implemented according to section 5.4.3 of the specification"""
    assertion: Assertion
    proof: Proof


def create_merkle_tree_proofs(nodes: NodesList, issuer_id: bytes, batch_number: int,
                              number_of_assertions_in_batch: int) -> list[Proof]:
    """
    Creates all the proofs for a particular batch.

    :param nodes: a :class:`NodesList` as returned by :func:`mtc.tree.create_merkle_tree`
    :param issuer_id: the issuer id, in bytes
    :param batch_number: the batch number to create proofs for
    :return: a :class:`Proof` for the assertion
    """
    l = len(nodes)

    p_issuer_id = IssuerID(issuer_id)
    p_batch_number = UInt32(batch_number)

    proofs: list[Proof] = []
    for i in range(number_of_assertions_in_batch):
        path = []
        for j in range(l - 1):
            path.append(nodes[j][(i >> j) ^ 1])

        proof = Proof(TrustAnchor(ProofType.merkle_tree_sha256,
                                  MerkleTreeTrustAnchor(p_issuer_id, p_batch_number)),
                      MerkleTreeProofSHA256(UInt64(i), SHA256Vector(*path)))
        proofs.append(proof)

    return proofs


def create_merkle_tree_proof(nodes: NodesList, issuer_id: bytes, batch_number: int, index: int) -> Proof:
    """
    Creates a single Proof for a particular batch.

    :param nodes: a :class:`NodesList` as returned by :func:`mtc.tree.create_merkle_tree`
    :param issuer_id: the issuer id, in bytes
    :param batch_number: the batch number to create a proof for
    :param index: the index of the assertion in the batch
    :return: a :class:`Proof` for the assertion
    """
    # TODO: only hash the necessary assertions instead of everything
    l = len(nodes)

    p_issuer_id = IssuerID(issuer_id)
    p_batch_number = UInt32(batch_number)

    path = []
    for j in range(l - 1):
        path.append(nodes[j][(index >> j) ^ 1])

    proof = Proof(TrustAnchor(ProofType.merkle_tree_sha256,
                              MerkleTreeTrustAnchor(p_issuer_id, p_batch_number)),
                  MerkleTreeProofSHA256(UInt64(index), SHA256Vector(*path)))

    return proof


def create_signed_validity_window(nodes: NodesList, issuer_id: bytes, batch_number: int,
                                  private_key: ed25519.Ed25519PrivateKey,
                                  previous_validity_window: Optional[
                                      SignedValidityWindow] = None) -> SignedValidityWindow:
    """
    :param nodes: a :class:`NodesList` as returned by :func:`mtc.tree.create_merkle_tree`
    :param issuer_id: The issuer id, in bytes
    :param batch_number: The batch number to be certified
    :param private_key: The private key of the issuer
    :param previous_validity_window: Optional. The validity window of the previous batch. This value must be None if the
        batch number is 0, and must not be None if the batch number is greater than 0. Additionally, the previous validity
        window must be signed using the same private key.
    :return: a :class:`SignedValidityWindow` for the batch
    """
    if previous_validity_window is None:
        if batch_number != 0:
            raise ValueError("Batch number must be 0 without previous validity window")
        previous_hashes = []
    else:
        if batch_number - 1 != previous_validity_window.window.batch_number.value:
            raise ValueError(
                f"Batch number must be continuous from previous validity window. Previous one is {previous_validity_window.window.batch_number}")

        previous_labeled_window = LabeledValidityWindow(ValidityWindowLabel(), IssuerID(issuer_id),
                                                        previous_validity_window.window)

        try:
            private_key.public_key().verify(previous_validity_window.signature.value,
                                            previous_labeled_window.to_bytes())
        except InvalidSignature:
            raise ValueError("Cannot verify the signature of previous validity window")

        previous_hashes = previous_validity_window.window.tree_heads.value[:-1]

    validity_window = ValidityWindow(UInt32(batch_number), TreeHeads(
        [nodes[-1][0]] + previous_hashes))
    labeled_validity_window = LabeledValidityWindow(ValidityWindowLabel(), IssuerID(issuer_id), validity_window)

    signature = Signature(private_key.sign(labeled_validity_window.to_bytes()))

    return SignedValidityWindow(validity_window, signature)


def create_bikeshed_certificate(assertion: Assertion, proof: Proof):
    """Creates a BikeshedCertificate"""
    return BikeshedCertificate(assertion, proof)


def verify_certificate(certificate: BikeshedCertificate, signed_validity_window: SignedValidityWindow,
                       issuer_id_bytes: bytes,
                       public_key: ed25519.Ed25519PublicKey):
    """
    Verifies the certificate. Returns `None` on success. Raises `ValueError` if something is improperly formatted.
    Raises :class:`cryptography:cryptography.exceptions.InvalidSignature` if the signature on the validity window
    cannot be verified.

    :param certificate: The certificate to be validated
    :param signed_validity_window: The SignedValidityWindow currently in effect
    :param issuer_id_bytes: The issuer id, in bytes
    :param public_key: The public key of the issuer
    :return: None
    """
    validity_window = signed_validity_window.window
    signature = signed_validity_window.signature
    issuer_id = IssuerID(issuer_id_bytes)

    labeled_validity_window = LabeledValidityWindow(ValidityWindowLabel(), issuer_id, validity_window)

    # this method raises if data cannot be validated
    public_key.verify(signature.value, labeled_validity_window.to_bytes())

    if certificate.proof.trust_anchor.proof_type != ProofType.merkle_tree_sha256:
        raise TypeError("Proof is not MerkleTreeProofSHA256 type")

    trust_anchor_data = cast(MerkleTreeTrustAnchor, certificate.proof.trust_anchor.trust_anchor_data)
    proof_data = cast(MerkleTreeProofSHA256, certificate.proof.proof_data)

    if trust_anchor_data.issuer_id != issuer_id:
        raise ValueError("Unrecognized certificate issuer")

    cert_batch_number: int = trust_anchor_data.batch_number.value
    window_batch_number: int = validity_window.batch_number.value

    if cert_batch_number > window_batch_number:
        raise ValueError("Certificate is from the future")

    if cert_batch_number < max(window_batch_number - VALIDITY_WINDOW_SIZE, 0):
        raise ValueError("This certificate has expired")
    index = proof_data.index

    h = sha256(HashAssertionInput(HashHead((Distinguisher.HashAssertionInput,
                                            issuer_id, UInt32(cert_batch_number)
                                            )),
                                  index, certificate.assertion))
    remaining = index.value

    node_head = HashHead((Distinguisher.HashNodeInput, issuer_id, UInt32(cert_batch_number)))
    for i, v in enumerate(proof_data.path.value):
        if remaining % 2 == 1:
            node = HashNodeInput(node_head, UInt64(remaining >> 1), UInt8(i + 1), v, h)
        else:
            node = HashNodeInput(node_head, UInt64(remaining >> 1), UInt8(i + 1), h, v)
        h = sha256(node)
        remaining >>= 1

    if remaining != 0:
        raise ValueError("Cannot verify certificate. Incorrect path")

    expected_hash_index = window_batch_number - cert_batch_number
    expected_hash = validity_window.tree_heads.value[expected_hash_index]
    if h != expected_hash:
        raise ValueError("Cannot verify certificate. Mismatching hash")


__all__ = ["BATCH_DURATION", "LIFETIME", "VALIDITY_WINDOW_SIZE", "SHA256_HASH_SIZE", "TreeHeads", "ValidityWindow",
           "ValidityWindowLabel", "LabeledValidityWindow", "Signature", "SignedValidityWindow", "ProofType", "Proof",
           "SHA256Vector", "TrustAnchor", "TrustAnchorData", "ProofData", "MerkleTreeTrustAnchor",
           "MerkleTreeProofSHA256", "BikeshedCertificate", "create_merkle_tree_proofs", "create_merkle_tree_proof",
           "create_signed_validity_window", "create_bikeshed_certificate", "create_merkle_tree", "verify_certificate"]
