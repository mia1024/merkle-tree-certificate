import os
from typing import Optional

from mtc import create_bikeshed_certificate, create_merkle_tree_proof, BikeshedCertificate
from .assertion_input import read_assertions_input
from .utils import save_batch, get_latest_batch_number, read_private_key, read_assertion, ROOT_DIR


def generate_batch(assertions_input_path: os.PathLike, issuer_id: str, private_key_path: os.PathLike,
                   batch_number: Optional[int] = None, ):
    if batch_number is None:
        batch_number = get_latest_batch_number() + 1

    private_key = read_private_key(private_key_path)
    assertions = read_assertions_input(assertions_input_path)

    save_batch(assertions, issuer_id.encode(), batch_number, private_key)


def generate_certificate(batch_number: int, index: int, issuer_id: str, dest: str) -> BikeshedCertificate:
    assertion = read_assertion(batch_number, index)
    proof = create_merkle_tree_proof(assertion.value, issuer_id.encode(), batch_number, index)
    cert = create_bikeshed_certificate(assertion, proof)

    with open(dest, "wb") as f:
        f.write(cert.to_bytes())

    return cert


def stress_test_batch(private_key_path: os.PathLike):
    batch_number = get_latest_batch_number() + 1
    private_key = read_private_key(private_key_path)

    assertions = read_assertions_input(ROOT_DIR / "input.example.json") * 1000000

    save_batch(assertions, b"test issuer", batch_number, private_key)
