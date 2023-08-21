from .utils import save_batch, get_latest_batch_number, read_private_key, read_assertions, ROOT_DIR
from .assertion_input import read_assertions_input
from typing import Optional
from parsers import create_bikeshed_certificate, create_merkle_tree_proof, BikeshedCertificate


def generate_batch(assertions_input_path: str, issuer_id: str, private_key_path: str,
                   batch_number: Optional[int] = None, ):
    if batch_number is None:
        batch_number = get_latest_batch_number() + 1

    private_key = read_private_key(private_key_path)
    assertions = read_assertions_input(assertions_input_path)

    save_batch(assertions, issuer_id.encode(), batch_number, private_key)


def generate_certificate(batch_number: int, index: int, issuer_id: str, dest: str) -> BikeshedCertificate:
    assertions = read_assertions(batch_number)
    print(len(assertions.value))
    if index >= len(assertions.value):
        raise ValueError(f"Invalid assertion index {index} for batch {batch_number}")
    proof = create_merkle_tree_proof(assertions.value, issuer_id.encode(), batch_number, index)
    cert = create_bikeshed_certificate(assertions.value[index], proof)

    # print(cert.print())
    # print(BikeshedCertificate.parse(cert.to_bytes()))

    with open(dest, "wb") as f:
        f.write(cert.to_bytes())


def stress_test_batch(private_key_path: str):
    batch_number = get_latest_batch_number() + 1
    private_key = read_private_key(private_key_path)

    assertions = read_assertions_input(ROOT_DIR / "input.example.json") * 1000000

    save_batch(assertions, b"test issuer", batch_number, private_key)
