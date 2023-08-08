from parsers.certificate import create_merkle_tree_proof, BikeshedCertificate
from parsers.assertions import Assertion
from pathlib import Path
import os


def save_merkle_tree(assertions: list[Assertion], issuer_id: bytes, batch_number: int):
    proofs, window = create_merkle_tree_proof(assertions, issuer_id, batch_number)
    dest = Path(os.path.dirname(os.path.abspath(__file__))).parent / "www" / issuer_id.decode() / str(batch_number)
    os.makedirs(dest, exist_ok=True)

    for i, p in enumerate(proofs):
        cert = BikeshedCertificate(assertions[i], p)
        f = open(dest / str(i), "wb")
        f.write(cert.to_bytes())
        f.close()

    f = open(dest / "window","wb")
    f.write(window.to_bytes())
    f.close()
