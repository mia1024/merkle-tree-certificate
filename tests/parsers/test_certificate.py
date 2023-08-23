import unittest
from mtc import *

from cryptography.hazmat.primitives.asymmetric import ed25519

TEST_PRIV_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_KEY = TEST_PRIV_KEY.public_key()


class TestCertificate(unittest.TestCase):

    def test_certificate_creation(self):
        issuer_id, batch_number = b"some issuer id", 0

        assertion = create_assertion(b"info", ipv4_addrs=("192.168.1.1",))

        nodes = create_merkle_tree([assertion] * 10, issuer_id, batch_number)
        signed_validity_window = create_signed_validity_window(nodes, issuer_id, batch_number, TEST_PRIV_KEY)
        proofs = create_merkle_tree_proofs(nodes, issuer_id, batch_number, 10)

        for proof in proofs:
            proof_new = Proof.parse(io.BytesIO(proof.to_bytes()))
            self.assertEqual(proof, proof_new)
            self.assertEqual(proof.to_bytes(), proof_new.to_bytes())

            certificate = BikeshedCertificate(assertion, proof)
            verify_certificate(certificate, signed_validity_window, issuer_id, TEST_PUB_KEY)
