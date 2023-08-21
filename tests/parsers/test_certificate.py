import unittest
from parsers import *

from cryptography.hazmat.primitives.asymmetric import ed25519

TEST_PRIV_KEY = ed25519.Ed25519PrivateKey.generate()
TEST_PUB_KEY = TEST_PRIV_KEY.public_key()


class TestCertificate(unittest.TestCase):

    def test_certificate_creation(self):
        issuer_id, batch_number = b"some issuer id", 0

        assertion = create_assertion(b"info", ipv4_addrs=("192.168.1.1",))
        signed_validity_window = create_signed_validity_window([assertion] * 10, issuer_id, batch_number, TEST_PRIV_KEY)
        proofs = create_merkle_tree_proofs([assertion] * 10, issuer_id, batch_number)

        for proof in proofs:
            proof_new = Proof.parse(proof.to_bytes())
            self.assertTrue(proof_new.success)
            self.assertEqual(proof, proof_new.result) # type: ignore
            self.assertEqual(proof.to_bytes(), proof_new.result.to_bytes()) # type: ignore

            certificate = BikeshedCertificate(assertion, proof)
            verify_certificate(certificate, signed_validity_window, issuer_id, TEST_PUB_KEY)
