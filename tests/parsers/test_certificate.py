import unittest
from parsers import *


class TestCertificate(unittest.TestCase):

    def test_certificate_creation(self):
        assertion = create_assertion("info", ipv4_addrs=("192.168.1.1",))
        proofs, window = create_merkle_tree_proof([assertion] * 10, b"some issuer id", 65535)

        for proof in proofs:
            proof_new = Proof.parse(proof.to_bytes())
            self.assertTrue(proof_new.success)
            self.assertEqual(proof, proof_new.result)
            self.assertEqual(proof.to_bytes(), proof_new.result.to_bytes())

            certificate = BikeshedCertificate(assertion, proof)
            verify_certificate(certificate,window)