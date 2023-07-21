import unittest, hashlib
from parsers import *


class TestMerkleTree(unittest.TestCase):
    def test_empty_tree(self):
        d, h = create_merkle_tree([], b"some issuer id", 65535)
        self.assertEqual(len(d), 1)

        expected_struct = b"\x00\x0esome issuer id\x00\x00\xff\xff" + b"\x00" * (44 + 8 + 1)
        hasher = hashlib.sha256()
        hasher.update(expected_struct)
        self.assertEqual(h.value, hasher.digest())

    def test_tree_with_one_assertion(self):
        assertion = create_assertion("some subject info", ipv4_addrs=("192.168.10.1", "192.168.2.1"),
                                     dns_names=("sub.example.com", "example.com",),
                                     dns_wild_cards=("example.com",),
                                     ipv6_addrs=("2606:4700:4700::64", "::1"))
        d, h = create_merkle_tree([assertion], b"some issuer id", 65535)
        self.assertEqual(len(d), 1)

        expected_struct = b"\x02\x0esome issuer id\x00\x00\xff\xff" + b"\x00" * (44 + 8) + assertion.to_bytes()
        hasher = hashlib.sha256()
        hasher.update(expected_struct)
        self.assertEqual(h.value, hasher.digest())

    def test_tree_with_multiple_assertions(self):
        assertion = create_assertion("info", ipv4_addrs=("192.168.1.1",))

        d, h = create_merkle_tree([assertion]*10, b"some issuer id", 65535)
        self.assertEqual(len(d), 23)
