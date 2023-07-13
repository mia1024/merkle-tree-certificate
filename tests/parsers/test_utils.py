import unittest
from parsers import *


class TestUtils(unittest.TestCase):
    def test_sort_dns_names(self):
        self.assertEqual(sort_dns_names(["SUB2.EXAMPLE.COM", "example.com", "sub1.example.com", "example.net"]),
                         ['example.com', 'sub1.example.com', 'SUB2.EXAMPLE.COM', 'example.net'])
