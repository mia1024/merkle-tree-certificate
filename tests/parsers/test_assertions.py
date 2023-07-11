import unittest
from parsers import *


class TestAssertion(unittest.TestCase):
    def testAssertionParsing(self):
        a = Assertion([
            SubjectType(SubjectTypeEnum.tls),
            SubjectInfo(b'some subject info'),
            ClaimList(
                [
                    Claim((ClaimType(ClaimTypeEnum.ipv4), IPv4AddressList([
                        IPv4Address("1.1.1.1"),
                        IPv4Address("1.2.3.4")
                    ]))),
                    Claim((ClaimType(ClaimTypeEnum.dns), DNSNameList([
                        DNSName(b'cloudflare.com'),
                        DNSName(b'cloudflareresearch.com'),
                    ]))),
                ]
            )
        ]
        )

        b = Assertion.parse(a.to_bytes())
        self.assertTrue(b.success)
        self.assertEqual(b.result, a)
        self.assertEqual(b.length, len(a))
        self.assertEqual(len(a), 77)
