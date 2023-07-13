import ipaddress
import unittest
from parsers import *


class TestAssertion(unittest.TestCase):
    def test_assertion_parsing(self):
        a = Assertion([
            SubjectType.tls,
            SubjectInfo(b'some subject info'),
            ClaimList(
                [
                    Claim((ClaimType.ipv4, IPv4AddressList([
                        IPv4Address("1.1.1.1"),
                        IPv4Address("1.2.3.4")
                    ]))),
                    Claim((ClaimType.dns, DNSNameList([
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

    def test_assertion_ip_ordering(self):
        with self.assertRaises(IPv4AddressList.ValidationError):
            IPv4AddressList([
                IPv4Address("192.168.10.1"),
                IPv4Address("192.168.2.1")
            ]
            )

    def test_create_assertion(self):
        a = create_assertion("some subject info", ipv4_addrs=("192.168.10.1", "192.168.2.1"),
                             dns_names=("sub.example.com", "example.com",), dns_wild_cards=("example.com",),
                             ipv6_addrs=("2606:4700:4700::64", "::1"))
        b = Assertion([
            SubjectType.tls,
            SubjectInfo(b'some subject info'),
            ClaimList(
                [
                    Claim((ClaimType.dns, DNSNameList([
                        DNSName(b'example.com'),
                        DNSName(b'sub.example.com'),
                    ]))),
                    Claim((ClaimType.dns_wildcard, DNSNameList([
                        DNSName(b'example.com'),
                    ]))),
                    Claim((ClaimType.ipv4, IPv4AddressList([
                        IPv4Address("192.168.2.1"),
                        IPv4Address("192.168.10.1"),
                    ]))),
                    Claim((ClaimType.ipv6, IPv6AddressList([
                        IPv6Address("::1"),
                        IPv6Address("2606:4700:4700::64")
                    ]))),
                ]
            )
        ]
        )
        self.assertEqual(a, b)
        self.assertEqual(a.to_bytes(), b.to_bytes())
