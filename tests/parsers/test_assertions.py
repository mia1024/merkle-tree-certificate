import io
import unittest
from mtc import *


class TestAssertion(unittest.TestCase):
    def test_assertion_parsing(self):
        a = Assertion(
            SubjectType.tls,
            SubjectInfo(b'some subject info'),
            ClaimList(
                Claim((ClaimType.ipv4, IPv4AddressList(
                    IPv4Address("1.1.1.1"),
                    IPv4Address("1.2.3.4")
                ))),
                Claim((ClaimType.dns, DNSNameList(
                    DNSName(b'cloudflare.com'),
                    DNSName(b'cloudflareresearch.com'),
                ))),

            )
        )
        b = Assertion.parse(io.BytesIO(a.to_bytes()))

        self.assertEqual(b, a)
        self.assertEqual(a.to_bytes(),
                         # SubjectType.tls
                         b"\x00\x00"
                         # vector of length 0x11 and content "some subject info"
                         b"\x00\x11some subject info"
                         # vector of length 0x36
                         b"\x00\x36"
                         # ClaimType.IPv4
                         b"\x00\x02"
                         # vector of length 0x08 (2 IPv4 address)
                         b"\x00\x08"
                         # IP Address 1.1.1.1
                         b"\x01\x01\x01\x01"
                         # IP Address 1.2.3.4
                         b"\x01\x02\x03\x04"
                         # ClaimType.dns
                         b"\x00\x00"
                         # vector of length 0x26
                         b"\x00\x26"
                         # vector of length 0x0e and content of "cloudflare.com"
                         b"\x0ecloudflare.com"
                         # vector of length 0x16 and content of "cloudflareresearch.com"
                         b"\x16cloudflareresearch.com")

    def test_assertion_ip_ordering(self):
        with self.assertRaises(IPv4AddressList.ValidationError):
            IPv4AddressList(
                IPv4Address("192.168.10.1"),
                IPv4Address("192.168.2.1")

            )

    def test_create_assertion(self):
        a = create_assertion(b"some subject info", ipv4_addrs=("192.168.10.1", "192.168.2.1"),
                             dns_names=("sub.example.com", "example.com",), dns_wild_cards=("example.com",),
                             ipv6_addrs=("2606:4700:4700::64", "::1"))
        print(a.print())
        b = Assertion(
            SubjectType.tls,
            SubjectInfo(b'some subject info'),
            ClaimList(
                Claim((ClaimType.dns, DNSNameList(
                    DNSName(b'example.com'),
                    DNSName(b'sub.example.com'),
                ))),
                Claim((ClaimType.dns_wildcard, DNSNameList(
                    DNSName(b'example.com'),
                ))),
                Claim((ClaimType.ipv4, IPv4AddressList(
                    IPv4Address("192.168.2.1"),
                    IPv4Address("192.168.10.1"),
                ))),
                Claim((ClaimType.ipv6, IPv6AddressList(
                    IPv6Address("::1"),
                    IPv6Address("2606:4700:4700::64")
                ))),
            )
        )
        self.assertEqual(a, b)
        self.assertEqual(a.to_bytes(), b.to_bytes())
        c = Assertion.parse(io.BytesIO(a.to_bytes()))
        self.assertEqual(c, b)

    def test_skip_assertion(self):
        a = create_assertion(b"some subject info", ipv4_addrs=("192.168.10.1", "192.168.2.1"),
                             dns_names=("sub.example.com", "example.com",), dns_wild_cards=("example.com",),
                             ipv6_addrs=("2606:4700:4700::64", "::1"))

        bs = a.to_bytes() * 10
        bio = io.BytesIO(bs)
        a.skip(bio)
        self.assertEqual(bio.tell(), len(a))

    def test_sort_dns_names(self):
        self.assertEqual(sort_dns_names(["SUB2.EXAMPLE.COM", "example.com", "sub1.example.com", "example.net"]),
                         ['example.com', 'sub1.example.com', 'SUB2.EXAMPLE.COM', 'example.net'])
