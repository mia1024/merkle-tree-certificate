from parsers.assertions import *

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
assert b.success
assert b.result == a
assert b.length == len(a)

print(a.print())
