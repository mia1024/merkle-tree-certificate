from dataclasses import dataclass
import json
from parsers import create_assertion, Assertion
import base64
from typing import Optional


@dataclass
class AssertionInput:
    subjectType: str
    subjectInfo: str

    dns: Optional[list[str]]
    dnsWildcard: Optional[list[str]]
    ipv4Addr: Optional[list[str]]
    ipv6Addr: Optional[list[str]]


def read_assertions_input(path: str)->list[Assertion]:
    f = open(path, "r")
    content = f.read()
    f.close()
    data = json.loads(content)

    if not isinstance(data, list):
        raise ValueError("Assertion input must be a list")

    l: list[Assertion] = []

    for i, v in enumerate(data):
        try:
            a_in = AssertionInput(**v)
        except:
            print(f"Cannot read item {i} from assertion input")
            raise
        if a_in.subjectType != "tls":
            raise ValueError("Only TLS is a supported subject type")

        assertion = create_assertion(subject_info=base64.b64decode(a_in.subjectInfo), ipv4_addrs=a_in.ipv4Addr,
                                     ipv6_addrs=a_in.ipv6Addr, dns_names=a_in.dns, dns_wild_cards=a_in.dnsWildcard)
        l.append(assertion)

    return l