import enum
import re
import ipaddress
from typing import Iterable
from .vector import Vector, OpaqueVector
from .ip import IPv6Address, IPv4Address
from .base import bytes_needed
from .enums import Enum
from .variant import Variant
from .structs import Struct, Field
from .utils import sort_dns_names


class IPv4AddressList(Vector):
    data_type = IPv4Address
    min_length = 4
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)

    def validate(self) -> None:
        if sorted(self.value, key=lambda v: v.value) != self.value:
            raise self.ValidationError("IP addresses must be in lexical order")


class IPv6AddressList(Vector):
    data_type = IPv6Address
    min_length = 16
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)

    def validate(self) -> None:
        if sorted(self.value, key=lambda v: v.value) != self.value:
            raise self.ValidationError("IP addresses must be in lexical order")


class SubjectTypeEnum(enum.IntEnum):
    tls = 0


class ClaimTypeEnum(enum.IntEnum):
    dns = 0
    dns_wildcard = 1
    ipv4 = 2
    ipv6 = 3


class SubjectType(Enum):
    EnumClass = SubjectTypeEnum
    size_in_bytes = 2

    tls: "SubjectType"


class ClaimType(Enum):
    EnumClass = ClaimTypeEnum
    size_in_bytes = 2

    dns: "ClaimType"
    dns_wildcard: "ClaimType"
    ipv4: "ClaimType"
    ipv6: "ClaimType"


class DNSName(OpaqueVector):
    min_length = 1
    max_length = 255
    marker_size = bytes_needed(max_length)

    def validate(self) -> None:
        super().validate()
        if re.match(b"^[a-z0-9-.]+$", self.value, re.I) is None:
            raise self.ValidationError(f"Invalid DNS name {self.value.decode('latin-1')}")


class DNSNameList(Vector):
    data_type = DNSName
    min_length = 1
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)

    def validate(self) -> None:
        super().validate()
        names = list(map(lambda b: b.value.decode("ascii"), self.value))
        sorted_names = sort_dns_names(names)
        if names != sorted_names:
            raise self.ValidationError("DNS Names must be in sorted order")


class SubjectInfo(OpaqueVector):
    min_length = 1
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


class Claim(Variant):
    vary_on_type = ClaimType
    mapping = {
        ClaimType.dns: DNSNameList,
        ClaimType.dns_wildcard: DNSNameList,
        ClaimType.ipv4: IPv4AddressList,
        ClaimType.ipv6: IPv6AddressList
    }


class ClaimList(Vector):
    data_type = Claim
    min_length = 0
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(2 ** 16 - 1)


class Assertion(Struct):
    fields = [
        Field("subject_type", SubjectType),
        Field("subject_info", SubjectInfo),
        Field("claims", ClaimList)
    ]


def create_assertion(subject_info: str, *, ipv4_addrs: Iterable[str] | None = None,
                     ipv6_addrs: Iterable[str] | None = None, dns_names: Iterable[str] | None = None,
                     dns_wild_cards: Iterable[str] | None = None) -> Assertion:
    subject_info_bytes = SubjectInfo(subject_info.encode())
    claims: list[Claim] = []

    if dns_names is not None:
        claims.append(Claim((ClaimType.dns, DNSNameList(
            list(map(DNSName, map(lambda s: s.encode(), sort_dns_names(dns_names))))))))

    if dns_wild_cards is not None:
        claims.append(Claim(
            (ClaimType.dns_wildcard,
             DNSNameList(list(map(DNSName, map(lambda s: s.encode(), sort_dns_names(dns_wild_cards))))))))

    if ipv4_addrs is not None:
        claims.append(
            Claim((ClaimType.ipv4, IPv4AddressList(
                list(map(IPv4Address, sorted(ipv4_addrs, key=lambda a: ipaddress.IPv4Address(a))))))))

    if ipv6_addrs is not None:
        claims.append(
            Claim((ClaimType.ipv6, IPv6AddressList(
                list(map(IPv6Address, sorted(ipv6_addrs, key=lambda a: ipaddress.IPv6Address(a))))))))

    # looks like mypy has a bug on the next line
    return Assertion([SubjectType.tls, subject_info_bytes, ClaimList(claims)])  # type: ignore


__all__ = ["IPv4AddressList", "IPv6AddressList", "SubjectType", "ClaimType",
           "DNSName", "DNSNameList", "SubjectInfo", "Claim", "ClaimList", "Assertion", "create_assertion"]
