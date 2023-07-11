import enum
from .vector import Vector, OpaqueVector
from .ip import IPv6Address, IPv4Address
from .base import bytes_needed
from .enums import Enum
from .variant import Variant
from .structs import Struct, Field


class IPv4AddressList(Vector):
    data_type = IPv4Address
    min_length = 4
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


class IPv6AddressList(Vector):
    data_type = IPv6Address
    min_length = 16
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


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


class ClaimType(Enum):
    EnumClass = ClaimTypeEnum
    size_in_bytes = 2


class DNSName(OpaqueVector):
    min_length = 1
    max_length = 255
    marker_size = bytes_needed(max_length)


class DNSNameList(Vector):
    data_type = DNSName
    min_length = 1
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


class SubjectInfo(OpaqueVector):
    min_length = 1
    max_length = 2 ** 16 - 1
    marker_size = bytes_needed(max_length)


class Claim(Variant):
    vary_on_type = ClaimType
    mapping = {
        ClaimType(ClaimTypeEnum.dns): DNSNameList,
        ClaimType(ClaimTypeEnum.dns_wildcard): DNSNameList,
        ClaimType(ClaimTypeEnum.ipv4): IPv4AddressList,
        ClaimType(ClaimTypeEnum.ipv6): IPv6AddressList
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


