import ipaddress
import enum
import io

class ParseError(Exception): pass
class PackError(Exception): pass

def writeBE(w, x, l):
    """ Write x, an l byte unsigned integer, in big endian to w """
    assert x < 1<<(8*l)
    w.write(bytes([(x >> (8*(l-i-1))) & 255 for i in range(l)]))

def readBE(r, l):
    """ Read an l byte unsigned integer from r in big endian """
    return sum([x << (8*(l-i-1)) for i, x in enumerate(r.read(l))])

def bytes_in_int(x):
    """ Returns number of bytes required to represent x """
    return (x.bit_length() - 1) // 8 + 1

def readSized(r, minLen, maxLen):
    """ Reads a variable length opaque buffer from r """
    nBytes = bytes_in_int(maxLen)
    size = readBE(r, nBytes)
    if size < minLen: raise ParseError
    if size > maxLen: raise ParseError
    return r.read(size)

def writeSized(w, x,  minLen, maxLen):
    """ Writes a variable length opaque buffer to w """
    size = len(x)
    if size < minLen or size > maxLen:
        raise PackError
    nBytes = bytes_in_int(maxLen)
    writeBE(w, size, nBytes)
    w.write(x)

class IPv4Address:
    def __init__(self, addr):
        self.addr = ipaddress.IPv4Address(addr)

    @classmethod
    def unpack(cls, r):
        return cls(r.read(4))
    
    def pack(self, w):
        w.write(self.addr.packed)

    def __eq__(self, other):
        return self.addr == other.addr

class OpaqueVec:
    minLen = None
    maxLen = None

    def __init__(self, raw):
        self.raw = raw

    @classmethod
    def unpack(cls, r):
        return cls(readSized(r, cls.minLen, cls.maxLen))

    def pack(self, w):
        writeSized(w, self.raw, self.minLen, self.maxLen)

    def __eq__(self, other):
        return self.raw == other.raw

class DNSName(OpaqueVec):
    minLen = 1
    maxLen = 255

class BaseVector:
    ecls = None
    minLen = None
    maxLen = None

    def __init__(self, elements):
        for x in elements:
            assert isinstance(x, self.ecls)
        self.elements = elements

    @classmethod
    def unpack(cls, r):
        nBytes = bytes_in_int(cls.maxLen)
        size = readBE(r, nBytes)
        if size < cls.minLen: raise ParseError
        if size > cls.maxLen: raise ParseError
        start = r.tell()
        ret = []
        while r.tell() - start < size:
            ret.append(cls.ecls.unpack(r))
        if r.tell() - start != size: raise ParseError
        return cls(ret)

    def pack(self, w):
        nBytes = bytes_in_int(self.maxLen)
        buf = io.BytesIO()
        for x in self.elements:
            x.pack(buf)
        ret = buf.getvalue()
        size = len(ret)
        if size < self.minLen: raise PackError
        if size > self.maxLen: raise PackError
        writeBE(w, size, nBytes)
        w.write(ret)

    def __eq__(self, other):
        return self.elements == other.elements


def Vector(name, cls, minLen, maxLen):
    return type(
        name,
        (BaseVector,), {
            'minLen': minLen,
            'maxLen': maxLen,
            'ecls': cls,
        },
    )

DNSNameList = Vector('DNSNameList', DNSName, 1, (1<<16)-1)
IPv4AddressList = Vector('IPv4AddressList', IPv4Address, 4, (1<<16)-1)

class ClaimType(enum.Enum):
    dns = 0
    ipv4 = 2

class Claim:
    claim_types = {
        ClaimType.dns: DNSNameList,
        ClaimType.ipv4: IPv4AddressList,
    }

    def __init__(self, claim_type, claim_info):
        assert isinstance(claim_info, self.claim_types[claim_type])
        self.claim_type = claim_type
        self.claim_info = claim_info

    @classmethod
    def unpack(cls, r):
        claim_type = ClaimType(readBE(r, 2))
        if claim_type not in cls.claim_types: raise ParseError
        claim_info = cls.claim_types[claim_type].unpack(r)
        return cls(claim_type, claim_info)

    def pack(self, w):
        writeBE(w, self.claim_type.value,  2)
        self.claim_info.pack(w)

    def __eq__(self, other):
        return (
            self.claim_type == other.claim_type and
            self.claim_info == other.claim_info
        )

Claims = Vector('Claims', Claim, 0, (1<<16)-1)

class SubjectType(enum.Enum):
    tls = 0

class Assertion:
    def __init__(self, subject_type, subject_info, claims):
        self.subject_info = subject_info
        self.subject_type = subject_type
        self.claims = claims

    @classmethod
    def unpack(cls, r):
        # TODO create proper class for subject type
        subject_type = SubjectType(readBE(r, 2))
        subject_info = readSized(r, 0, (1<<16)-1)
        claims = Claims.unpack(r)
        return cls(subject_type, subject_info, claims)

    def pack(self, w):
        writeBE(w, self.subject_type.value, 2)
        writeSized(w, self.subject_info, 0, (1<<16)-1)
        self.claims.pack(w)

    def __eq__(self, other):
        return (
            self.subject_info == other.subject_info and
            self.subject_type == other.subject_type and
            self.claims == other.claims
        )

# Example of usage:

assertion = Assertion(
    SubjectType.tls,
    b'some subject info', 
    Claims([
        Claim(
            ClaimType.ipv4,
            IPv4AddressList([
                IPv4Address('1.1.1.1'),
                IPv4Address('1.2.3.4'),
            ]),
        ),
        Claim(
            ClaimType.dns,
            DNSNameList([
                DNSName(b'cloudflare.com'),
                DNSName(b'cloudflareresearch.com'),
            ]),
        ),
    ]),
)

w = io.BytesIO()
assertion.pack(w)
f=open("claim","bw")
f.write(w.getvalue())
f.close()
import binascii
print("packed hex: ", binascii.hexlify(w.getvalue()))
r = io.BytesIO(w.getvalue())
assertion2 = Assertion.unpack(r)

w2 = io.BytesIO()
assertion2.pack(w2)
assert w.getvalue() == w2.getvalue()
assert assertion == assertion2
print(assertion2.claims[1])