from typing import Self, TypeVar, Any, NamedTuple


class BinRep:
    """
    Provides an interface to serialize and deserialize an object to bytes. Do not use directly.
    """

    n_bytes = 1

    def __init__(self, /, value: Any) -> None:
        self.value = value

    @classmethod
    def from_bytes(cls, binary: bytes) -> Self:
        raise NotImplementedError("Do not use this class directly")

    def to_bytes(self) -> bytes:
        raise NotImplementedError("Do not use this class directly")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.value}>"


class Integer(BinRep):
    def __init__(self, /, value: int):
        self.value = value

    @classmethod
    def from_bytes(cls, binary: bytes) -> Self:
        return cls(int.from_bytes(binary, "big", signed=False))

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(self.n_bytes, "big", signed=False)


class String(BinRep):
    def __init__(self, /, value: str):
        self.value = value

    @classmethod
    def from_bytes(cls, binary: bytes) -> Self:
        return cls(binary.decode("ascii"))

    def to_bytes(self) -> bytes:
        return self.value.encode("ascii")


class BaseVector(BinRep):
    data_type = BinRep

    def __init__(self, /, value: list[Any]):
        l:list[BinRep]=[]
        for v in value:
            if isinstance(v,BinRep):
                l.append(v)
            else:
                l.append(self.data_type(v))
        self.value = l

    @classmethod
    def from_bytes(cls, binary: bytes) -> Self:
        if len(binary) % cls.n_bytes != 0:
            raise ValueError("Vector of incorrect length")
        l = []
        for i in range(0, len(binary), cls.n_bytes):
            l.append(cls.data_type.from_bytes(binary[cls.n_bytes * i:cls.n_bytes * (i + 1)]))
        return cls(l)

    def to_bytes(self) -> bytes:
        res = b""
        for v in self.value:
            res += v.to_bytes()
        return res


class StringVector(BaseVector):
    # TODO: define byte length
    data_type = String


class IPv4Address(BaseVector):
    data_type = Integer
    n_bytes = 1

class IPv4AddressVector(BaseVector):
    data_type = IPv4Address
    n_bytes = 4

class IPv6Address(BaseVector):
    data_type = Integer
    n_bytes = 4

class IPv6AddressVector(BaseVector):
    data_type = IPv6Address
    n_bytes = 16


V = TypeVar("V", bound=BaseVector)


class OpaqueVector(BinRep):
    def __init__(self, /, value: bytes):
        self.value = value

    @classmethod
    def from_bytes(cls, binary: bytes) -> Self:
        raise ValueError("Cannot parse an opaque vector without a data type")

    def to_bytes(self) -> bytes:
        return self.value

    def instantiate(self, vector_type: type[V]) -> V:
        return vector_type.from_bytes(self.value)


class Field(NamedTuple):
    name: str
    data_type: type[BinRep]


class BaseStruct(BinRep):
    fields: list[Field] = []

    def __init__(self, /, value: list[Any]) -> None:
        if len(value) != len(self.fields):
            raise ValueError("Input to a struct must have the same length as struct definition")
        l: list[BinRep] = []

        # accepts both raw value and instantiated BinRep
        for i, v in enumerate(value):
            if isinstance(v, BinRep):
                l.append(v)
            else:
                l.append(self.fields[i].data_type(v))

        self.value = l

    @classmethod
    def from_bytes(cls, binary: bytes) -> Self:
        # TODO: we probably need a parser for this...
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        r = b""
        for v in self.value:
            r += v.to_bytes()
        return r


class Claim(BaseStruct):
    # we need to somehow define a way to associate ClaimType to different types of vectors
    fields = [
        Field("claim_type", Integer),
        Field("claim_info", OpaqueVector),
    ]


class ClaimVector(BaseVector):
    data_type = Claim


class Assertion(BaseStruct):
    fields = [
        Field("subject_type", Integer),
        Field("subject_info", OpaqueVector),
        Field("claims", ClaimVector)
    ]


a=Assertion([0, b"subject info", [
    [0,b"1.1.1.1"],
    [2,b"cloudflare.com"]
]])

print(a.to_bytes())