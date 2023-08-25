.. _Base:

============
Base Parsers
============

This package contains the basic building blocks that the rest of the code is built on.
The foundational element is the :class:`~mtc.base.Parser` class. Everything documented
here can be imported from :mod:`mtc.base`.

.. contents::


######
Parser
######

.. autoclass:: mtc.base.parser.Parser(value:typing.Any)
    :members: disable_validation, print, parse, to_bytes, skip, validate
    :special-members: __init__, __repr__, __str__, __eq__, __hash__, __len__

.. autoexception:: mtc.base.parser.ParserError
.. autoexception:: mtc.base.parser.Parser.ParsingError
.. autoexception:: mtc.base.parser.Parser.ValidationError

######
Struct
######

The :mod:`~mtc.base.struct` module defines the :class:`~mtc.base.struct.Struct` class, which creates structs in
accordance to the TLS presentation language and allows you to define them in a declarative way.

.. autoclass:: mtc.base.struct.Struct(*values:~mtc.base.parser.Parser)
    :members: print, parse, to_bytes, skip, validate
    :exclude-members: __new__
    :undoc-members:

.. autoclass:: mtc.base.struct.StructMeta


######
Vector
######

The :mod:`~mtc.base.vector` module defines 3 common types encountered in the
TLS presentation language: :class:`~mtc.base.vector.Vector`, :class:`~mtc.base.vector.OpaqueVector`,
and :class:`~mtc.base.vector.Array`. Both :class:`~mtc.base.vector.Vector` and :class:`~mtc.base.vector.OpaqueVector` have
a marker at the beginning of their serialized forms indicating how many bytes this vector contain, whereas
:class:`~mtc.base.vector.Array` does not because it is fixed size. All the lengths referred to in this module are in
bytes.

To define a new vector, subclass :class:`~mtc.base.vector.Vector` and define :attr:`min_length`, :attr:`max_length`,
and :attr:`data_type`. For example,

.. code-block::

    class ClaimList(Vector):
        data_type = Claim
        min_length = 0
        max_length = 2 ** 16 - 1

To define a new opaque vector, subclass :class:`~mtc.base.vector.OpaqueVector` and define :attr:`min_length` and :attr:`max_length`.

To define a new array, subclass :class:`~mtc.base.vector.Array` and define :attr:`length`.

.. autoclass:: mtc.base.vector.Vector(*values:~mtc.base.parser.Parser)
    :members: print, parse, to_bytes, skip, validate, min_length, max_length, marker_size, data_type
    :undoc-members:


.. autoclass:: mtc.base.vector.OpaqueVector(value:bytes)
    :members: print, parse, to_bytes, skip, validate, min_length, max_length, marker_size
    :undoc-members:


.. autoclass:: mtc.base.vector.Array(value:bytes)
    :members: print, parse, to_bytes, skip, validate, length
    :undoc-members:


.. autoclass:: mtc.base.vector.VectorMeta

    Similar to :class:`~mtc.base.struct.StructMeta`, this is what allows vectors to be defined in a declarative way behind
    the scene.


#########
Numerical
#########

Numerical classes handle common unsigned integer types. To define a new unsigned integer type, simply subclass :class:`~mtc.base.numerical.Integer`
and define the :attr:`size_in_bytes` attribute. For example

    .. code-block::

        class UInt32(Integer):
            size_in_bytes = 4

defines an unsigned 32-bit integer.

.. autoclass:: mtc.base.numerical.Integer(value:int)
    :members: print, parse, to_bytes, skip, validate, size_in_bytes
    :undoc-members:

.. autoclass:: mtc.base.numerical.UInt8(value:int)

.. autoclass:: mtc.base.numerical.UInt16(value:int)

.. autoclass:: mtc.base.numerical.UInt32(value:int)

.. autoclass:: mtc.base.numerical.UInt64(value:int)


#####
Enums
#####

The :class:`~mtc.base.enums.Enum` class is a thin wrapper around Python's built-in enum type. To define a enum, you first
define it as you normally would through :class:`enum.IntEnum`. Then, define a new subclass of :class:`~mtc.base.enums.Enum`
and define both :attr:`EnumClass` and :attr:`size_in_bytes`. For example

.. code-block::

    class ClaimTypeEnum(enum.IntEnum):
        dns = 0
        dns_wildcard = 1
        ipv4 = 2
        ipv6 = 3

    class ClaimType(Enum):
        EnumClass = ClaimTypeEnum
        size_in_bytes = 2

        dns: "ClaimType"
        dns_wildcard: "ClaimType"
        ipv4: "ClaimType"
        ipv6: "ClaimType"

Technically speaking, you don't have to annotate anything on the :class:`~mtc.base.enums.Enum` to access the attributes. In the
example above, you can actually remove the last four lines of code and everything will still work just fine (e.g.
you can still access :code:`ClaimType.ipv4`). However,
in order for IDE auto-completions and static type checkers to work correctly, you have to provide those annotations.

.. autoclass:: mtc.base.enums.Enum(value:int)
    :members: print, parse, to_bytes, skip
    :undoc-members:

.. autoclass:: mtc.base.enums.EnumMeta

    Similar to :class:`~mtc.base.struct.StructMeta`, this is what allows enums to be proxied through a built-in enum and
    accessed by names.



#######
Variant
#######

Implements variant as defined in the TLS presentation language using :class:`~mtc.base.enums.Enum`. To define a new
variant, subclass :class:`mtc.base.variant.Variant` and define :attr:`vary_on_type` and :attr:`mapping`. For example

.. code-block::

    class Claim(Variant):
    vary_on_type = ClaimType
    mapping = {
        ClaimType.dns: DNSNameList,
        ClaimType.dns_wildcard: DNSNameList,
        ClaimType.ipv4: IPv4AddressList,
        ClaimType.ipv6: IPv6AddressList
    }


.. autoclass:: mtc.base.variant.Variant
    :members: print, parse, to_bytes
    :undoc-members:



#####
Utils
#####

This module contains some simple utility functions.

.. automodule:: mtc.base.utils
    :members: