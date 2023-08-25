====================================================================
Merkle Tree Certificate Reference Implementation: API documentations
====================================================================

.. toctree::
    :hidden:
    :caption: Table of Contents
    :glob:
    :maxdepth: 1

    *


Design Philosophy
=================

The primary role of this project is to be the reference implementation of
the Merkle Tree Certificate. As such, all the code in this project is designed
to be (hopefully) easily transcribed into other languages. This is why this project is written in Python
instead of a lower level language. While this code is reasonably performant, due to
the nature of Python, it is most likely to be many orders of magnitudes slower than
an implementation in C or rust.

There is a tiny serialization and deserialization framework written to facilitate this goal.
All of them are implemented in the :mod:`mtc.base` module and documented in :ref:`base`. However,
they are very specific to Python and employs a fair amount of pythonic hacks. If you aren't interested in the
Python-specific part, you can mostly just ignore them.

Dependencies
============

The only dependency of this project is :doc:`cryptography <cryptography:installation>`.

High level functions
====================

This package exposes the following high-level functions. If you only want to use the API from this library, these are
all you need.

.. autofunction:: mtc.assertion.create_assertion
.. autofunction:: mtc.tree.create_merkle_tree
.. autofunction:: mtc.certificate.create_merkle_tree_proofs(nodes: NodesList, issuer_id: bytes, batch_number: int, index: int) -> Proof
.. autofunction:: mtc.certificate.create_merkle_tree_proof(nodes: NodesList, issuer_id: bytes, batch_number: int, number_of_assertions_in_batch: int) -> list[Proof]
.. autofunction:: mtc.certificate.create_signed_validity_window(nodes: NodesList, issuer_id: bytes, batch_number: int,private_key: ed25519.Ed25519PrivateKey,previous_validity_window: Optional[SignedValidityWindow] = None)
.. autofunction:: mtc.certificate.create_bikeshed_certificate
.. autofunction:: mtc.certificate.verify_certificate

Interfaces
==========

The following interfaces (i.e. :class:`~mtc.base.parser.Parser` s) are implemented


.. autoclass:: mtc.ip.IPv4Address(value:str|bytes)
.. autoclass:: mtc.ip.IPv6Address(value:str|bytes)
.. autoclass:: mtc.assertion.IPv4AddressList(*value:IPv4Address)
    :members: min_length, max_length, data_type
.. autoclass:: mtc.assertion.IPv6AddressList(*value:IPv6Address)
    :members: min_length, max_length, data_type
.. autoclass:: mtc.assertion.SubjectType(value:int)
    :members: tls
.. autoclass:: mtc.assertion.ClaimType(value:int)
    :members: dns, dns_wildcard, ipv4, ipv6
.. autoclass:: mtc.assertion.DNSName(value:bytes)
        :members: min_length, max_length
.. autoclass:: mtc.assertion.DNSNameList(*value:DNSNameList)
    :members: min_length, max_length, data_type
.. autoclass:: mtc.assertion.SubjectInfo(value:bytes)
    :members: min_length, max_length
.. autoclass:: mtc.assertion.Claim(value:tuple[ClaimType,DNSNameList|IPv4AddressList|IPv6AddressList]))
.. autoclass:: mtc.assertion.ClaimList(value:bytes)
.. autoclass:: mtc.assertion.Assertion(*value:tuple[SubjectType, SubjectInfo, ClaimList])
    :members: subject_type, subject_info, claims
.. autoclass:: mtc.assertion.Assertions(*value:Assertion)
    :members: data_type, min_length, max_length