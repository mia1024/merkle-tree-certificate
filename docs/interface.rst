.. _Interface:

==========
Interfaces
==========

Here is a list of interfaces (i.e. :class:`~mtc.base.parser.Parser` s) implemented as defined in
the specification. When you are working with them, it might sometimes be helpful to check out the
result of their :meth:`~mtc.base.parser.Parser.print` method. For example, calling this on a
:class:`~mtc.certificate.BikeshedCertificate` produces

.. code-block::

    --------------------Struct BikeshedCertificate (780)--------------------
            --------------------Struct Assertion (109)--------------------
                    2 SubjectType tls(0)
                    34 SubjectInfo ..X.....z.X.Q.....(.1....y....]`
                    --------------------Vector ClaimList (73)--------------------
                            2 ClaimType dns(0)
                                    --------------------Vector DNSNameList (21)--------------------
                                            19 DNSName www.cloudflare.com
                                    ------------------End vector DNSNameList------------------
                            2 ClaimType ipv4(2)
                                    --------------------Vector IPv4AddressList (10)--------------------
                                            4 IPv4Address 1.0.0.1
                                            4 IPv4Address 1.1.1.1
                                    ------------------End vector IPv4AddressList------------------
                            2 ClaimType ipv6(3)
                                    --------------------Vector IPv6AddressList (34)--------------------
                                            16 IPv6Address 2606:4700:4700::1001
                                            16 IPv6Address 2606:4700:4700::1111
                                    ------------------End vector IPv6AddressList------------------
                    ------------------End vector ClaimList------------------
            ------------------End struct Assertion------------------
            --------------------Struct Proof (671)--------------------
                    --------------------Struct TrustAnchor (19)--------------------
                            2 ProofType merkle_tree_sha256(0)
                            --------------------Struct MerkleTreeTrustAnchor (17)--------------------
                                    12 IssuerID test.issuer
                                    4 UInt32 8
                            ------------------End struct MerkleTreeTrustAnchor------------------
                    ------------------End struct TrustAnchor------------------
                    --------------------Struct MerkleTreeProofSHA256 (652)--------------------
                            8 UInt64 25
                            --------------------Vector SHA256Vector (642)--------------------
                                    32 Array SHA256Hash .......<-1.$..6..l......[......(
                                    32 Array SHA256Hash 6.v.e......%`S..j.9PL#..~......u
                                    32 Array SHA256Hash .`<.?3...ZH.+.t.hn..2......HN..Q
                                    32 Array SHA256Hash ......A.*........JJ@9..4.o....e.
                                    32 Array SHA256Hash ...$.sAV..Z..}((..`....~x.qRZ5.$
                                    32 Array SHA256Hash 7..t.LL...Vy7.........r...@..6.@
                                    32 Array SHA256Hash .B`.O.....a.g.C:D.KC+..Y5.#fx..A
                                    32 Array SHA256Hash .x.X..q....cF"b....RG.S......N|W
                                    32 Array SHA256Hash ..w.jP=(v.bT.l*.!....P......#=;3
                                    32 Array SHA256Hash ..../N".c$.H;#.h&0..............
                                    32 Array SHA256Hash TP..G.,.,.-.^".k..6qE..b.1..6..M
                                    32 Array SHA256Hash ...F\{,f.n*_..W.......e.F.^."..v
                                    32 Array SHA256Hash 53...y...rf.(",..[=[:...\l.....4
                                    32 Array SHA256Hash .f.."".,.:q......=gj...^..../..4
                                    32 Array SHA256Hash ..'/...Y.B)-.b(H@.+.=..G.._J*.R.
                                    32 Array SHA256Hash &.V...(..l.?[.5...I[.z...!....Am
                                    32 Array SHA256Hash 5.r2=.-..s}.b...........P_.|.5~F
                                    32 Array SHA256Hash ....>...3t....~'..-..O..&.@..L.W
                                    32 Array SHA256Hash .!..&$8..br%..............1.2...
                                    32 Array SHA256Hash .L..0um.o..&$.u..Al.?.R.%..T..J.
                            ------------------End vector SHA256Vector------------------
                    ------------------End struct MerkleTreeProofSHA256------------------
            ------------------End struct Proof------------------
    ------------------End struct BikeshedCertificate------------------




The following interfaces are implemented


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
.. autoclass:: mtc.tree.Distinguisher(value:int)
    :members: HashEmptyInput, HashNodeInput, HashAssertionInput
.. autoclass:: mtc.tree.SHA256Hash(*value:bytes)
    :members: length
.. autoclass:: mtc.tree.IssuerID(*value:bytes)
    :members: min_length, max_length
.. autoclass:: mtc.tree.HashHead(value:tuple[Distinguisher, IssuerID, UInt32])
    :members: to_bytes, parse, print
.. autoclass:: mtc.tree.HashEmptyInput(*value:tuple[HashHead,UInt64,UInt8])
    :members: hash_head, index, level
.. autoclass:: mtc.tree.HashNodeInput(*value:tuple[HashHead,UInt64,UInt8,SHA256Hash,SHA256Hash])
    :members: hash_head, index, level, left, right
.. autoclass:: mtc.tree.HashAssertionInput(*value:tuple[HashHead,UInt64,Assertion])
    :members: hash_head, index, assertion
.. autoclass:: mtc.certificate.TreeHeads(value:list[SHA256Hash])
    :members: to_bytes, parse, validate
.. autoclass:: mtc.certificate.ValidityWindow(*value:tuple[UInt32,TreeHeads])
    :members: batch_number, tree_heads
.. autoclass:: mtc.certificate.ValidityWindowLabel(value: bytes = b"Merkle Tree Crts ValidityWindow\0")
    :members: to_bytes, parse, validate
.. autoclass:: mtc.certificate.LabeledValidityWindow(*value:tuple[ValidityWindowLabel,IssuerID,ValidityWindow])
    :members: label, issuer_id, window
.. autoclass:: mtc.certificate.Signature(value:bytes)
    :members: min_length, max_length
.. autoclass:: mtc.certificate.SignedValidityWindow(*value:tuple[ValidityWindow,Signature])
    :members: window, signature
.. autoclass:: mtc.certificate.ProofType(value:int)
    :members: merkle_tree_sha256
.. autoclass:: mtc.certificate.SHA256Vector(*value:tuple[SHA256Hash])
    :members: min_length, max_length, data_type
.. autoclass:: mtc.certificate.TrustAnchorData(value:bytes)
    :members: min_length, max_length
.. autoclass:: mtc.certificate.ProofData(value:bytes)
    :members: min_length, max_length
.. autoclass:: mtc.certificate.MerkleTreeTrustAnchor(*value:tuple[IssuerID, UInt32])
    :members: issuer_id, batch_number, to_bytes
.. autoclass:: mtc.certificate.MerkleTreeProofSHA256(*value:tuple[UInt64, SHA256Vector])
    :members: index, path, to_bytes
.. autoclass:: mtc.certificate.TrustAnchor(*value:tuple[ProofType, TrustAnchorData | MerkleTreeTrustAnchor])
    :members: proof_type, trust_anchor_data, skip
.. autoclass:: mtc.certificate.Proof(*value:tuple[TrustAnchor, ProofData | MerkleTreeProofSHA256])
    :members: trust_anchor, proof_data, parse, skip
.. autoclass:: mtc.certificate.BikeshedCertificate(*value:tuple[Assertion, Proof])
    :members: assertion, proof