from math import ceil


def bytes_needed(n: int) -> int:
    """
    calculates the minimum number of bytes needed to represent n (unsigned)
    """
    # avoid using log2 because it might cause floating-point errors when n is large
    return ceil(n.bit_length() / 8)


def bytes_to_int(b: bytes) -> int:
    """
    converts a bytes object to an int (unsigned)
    """
    return int.from_bytes(b, "big", signed=False)


def int_to_bytes(n: int, size: int) -> bytes:
    """
    converts n into its byte representation (unsigned) of *size* bytes.
    """
    return n.to_bytes(size, "big", signed=False)


def printable_bytes_truncate(b: bytes, limit: int) -> str:
    """
    Converts a bytes object into a string, with non-printable characters replaced by _.
    Similar to what you see in a hex-editor

    :param b: the bytes to be printed
    :param limit: the length limit
    :return: the string with non-printable bytes replaced
    """
    if len(b) > limit:
        b = b[:limit - 3] + b"..."

    s = ""
    for c in b:
        if not 33 <= c <= 126:
            s += "."
        else:
            s += chr(c)

    return s


__all__ = ["bytes_needed", "bytes_to_int", "int_to_bytes", "printable_bytes_truncate", ]
