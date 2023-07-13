from typing import Iterable
def sort_dns_names(names: Iterable[str]):
    # we assume everything here is valid dns name
    names_tmp: list[list[str]] = list(map(lambda s: list(reversed(s.split("."))), names))

    # names_tmp is now a lists of lists of dns name fragments. e.g.
    # ['example.com', 'sub.example.com'] is now [['com', 'example'], ['com', 'example', 'sub']]
    names_tmp.sort(key=lambda l: list(map(str.lower, l)))
    return list(map(lambda l: ".".join(reversed(l)), names_tmp))
