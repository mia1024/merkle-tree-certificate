import argparse, sys, os
from parsers.certificate import verify_certificate, BikeshedCertificate, LabeledValidityWindow, create_merkle_tree_proof
from parsers.assertions import create_assertion
from .utils import save_merkle_tree


def get_absolute_path(p: str):
    if os.path.isabs(p):
        return p
    return os.path.join(os.getcwd(), p)


parser = argparse.ArgumentParser(
    prog='mtc',
    description='Merkle Tree Certificate CLI')
subparsers = parser.add_subparsers(title="commands", dest="command")
verify_parser = subparsers.add_parser("verify")
verify_parser.add_argument("--certificate", required=True)
verify_parser.add_argument("--validity-window", required=True)

subparsers.add_parser("generate-test")

res = parser.parse_args(sys.argv[1:])

if res.command == "verify":
    cert_path = get_absolute_path(res.certificate)
    window_path = get_absolute_path(res.validity_window)

    with open(cert_path, "rb") as f:
        cert = BikeshedCertificate.parse(f.read())
        if not cert.success:
            raise ValueError("Cannot parse certificate")

    with open(window_path, "rb") as f:
        window = LabeledValidityWindow.parse(f.read())
        if not window.success:
            raise ValueError("Cannot parse validity window")
    try:
        verify_certificate(cert.result, window.result)
    except:
        print("Cannot verify the certificate")
        raise
    else:
        print("Certificate is valid")
elif res.command == "generate-test":
    assertion = create_assertion("info", ipv4_addrs=("192.168.1.1",))
    save_merkle_tree([assertion] * 10, b"some_issuer_id", 65535)
