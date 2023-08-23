import os

from mtc import verify_certificate, BikeshedCertificate, SignedValidityWindow
from .utils import read_public_key


def verify_cli(cert_path:os.PathLike, window_path:os.PathLike, pub_key_path:os.PathLike, issuer_id:str):
    with open(cert_path, "rb") as f:
        cert = BikeshedCertificate.parse(f)

    with open(window_path, "rb") as f:
        window = SignedValidityWindow.parse(f)

    pub_key = read_public_key(pub_key_path)

    try:
        verify_certificate(cert, window, issuer_id.encode(), pub_key)
    except:
        print("Cannot verify the certificate")
        raise
    else:
        print("Certificate is valid")
