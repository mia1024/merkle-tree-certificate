from parsers.certificate import verify_certificate, BikeshedCertificate, SignedValidityWindow
from .utils import read_public_key


def verify_cli(cert_path, window_path, pub_key_path, issuer_id):
    with open(cert_path, "rb") as f:
        cert = BikeshedCertificate.parse(f)

    with open(window_path, "rb") as f:
        window = SignedValidityWindow.parse(f)

    pub_key = read_public_key(pub_key_path)

    try:
        verify_certificate(cert.result, window.result, issuer_id.decode(), pub_key)
    except:
        print("Cannot verify the certificate")
        raise
    else:
        print("Certificate is valid")
