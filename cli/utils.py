import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from mtc import create_signed_validity_window, Assertion, Assertions, SignedValidityWindow, create_merkle_tree, \
    create_merkle_tree_proofs, create_bikeshed_certificate, BikeshedCertificate

ROOT_DIR = Path(os.path.dirname(os.path.abspath(__file__))).parent
BATCHES_ROOT = ROOT_DIR / "www" / "batches"


def get_absolute_path(path: os.PathLike):
    expanded = os.path.expanduser(path)
    if os.path.isabs(expanded):
        return expanded
    return os.path.join(os.getcwd(), path)


def read_private_key(path: os.PathLike) -> ed25519.Ed25519PrivateKey:
    f = open(path, "rb")
    data = f.read()
    f.close()
    key = serialization.load_pem_private_key(data, None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("Supplied private key is not a PEM-encoded ED25519 key")
    return key


def read_public_key(path: os.PathLike) -> ed25519.Ed25519PublicKey:
    f = open(path, "rb")
    data = f.read()
    f.close()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("Supplied public key is not a PEM-encoded ED25519 key")
    return key


def save_batch(assertions: list[Assertion], issuer_id: bytes, batch_number: int,
               private_key: ed25519.Ed25519PrivateKey):
    if batch_number == 0:
        validity_window = None
    else:
        try:
            validity_window = read_validity_window(batch_number - 1)
        except FileNotFoundError:
            raise ValueError(f"Invalid batch number {batch_number}. Previous batch not found")

    dest = BATCHES_ROOT / str(batch_number)

    nodes = create_merkle_tree(assertions, issuer_id, batch_number)
    window = create_signed_validity_window(nodes, issuer_id, batch_number, private_key, validity_window)
    proofs = create_merkle_tree_proofs(nodes, issuer_id, batch_number, len(assertions))

    os.makedirs(dest, exist_ok=True)

    f = open(dest / "signed-validity-window", "wb")
    f.write(window.to_bytes())
    f.close()

    f = open(dest / "assertions", "wb")
    f.write(Assertions(*assertions).to_bytes())
    f.close()

    f = open(dest / "certificates", "wb")
    for i in range(len(assertions)):
        cert = create_bikeshed_certificate(assertions[i], proofs[i])
        f.write(cert.to_bytes())
    f.close()

    try:
        os.remove(BATCHES_ROOT / "latest")
    except FileNotFoundError:
        pass
    os.symlink(str(batch_number), BATCHES_ROOT / "latest", target_is_directory=True)


def get_latest_batch_number():
    try:
        # the created link was relative
        return int(os.readlink(BATCHES_ROOT / "latest"))
    except (OSError, ValueError):
        return -1


def read_validity_window(batch_number: int) -> SignedValidityWindow:
    f = open(BATCHES_ROOT / str(batch_number) / "signed-validity-window", "rb")
    window = SignedValidityWindow.parse(f)
    return window


def read_assertion(batch_number: int, index: int) -> Assertion:
    with open(BATCHES_ROOT / str(batch_number) / "assertions", "rb") as f:
        f.seek(Assertions.marker_size)
        for i in range(index):
            Assertion.skip(f)
        return Assertion.parse(f)


def read_certificate(batch_number: int, index: int) -> BikeshedCertificate:
    with open(BATCHES_ROOT / str(batch_number) / "certificates", "rb") as f:
        for i in range(index):
            BikeshedCertificate.skip(f)
        cert= BikeshedCertificate.parse(f)
        print(cert.print())
        return cert


def generate_test_key_pairs(path: str):
    if not os.path.isdir(path):
        raise ValueError(f"{path} is not a directory")

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    with open(os.path.join(path, "test_priv.pem"), "wb") as f:
        data = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
        f.write(data)

    with open(os.path.join(path, "test_pub.pem"), "wb") as f:
        data = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        f.write(data)
