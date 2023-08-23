import argparse, sys
import time

from .utils import get_absolute_path, generate_test_key_pairs
from .verify import verify_cli
from .batch import generate_batch, load_certificate, stress_test_batch
from mtc.base import Parser

parser = argparse.ArgumentParser(
    prog='mtc',
    description='Merkle Tree Certificate CLI')

parser.add_argument("--no-validation", action="store_true", help="disable object validation")
subparsers = parser.add_subparsers(title="modes", dest="command",
                                   description="The mode to run the CLI in. Run this program with --help after a mode to see more options",
                                   metavar="mode", required=True)

# ----------- run batch command ----------
batch_parser = subparsers.add_parser("run-batch", help="Run a batch as a CA")
batch_parser.add_argument("-k", "--private-key", required=True,
                          help="path to issuer's private key, pem encoded")
batch_parser.add_argument("-b", "--batch-number", type=int,
                          help="optional. batch number to generate. leave blank to use latest batch number from previous batch")
batch_parser.add_argument("-a", "--assertions", required=True, help="path to the json file for the assertion list")
batch_parser.add_argument("-i", "--issuer-id", required=True, help="the issuer ID for the CA")

# ----------- generate certificate command ----------

certificate_parser = subparsers.add_parser("generate-certificate",
                                           help="generate a certificate for an assertion within a batch")
certificate_parser.add_argument("-b", "--batch-number", type=int, required=True,
                                help="batch number of the assertion")
certificate_parser.add_argument("-i", "--issuer-id", required=True, help="the issuer ID for the CA")
certificate_parser.add_argument("-n", "--index", required=True, type=int,
                                help="the index of the assertion within the batch")
certificate_parser.add_argument("-o", "--out", required=True, help="the path to save generated certificate to")

# ----------- verify command ----------
verify_parser = subparsers.add_parser("verify", help="Verify a certificate")
verify_parser.add_argument("-c", "--certificate", required=True, help="path to certificate")
verify_parser.add_argument("-v", "--validity-window", required=True, help="path to validity window")
verify_parser.add_argument("-k", "--public-key", required=True,
                           help="path to expected issuer's public key, pem encoded")
verify_parser.add_argument("-i", "--issuer-id", required=True, help="the expected issuer ID for the certificate")

# ----------- stress test command ----------
test_parser = subparsers.add_parser("stress-test",
                                    help="Stress test by loading the sample and run a batch with 1M copies of it")
test_parser.add_argument("-k", "--private-key",
                         help="The path to the pem encoded private key file. Can be generated with generate-test-keys",
                         required=True)

# ----------- generate key pair command ----------
test_key_pair_parser = subparsers.add_parser("generate-test-keys",
                                             help="Generate a test key pair. Files will be saved as test-pub.pem and test-priv.pem")
test_key_pair_parser.add_argument("out_dir", help="the directory path to save the test key pair in.")


def run():
    time_start = time.time()
    res = parser.parse_args(sys.argv[1:])

    if res.no_validation:
        Parser.disable_validation()

    match res.command:
        case "verify":
            verify_cli(get_absolute_path(res.certificate),
                       get_absolute_path(res.validity_window),
                       get_absolute_path(res.public_key), res.issuer_id)
        case "run-batch":
            generate_batch(
                get_absolute_path(res.assertions), res.issuer_id, get_absolute_path(res.private_key), res.batch_number
            )
        case "generate-certificate":
            load_certificate(res.batch_number, res.index, get_absolute_path(res.out))
        case "stress-test":
            stress_test_batch(
                get_absolute_path(res.private_key)
            )
        case "generate-test-keys":
            generate_test_key_pairs(get_absolute_path(res.out_dir))

        case _:
            parser.print_help()

    print(f"Completed in {round((time.time() - time_start) * 1000, 2)}ms")
