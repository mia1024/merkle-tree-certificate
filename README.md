# Merkle Tree Certificates


## Dependencies

The only dependency of this package is [cryptography](https://github.com/pyca/cryptography) (version 41.0.3), 
which can be installed by `pip install cryptography`. Because of the minimal dependency, 
a virtualenv is not provided with this project.


## CLI

You can supply `-h/--help` to any CLI command for more details. The base
command is `python3 -m cli`. There is a global flag `--no-validation`, 
which will disable object-level validations. Supplying this flag can reduce the 
execution time by around 30% when running a batch. 

### Quickstart

```bash
# generate test key pairs
python3 -m cli generate-test-keys .

# run a batch
python3 -m cli run-batch -i "test issuer" -k test_priv.pem -a input.example.json 

# run stress test (which also creates a batch)
python3 -m cli stress-test -k test_priv.pem

# generate a certificate for batch 0, index 25519
python3 -m cli generate-certificate -b 1 -n 25519 -i "test issuer" -o cert.mtc

# verify a certificate against published validity window
python3 -m cli verify -c cert.mtc -v www/batches/1/signed-validity-window -k test_pub.pem -i "test issuer"
```

### Generate keys

For testing convenience, you can run 

``` 
python3 -m cli generate-keys <output_dir>
```

to generate an ed25519 key pair, saved to specified `output_dir`. 
The keys are generated with `test_priv.pem` and `test_pub.pem` respectively. 

### Run batch

TODO

### Generate certificate

TODO

### Verify

TODO

### Stress Test

TODO

## Developing

### Unit tests

To run all tests, run this command at project root
```
python3 -m unittest
```

### Typechecking

To typecheck, run

```
mypy --check-untyped-defs .             
```