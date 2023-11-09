# Merkle Tree Certificates

This is a reference implementation of the [Merkle Tree Certificate](https://datatracker.ietf.org/doc/draft-davidben-tls-merkle-tree-certs/00/) proposal. API documentations can be found at [Github Pages](https://mia1024.github.io/merkle-tree-certificate/).

## Dependencies

The only dependency of this package is [cryptography](https://github.com/pyca/cryptography) (version 41.0.3), 
which can be installed by `pip install cryptography`. Because of the minimal dependency, 
a virtualenv is not provided with this project.

Requires Python version 3.11 or higher. 

## CLI

You can supply `-h/--help` to any CLI command for more details. The base
command is `python3 -m cli`. There is a global flag `--no-validation`, 
which will disable object-level validations. Supplying this flag can reduce the 
execution time by around 30% when running a batch. Additionally, you can specify `--no-gc`
to disable the Python garbage collection to further speed-up the process. However, this 
comes with the obvious downside of having no garbage collection (which is not really necessary if you 
are running everything from CLI as once-off action). 

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

### Performances

I want to prefix this by the fact that, due to its nature, Python is normally a few orders of magnitude slower than 
equivalent implementations in a lower level language such as C or rust. The primary purpose of this reference implementation
is to be transcribed into other production languages, instead of being production-ready itself. While care has
been taken to make sure it's reasonably performant, it is far from *optimized*.  

With that said, here is the result of running the following commands (exactly as how they appear in the quickstart section)
on a M2 MacBook Pro. 

| Command              | No flag | --no-gc | --no-validation | --no-gc --no-validation |
|----------------------|---------|---------|-----------------|-------------------------|
| stress-test          | 27.0s   | 22.5s   | 20.0s           | 15.6s                   |
| generate-certificate | 57.3ms  | 54.1ms  | 53.0ms          | 53.5ms                  |
| verify               | 21.6ms  | 18.1ms  | 18.9ms          | 17.7ms                  |

Specifically, `stress-test` simulates issuing 1M certificates. Considering a CA only needs to run this command once an hour, 
this level of performance is certainly enough. Additionally, profiling reveals that a significant amount of time is spent on 
doing filesystem IO. This can be further optimized by using a production database instead of reading and writing everything from/to 
a few files on the disk. 

For example, the `verify` CLI command takes around 20ms to execute, while the underlying call to 
API method `verify_certificate()` only takes 2.84ms. Similarly, the time for `stress-test` includes writing a 732MB file
to disk. The underlying call time to the API methods is 18.6s when no flag is specified, and 8.0s when both `--no-gc` and
`--no-validation` are specified. 

### Generate keys

For testing convenience, you can run 

``` 
python3 -m cli generate-keys <output_dir>
```

to generate an ed25519 key pair, saved to specified `output_dir`. 
The keys are generated with `test_priv.pem` and `test_pub.pem` respectively. 

### Run batch

To run a batch
``` 
python3 -m cli run-batch -i "test issuer" -k test_priv.pem -a input.example.json 
```
you can optionally specify a batch number with `-b/--batch` . If you don't, it's automatically determined from 
whichever batch number is linked to by `www/batches/latest`. The output is stored inside `www/` and you can run
a static file server over this folder to meet the requirements of section 8.1 of the specification.

## Developing

### Documentations

To generate documentations, first install sphinx, then run

```
cd docs
make html
```

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
