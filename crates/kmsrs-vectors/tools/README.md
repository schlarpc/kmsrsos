# Reference vector generators

The known-answer tests in `kmsrs-crypto` pin our output against the vlmcsd
reference implementation. This directory holds the harness that produced those
vectors, so they can be regenerated and audited rather than trusted.

## `vlmcsd_crypto_vectors.c`

Emits block-cipher, CBC-MAC, CBC-mode and SHA-256/HMAC vectors from vlmcsd's
own `crypto.c`. Its first output is the FIPS-197 §C.1 AES-128 vector, which
validates the build itself: if that line is wrong, nothing below it is worth
reading.

Vectors currently in the tree were generated from
[`Wind4/vlmcsd`](https://github.com/Wind4/vlmcsd) at `70e0357` (2023-07-28),
the final commit before the project was archived.

```shell
$ git clone --depth 1 https://github.com/Wind4/vlmcsd.git
$ gcc -O1 -I vlmcsd/src -o vectorgen vlmcsd_crypto_vectors.c \
      vlmcsd/src/crypto.c vlmcsd/src/crypto_internal.c vlmcsd/src/endian.c
$ ./vectorgen
```

Cross-implementation vectors from py-kms arrive with `TEST-004` (#225); the
differential harness there covers whole exchanges rather than primitives.
