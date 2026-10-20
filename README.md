# eMudhra CA Key Compromise Proof-of-Concept

In October 2026, eight eMudhra/emSign intermediate CA keys were distrusted across
the ecosystem (Go, Firefox, Chrome, Apple, Microsoft). The root cause was a
catastrophic key-generation failure: the P-384 (secp384r1) private keys are tiny
integers. This PoC recovers all eight from public certificate data alone by a
trivial search, then proves each recovery by signing under the published key.

The recovered private keys are the scalars `4, 56, 66, 115, 155, 156, 230, 237`.

## Requirements

- Python 3.10+
- `cryptography` (`pip install cryptography`)

## Usage

```bash
python3 emudhra_poc.py
```

## Example output

```
eMudhra OV TLS CA - G3C  (secp384r1, 4.7 ms, verified=True)
        SPKI 63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8
        carried by 2 cert(s), issued by: AAA Certificate Services, emSign Root TLS CA - G3
        private key recovered: d = 4
...
RESULT: recovered 8/8 distinct private keys from public certificates by a 256-value search.
```

## How it works

For each certificate's public key `Q`, it searches `d = 1..256` for `d·G == Q`.
A properly generated P-384 key sits in a ~2^384 space and needs ~2^192 operations to
recover, i.e. it should be computationally infeasible. Each hit is confirmed by signing a
challenge with the recovered key and verifying it against the published key.

PoC inspired by https://mastodon.catgirl.cloud/@49016/117474217042191790
