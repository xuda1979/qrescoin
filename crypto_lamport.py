
"""
Minimal Lamport one-time signature (OTS) using SHA3-256.
This is for demonstration—do not use as-is in production.

Public key: 512 hashes (each 32 bytes) corresponding to two secrets per message bit.
Signature: reveal one secret per bit according to the digest bit of the message.
"""

from dataclasses import dataclass
from typing import List, Tuple
import secrets
from .crypto_hash import h256, hash_concat

BITS = 256
BYTES = 32

@dataclass
class LamportSecretKey:
    # list of (s0, s1) secrets
    pairs: List[Tuple[bytes, bytes]]

@dataclass
class LamportPublicKey:
    # list of (H(s0), H(s1))
    pairs: List[Tuple[bytes, bytes]]

@dataclass
class LamportSignature:
    # list of revealed secrets corresponding to the digest bits
    parts: List[bytes]

def keygen() -> Tuple[LamportSecretKey, LamportPublicKey]:
    pairs_sk = []
    pairs_pk = []
    for _ in range(BITS):
        s0 = secrets.token_bytes(BYTES)
        s1 = secrets.token_bytes(BYTES)
        pairs_sk.append((s0, s1))
        pairs_pk.append((h256(s0), h256(s1)))
    return LamportSecretKey(pairs_sk), LamportPublicKey(pairs_pk)

def sign(message: bytes, sk: LamportSecretKey) -> LamportSignature:
    dg = h256(message)  # 32 bytes -> 256 bits
    parts: List[bytes] = []
    for i in range(BITS):
        byte = dg[i // 8]
        bit = (byte >> (7 - (i % 8))) & 1
        s = sk.pairs[i][bit]
        parts.append(s)
    return LamportSignature(parts)

def verify(message: bytes, sig: LamportSignature, pk: LamportPublicKey) -> bool:
    dg = h256(message)
    if len(sig.parts) != BITS:
        return False
    for i in range(BITS):
        b = (dg[i // 8] >> (7 - (i % 8))) & 1
        if h256(sig.parts[i]) != pk.pairs[i][b]:
            return False
    return True

def compress_pk(pk: LamportPublicKey) -> bytes:
    return b''.join([p0 + p1 for (p0, p1) in pk.pairs])

def decompress_pk(buf: bytes) -> LamportPublicKey:
    if len(buf) != 512 * BYTES:
        raise ValueError("invalid pk length")
    pairs = []
    for i in range(512):
        p0 = buf[i*BYTES*2:(i*BYTES*2)+BYTES]
        p1 = buf[(i*BYTES*2)+BYTES:(i*BYTES*2)+2*BYTES]
        pairs.append((p0, p1))
    return LamportPublicKey(pairs)

def serialize_sig(sig: LamportSignature) -> bytes:
    return b''.join(sig.parts)

def deserialize_sig(buf: bytes) -> LamportSignature:
    if len(buf) != BITS * BYTES:
        raise ValueError("invalid signature length")
    parts = [buf[i*BYTES:(i+1)*BYTES] for i in range(BITS)]
    return LamportSignature(parts)

def pk_leaf_hash(pk: LamportPublicKey) -> bytes:
    """Hash of the compressed public key; used as leaf in Merkle tree."""
    return h256(compress_pk(pk))
