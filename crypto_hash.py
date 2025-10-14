
import hashlib
from typing import Iterable

def h256(data: bytes) -> bytes:
    """SHA3-256"""
    return hashlib.sha3_256(data).digest()

def h256_hex(data: bytes) -> str:
    return h256(data).hex()

def hash_concat(chunks: Iterable[bytes]) -> bytes:
    h = hashlib.sha3_256()
    for c in chunks:
        h.update(c)
    return h.digest()
