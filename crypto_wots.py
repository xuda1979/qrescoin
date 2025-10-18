# QResCoin-Q+ WOTS+ (Winternitz One-Time Signature Plus)
# Educational, minimal, domain-separated implementation intended for small demos.
# Based on WOTS+ as specified in RFC 8391 (XMSS). This module is designed to be
# used by crypto_xmss.py and can also be used standalone for one-time signatures.
#
# SECURITY NOTE:
# - Parameters default to n=32 (256-bit), w=16. This yields len = 67 chains.
# - This code is for research/education; review before production use.
#
# References:
#   - RFC 8391: XMSS: eXtended Merkle Signature Scheme (includes WOTS+)
#   - NIST SP 800-208: Stateful Hash-Based Signature Schemes (XMSS/LMS)
#
# (c) 2025 QResCoin Contributors. MIT License.

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Tuple
import hashlib, hmac, math


def _shake256(data: bytes, outlen: int = 32) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def _H(tag: bytes, *pieces: bytes, n: int = 32) -> bytes:
    # Domain-separated hash with SHAKE256
    return _shake256(tag + b"||" + b"||".join(pieces), outlen=n)


def _prf(key: bytes, data: bytes, n: int = 32) -> bytes:
    return hmac.new(key, data, digestmod=hashlib.sha256).digest()[:n]


def _int_to_bytes(x: int, l: int) -> bytes:
    return x.to_bytes(l, "big")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass
class WOTSParams:
    n: int = 32       # security parameter in bytes (e.g., 32 -> 256 bits)
    w: int = 16       # Winternitz parameter (power of two)
    len1: int = 0     # number of base-w digits for message
    len2: int = 0     # number of base-w digits for checksum
    length: int = 0   # total number of chains = len1 + len2

    @staticmethod
    def for_n_w(n: int = 32, w: int = 16) -> "WOTSParams":
        log_w = int(math.log2(w))
        len1 = math.ceil(8 * n / log_w)
        len2 = math.floor(math.log(len1 * (w - 1), w)) + 1
        return WOTSParams(n=n, w=w, len1=len1, len2=len2, length=len1 + len2)


class WOTSPlus:
    """
    WOTS+ with per-chain bitmasks derived from a public seed and address
    (index, chain, step). Secret keys are derived via a PRF from a master seed.
    """

    def __init__(self, n: int = 32, w: int = 16):
        self.params = WOTSParams.for_n_w(n=n, w=w)
        self.log_w = int(math.log2(w))

    # ----- base-w encoding with checksum -----
    def _base_w(self, x: bytes, out_len: int) -> List[int]:
        """Return out_len digits in base-w of byte string x (big-endian)."""
        bits = 0
        total = 0
        out = []
        for _ in range(out_len):
            if bits < self.log_w:
                if len(x) == 0:
                    total = 0
                else:
                    total = (total << 8) | x[0]
                    x = x[1:]
                    bits += 8
            bits -= self.log_w
            out.append((total >> bits) & (self.params.w - 1))
        return out

    def _checksum(self, msg_digits: List[int]) -> List[int]:
        csum = 0
        for a in msg_digits:
            csum += self.params.w - 1 - a
        # compute len2 digits of csum in base-w (big-endian)
        csum_bytes = _int_to_bytes(
            csum << (8 - (self.log_w * self.params.len2) % 8),
            (self.params.len2 * self.log_w + 7) // 8,
        )
        return self._base_w(csum_bytes, self.params.len2)

    def _chain(self, x: bytes, start: int, steps: int, masks_row: List[bytes]) -> bytes:
        y = x
        for i in range(start, min(self.params.w - 1, start + steps)):
            y = _H(b"WOTS.F", _xor(y, masks_row[i]), n=self.params.n)
        return y

    # ----- key/addr derivation -----
    def _sk_elem(self, sk_seed: bytes, idx: int, chain: int) -> bytes:
        return _prf(
            sk_seed,
            b"SK" + _int_to_bytes(idx, 4) + _int_to_bytes(chain, 2),
            self.params.n,
        )

    def _masks_for_chain(self, pub_seed: bytes, idx: int, chain: int) -> List[bytes]:
        # masks for steps 0..w-2
        return [
            _H(
                b"WOTS.MASK",
                pub_seed,
                _int_to_bytes(idx, 4),
                _int_to_bytes(chain, 2),
                _int_to_bytes(i, 2),
                n=self.params.n,
            )
            for i in range(self.params.w - 1)
        ]

    def message_to_digits(self, msg32: bytes) -> List[int]:
        assert len(msg32) == self.params.n
        digits = self._base_w(msg32, self.params.len1)
        digits.extend(self._checksum(digits))
        assert len(digits) == self.params.length
        return digits

    # ----- API -----
    def pkgen(self, sk_seed: bytes, pub_seed: bytes, idx: int) -> List[bytes]:
        """Return list of WOTS+ public key elements (len chains)."""
        pk = []
        for j in range(self.params.length):
            sk_j = self._sk_elem(sk_seed, idx, j)
            masks = self._masks_for_chain(pub_seed, idx, j)
            pk_j = self._chain(sk_j, 0, self.params.w - 1, masks)
            pk.append(pk_j)
        return pk

    def sign(self, sk_seed: bytes, pub_seed: bytes, idx: int, msg32: bytes) -> List[bytes]:
        a = self.message_to_digits(msg32)
        sig = []
        for j, a_j in enumerate(a):
            sk_j = self._sk_elem(sk_seed, idx, j)
            masks = self._masks_for_chain(pub_seed, idx, j)
            sig_j = self._chain(sk_j, 0, a_j, masks)
            sig.append(sig_j)
        return sig

    def pk_from_sig(
        self, pub_seed: bytes, idx: int, msg32: bytes, sig: List[bytes]
    ) -> List[bytes]:
        a = self.message_to_digits(msg32)
        pk = []
        for j, a_j in enumerate(a):
            masks = self._masks_for_chain(pub_seed, idx, j)
            y = self._chain(sig[j], a_j, (self.params.w - 1) - a_j, masks)
            pk.append(y)
        return pk


def l_tree(elements: List[bytes], n: int = 32) -> bytes:
    """Compress a list of n-byte strings into one n-byte root (XMSS-style L-tree)."""
    nodes = elements[:]
    if not nodes:
        return b"\x00" * n
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                nxt.append(_H(b"L", nodes[i] + nodes[i + 1], n=n))
            else:
                nxt.append(nodes[i])
        nodes = nxt
    return nodes[0]


def compress_wots_pk(pk_elems: List[bytes], n: int = 32) -> bytes:
    return l_tree(pk_elems, n=n)


def wots_params(n: int = 32, w: int = 16) -> Tuple[int, int, int]:
    p = WOTSParams.for_n_w(n=n, w=w)
    return (p.len1, p.len2, p.length)
