# QResCoin-Q+ XMSS-Lite (single-tree) over WOTS+ with stateless leaf derivation.
# Educational prototype for post-quantum signatures integrated with QResCoin.
#
# Highlights:
# - WOTS+ leaves (RFC 8391) with domain-separated SHAKE256 hashing.
# - Stateless leaf SK derivation from a master seed (PRF), no per-leaf SK storage.
# - Precomputed small trees (e.g., height h<=10) for clarity; OK for demos.
# - Signature format: (idx, R, WOTS sig, auth path), public key: (root, pub_seed).
#
# References:
#   RFC 8391 (XMSS/WOTS+), NIST SP 800-208 (XMSS/LMS), FIPS 205 (SPHINCS+ context)
#
# (c) 2025 QResCoin Contributors. MIT License.

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple
import os, hashlib, hmac
from .crypto_wots import WOTSPlus, compress_wots_pk


def _shake256(data: bytes, outlen: int = 32) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def _H(tag: bytes, *pieces: bytes, n: int = 32) -> bytes:
    return _shake256(tag + b"||" + b"||".join(pieces), outlen=n)


def _prf(key: bytes, data: bytes, n: int = 32) -> bytes:
    return hmac.new(key, data, digestmod=hashlib.sha256).digest()[:n]


def _int_to_bytes(x: int, l: int) -> bytes:
    return x.to_bytes(l, "big")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _tree_parent(left: bytes, right: bytes, n: int = 32) -> bytes:
    return _H(b"XMSS.NODE", left + right, n=n)


def _leaf_from_wots_pk(wots_pk_compressed: bytes, n: int = 32) -> bytes:
    return _H(b"XMSS.LEAF", wots_pk_compressed, n=n)


@dataclass
class XMSSPublicKey:
    n: int
    h: int
    w: int
    root: bytes
    pub_seed: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "n": self.n,
            "h": self.h,
            "w": self.w,
            "root": self.root.hex(),
            "pub_seed": self.pub_seed.hex(),
        }


@dataclass
class XMSSKeypair:
    n: int = 32         # digest size in bytes
    h: int = 8          # tree height (demo default -> 256 signatures)
    w: int = 16         # Winternitz parameter
    sk_seed: bytes = None
    prf_seed: bytes = None
    pub_seed: bytes = None

    # internal state
    idx: int = 0
    wots: WOTSPlus = None
    root: bytes = None
    _auth_paths: List[List[bytes]] = None     # auth path per leaf index

    def __post_init__(self):
        if self.sk_seed is None:
            self.sk_seed = os.urandom(self.n)
        if self.prf_seed is None:
            self.prf_seed = os.urandom(self.n)
        if self.pub_seed is None:
            self.pub_seed = os.urandom(self.n)
        self.wots = WOTSPlus(n=self.n, w=self.w)
        self._precompute_tree()

    # ---------- Precomputation of leaves and auth paths (small h) ----------
    def _wots_pk_for_leaf(self, leaf_idx: int) -> bytes:
        pk_elems = self.wots.pkgen(self.sk_seed, self.pub_seed, leaf_idx)
        return compress_wots_pk(pk_elems, n=self.n)

    def _precompute_tree(self):
        num_leaves = 1 << self.h
        leaves = [
            _leaf_from_wots_pk(self._wots_pk_for_leaf(i), n=self.n)
            for i in range(num_leaves)
        ]
        # Build full tree levels
        levels: List[List[bytes]] = [leaves]
        for _ in range(self.h):
            prev = levels[-1]
            nxt = []
            for i in range(0, len(prev), 2):
                nxt.append(_tree_parent(prev[i], prev[i + 1], n=self.n))
            levels.append(nxt)
        self.root = levels[-1][0]
        # Auth paths:
        self._auth_paths = []
        for leaf_idx in range(num_leaves):
            path = []
            idx = leaf_idx
            for level in range(self.h):
                sibling = idx ^ 1
                path.append(levels[level][sibling])
                idx >>= 1
            self._auth_paths.append(path)

    def _msg_digest(self, R: bytes, idx: int, msg: bytes) -> bytes:
        # RFC 8391-like binding: H("msg" || R || root || idx || msg)
        return _H(b"XMSS.MSG", R, self.root, _int_to_bytes(idx, 4), msg, n=self.n)

    def public_key(self) -> XMSSPublicKey:
        return XMSSPublicKey(
            n=self.n, h=self.h, w=self.w, root=self.root, pub_seed=self.pub_seed
        )

    # ---------- Signing ----------
    def sign(self, msg: bytes) -> Dict[str, Any]:
        if self.idx >= (1 << self.h):
            raise ValueError("XMSS key exhausted (all leaves used)")
        idx = self.idx
        # Per-signature randomness R
        R = _prf(self.prf_seed, b"R" + _int_to_bytes(idx, 4) + msg, n=self.n)
        mhash = self._msg_digest(R, idx, msg)
        sig_wots = self.wots.sign(self.sk_seed, self.pub_seed, idx, mhash)
        auth = [x for x in self._auth_paths[idx]]
        self.idx += 1
        return {
            "scheme": "XMSS-Lite-WOTS+",
            "n": self.n,
            "h": self.h,
            "w": self.w,
            "idx": idx,
            "R": R.hex(),
            "wots_sig": [s.hex() for s in sig_wots],
            "auth": [a.hex() for a in auth],
            "root": self.root.hex(),       # optional convenience
            "pub_seed": self.pub_seed.hex(),
        }

    # ---------- Verification ----------
    @staticmethod
    def verify(pk: XMSSPublicKey, sig: Dict[str, Any], msg: bytes) -> bool:
        # Rebuild message hash:
        n = pk.n
        w = pk.w
        R = bytes.fromhex(sig["R"])
        idx = int(sig["idx"])
        pub_seed = bytes.fromhex(sig["pub_seed"])
        root = bytes.fromhex(sig["root"]) if "root" in sig else pk.root
        # Recompute mhash using provided root (bound in signature)
        mhash = _H(b"XMSS.MSG", R, root, _int_to_bytes(idx, 4), msg, n=n)
        wots = WOTSPlus(n=n, w=w)
        sig_wots = [bytes.fromhex(s) for s in sig["wots_sig"]]
        pk_elems = wots.pk_from_sig(pub_seed, idx, mhash, sig_wots)
        wots_comp = compress_wots_pk(pk_elems, n=n)
        leaf = _H(b"XMSS.LEAF", wots_comp, n=n)
        # Climb tree with auth path
        node = leaf
        auth = [bytes.fromhex(a) for a in sig["auth"]]
        node_idx = idx
        for level in range(pk.h):
            if node_idx % 2 == 0:
                node = _H(b"XMSS.NODE", node + auth[level], n=n)
            else:
                node = _H(b"XMSS.NODE", auth[level] + node, n=n)
            node_idx >>= 1
        return node == pk.root


# Convenience wrapper
def xmss_verify(pk_dict: Dict[str, Any], sig: Dict[str, Any], msg: bytes) -> bool:
    pk = XMSSPublicKey(
        n=pk_dict["n"],
        h=pk_dict["h"],
        w=pk_dict["w"],
        root=bytes.fromhex(pk_dict["root"]),
        pub_seed=bytes.fromhex(pk_dict["pub_seed"]),
    )
    return XMSSKeypair.verify(pk, sig, msg)
