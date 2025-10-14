
"""
Merkle Signature Scheme (MSS) using Lamport OTS leaves.
This is a compact, PQ-resistant signature scheme suitable for demos.
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict
from .crypto_hash import h256, hash_concat
from . import crypto_lamport as lamport

BYTES = 32

@dataclass
class MerkleTree:
    height: int
    # tree[level][index] -> hash bytes
    tree: List[List[bytes]]

    @property
    def root(self) -> bytes:
        return self.tree[-1][0]

def build_merkle(leaves: List[bytes]) -> MerkleTree:
    if len(leaves) == 0 or (len(leaves) & (len(leaves) - 1)) != 0:
        raise ValueError("leaves must be a non-empty power of two")
    tree = [list(leaves)]
    while len(tree[-1]) > 1:
        level = tree[-1]
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(h256(level[i] + level[i+1]))
        tree.append(nxt)
    return MerkleTree(height=len(tree)-1, tree=tree)

def auth_path(mt: MerkleTree, index: int) -> List[bytes]:
    """Authentication path for a leaf index."""
    path = []
    idx = index
    for level in range(mt.height):
        sibling = idx ^ 1
        path.append(mt.tree[level][sibling])
        idx //= 2
    return path

def verify_path(leaf: bytes, path: List[bytes], index: int, root: bytes) -> bool:
    """Verify Merkle path up to the root."""
    h = leaf
    idx = index
    for sib in path:
        if idx % 2 == 0:
            h = h256(h + sib)
        else:
            h = h256(sib + h)
        idx //= 2
    return h == root

@dataclass
class MSSPrivateKey:
    height: int
    lamport_sks: List[lamport.LamportSecretKey]
    lamport_pks: List[lamport.LamportPublicKey]
    merkle: MerkleTree
    used: Dict[int, bool]  # one-time indices used

@dataclass
class MSSPublicKey:
    root: bytes
    height: int

@dataclass
class MSSSignature:
    index: int
    lamport_sig: bytes          # serialized LamportSignature (8192 bytes)
    lamport_pk_compressed: bytes  # 512*32 bytes
    path: List[bytes]           # authentication path

def keygen(height: int = 4) -> Tuple[MSSPrivateKey, MSSPublicKey]:
    """Generate 2^height Lamport OTS keys and a Merkle tree over their pk hashes."""
    n = 1 << height
    l_sks = []
    l_pks = []
    leaves = []
    for _ in range(n):
        sk, pk = lamport.keygen()
        l_sks.append(sk)
        l_pks.append(pk)
        leaves.append(lamport.pk_leaf_hash(pk))
    mt = build_merkle(leaves)
    return MSSPrivateKey(height, l_sks, l_pks, mt, used={}), MSSPublicKey(mt.root, height)

def sign(message: bytes, mssk: MSSPrivateKey, index: int) -> MSSSignature:
    if index < 0 or index >= (1 << mssk.height):
        raise ValueError("index out of range")
    if mssk.used.get(index, False):
        raise ValueError("one-time key already used")
    sk = mssk.lamport_sks[index]
    pk = mssk.lamport_pks[index]
    sig = lamport.sign(message, sk)
    mssk.used[index] = True
    auth = auth_path(mssk.merkle, index)
    return MSSSignature(
        index=index,
        lamport_sig=lamport.serialize_sig(sig),
        lamport_pk_compressed=lamport.compress_pk(pk),
        path=auth
    )

def verify(message: bytes, sig: MSSSignature, mspk: MSSPublicKey) -> bool:
    """Verify MSS signature by (1) Lamport verify using included pk, (2) Merkle path to root."""
    try:
        pk = lamport.decompress_pk(sig.lamport_pk_compressed)
        lam_sig = lamport.deserialize_sig(sig.lamport_sig)
    except Exception:
        return False
    ok1 = lamport.verify(message, lam_sig, pk)
    if not ok1:
        return False
    leaf = lamport.pk_leaf_hash(pk)
    ok2 = verify_path(leaf, sig.path, sig.index, mspk.root)
    return ok2
