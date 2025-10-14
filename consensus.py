
from dataclasses import dataclass
from typing import Dict, List, Tuple, Any
import time
from .crypto_hash import h256
from .crypto_mss import MSSPublicKey, MSSPrivateKey, MSSSignature, sign as mss_sign, verify as mss_verify
from .block import Block, BlockHeader
from .tx import Tx
from . import quantum_beacon as qb

class State:
    """Account-based state: balances and used one-time indices per address."""
    def __init__(self):
        self.balances: Dict[str, int] = {}
        self.used_index: Dict[Tuple[str, int], bool] = {}  # (address, index) -> bool
        self.nonces: Dict[str, int] = {}  # per-address monotonically increasing

    def clone(self) -> 'State':
        s = State()
        s.balances = dict(self.balances)
        s.used_index = dict(self.used_index)
        s.nonces = dict(self.nonces)
        return s

@dataclass
class Validator:
    address: str
    stake: int
    mssk: MSSPrivateKey
    mspk: MSSPublicKey

def select_leader(validators: List[Validator], rnd: bytes, round_no: int) -> Validator:
    """Weighted lottery: score = H(rnd|address|round)/stake; minimum wins."""
    best = None
    best_score = None
    for v in validators:
        inp = rnd + bytes.fromhex(v.address) + round_no.to_bytes(8, 'big')
        score = int.from_bytes(h256(inp), 'big') / max(1, v.stake)
        if best is None or score < best_score:
            best = v
            best_score = score
    return best

def verify_tx(tx: Tx, state: State) -> bool:
    """Verify signature and funds and nonce and index reuse."""
    # Check index misuse
    if state.used_index.get((tx.sender_root_hex, tx.index), False):
        return False
    # Verify MSS signature on the canonical tx message (without sig)
    from .crypto_mss import MSSPublicKey, MSSSignature, verify as mss_verify
    mspk = MSSPublicKey(root=bytes.fromhex(tx.sender_root_hex), height=len(tx.signature["path"]))
    sig = MSSSignature(
        index=tx.signature["index"],
        lamport_sig=bytes.fromhex(tx.signature["lamport_sig"]),
        lamport_pk_compressed=bytes.fromhex(tx.signature["lamport_pk_compressed"]),
        path=[bytes.fromhex(x) for x in tx.signature["path"]],
    )
    ok = mss_verify(tx_message_for_signing(tx), sig, mspk)
    if not ok:
        return False
    # Funds
    bal = state.balances.get(tx.sender_root_hex, 0)
    if bal < tx.amount:
        return False
    # Nonce
    expected_nonce = state.nonces.get(tx.sender_root_hex, 0)
    if tx.nonce != expected_nonce:
        return False
    return True

def apply_tx(tx: Tx, state: State):
    state.balances[tx.sender_root_hex] = state.balances.get(tx.sender_root_hex, 0) - tx.amount
    state.balances[tx.receiver_root_hex] = state.balances.get(tx.receiver_root_hex, 0) + tx.amount
    state.used_index[(tx.sender_root_hex, tx.index)] = True
    state.nonces[tx.sender_root_hex] = state.nonces.get(tx.sender_root_hex, 0) + 1

def tx_message_for_signing(tx: Tx) -> bytes:
    # exclude the signature itself when signing
    d = {
        "sender_root_hex": tx.sender_root_hex,
        "receiver_root_hex": tx.receiver_root_hex,
        "amount": tx.amount,
        "index": tx.index,
        "nonce": tx.nonce,
    }
    import json
    return json.dumps(d, sort_keys=True, separators=(',', ':')).encode()

def make_block(parent_hash: str, height: int, proposer: Validator, txs: List[Tx], threshold=0.82) -> Block:
    # Generate CHSH transcript and beacon randomness
    tr = qb.generate_chsh_transcript(n=512, mode="quantum")
    ser = qb.serialize_transcript(tr)
    ok, rnd, frac, n = qb.verify_and_beacon(ser, threshold, context=height.to_bytes(8, 'big'))
    assert ok, "internal error: simulated quantum transcript failed threshold"
    header = BlockHeader(
        parent_hash=parent_hash,
        height=height,
        proposer=proposer.address,
        beacon_randomness=rnd.hex(),
        chsh_proof=ser,
        timestamp=time.time(),
    )
    # Sign header with proposer's next available MSS index (use nonce as index)
    idx = next_free_index(proposer.mssk)
    sig = mss_sign(header.to_bytes(), proposer.mssk, idx)
    sig_ser = {
        "index": sig.index,
        "lamport_sig": sig.lamport_sig.hex(),
        "lamport_pk_compressed": sig.lamport_pk_compressed.hex(),
        "path": [h.hex() for h in sig.path],
    }
    return Block(header=header, txs=txs, proposer_signature=sig_ser)

def next_free_index(mssk: MSSPrivateKey) -> int:
    for i in range(1 << mssk.height):
        if not mssk.used.get(i, False):
            return i
    raise ValueError("exhausted one-time keys in MSS")

def verify_block(block: Block, state: State, validators: Dict[str, Validator], threshold=0.82) -> bool:
    # Verify beacon
    ok, rnd, frac, n = qb.verify_and_beacon(block.header.chsh_proof, threshold, context=block.header.height.to_bytes(8,'big'))
    if not ok or rnd.hex() != block.header.beacon_randomness:
        return False
    # Verify proposer signature
    from .crypto_mss import MSSPublicKey, MSSSignature, verify as mss_verify
    proposer = validators.get(block.header.proposer)
    if proposer is None:
        return False
    mspk = proposer.mspk  # public key (root)
    sigd = block.proposer_signature
    sig = MSSSignature(
        index=sigd["index"],
        lamport_sig=bytes.fromhex(sigd["lamport_sig"]),
        lamport_pk_compressed=bytes.fromhex(sigd["lamport_pk_compressed"]),
        path=[bytes.fromhex(x) for x in sigd["path"]],
    )
    ok2 = mss_verify(block.header.to_bytes(), sig, mspk)
    if not ok2:
        return False
    # Verify txs
    tmp = state.clone()
    for tx in block.txs:
        if not verify_tx(tx, tmp):
            return False
        apply_tx(tx, tmp)
    return True
