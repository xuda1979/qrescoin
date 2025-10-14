
from dataclasses import dataclass, field
from typing import List, Dict, Any
import json, time
from .crypto_hash import h256
from .tx import Tx

@dataclass
class BlockHeader:
    parent_hash: str
    height: int
    proposer: str  # proposer address (hex root)
    beacon_randomness: str  # hex of 32 bytes
    chsh_proof: Dict[str, str]  # serialized transcript
    timestamp: float

    def to_bytes(self) -> bytes:
        d = {
            "parent_hash": self.parent_hash,
            "height": self.height,
            "proposer": self.proposer,
            "beacon_randomness": self.beacon_randomness,
            "chsh_proof": self.chsh_proof,
            "timestamp": round(self.timestamp, 6),
        }
        return json.dumps(d, sort_keys=True, separators=(',', ':')).encode()

    def hash_hex(self) -> str:
        return h256(self.to_bytes()).hex()

@dataclass
class Block:
    header: BlockHeader
    txs: List[Tx]
    proposer_signature: Dict[str, Any]  # MSS signature over header bytes

    def to_bytes(self) -> bytes:
        d = {
            "header": json.loads(self.header.to_bytes().decode()),
            "txs": [json.loads(tx.to_bytes().decode()) for tx in self.txs],
            "proposer_signature": self.proposer_signature,
        }
        return json.dumps(d, sort_keys=True, separators=(',', ':')).encode()

    def block_hash(self) -> str:
        return h256(self.to_bytes()).hex()
