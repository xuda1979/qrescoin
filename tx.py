
from dataclasses import dataclass, asdict
from typing import Dict, Any
import json
from .crypto_hash import h256
from .crypto_mss import MSSSignature

@dataclass
class Tx:
    sender_root_hex: str
    receiver_root_hex: str
    amount: int
    index: int  # one-time index used by sender
    signature: Dict[str, Any]  # serialized MSSSignature fields
    nonce: int

    def to_bytes(self) -> bytes:
        # Deterministic serialization
        d = {
            "sender_root_hex": self.sender_root_hex,
            "receiver_root_hex": self.receiver_root_hex,
            "amount": self.amount,
            "index": self.index,
            "signature": {
                "index": self.signature["index"],
                "lamport_sig": self.signature["lamport_sig"],
                "lamport_pk_compressed": self.signature["lamport_pk_compressed"],
                "path": self.signature["path"],
            },
            "nonce": self.nonce,
        }
        return json.dumps(d, sort_keys=True, separators=(',', ':')).encode()

    def txid(self) -> str:
        return h256(self.to_bytes()).hex()
