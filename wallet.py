
from dataclasses import dataclass
from typing import Dict, Any
from .crypto_mss import keygen as mss_keygen, sign as mss_sign, MSSSignature, MSSPublicKey, MSSPrivateKey
from .crypto_hash import h256
from .tx import Tx

@dataclass
class Wallet:
    mssk: MSSPrivateKey
    mspk: MSSPublicKey
    next_index: int = 0

    @property
    def address(self) -> str:
        return self.mspk.root.hex()

    @staticmethod
    def new(height: int = 4) -> 'Wallet':
        mssk, mspk = mss_keygen(height=height)
        return Wallet(mssk=mssk, mspk=mspk)

    def sign_tx(self, receiver_addr: str, amount: int, nonce: int) -> Tx:
        idx = self.next_index
        msg_dict = {
            "sender_root_hex": self.address,
            "receiver_root_hex": receiver_addr,
            "amount": amount,
            "index": idx,
            "nonce": nonce,
        }
        import json
        msg = json.dumps(msg_dict, sort_keys=True, separators=(',', ':')).encode()
        sig = mss_sign(msg, self.mssk, idx)
        self.next_index += 1
        sig_ser = {
            "index": sig.index,
            "lamport_sig": sig.lamport_sig.hex(),
            "lamport_pk_compressed": sig.lamport_pk_compressed.hex(),
            "path": [x.hex() for x in sig.path],
        }
        return Tx(
            sender_root_hex=self.address,
            receiver_root_hex=receiver_addr,
            amount=amount,
            index=idx,
            signature=sig_ser,
            nonce=nonce
        )
