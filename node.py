
from dataclasses import dataclass, field
from typing import List, Dict, Tuple
from .wallet import Wallet
from .consensus import State, Validator, select_leader, make_block, verify_block, apply_tx, verify_tx
from .block import Block

@dataclass
class Node:
    wallet: Wallet
    stake: int
    state: State = field(default_factory=State)
    chain: List[Block] = field(default_factory=list)
    mempool: List['Tx'] = field(default_factory=list)

    def init_genesis(self, allocations: Dict[str, int]):
        """Initialize balances; create a dummy genesis block."""
        for addr, amt in allocations.items():
            self.state.balances[addr] = self.state.balances.get(addr, 0) + amt
        self.state.nonces = {addr: 0 for addr in allocations}
        # Empty genesis block
        from .block import BlockHeader
        hdr = BlockHeader(parent_hash="0"*64, height=0, proposer="GENESIS",
                          beacon_randomness="00"*32, chsh_proof={},
                          timestamp=0.0)
        genesis = Block(header=hdr, txs=[], proposer_signature={})
        self.chain = [genesis]

    def add_tx(self, tx: 'Tx'):
        self.mempool.append(tx)

    def current_height(self) -> int:
        return self.chain[-1].header.height

    def parent_hash(self) -> str:
        return self.chain[-1].header.hash_hex()

    def propose_block(self, validators: Dict[str, Validator], threshold: float = 0.82) -> Block:
        """Leader selection and block proposal from this node's view (deterministic across nodes)."""
        height = self.current_height() + 1
        from .crypto_hash import h256
        rnd = h256(bytes.fromhex(self.parent_hash()))
        leader = select_leader(list(validators.values()), rnd, height)
        # Collect up to 3 valid txs from our mempool
        txs = []
        temp_state = self.state.clone()
        for tx in list(self.mempool):
            if len(txs) >= 3:
                break
            if verify_tx(tx, temp_state):
                apply_tx(tx, temp_state)
                txs.append(tx)
                self.mempool.remove(tx)
        block = make_block(parent_hash=self.parent_hash(), height=height, proposer=leader, txs=txs)
        return block

    def accept_block(self, block: Block, validators: Dict[str, Validator], threshold: float = 0.82) -> bool:
        """Verify a received block and append/apply it."""
        ok = verify_block(block, self.state, validators, threshold=threshold)
        if ok:
            for tx in block.txs:
                apply_tx(tx, self.state)
            self.chain.append(block)
        return ok
