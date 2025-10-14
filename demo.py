
"""
Run a small demo with 3 nodes, PQ signatures via MSS(Lamport), and a CHSH-based beacon.
"""
from .wallet import Wallet
from .node import Node
from .consensus import Validator

def run_demo(rounds: int = 5):
    # Create 3 wallets
    w1 = Wallet.new(height=3)  # 8 signatures available
    w2 = Wallet.new(height=3)
    w3 = Wallet.new(height=3)

    # Nodes and initial stakes
    n1 = Node(wallet=w1, stake=100)
    n2 = Node(wallet=w2, stake=50)
    n3 = Node(wallet=w3, stake=25)

    # Initialize genesis balances
    alloc = {w1.address: 1000, w2.address: 500, w3.address: 0}
    for n in (n1, n2, n3):
        n.init_genesis(alloc)

    validators = {
        w1.address: Validator(address=w1.address, stake=n1.stake, mssk=w1.mssk, mspk=w1.mspk),
        w2.address: Validator(address=w2.address, stake=n2.stake, mssk=w2.mssk, mspk=w2.mspk),
        w3.address: Validator(address=w3.address, stake=n3.stake, mssk=w3.mssk, mspk=w3.mspk),
    }

    # Submit a few txs into mempools
    tx1 = w1.sign_tx(receiver_addr=w3.address, amount=120, nonce=0)
    tx2 = w2.sign_tx(receiver_addr=w1.address, amount=50, nonce=0)
    tx3 = w1.sign_tx(receiver_addr=w2.address, amount=60, nonce=1)
    tx4 = w2.sign_tx(receiver_addr=w3.address, amount=25, nonce=1)
    txs = [tx1, tx2, tx3, tx4]
    for tx in txs:
        for n in (n1, n2, n3):
            n.add_tx(tx)

    # Coordinator runs rounds; others accept the proposed block
    nodes = [n1, n2, n3]
    for r in range(rounds):
        block = nodes[0].propose_block(validators)
        # Everyone verifies and appends
        for nd in nodes:
            ok = nd.accept_block(block, validators)
            assert ok, "block rejected by a node"

        # keep mempools in sync (naive)
        for nd in nodes[1:]:
            # remove included txs from mempools
            for tx in block.txs:
                if tx in nd.mempool:
                    nd.mempool.remove(tx)

    # Print final balances
    print("Final balances:")
    print({addr[:16]+'...': n1.state.balances.get(addr,0) for addr in validators})

if __name__ == "__main__":
    run_demo()
