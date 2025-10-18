# Minimal demo for XMSS-Lite over WOTS+ in QResCoin-Q+
# Run:  python -m qrescoin.demo_xmss

from __future__ import annotations
from .crypto_xmss import XMSSKeypair, xmss_verify


def _fmt_sz(x: int) -> str:
    units = ["B", "KB", "MB"]
    s = x
    i = 0
    while s >= 1024 and i < len(units) - 1:
        s /= 1024.0
        i += 1
    return f"{s:.1f} {units[i]}"


def main():
    print("QResCoin-Q+ XMSS demo (WOTS+ over SHAKE256)")
    # Small tree for demo: h=8 -> 256 signatures
    kp = XMSSKeypair(n=32, h=8, w=16)
    pk = kp.public_key().to_dict()
    print("Public key (root):", pk["root"][:16] + "...")
    msg = b"hello qrescoin::post-quantum"
    sig = kp.sign(msg)
    ok = xmss_verify(pk, sig, msg)
    print("Verify:", ok)
    # sizes
    sig_bytes = (
        sum(len(bytes.fromhex(x)) for x in sig["wots_sig"])
        + sum(len(bytes.fromhex(x)) for x in sig["auth"])
        + len(bytes.fromhex(sig["R"]))
        + 4
    )
    print("Signature size (approx):", _fmt_sz(sig_bytes))
    print(
        "Params: n=%d, w=%d, h=%d, WOTS chains=%d"
        % (kp.n, kp.w, kp.h, kp.wots.params.length)
    )


if __name__ == "__main__":
    main()
