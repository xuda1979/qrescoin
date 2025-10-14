
"""
Quantum-inspired randomness beacon using CHSH game transcripts.

- generate_chsh_transcript: simulate "quantum" or "classical" behavior
- verify_and_beacon: verify CHSH threshold and derive a randomness output

References: CHSH game; quantum max winning prob p_q = cos^2(pi/8) ~ 0.853553
Classical bound p_c = 0.75.
"""
from dataclasses import dataclass
from typing import List, Tuple, Dict
import secrets
import math
from .crypto_hash import h256, hash_concat

@dataclass
class CHSHTranscript:
    x: List[int]
    y: List[int]
    a: List[int]
    b: List[int]

def generate_chsh_transcript(n: int = 512, mode: str = "quantum") -> CHSHTranscript:
    """Simulate a CHSH experiment with n rounds."""
    if mode not in ("quantum", "classical"):
        raise ValueError("mode must be 'quantum' or 'classical'")
    x = []
    y = []
    a = []
    b = []
    # winning probability
    if mode == "quantum":
        p_win = 0.5 + 1/(2*math.sqrt(2))  # cos^2(pi/8)
    else:
        p_win = 0.75
    for _ in range(n):
        xi = secrets.randbits(1)
        yi = secrets.randbits(1)
        win = secrets.randbelow(10**6) < int(p_win * 10**6)
        ai = secrets.randbits(1)
        parity = (xi & yi)
        if win:
            bi = ai ^ parity
        else:
            bi = ai ^ parity ^ 1
        x.append(xi); y.append(yi); a.append(ai); b.append(bi)
    return CHSHTranscript(x, y, a, b)

def chsh_win_fraction(tr: CHSHTranscript) -> float:
    n = len(tr.x)
    wins = 0
    for i in range(n):
        if (tr.a[i] ^ tr.b[i]) == (tr.x[i] & tr.y[i]):
            wins += 1
    return wins / max(1, n)

def pack_bits(bits: List[int]) -> bytes:
    """Pack a list of 0/1 ints into bytes (big-endian)."""
    out = bytearray((len(bits) + 7)//8)
    for i, bit in enumerate(bits):
        if bit:
            out[i//8] |= (1 << (7 - (i % 8)))
    return bytes(out)

def serialize_transcript(tr: CHSHTranscript) -> Dict[str, str]:
    return {
        "x": pack_bits(tr.x).hex(),
        "y": pack_bits(tr.y).hex(),
        "a": pack_bits(tr.a).hex(),
        "b": pack_bits(tr.b).hex(),
    }

def derive_beacon(tr: CHSHTranscript, context: bytes) -> bytes:
    """Derive beacon randomness by hashing the transcript and context."""
    return hash_concat([
        b'QRES-CHSH-BEACON',
        pack_bits(tr.x), pack_bits(tr.y),
        pack_bits(tr.a), pack_bits(tr.b),
        context
    ])

def verify_and_beacon(serialized: Dict[str, str], threshold: float, context: bytes) -> Tuple[bool, bytes, float, int]:
    """Verify the CHSH win-rate threshold and, if OK, return (True, randomness, win_frac, nbits)."""
    def unpack(hexstr: str) -> List[int]:
        buf = bytes.fromhex(hexstr)
        bits = []
        for i in range(len(buf)*8):
            bits.append((buf[i//8] >> (7 - (i%8))) & 1)
        return bits

    x = unpack(serialized["x"])
    y = unpack(serialized["y"])
    a = unpack(serialized["a"])
    b = unpack(serialized["b"])
    n = min(len(x), len(y), len(a), len(b))
    tr = CHSHTranscript(x[:n], y[:n], a[:n], b[:n])
    frac = chsh_win_fraction(tr)
    ok = frac >= threshold
    rnd = derive_beacon(tr, context) if ok else b'\x00'*32
    return ok, rnd, frac, n

def openqasm_chsh() -> str:
    """
    Return an OpenQASM 2.0 program template illustrating a single CHSH test round.
    The angles implement the optimal quantum strategy for CHSH.
    """
    qasm = r"""
OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
// x,y measurement settings are classical; here we show the x=0,y=0 case.
// Prepare EPR pair
h q[0];
cx q[0], q[1];
// Alice measurement for x=0: measure Z basis (no rotation)
barrier q;
// Bob measurement for y=0: rotate by -pi/8 around Y then measure Z
ry(-pi/8) q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""
    return qasm.strip()
