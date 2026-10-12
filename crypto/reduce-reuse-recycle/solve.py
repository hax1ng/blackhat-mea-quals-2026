#!/usr/bin/env python3
"""Solver for Reduce, Reuse, Recycle.

Run ``.venv/bin/python solve.py --selftest`` for a fixed local reproduction.
The network path is deliberately separate and makes only one connection.
"""

from __future__ import annotations

import argparse
import socket
from dataclasses import dataclass

from Crypto.Cipher import AES

try:
    import z3
except ImportError:
    z3 = None


# Exactly six Unicode code points. Their UTF-8 lengths are 1,2,2,2,3,4.
# The three 2-byte characters give a full-rank linear system for H^4.
CHARS = ["A", "é", "ק", "ˎ", "€", "😀"]
LINE = "".join(CHARS)

R = 0xE1000000000000000000000000000000
FIELD_ONE = 1 << 127
HIGH_MASK = int("f0" * 16, 16)
MASK128 = (1 << 128) - 1


def gf_mul(x: int, y: int) -> int:
    """GCM multiplication, using the big-endian bit convention."""
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ (R if v & 1 else 0)
    return z


def gf_pow(x: int, n: int) -> int:
    y = FIELD_ONE
    while n:
        if n & 1:
            y = gf_mul(y, x)
        x = gf_mul(x, x)
        n >>= 1
    return y


def gf_inv(x: int) -> int:
    if not x:
        raise ZeroDivisionError
    return gf_pow(x, (1 << 128) - 2)


def gf_div(x: int, y: int) -> int:
    return gf_mul(x, gf_inv(y))


def ghash(h: int, data: bytes) -> int:
    """GHASH ciphertext bytes with empty AAD and the appropriate length block."""
    blocks = [data[i : i + 16].ljust(16, b"\0") for i in range(0, len(data), 16)]
    blocks.append((0).to_bytes(8, "big") + (len(data) * 8).to_bytes(8, "big"))
    y = 0
    for block in blocks:
        y = gf_mul(y ^ int.from_bytes(block, "big"), h)
    return y


def parse_half(s: str, high: bool) -> int:
    """Place 16 printed nibbles back into their positions in a 128-bit tag."""
    s = s.strip()
    assert len(s) == 16 and all(c in "0123456789abcdef" for c in s)
    return int("".join((c + "0") if high else ("0" + c) for c in s), 16)


def join_halves(high: str, low: str) -> int:
    assert len(high.strip()) == len(low.strip()) == 16
    return int("".join(a + b for a, b in zip(high.strip(), low.strip())), 16)


def selected_bit_positions():
    # Integer positions corresponding to the high four bits of each big-endian byte.
    return [127 - stream_pos for stream_pos in range(128) if stream_pos % 8 < 4]


def recover_h(high_halves: list[str]) -> int:
    """Recover H from two truncated tag differences on 2-byte messages."""
    base = CHARS[1].encode()
    deltas = []
    observations = []
    base_tag = parse_half(high_halves[1], True)
    for idx in (2, 3):
        other = CHARS[idx].encode()
        delta = int.from_bytes(bytes(a ^ b for a, b in zip(base, other)) + bytes(14), "big")
        deltas.append(delta)
        observations.append(base_tag ^ parse_half(high_halves[idx], True))

    # Unknown X=H^4. Build 128 Boolean equations in its 128 bits.
    equations: list[list[int]] = []
    for delta, obs in zip(deltas, observations):
        columns = [gf_mul(delta, 1 << j) for j in range(128)]
        for pos in selected_bit_positions():
            coeff = sum(((columns[j] >> pos) & 1) << j for j in range(128))
            rhs = (obs >> pos) & 1
            equations.append([coeff, rhs])

    # Gauss-Jordan elimination over GF(2).
    pivot_for_col: dict[int, int] = {}
    row = 0
    for col in range(128):
        pivot = next((i for i in range(row, len(equations)) if (equations[i][0] >> col) & 1), None)
        if pivot is None:
            continue
        equations[row], equations[pivot] = equations[pivot], equations[row]
        pc, pr = equations[row]
        for i in range(len(equations)):
            if i != row and ((equations[i][0] >> col) & 1):
                equations[i][0] ^= pc
                equations[i][1] ^= pr
        pivot_for_col[col] = row
        row += 1
    if row != 128:
        raise ValueError(f"H^4 system rank is only {row}")
    x = sum(equations[pivot_for_col[col]][1] << col for col in range(128))

    # In GF(2^128), (H^4)^(2^126) = H^(2^128) = H.
    h = x
    for _ in range(126):
        h = gf_mul(h, h)
    assert gf_pow(h, 4) == x
    return h


def plaintext(ch: str, key: bytes) -> bytes:
    return f"{ch}|encrypted by {key.hex()}".encode()


def tag_for(key: bytes, nonce: bytes, ch: str) -> str:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.encrypt(plaintext(ch, key))
    return cipher.hexdigest()


def pair_delta_for_key(h: int, short_ch: str, long_ch: str, key: bytes, extra_z: int = 0) -> int:
    """Tag XOR for adjacent lengths with equal GCM block count.

    ``extra_z`` is the one newly used CTR-stream byte at the end of the longer
    message (byte 47 for lengths 47/48, byte 49 for lengths 49/50).
    """
    a = plaintext(short_ch, key)
    b = plaintext(long_ch, key)
    assert len(b) == len(a) + 1 and (len(a) + 15) // 16 == (len(b) + 15) // 16
    nblocks = (len(b) + 15) // 16
    pa = a.ljust(nblocks * 16, b"\0")
    pb = b.ljust(nblocks * 16, b"\0")
    delta = bytearray(x ^ y for x, y in zip(pa, pb))
    delta[len(b) - 1] ^= extra_z
    out = ghash(h, bytes(delta))
    # ghash(delta) incorrectly hashes a zero length block. Replace its final
    # length contribution with the XOR of the two real length blocks.
    zero_len_term = gf_mul(0, h)
    del zero_len_term  # documentary: it is zero
    # The helper used len(delta), so directly compute the data-block polynomial.
    y = 0
    for i in range(0, len(delta), 16):
        y = gf_mul(y ^ int.from_bytes(delta[i:i+16], "big"), h)
    len_delta = ((len(a) * 8) ^ (len(b) * 8))
    return gf_mul(y ^ len_delta, h)


SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]


def z3_lookup(var, values: list[int], width: int):
    expr = z3.BitVecVal(values[-1], width)
    for i in reversed(range(len(values) - 1)):
        expr = z3.If(var == i, z3.BitVecVal(values[i], width), expr)
    return expr


def aes128_z3_zero(key_bytes):
    """Symbolic AES-128 encryption of an all-zero block."""
    bv8 = lambda x: z3.BitVecVal(x, 8)

    def sb(x):
        # Do not encode the S-box as a 256-way ITE.  That representation is
        # convenient but makes Z3 spend minutes just bit-blasting AES.  The
        # AES S-box is inversion in GF(2^8), followed by an affine map.  A
        # short addition chain for x^254 gives a much smaller Boolean circuit
        # (and maps 0 to 0 as required).
        def mul(a, b):
            p = bv8(0)
            aa, bb = a, b
            for _ in range(8):
                p = p ^ z3.If((bb & bv8(1)) == bv8(1), aa, bv8(0))
                aa = (aa << 1) ^ z3.If(z3.Extract(7, 7, aa) == 1,
                                       bv8(0x1B), bv8(0))
                bb = z3.LShR(bb, 1)
            return p

        x2 = mul(x, x)
        x3 = mul(x2, x)
        x6 = mul(x3, x3)
        x7 = mul(x6, x)
        x14 = mul(x7, x7)
        x15 = mul(x14, x)
        x30 = mul(x15, x15)
        x60 = mul(x30, x30)
        x120 = mul(x60, x60)
        x127 = mul(x120, x7)
        inv = mul(x127, x127)

        def rol8(v, n):
            return (v << n) | z3.LShR(v, 8 - n)

        return inv ^ rol8(inv, 1) ^ rol8(inv, 2) ^ rol8(inv, 3) ^ rol8(inv, 4) ^ bv8(0x63)

    def xtime(x):
        return (x << 1) ^ z3.If(z3.Extract(7, 7, x) == 1, bv8(0x1B), bv8(0))

    def mix_col(a):
        a0,a1,a2,a3 = a
        return [
            xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3,
            a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3,
            a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3,
            xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3),
        ]

    # Key schedule as 44 words, each represented by four bytes.
    words = [key_bytes[i:i+4] for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        temp = words[i-1][:]
        if i % 4 == 0:
            temp = [sb(temp[1]), sb(temp[2]), sb(temp[3]), sb(temp[0])]
            temp[0] = temp[0] ^ bv8(rcon)
            rcon = ((rcon << 1) ^ (0x11B if rcon & 0x80 else 0)) & 0xFF
        words.append([words[i-4][j] ^ temp[j] for j in range(4)])

    round_keys = [sum(words[4*r:4*r+4], []) for r in range(11)]
    state = [bv8(0) ^ round_keys[0][i] for i in range(16)]
    for rnd in range(1, 11):
        state = [sb(x) for x in state]
        # State is serialized in AES column-major order.
        state = [state[4*((c+r) % 4)+r] for c in range(4) for r in range(4)]
        if rnd != 10:
            state = sum((mix_col(state[4*c:4*c+4]) for c in range(4)), [])
        state = [state[i] ^ round_keys[rnd][i] for i in range(16)]
    return state


def recover_key(high_halves: list[str], h: int, timeout_ms: int | None = None) -> bytes:
    """Solve the two truncated shift equations plus AES_K(0)=H."""
    if z3 is None:
        raise RuntimeError("z3py is required (use .venv/bin/python)")
    nibs = [z3.BitVec(f"n{i}", 4) for i in range(32)]
    z47 = z3.BitVec("z47", 8)
    z49 = z3.BitVec("z49", 8)

    def lookup_pair(short_ch, long_ch, zvar):
        zero_key = bytes(16)
        base = pair_delta_for_key(h, short_ch, long_ch, zero_key, 0)
        expr = z3.BitVecVal(base, 128)
        for i, nv in enumerate(nibs):
            values = []
            for v in range(16):
                kb = bytearray(16)
                if i % 2 == 0:
                    kb[i // 2] = v << 4
                else:
                    kb[i // 2] = v
                values.append(base ^ pair_delta_for_key(h, short_ch, long_ch, bytes(kb), 0))
            expr = expr ^ z3_lookup(nv, values, 128)
        # The newly exposed stream byte enters GHASH linearly, so use its
        # eight basis contributions instead of a 256-way lookup.
        for bit in range(8):
            contribution = (pair_delta_for_key(
                h, short_ch, long_ch, zero_key, 1 << bit) ^ base)
            expr = expr ^ z3.If(z3.Extract(bit, bit, zvar) == 1,
                                z3.BitVecVal(contribution, 128),
                                z3.BitVecVal(0, 128))
        return expr

    expr12 = lookup_pair(CHARS[0], CHARS[1], z47)
    expr34 = lookup_pair(CHARS[4], CHARS[5], z49)
    obs12 = parse_half(high_halves[0], True) ^ parse_half(high_halves[1], True)
    obs34 = parse_half(high_halves[4], True) ^ parse_half(high_halves[5], True)

    s = z3.Solver()
    if timeout_ms is not None:
        s.set(timeout=timeout_ms)
    s.add((expr12 & z3.BitVecVal(HIGH_MASK, 128)) == z3.BitVecVal(obs12, 128))
    s.add((expr34 & z3.BitVecVal(HIGH_MASK, 128)) == z3.BitVecVal(obs34, 128))

    key_bytes = [z3.Concat(nibs[2*i], nibs[2*i+1]) for i in range(16)]
    aes_out = aes128_z3_zero(key_bytes)
    h_bytes = h.to_bytes(16, "big")
    s.add(*[aes_out[i] == h_bytes[i] for i in range(16)])

    result = s.check()
    if result != z3.sat:
        raise RuntimeError(f"key solver returned {result}")
    model = s.model()
    key = bytes((model.eval(nibs[2*i]).as_long() << 4) | model.eval(nibs[2*i+1]).as_long() for i in range(16))
    if AES.new(key, AES.MODE_ECB).encrypt(bytes(16)) != h.to_bytes(16, "big"):
        raise AssertionError("symbolic AES/model mismatch")
    return key


def inc32(x: int, amount: int) -> int:
    return (x & ~0xFFFFFFFF) | (((x & 0xFFFFFFFF) + amount) & 0xFFFFFFFF)


def recover_nonce(key: bytes, h: int, full_tags: list[int]) -> bytes:
    """Recover J0 with a 2^16 search, then invert the 16-byte-nonce GHASH."""
    p48 = plaintext(CHARS[1], key)
    p50 = plaintext(CHARS[5], key)
    assert len(p48) == 48 and len(p50) == 50
    a3 = full_tags[1] ^ ghash(h, p48)
    b50 = full_tags[5] ^ ghash(h, p50)
    h2 = gf_mul(h, h)
    denom = h ^ FIELD_ONE
    if denom == 0:
        raise RuntimeError("degenerate H=1")
    aes = AES.new(key, AES.MODE_ECB)
    solutions = []
    fixed = b50 ^ gf_mul(a3, h)
    denom_inv = gf_inv(denom)
    h2_inv = gf_inv(h2)
    for prefix in range(1 << 16):
        zp = prefix << 112
        mask = gf_mul(fixed ^ gf_mul(zp, h2), denom_inv)
        j0 = int.from_bytes(aes.decrypt(mask.to_bytes(16, "big")), "big")
        z4 = aes.encrypt(inc32(j0, 4).to_bytes(16, "big"))
        if int.from_bytes(z4[:2], "big") == prefix:
            # A false 16-bit fixed point occurs with non-negligible
            # probability.  Invert J0 and retain only candidates that
            # reproduce all six complete tags.
            len_block = 128  # 0^64 || (16-byte nonce * 8)
            nonce_int = gf_mul(j0 ^ gf_mul(len_block, h), h2_inv)
            nonce = nonce_int.to_bytes(16, "big")
            expected = [int(tag_for(key, nonce, ch), 16) for ch in CHARS]
            if expected == full_tags:
                solutions.append(nonce)
    if len(solutions) != 1:
        raise RuntimeError(f"expected one validated nonce, got {len(solutions)}")
    return solutions[0]


def selftest(timeout_ms: int | None):
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    tags = [tag_for(key, nonce, ch) for ch in CHARS]
    highs = [t[0::2] for t in tags]
    lows = [t[1::2] for t in tags]
    h = recover_h(highs)
    expected_h = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(bytes(16)), "big")
    assert h == expected_h
    print(f"[+] recovered H = {h:032x}")
    got_key = recover_key(highs, h, timeout_ms)
    assert got_key == key
    print(f"[+] recovered key = {got_key.hex()}")
    full = [join_halves(a, b) for a, b in zip(highs, lows)]
    got_nonce = recover_nonce(got_key, h, full)
    assert got_nonce == nonce
    print(f"[+] recovered nonce = {got_nonce.hex()}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--timeout-ms", type=int)
    args = ap.parse_args()
    if args.selftest:
        selftest(args.timeout_ms)
    else:
        raise SystemExit("Network interaction will be enabled only after the local self-test passes.")


if __name__ == "__main__":
    main()
