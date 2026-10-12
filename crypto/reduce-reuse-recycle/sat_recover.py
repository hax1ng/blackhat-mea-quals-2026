#!/usr/bin/env python3
"""Compact CNF key-recovery experiment for Reduce, Reuse, Recycle.

This replaces the very large 256-way symbolic S-boxes in the first draft with
an ordinary Boolean circuit.  It is kept separate until the fixed-key local
self-test passes.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile

from Crypto.Cipher import AES

import solve


class CNF:
    def __init__(self, native_xor: bool = True, native_tables: bool = False):
        self.native_xor = native_xor
        self.native_tables = native_tables
        self.nvars = 1
        self.true = 1
        self.clauses: list[list[int]] = [[self.true]]
        self.xor_clauses: list[tuple[list[int], bool]] = []
        self.tables: list[tuple[list[int], list[tuple[int, ...]]]] = []

    @property
    def false(self) -> int:
        return -self.true

    def var(self) -> int:
        self.nvars += 1
        return self.nvars

    def add(self, *lits: int):
        self.clauses.append(list(lits))

    def AND(self, a: int, b: int) -> int:
        if a == self.false or b == self.false or a == -b:
            return self.false
        if a == self.true:
            return b
        if b == self.true or a == b:
            return a
        c = self.var()
        # c <-> (a & b), where a and b may themselves be negated literals.
        self.add(-a, -b, c)
        self.add(a, -c)
        self.add(b, -c)
        return c

    def XOR(self, a: int, b: int) -> int:
        if a == self.false:
            return b
        if b == self.false:
            return a
        if a == self.true:
            return -b
        if b == self.true:
            return -a
        if a == b:
            return self.false
        if a == -b:
            return self.true
        c = self.var()
        if self.native_xor:
            self.add_xor([a, b, c], False)
            return c
        # c <-> (a xor b), with literal semantics for a and b.
        self.add(a, b, -c)
        self.add(-a, -b, -c)
        self.add(a, -b, c)
        self.add(-a, b, c)
        return c

    def xor_all(self, lits) -> int:
        if self.native_xor:
            variables, rhs = self._normalise_xor(lits, False)
            if not variables:
                return self.true if rhs else self.false
            if len(variables) == 1:
                return -variables[0] if rhs else variables[0]
            out = self.var()
            # XOR(inputs) XOR out = 0.
            self.add_xor(variables + [out], rhs)
            return out
        out = self.false
        for lit in lits:
            out = self.XOR(out, lit)
        return out

    def _normalise_xor(self, lits, rhs: bool):
        """Return unique positive variables and the adjusted XOR RHS."""
        parity: set[int] = set()
        for lit in lits:
            if lit == self.true:
                rhs = not rhs
                continue
            if lit == self.false:
                continue
            if lit < 0:
                rhs = not rhs
                lit = -lit
            if lit in parity:
                parity.remove(lit)
            else:
                parity.add(lit)
        return sorted(parity), rhs

    def add_xor(self, lits, rhs: bool):
        variables, rhs = self._normalise_xor(lits, rhs)
        if not variables:
            if rhs:
                self.add()  # contradiction
            return
        if not self.native_xor:
            out = self.false
            for variable in variables:
                out = self.XOR(out, variable)
            self.force(out, rhs)
            return
        self.xor_clauses.append((variables, rhs))

    def add_table(self, variables: list[int], rows):
        assert all(v > 0 for v in variables)
        self.tables.append((variables, [tuple(row) for row in rows]))

    def force(self, lit: int, value: int | bool):
        self.add(lit if value else -lit)

    def write(self, path: str):
        with open(path, "w", encoding="ascii") as fp:
            fp.write(f"p cnf {self.nvars} {len(self.clauses) + len(self.xor_clauses)}\n")
            for clause in self.clauses:
                fp.write(" ".join(map(str, clause)) + " 0\n")
            for variables, rhs in self.xor_clauses:
                # CryptoMiniSat's extended DIMACS gives every x-line parity
                # one.  Negating one literal toggles that parity.
                row = variables[:]
                if not rhs:
                    row[0] = -row[0]
                fp.write("x " + " ".join(map(str, row)) + " 0\n")


def byte_xor(cnf: CNF, *values: list[int], constant: int = 0) -> list[int]:
    return [cnf.xor_all(
        [v[bit] for v in values] + ([cnf.true] if (constant >> bit) & 1 else [])
    ) for bit in range(8)]


def xtime(cnf: CNF, x: list[int]) -> list[int]:
    # Multiplication by x modulo x^8+x^4+x^3+x+1 (0x11b).
    return [
        x[7],
        cnf.XOR(x[0], x[7]),
        x[1],
        cnf.XOR(x[2], x[7]),
        cnf.XOR(x[3], x[7]),
        x[4],
        x[5],
        x[6],
    ]


def gf8_mul_const(a: int, b: int) -> int:
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        a = ((a << 1) ^ (0x11B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return out


SQUARE_BASIS = [gf8_mul_const(1 << i, 1 << i) for i in range(8)]


def gf8_square(cnf: CNF, a: list[int]) -> list[int]:
    return [cnf.xor_all(a[i] for i in range(8) if (SQUARE_BASIS[i] >> j) & 1)
            for j in range(8)]


def gf8_mul(cnf: CNF, a: list[int], b: list[int]) -> list[int]:
    # Russian-peasant multiplication.  Each output is the XOR of one bit from
    # each conditionally included x^i*a byte.
    powers = []
    cur = a
    for _ in range(8):
        powers.append(cur)
        cur = xtime(cnf, cur)
    terms = [[cnf.AND(b[i], powers[i][j]) for i in range(8)] for j in range(8)]
    return [cnf.xor_all(row) for row in terms]


def aes_sbox_algebraic(cnf: CNF, x: list[int]) -> list[int]:
    # x^-1 = x^254, using four general multiplications and linear squarings.
    x2 = gf8_square(cnf, x)
    x3 = gf8_mul(cnf, x2, x)
    x6 = gf8_square(cnf, x3)
    x7 = gf8_mul(cnf, x6, x)
    x14 = gf8_square(cnf, x7)
    x15 = gf8_mul(cnf, x14, x)
    x30 = gf8_square(cnf, x15)
    x60 = gf8_square(cnf, x30)
    x120 = gf8_square(cnf, x60)
    x127 = gf8_mul(cnf, x120, x7)
    inv = gf8_square(cnf, x127)
    # Affine map: y ^ rol(y,1) ^ ... ^ rol(y,4) ^ 0x63.
    return [cnf.xor_all(
        [inv[(j - r) % 8] for r in range(5)]
        + ([cnf.true] if (0x63 >> j) & 1 else [])
    ) for j in range(8)]


def aes_sbox_table(cnf: CNF, x: list[int]) -> list[int]:
    """AES S-box encoded directly as a permutation table.

    For each possible input, eight 9-literal implication clauses fix the
    output.  The reverse implications are included too: AES constraints often
    arrive from both directions and this encoding propagates much better than
    a large arithmetic inversion circuit.
    """
    y = [cnf.var() for _ in range(8)]
    if cnf.native_tables:
        rows = [tuple((value >> bit) & 1 for bit in range(8))
                      + tuple((mapped >> bit) & 1 for bit in range(8))
                for value, mapped in enumerate(solve.SBOX)]
        cnf.add_table(x + y, rows)
        return y
    for value, mapped in enumerate(solve.SBOX):
        not_input_match = [(-x[bit] if (value >> bit) & 1 else x[bit])
                           for bit in range(8)]
        for bit in range(8):
            cnf.add(*not_input_match,
                    y[bit] if (mapped >> bit) & 1 else -y[bit])

        not_output_match = [(-y[bit] if (mapped >> bit) & 1 else y[bit])
                            for bit in range(8)]
        for bit in range(8):
            cnf.add(*not_output_match,
                    x[bit] if (value >> bit) & 1 else -x[bit])
    return y


# Boyar-Peralta bitsliced AES S-box circuit, in the variable naming used by
# BearSSL's constant-time implementation.  On a single SAT bit, C's &, ^ and
# ~ become AND, XOR and literal negation respectively.
BOYAR_PERALTA = r"""
y14 = x3 ^ x5
y13 = x0 ^ x6
y9 = x0 ^ x3
y8 = x0 ^ x5
t0 = x1 ^ x2
y1 = t0 ^ x7
y4 = y1 ^ x3
y12 = y13 ^ y14
y2 = y1 ^ x0
y5 = y1 ^ x6
y3 = y5 ^ y8
t1 = x4 ^ y12
y15 = t1 ^ x5
y20 = t1 ^ x1
y6 = y15 ^ x7
y10 = y15 ^ t0
y11 = y20 ^ y9
y7 = x7 ^ y11
y17 = y10 ^ y11
y19 = y10 ^ y8
y16 = t0 ^ y11
y21 = y13 ^ y16
y18 = x0 ^ y16
t2 = y12 & y15
t3 = y3 & y6
t4 = t3 ^ t2
t5 = y4 & x7
t6 = t5 ^ t2
t7 = y13 & y16
t8 = y5 & y1
t9 = t8 ^ t7
t10 = y2 & y7
t11 = t10 ^ t7
t12 = y9 & y11
t13 = y14 & y17
t14 = t13 ^ t12
t15 = y8 & y10
t16 = t15 ^ t12
t17 = t4 ^ t14
t18 = t6 ^ t16
t19 = t9 ^ t14
t20 = t11 ^ t16
t21 = t17 ^ y20
t22 = t18 ^ y19
t23 = t19 ^ y21
t24 = t20 ^ y18
t25 = t21 ^ t22
t26 = t21 & t23
t27 = t24 ^ t26
t28 = t25 & t27
t29 = t28 ^ t22
t30 = t23 ^ t24
t31 = t22 ^ t26
t32 = t31 & t30
t33 = t32 ^ t24
t34 = t23 ^ t33
t35 = t27 ^ t33
t36 = t24 & t35
t37 = t36 ^ t34
t38 = t27 ^ t36
t39 = t29 & t38
t40 = t25 ^ t39
t41 = t40 ^ t37
t42 = t29 ^ t33
t43 = t29 ^ t40
t44 = t33 ^ t37
t45 = t42 ^ t41
z0 = t44 & y15
z1 = t37 & y6
z2 = t33 & x7
z3 = t43 & y16
z4 = t40 & y1
z5 = t29 & y7
z6 = t42 & y11
z7 = t45 & y17
z8 = t41 & y10
z9 = t44 & y12
z10 = t37 & y3
z11 = t33 & y4
z12 = t43 & y13
z13 = t40 & y5
z14 = t29 & y2
z15 = t42 & y9
z16 = t45 & y14
z17 = t41 & y8
t46 = z15 ^ z16
t47 = z10 ^ z11
t48 = z5 ^ z13
t49 = z9 ^ z10
t50 = z2 ^ z12
t51 = z2 ^ z5
t52 = z7 ^ z8
t53 = z0 ^ z3
t54 = z6 ^ z7
t55 = z16 ^ z17
t56 = z12 ^ t48
t57 = t50 ^ t53
t58 = z4 ^ t46
t59 = z3 ^ t54
t60 = t46 ^ t57
t61 = z14 ^ t57
t62 = t52 ^ t58
t63 = t49 ^ t58
t64 = z4 ^ t59
t65 = t61 ^ t62
t66 = z1 ^ t63
s0 = t59 ^ t63
s6 = t56 ^ ~t62
s7 = t48 ^ ~t60
t67 = t64 ^ t65
s3 = t53 ^ t66
s4 = t51 ^ t66
s5 = t47 ^ t65
s1 = t64 ^ ~s3
s2 = t55 ^ ~t67
"""


def aes_sbox(cnf: CNF, q: list[int]) -> list[int]:
    values = {f"x{i}": q[7 - i] for i in range(8)}

    def operand(name: str) -> int:
        if name.startswith("~"):
            return -values[name[1:]]
        return values[name]

    for line in BOYAR_PERALTA.strip().splitlines():
        lhs, rhs = (part.strip() for part in line.split("=", 1))
        a, op, b = rhs.split()
        if op == "^":
            values[lhs] = cnf.XOR(operand(a), operand(b))
        elif op == "&":
            values[lhs] = cnf.AND(operand(a), operand(b))
        else:
            raise AssertionError(op)
    return [values["s7"], values["s6"], values["s5"], values["s4"],
            values["s3"], values["s2"], values["s1"], values["s0"]]


def aes128_zero(cnf: CNF, key: list[list[int]]) -> list[list[int]]:
    """AES-128(0) as a CNF Boolean circuit; bytes/bits are little-endian."""
    words = [key[i:i + 4] for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = [aes_sbox(cnf, temp[1]), aes_sbox(cnf, temp[2]),
                    aes_sbox(cnf, temp[3]), aes_sbox(cnf, temp[0])]
            temp[0] = byte_xor(cnf, temp[0], constant=rcon)
            rcon = ((rcon << 1) ^ (0x11B if rcon & 0x80 else 0)) & 0xFF
        words.append([byte_xor(cnf, words[i - 4][j], temp[j]) for j in range(4)])

    round_keys = [sum(words[4 * r:4 * r + 4], []) for r in range(11)]
    state = [byte_xor(cnf, round_keys[0][i]) for i in range(16)]
    for rnd in range(1, 11):
        state = [aes_sbox(cnf, x) for x in state]
        state = [state[4 * ((c + r) % 4) + r] for c in range(4) for r in range(4)]
        if rnd != 10:
            mixed = []
            for c in range(4):
                a0, a1, a2, a3 = state[4 * c:4 * c + 4]
                m0, m1, m2, m3 = (xtime(cnf, x) for x in (a0, a1, a2, a3))
                mixed.extend([
                    byte_xor(cnf, m0, m1, a1, a2, a3),
                    byte_xor(cnf, a0, m1, m2, a2, a3),
                    byte_xor(cnf, a0, a1, m2, m3, a3),
                    byte_xor(cnf, m0, a0, a1, a2, m3),
                ])
            state = mixed
        state = [byte_xor(cnf, state[i], round_keys[rnd][i]) for i in range(16)]
    return state


def ascii_hex_bits(cnf: CNF, b: list[int]) -> list[int]:
    """Map the four little-endian bits of a nibble to lowercase hex ASCII."""
    if cnf.native_tables:
        out = [cnf.var() for _ in range(8)]
        rows = []
        alphabet = b"0123456789abcdef"
        for value, mapped in enumerate(alphabet):
            rows.append(tuple((value >> bit) & 1 for bit in range(4))
                        + tuple((mapped >> bit) & 1 for bit in range(8)))
        cnf.add_table(b + out, rows)
        return out
    b0, b1, b2, b3 = b
    q01 = cnf.AND(b0, b1)
    q02 = cnf.AND(b0, b2)
    q12 = cnf.AND(b1, b2)
    m10 = cnf.AND(b1, b3)
    m11 = cnf.AND(q01, b3)
    m12 = cnf.AND(b2, b3)
    m13 = cnf.AND(q02, b3)
    m14 = cnf.AND(q12, b3)
    m15 = cnf.AND(m11, b2)
    return [
        cnf.xor_all([b0, m10, m12, m14]),
        cnf.xor_all([b1, m10, m11, m12, m13, m14, m15]),
        cnf.xor_all([b2, m12, m13, m14, m15]),
        cnf.xor_all([b3, m10, m12, m14]),
        cnf.xor_all([cnf.true, m10, m12, m14]),
        cnf.true,
        cnf.xor_all([m10, m12, m14]),
        cnf.false,
    ]


def pair_delta_for_hex(h: int, short_ch: str, long_ch: str,
                       hex_bytes: bytes, extra_z: int = 0) -> int:
    assert len(hex_bytes) == 32
    suffix = b"|encrypted by "
    a = short_ch.encode() + suffix + hex_bytes
    b = long_ch.encode() + suffix + hex_bytes
    assert len(b) == len(a) + 1
    assert (len(a) + 15) // 16 == (len(b) + 15) // 16
    size = ((len(b) + 15) // 16) * 16
    delta = bytearray(x ^ y for x, y in zip(a.ljust(size, b"\0"), b.ljust(size, b"\0")))
    delta[len(b) - 1] ^= extra_z
    y = 0
    for off in range(0, size, 16):
        y = solve.gf_mul(y ^ int.from_bytes(delta[off:off + 16], "big"), h)
    length_xor = (len(a) * 8) ^ (len(b) * 8)
    return solve.gf_mul(y ^ length_xor, h)


def add_tag_equations(cnf: CNF, h: int, high_halves: list[str],
                      ascii_bits: list[list[int]], z47: list[int], z49: list[int]):
    pairs = [
        (solve.CHARS[0], solve.CHARS[1], z47, 0, 1),
        (solve.CHARS[4], solve.CHARS[5], z49, 4, 5),
    ]
    zero = bytes(32)
    for short_ch, long_ch, zbits, ia, ib in pairs:
        base = pair_delta_for_hex(h, short_ch, long_ch, zero, 0)
        observed = (solve.parse_half(high_halves[ia], True)
                    ^ solve.parse_half(high_halves[ib], True))
        contributions: list[tuple[int, int]] = []
        for pos in range(32):
            for bit in range(8):
                hb = bytearray(32)
                hb[pos] = 1 << bit
                contributions.append((ascii_bits[pos][bit],
                                      pair_delta_for_hex(h, short_ch, long_ch,
                                                         bytes(hb), 0) ^ base))
        for bit in range(8):
            contributions.append((zbits[bit],
                                  pair_delta_for_hex(h, short_ch, long_ch,
                                                     zero, 1 << bit) ^ base))

        # Only the high nibble of each tag byte was printed in round zero.
        for out_pos in solve.selected_bit_positions():
            lits = [lit for lit, coeff in contributions if (coeff >> out_pos) & 1]
            rhs = ((observed ^ base) >> out_pos) & 1
            cnf.force(cnf.xor_all(lits), rhs)


def build_instance(high_halves: list[str], h: int, known_key: bytes | None = None,
                   native_xor: bool = True, native_tables: bool = False):
    cnf, nibs = build_tag_instance(high_halves, h, native_xor, native_tables)
    key_bits = []
    for i in range(16):
        # Low nibble occupies byte bits 0..3; high nibble occupies 4..7.
        key_bits.append(nibs[2 * i + 1] + nibs[2 * i])
    if known_key is not None:
        for i, value in enumerate(known_key):
            for bit in range(8):
                cnf.force(key_bits[i][bit], (value >> bit) & 1)

    out = aes128_zero(cnf, key_bits)
    h_bytes = h.to_bytes(16, "big")
    for i, value in enumerate(h_bytes):
        for bit in range(8):
            cnf.force(out[i][bit], (value >> bit) & 1)
    return cnf, nibs


def build_tag_instance(high_halves: list[str], h: int,
                       native_xor: bool = True, native_tables: bool = False):
    """Build only the small truncated-tag relation (no symbolic AES)."""
    cnf = CNF(native_xor=native_xor, native_tables=native_tables)
    nibs = [[cnf.var() for _ in range(4)] for _ in range(32)]
    ascii_bits = [ascii_hex_bits(cnf, n) for n in nibs]
    z47 = [cnf.var() for _ in range(8)]
    z49 = [cnf.var() for _ in range(8)]
    cnf.z47 = z47
    cnf.z49 = z49
    add_tag_equations(cnf, h, high_halves, ascii_bits, z47, z49)
    return cnf, nibs


def solve_cnf(cnf: CNF, nibs: list[list[int]], solver: str, keep: str | None = None) -> bytes:
    if keep:
        path = keep
        cnf.write(path)
        remove = False
    else:
        fd, path = tempfile.mkstemp(prefix="rrr-", suffix=".cnf")
        os.close(fd)
        cnf.write(path)
        remove = True
    try:
        proc = subprocess.run([solver, path], text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        if proc.returncode not in (10,):
            print(proc.stdout)
            raise RuntimeError(f"SAT solver exited {proc.returncode}")
        model: set[int] = set()
        for line in proc.stdout.splitlines():
            if line.startswith("v "):
                model.update(int(x) for x in line[2:].split() if int(x) > 0)
        key_nibbles = []
        for group in nibs:
            key_nibbles.append(sum((var in model) << bit for bit, var in enumerate(group)))
        key = bytes((key_nibbles[2 * i] << 4) | key_nibbles[2 * i + 1]
                    for i in range(16))
        return key
    finally:
        if remove:
            os.unlink(path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solver", default="cryptominisat5")
    ap.add_argument("--no-native-xor", action="store_true")
    ap.add_argument("--known-key", action="store_true",
                    help="unit-constrain the fixed test key (circuit sanity test)")
    ap.add_argument("--write-cnf")
    args = ap.parse_args()

    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    tags = [solve.tag_for(key, nonce, ch) for ch in solve.CHARS]
    highs = [tag[0::2] for tag in tags]
    h = solve.recover_h(highs)
    expected_h = int.from_bytes(AES.new(key, AES.MODE_ECB).encrypt(bytes(16)), "big")
    assert h == expected_h
    print(f"[+] H = {h:032x}", flush=True)
    cnf, nibs = build_instance(highs, h, key if args.known_key else None,
                               native_xor=not args.no_native_xor)
    print(f"[+] CNF: {cnf.nvars} variables, {len(cnf.clauses)} CNF + "
          f"{len(cnf.xor_clauses)} XOR clauses", flush=True)
    got = solve_cnf(cnf, nibs, args.solver, args.write_cnf)
    print(f"[+] key = {got.hex()}", flush=True)
    assert got == key


if __name__ == "__main__":
    main()
