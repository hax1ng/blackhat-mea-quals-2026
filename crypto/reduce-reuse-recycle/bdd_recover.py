#!/usr/bin/env python3
"""Compile the truncated-tag solution space to a CUDD BDD.

This is an experiment in projected AllSAT: Gaussian elimination first turns
the 128 tag XORs into affine expressions in 48 free bits.  The only remaining
conditions are the 32 tiny predicates saying that each five-bit byte is a
lowercase hexadecimal ASCII character.
"""

from __future__ import annotations

import time

from Crypto.Cipher import AES
import ascii_recover
import solve


def affine_system(highs, h, chosen_free=None, direction=None):
    cnf, chars, _ = ascii_recover.build(highs, h, False)
    logical = [v for group in chars for v in group]
    logical += sorted({v for xs, _ in cnf.xor_clauses for v in xs}
                      - set(logical))
    assert len(logical) == 176
    index = {v: i for i, v in enumerate(logical)}
    rows = []
    for xs, rhs in cnf.xor_clauses:
        mask = 0
        value = int(rhs)
        for lit in xs:
            if lit < 0:
                value ^= 1
                lit = -lit
            if lit == cnf.true:
                value ^= 1
            else:
                mask ^= 1 << index[lit]
        rows.append([mask, value])

    # Optionally change the five coordinates of every character.  The final
    # coordinate is a direction ``d`` through the five-bit alphabet and the
    # first four remain the standard basis.  Directions 0b11000, 0b11001,
    # 0b11110 and 0b11111 are especially useful: only one of the 16 cosets in
    # that direction contains two valid hexadecimal characters (and only one
    # contains none), so validity almost determines this coordinate.
    if direction is not None:
        assert direction & 0x10 and 0 < direction < 32
        transformed = []
        for old_mask, value in rows:
            new_mask = old_mask
            for base in range(0, 160, 5):
                # u0..u3 have columns e0..e3 and u4 has column ``direction``.
                bit = (old_mask >> (base + 4)) & 1
                for j in range(4):
                    if direction >> j & 1:
                        bit ^= (old_mask >> (base + j)) & 1
                if bit:
                    new_mask |= 1 << (base + 4)
                else:
                    new_mask &= ~(1 << (base + 4))
            transformed.append([new_mask, value])
        rows = transformed
        if chosen_free is None:
            chosen_free = list(range(160, 176)) + list(range(4, 160, 5))

    # By default use ordinary left-to-right pivots.  A caller can instead
    # provide 48 non-pivot columns.  In particular, leaving one bit from
    # every character plus the 16 stream bits free produces a much better
    # distributed coordinate system than leaving the final characters free.
    if chosen_free is None:
        pivot_order = list(range(176))
    else:
        chosen_free = list(chosen_free)
        assert len(chosen_free) == 48 and len(set(chosen_free)) == 48
        chosen_set = set(chosen_free)
        pivot_order = [i for i in range(176) if i not in chosen_set]

    row = 0
    pivots = []
    for col in pivot_order:
        pivot = next((i for i in range(row, len(rows))
                      if rows[i][0] >> col & 1), None)
        if pivot is None:
            continue
        rows[row], rows[pivot] = rows[pivot], rows[row]
        for i in range(len(rows)):
            if i != row and rows[i][0] >> col & 1:
                rows[i][0] ^= rows[row][0]
                rows[i][1] ^= rows[row][1]
        pivots.append(col)
        row += 1
    assert row == 128
    if chosen_free is None:
        free = [i for i in range(176) if i not in set(pivots)]
    else:
        assert set(pivots).isdisjoint(chosen_free)
        free = chosen_free
    expressions = [None] * 176
    for j, col in enumerate(free):
        expressions[col] = (1 << j, 0)
    for i, col in enumerate(pivots):
        mask = 0
        for j, free_col in enumerate(free):
            if rows[i][0] >> free_col & 1:
                mask |= 1 << j
        expressions[col] = (mask, rows[i][1])
    if direction is not None:
        # Convert affine expressions in u back to the original compact ASCII
        # coordinates y = B*u, so callers need no other changes.
        def axor(a, b):
            return a[0] ^ b[0], a[1] ^ b[1]
        original = expressions[:]
        for base in range(0, 160, 5):
            for j in range(4):
                original[base + j] = expressions[base + j]
                if direction >> j & 1:
                    original[base + j] = axor(original[base + j],
                                               expressions[base + 4])
            original[base + 4] = expressions[base + 4]
        expressions = original
    return expressions, chars, logical


def main():
    from dd import cudd
    key0 = bytes.fromhex("00112233445566778899aabbccddeeff")
    nonce = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    highs = [solve.tag_for(key0, nonce, ch)[::2] for ch in solve.CHARS]
    h = solve.recover_h(highs)
    expressions, chars, logical = affine_system(highs, h)
    pos = {v: i for i, v in enumerate(logical)}

    bdd = cudd.BDD()
    names = [f"f{i}" for i in range(48)]
    bdd.declare(*names)
    # Leave dynamic reordering off initially; explicit ordering is reproducible.
    free_nodes = [bdd.var(name) for name in names]

    cache = {}
    def expr(mask, const):
        key = (mask, const)
        if key in cache:
            return cache[key]
        out = bdd.true if const else bdd.false
        while mask:
            bit = (mask & -mask).bit_length() - 1
            out = bdd.apply("xor", out, free_nodes[bit])
            mask &= mask - 1
        cache[key] = out
        return out

    values = [expr(*e) for e in expressions]
    root = bdd.true
    started = time.monotonic()
    order = list(range(32))
    # Shorter supports first tends to keep intermediate BDDs smaller.
    order.sort(key=lambda i: sum(expressions[pos[v]][0].bit_count()
                                 for v in chars[i]))
    for step, i in enumerate(order, 1):
        low = [values[pos[v]] for v in chars[i][:4]]
        alpha = values[pos[chars[i][4]]]
        l0, l1, l2, l3 = low
        le9 = ~(l3 & (l2 | l1))
        one_to_six = ~l3 & (l0 | l1 | l2) & ~(l0 & l1 & l2)
        valid = le9 & (~alpha | one_to_six)
        root &= valid
        print(step, i, len(bdd), root.dag_size,
              bdd.count(root, nvars=48), time.monotonic() - started,
              flush=True)

    target = h.to_bytes(16, "big")
    count = 0
    for model in bdd.pick_iter(root, care_vars=set(names)):
        free_value = sum(bool(model[n]) << i for i, n in enumerate(names))
        ascii_vals = []
        for group in chars:
            bits = []
            for var in group:
                mask, const = expressions[pos[var]]
                bits.append(((free_value & mask).bit_count() ^ const) & 1)
            lo = sum(bits[i] << i for i in range(4))
            ascii_vals.append(lo + 9 if bits[4] else lo)
        key = bytes((ascii_vals[2*i] << 4) | ascii_vals[2*i+1]
                    for i in range(16))
        count += 1
        if AES.new(key, AES.MODE_ECB).encrypt(bytes(16)) == target:
            print("FOUND", key.hex(), count, time.monotonic() - started)
            assert key == key0
            return
    print("exhausted", count)


if __name__ == "__main__":
    main()
