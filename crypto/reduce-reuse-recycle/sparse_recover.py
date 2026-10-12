#!/usr/bin/env python3
"""Fast first-key recovery for the Reduce, Reuse, Recycle challenge.

The two truncated, adjacent-length tag differences give 128 linear equations
in 160 variable bits of the hexadecimal ASCII key and 16 stream bits.  A
lowercase hexadecimal character has the compact representation

    (low ASCII nibble, is_a_through_f).

Bit 3 of the low ASCII nibble is one only for the characters ``8`` and ``9``.
For a random hexadecimal key its Hamming weight is therefore Binomial(32,1/8).
After fixing those 32 sparse bits, the linear system has only 16 dimensions.
Moreover, at every set bit, validity forces low bits 1 and 2 and the alphabetic
bit to zero.  These extra linear conditions normally remove three more
dimensions per occurrence.  Enumerating sparse supports in increasing weight
therefore replaces the impractical projected-AllSAT search.
"""

from __future__ import annotations

import itertools
import time

from Crypto.Cipher import AES

import ascii_recover
import bdd_recover


class SparseBasisError(RuntimeError):
    """The desired 32 sparse coordinates cannot be extended to a basis."""


def _logical_system(highs: list[str], h: int):
    """Return the 128 tag rows in the logical 176-variable coordinate order."""
    cnf, chars, _ = ascii_recover.build(highs, h, False)
    logical = [variable for group in chars for variable in group]
    logical += sorted(
        {variable for variables, _ in cnf.xor_clauses for variable in variables}
        - set(logical)
    )
    if len(logical) != 176:
        raise AssertionError(f"expected 176 logical variables, got {len(logical)}")
    position = {variable: index for index, variable in enumerate(logical)}

    rows: list[list[int]] = []
    for variables, rhs in cnf.xor_clauses:
        mask = 0
        value = int(rhs)
        for literal in variables:
            if literal < 0:
                value ^= 1
                literal = -literal
            if literal == cnf.true:
                value ^= 1
            else:
                mask ^= 1 << position[literal]
        rows.append([mask, value])
    if len(rows) != 128:
        raise AssertionError(f"expected 128 tag equations, got {len(rows)}")
    return rows


def _sparse_affine_system(highs: list[str], h: int):
    """Use all 32 low-nibble bit-3 values as the first free coordinates."""
    rows = _logical_system(highs, h)
    sparse_columns = [5 * index + 3 for index in range(32)]
    sparse_set = set(sparse_columns)

    # Find a 128-column basis without using the desired sparse coordinates.
    # The 16 unused non-sparse columns complete them to 48 free coordinates.
    work = [row[:] for row in rows]
    pivots: list[int] = []
    rank = 0
    for column in (i for i in range(176) if i not in sparse_set):
        pivot = next(
            (i for i in range(rank, len(work)) if (work[i][0] >> column) & 1),
            None,
        )
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        for i in range(len(work)):
            if i != rank and ((work[i][0] >> column) & 1):
                work[i][0] ^= work[rank][0]
                work[i][1] ^= work[rank][1]
        pivots.append(column)
        rank += 1
        if rank == 128:
            break
    if rank != 128:
        raise SparseBasisError(
            f"non-sparse columns have rank {rank}, expected 128; reconnect"
        )

    pivot_set = set(pivots)
    residual = [
        i for i in range(176) if i not in sparse_set and i not in pivot_set
    ]
    if len(residual) != 16:
        raise AssertionError(f"expected 16 residual coordinates, got {len(residual)}")
    chosen_free = sparse_columns + residual

    expressions, chars, logical = bdd_recover.affine_system(
        highs, h, chosen_free=chosen_free
    )
    position = {variable: index for index, variable in enumerate(logical)}
    ordered = [expressions[position[variable]] for group in chars for variable in group]

    # Split every affine expression into the 32 sparse coordinates, 16
    # residual coordinates, and its constant.
    compact = [
        (mask & 0xFFFFFFFF, (mask >> 32) & 0xFFFF, constant)
        for mask, constant in ordered
    ]
    for index in range(32):
        if compact[5 * index + 3] != (1 << index, 0, 0):
            raise AssertionError("sparse coordinate was not left free")
    return compact


def _solve_16(equations: list[tuple[int, int]]):
    """Solve affine equations in 16 bits; return a point and nullspace basis."""
    rows = [[mask, rhs] for mask, rhs in equations]
    rank = 0
    pivot_columns: list[int] = []
    for column in range(16):
        pivot = next(
            (i for i in range(rank, len(rows)) if (rows[i][0] >> column) & 1),
            None,
        )
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and ((rows[i][0] >> column) & 1):
                rows[i][0] ^= rows[rank][0]
                rows[i][1] ^= rows[rank][1]
        pivot_columns.append(column)
        rank += 1

    if any(mask == 0 and rhs for mask, rhs in rows):
        return None

    particular = sum(rows[i][1] << column for i, column in enumerate(pivot_columns))
    pivot_set = set(pivot_columns)
    basis: list[int] = []
    for free in range(16):
        if free in pivot_set:
            continue
        vector = 1 << free
        for i, column in enumerate(pivot_columns):
            if (rows[i][0] >> free) & 1:
                vector |= 1 << column
        basis.append(vector)
    return particular, basis


def recover_key_sparse(
    highs: list[str],
    h: int,
    *,
    max_weight: int = 5,
    progress: bool = True,
) -> bytes | None:
    """Recover the AES key, or return ``None`` if its 8/9 weight is too high.

    Searching through weight five covers about 79.6% of independently random
    keys.  A caller with a live service should simply reconnect for a fresh key
    if this returns ``None``; a complete pass normally takes well below the
    service's 300-second alarm.
    """
    expressions = _sparse_affine_system(highs, h)
    target = h.to_bytes(16, "big")
    zero = bytes(16)
    started = time.monotonic()
    patterns = assignments = candidates = 0

    def bit_value(expression, sparse: int, residual: int) -> int:
        sparse_mask, residual_mask, constant = expression
        return (
            (sparse_mask & sparse).bit_count()
            ^ (residual_mask & residual).bit_count()
            ^ constant
        ) & 1

    for weight in range(max_weight + 1):
        for support in itertools.combinations(range(32), weight):
            patterns += 1
            sparse = sum(1 << index for index in support)

            # If bit 3 of the ASCII low nibble is one, the only valid
            # characters are 8 and 9.  Therefore low bits 1 and 2 and the
            # alphabetic flag must all be zero; low bit 0 remains free.
            equations: list[tuple[int, int]] = []
            for index in support:
                for offset in (1, 2, 4):
                    sparse_mask, residual_mask, constant = expressions[5 * index + offset]
                    rhs = ((sparse_mask & sparse).bit_count() ^ constant) & 1
                    equations.append((residual_mask, rhs))
            solution = _solve_16(equations)
            if solution is None:
                continue
            residual, basis = solution

            # Gray-code traversal changes only one nullspace direction at a
            # time and avoids rebuilding the residual word for every model.
            previous_gray = 0
            for counter in range(1 << len(basis)):
                if counter:
                    gray = counter ^ (counter >> 1)
                    changed = gray ^ previous_gray
                    previous_gray = gray
                    residual ^= basis[(changed & -changed).bit_length() - 1]
                assignments += 1

                # With sparse bit 0, validity fails only for alphabetic low
                # nibbles 0 and 7.  Reject those cases before decoding/AES.
                valid = True
                for index in range(32):
                    if (sparse >> index) & 1:
                        continue
                    values = [
                        bit_value(expressions[5 * index + offset], sparse, residual)
                        for offset in (0, 1, 2, 4)
                    ]
                    if values[3] and (
                        not (values[0] | values[1] | values[2])
                        or (values[0] & values[1] & values[2])
                    ):
                        valid = False
                        break
                if not valid:
                    continue

                candidates += 1
                nibbles: list[int] = []
                for index in range(32):
                    low = sum(
                        bit_value(expressions[5 * index + bit], sparse, residual) << bit
                        for bit in range(4)
                    )
                    alpha = bit_value(expressions[5 * index + 4], sparse, residual)
                    nibbles.append(low + 9 if alpha else low)
                key = bytes(
                    (nibbles[2 * i] << 4) | nibbles[2 * i + 1] for i in range(16)
                )
                if AES.new(key, AES.MODE_ECB).encrypt(zero) == target:
                    if progress:
                        elapsed = time.monotonic() - started
                        print(
                            f"[+] key {key.hex()} (8/9 weight {weight}; "
                            f"{patterns} supports, {candidates} candidates, "
                            f"{elapsed:.2f}s)",
                            flush=True,
                        )
                    return key

        if progress:
            elapsed = time.monotonic() - started
            print(
                f"[*] exhausted 8/9 weight {weight}: {patterns} supports, "
                f"{assignments} affine models, {candidates} keys, {elapsed:.2f}s",
                flush=True,
            )
    return None

