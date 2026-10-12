#!/usr/bin/env python3
"""SAT model using the five nonconstant bits of each lowercase hex byte."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile

from Crypto.Cipher import AES

import solve
import sat_recover


def build(highs: list[str], h: int, full: bool, aes_output_bits: int = 128):
    cnf = sat_recover.CNF(native_xor=True)
    chars = []
    key_nibs = []
    alphabet = b"0123456789abcdef"
    for _ in range(32):
        low = [cnf.var() for _ in range(4)]
        alpha = cnf.var()
        chars.append(low + [alpha])

        # Exactly the sixteen lowercase hexadecimal ASCII combinations are
        # legal.  A 5-bit value has only sixteen invalid rows, so forbidding
        # them is much smaller than a one-hot selector encoding.
        valid = {(ord(chr(c)) & 0xF, 1 if c >= ord('a') else 0)
                 for c in alphabet}
        for a in range(2):
            for lo in range(16):
                if (lo, a) in valid:
                    continue
                assignment = [(lo >> bit) & 1 for bit in range(4)] + [a]
                cnf.add(*[-var if value else var
                          for var, value in zip(low + [alpha], assignment)])

        if full:
            raw = [cnf.var() for _ in range(4)]
            key_nibs.append(raw)
            # Bidirectional table implications between ASCII form and the raw
            # key nibble.  Both sides are useful to AES/tag propagation.
            for value, char in enumerate(alphabet):
                lo, a = char & 0xF, int(char >= ord('a'))
                not_ascii = [(-low[bit] if (lo >> bit) & 1 else low[bit])
                             for bit in range(4)]
                not_ascii.append(-alpha if a else alpha)
                for bit in range(4):
                    cnf.add(*not_ascii,
                            raw[bit] if (value >> bit) & 1 else -raw[bit])
                not_raw = [(-raw[bit] if (value >> bit) & 1 else raw[bit])
                           for bit in range(4)]
                for var, expected in zip(low + [alpha],
                                         [(lo >> bit) & 1 for bit in range(4)] + [a]):
                    cnf.add(*not_raw, var if expected else -var)

    z47 = [cnf.var() for _ in range(8)]
    z49 = [cnf.var() for _ in range(8)]
    zero = bytes(32)
    pairs = [
        (solve.CHARS[0], solve.CHARS[1], z47, 0, 1),
        (solve.CHARS[4], solve.CHARS[5], z49, 4, 5),
    ]
    for short, long, zbits, ia, ib in pairs:
        base = sat_recover.pair_delta_for_hex(h, short, long, zero, 0)
        obs = solve.parse_half(highs[ia], True) ^ solve.parse_half(highs[ib], True)
        terms = []
        # ASCII byte bits are low[0:4], !alpha, 1, alpha, 0.
        for pos, five in enumerate(chars):
            low, alpha = five[:4], five[4]
            ascii_bits = low + [-alpha, cnf.true, alpha, cnf.false]
            for bit, var in enumerate(ascii_bits):
                raw = bytearray(32)
                raw[pos] = 1 << bit
                coeff = (sat_recover.pair_delta_for_hex(
                    h, short, long, bytes(raw), 0) ^ base)
                terms.append((var, coeff))
        for bit, var in enumerate(zbits):
            coeff = (sat_recover.pair_delta_for_hex(
                h, short, long, zero, 1 << bit) ^ base)
            terms.append((var, coeff))
        for out_pos in solve.selected_bit_positions():
            lits = [var for var, coeff in terms if (coeff >> out_pos) & 1]
            # add_xor normalises negative literals and constant bits.
            cnf.add_xor(lits, bool(((obs ^ base) >> out_pos) & 1))

    if full:
        key_bits = [key_nibs[2 * i + 1] + key_nibs[2 * i] for i in range(16)]
        out = sat_recover.aes128_zero(cnf, key_bits)
        constrained = 0
        for i, value in enumerate(h.to_bytes(16, 'big')):
            for bit in range(8):
                if constrained < aes_output_bits:
                    cnf.force(out[i][bit], (value >> bit) & 1)
                constrained += 1
    return cnf, chars, key_nibs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--full', action='store_true')
    ap.add_argument('--aes-bits', type=int, default=128)
    ap.add_argument('--output')
    ap.add_argument('--solver', default='cryptominisat5')
    args = ap.parse_args()
    key=bytes.fromhex('00112233445566778899aabbccddeeff')
    nonce=bytes.fromhex('ffeeddccbbaa99887766554433221100')
    highs=[solve.tag_for(key,nonce,ch)[::2] for ch in solve.CHARS]
    h=solve.recover_h(highs)
    cnf,chars,nibs=build(highs,h,args.full,args.aes_bits)
    print(f'[+] vars={cnf.nvars} cnf={len(cnf.clauses)} xor={len(cnf.xor_clauses)}',flush=True)
    path=args.output
    remove=False
    if not path:
        fd,path=tempfile.mkstemp(suffix='.cnf');os.close(fd);remove=True
    cnf.write(path)
    try:
        p=subprocess.run([args.solver,'--verb=0',path],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        print(p.stdout[:1000],flush=True)
        if p.returncode!=10: raise RuntimeError(p.returncode)
        positive={int(x) for line in p.stdout.splitlines() if line.startswith('v ')
                  for x in line[2:].split() if int(x)>0}
        if args.full:
            ns=[sum((v in positive)<<bit for bit,v in enumerate(group)) for group in nibs]
            got=bytes((ns[2*i]<<4)|ns[2*i+1] for i in range(16))
            print('[+] key',got.hex());assert got==key
    finally:
        if remove:os.unlink(path)


if __name__=='__main__':main()
