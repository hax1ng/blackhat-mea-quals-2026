# Reduce, Reuse, Recycle

**Category:** Crypto &nbsp;|&nbsp; **Author:** FlagYard &nbsp;|&nbsp; **Solves:** 33 &nbsp;|&nbsp; **Flag:** `BHFlagY{44bba543c5f59b47e5204e0c1fc8b86d}`

> Reduce what you waste. Reuse what you can. Recycle what remains.

## TL;DR

The server reuses a single AES-GCM key **and** nonce, puts the AES key itself
inside every plaintext, and leaks only alternating halves of each GCM tag. Three
same-length messages recover the GCM authentication value `H = AES_K(0)`; two
adjacent-length pairs turn into a big `GF(2)` linear system for the key's
hexadecimal text. That system still leaves ~`2^16` candidate keys, and getting
them out of a generic SAT solver is too slow — so the trick is to notice that one
particular ASCII bit is set **only** for the digits `8` and `9`, which are sparse
in a random key. Guessing their positions collapses the search into tiny 16-bit
linear systems, each candidate checked with `AES_K(0) == H`. Once the key is
accepted, round 1 completes the tags and the nonce falls out of a `2^16` search.

## What we're given

A single Python service (`prob.py`). The whole challenge is these few lines:

```python
from Crypto.Cipher import AES
import os, signal

signal.alarm(300)
keys = [os.urandom(16), os.urandom(16)]

for r in [0, 1]:
    for ch in input("> ")[:6]:
        cipher = AES.new(keys[0], AES.MODE_GCM, nonce=keys[1])
        cipher.encrypt(f"{ch}|encrypted by {keys[0].hex()}".encode())
        print(cipher.hexdigest()[r::2])
    assert input(f"keys[{r}]> ") == keys[r].hex()

print(os.environ.get("DYN_FLAG", ...))
```

To get the flag we have to submit `keys[0]` (the AES key) after only round 0, and
then `keys[1]` (the nonce) after round 1.

## Initial analysis

There are several independent mistakes packed into those lines:

1. The **same** AES key and GCM nonce are reused for every message.
2. The plaintext contains the hexadecimal AES key (`keys[0].hex()`).
3. `hexdigest()` is the GCM authentication **tag**, not the ciphertext.
4. Round 0 prints hex positions `0, 2, 4, …` — the *high* nibble of each tag byte.
5. Round 1 prints positions `1, 3, 5, …` — the *low* nibble of each tag byte.
6. `input()[:6]` slices six **Unicode code points**, not six encoded bytes.

The awkward constraint is ordering: we must produce `keys[0]` from only the high
half of each tag, and a wrong guess hits the `assert` and kills the connection
(keys are fresh per process, so you can't retry on the same instance). The
service also installs a 300-second alarm, so the key recovery has to be fast.

### A short GCM refresher

A GCM tag can be written as `T = AES_K(J0) XOR GHASH_H(ciphertext)`, where
`H = AES_K(0^128)` and `J0` is derived from the nonce. The key property we abuse
is that **GHASH is linear over `GF(2^128)`**: if two messages share the key,
nonce and length, XORing their tags cancels the entire secret counter stream and
leaves a predictable equation in their plaintext difference and `H`. That is the
"reuse" in the title.

## The vulnerability / core idea

Point 6 lets us control message lengths precisely. We send six characters whose
UTF-8 encodings have hand-picked lengths:

```
Character:       A   é   ק   ˎ   €   😀
UTF-8 length:    1   2   2   2   3   4
Message length: 47  48  48  48  49  50     (fixed suffix "|encrypted by "+32 hex = 46 bytes)
```

That layout gives us exactly:

* **three** 48-byte messages → recover `H`;
* a 47/48-byte adjacent pair, and a 49/50-byte adjacent pair → key equations.

### Step 1 — recover `H` from half-tags

The three 48-byte messages differ only in their first data block. A 48-byte
plaintext spans three GHASH data blocks plus a length block, so a first-block
difference is multiplied by `H^4`:

```
T_a XOR T_b = delta(a, b) * H^4
```

Multiplication by a known field element is **linear** on the 128 bits of `H^4`.
Round 0 gives 64 known bits per tag difference; two independent differences give
128 equations, which (for these characters) are full rank. Solve over `GF(2)` for
`X = H^4`, then take a fourth root in the field: `H = X^(2^126)` (because
`x^(2^128) = x`). Implemented as `recover_h()` in [`solve.py`](solve.py).

### Step 2 — turn the shifted messages into key equations

Compare a 47-byte with a 48-byte message: the one-byte-longer prefix shifts the
`|encrypted by <hex key>` text by one byte, so almost all reused counter-stream
bytes cancel in the tag difference — the only new unknown is one freshly-used
stream byte (`z47`; the 49/50 pair introduces `z49`). Each pair gives 64 visible
tag bits, i.e. 128 linear equations in:

* the variable bits of the 32 hex ASCII key characters, and
* the 16 bits of `z47 || z49`.

Each lowercase hex character needs only five changing bits
`(l0, l1, l2, l3, alpha)`. That's `32*5 + 16 = 176` unknowns, 128 equations →
a 48-dimensional affine space; hex-validity trims ~1 bit/char, leaving ≈ `2^16`
valid keys. Small enough to AES-test — but hard to *enumerate* with generic
SAT/SMT/BDD tooling (see "Dead ends").

### Step 3 — the sparse `8`/`9` trick (the part that makes it practical)

Look at the low nibbles of hex ASCII. Bit `l3` (value 8) is set **only** for the
characters `8` and `9`. For a random key that happens with probability
`2/16 = 1/8` per character — about four set bits across 32 characters.

So pick all 32 `l3` bits as free coordinates of the affine solution space;
Gaussian elimination gives 16 more residual coordinates. Then enumerate possible
positions of `8`/`9` in increasing Hamming weight. Wherever `l3 = 1`, validity
forces `l1 = l2 = alpha = 0` (three extra linear equations per occurrence), so the
remaining 16-bit system usually has only ~`16 - 3w` free bits (≈ 4 bits for the
common `w = 4`). Each surviving candidate is converted back to 16 raw key bytes
and checked with:

```python
AES.new(candidate, AES.MODE_ECB).encrypt(bytes(16)) == H   # i.e. AES_K(0) == H
```

Supports up to weight 5 cover ≈ 79.6% of random keys; if none match, the exploit
just reconnects for a fresh key rather than burning the whole 300-second budget.
Implemented in [`sparse_recover.py`](sparse_recover.py). The live key had three
`8`/`9` occurrences and was recovered in ≈ 14 seconds.

### Step 4 — complete the tags and recover the nonce

After the key is accepted, we replay the same six characters in round 1 and
interleave the halves into six full 128-bit tags. With the key, `H`, plaintexts
and full tags known, write the 48- and 50-byte tag equations in terms of
`M = AES_K(J0)` and the CTR blocks. XORing `A*H` into `B` cancels the shared
stream blocks and leaves one equation whose only remaining unknown is the first
two bytes of a counter block — a `2^16` search. For each guess derive `M`,
decrypt to a candidate `J0`, verify `AES_K(inc32(J0,4))[:2]`, then invert the
16-byte-nonce relation `J0 = N*H^2 XOR 128*H` and confirm against **all six**
tags (an occasional false 16-bit match is expected). See
`recover_nonce_checked()` in [`exploit.py`](exploit.py).

## Exploitation

The full chain is automated in [`exploit.py`](exploit.py):

```
connect  → send "Aéקˎ€😀"  → read 6 high-nibble tag lines → recover H
         → enumerate key (sparse 8/9) → submit keys[0]
replay   → read 6 low-nibble tag lines → join full tags → recover nonce
         → submit keys[1] → read flag
```

### Running it

```bash
python3 -m pip install pycryptodome

# Fixed local reproduction (no network) — recovers a known key+nonce:
python3 exploit.py --selftest --max-weight 4

# Against the live service (per-instance host/port from the platform):
python3 exploit.py tcp.flagyard.com <PORT> --max-weight 5 --attempts 10
```

The exploit makes exactly one scoring connection per attempt and auto-reconnects
on an unfavorable (heavy `8`/`9`) key or a flaky instance.

## Flag retrieval

```
[*] high halves: [...]
[+] H     = <recovered at runtime>
[+] key   = <recovered in ~14 s>
[*] low halves:  [...]
[+] nonce = <recovered via 2^16 search>
[+] flag  = BHFlagY{44bba543c5f59b47e5204e0c1fc8b86d}
```

## Dead ends (what *didn't* work)

The ≈ `2^16` candidate count makes AES-filtering trivial, but **enumerating** the
candidates defeated every generic tool we tried:

* Monolithic Z3 / cvc5 / Bitwuzla over full symbolic AES + tag equations — timeout.
* Full-AES SAT with a Boyar–Peralta S-box in CryptoMiniSat/CaDiCaL/Kissat —
  correct circuit, still over budget (weak propagation from one known pair).
* Native-XOR candidate enumeration — ~2–3 candidates/sec, far too slow for 2^16.
* Fixing `z47 || z49` and solving per value — wrong values gave brutal UNSAT proofs.
* CUDD / `pc2bdd` BDD compilation — intermediate BDDs exploded on dense affine supports.
* PolyBoRi / Sage Gröbner bases — degree-4 predicates blew up to ~10k terms.
* Projected AllSAT (TabularAllSAT), even 16-way on a 20-thread box — best generic
  method but still too slow and scaled poorly under contention.

The lesson: the final win wasn't an AES weakness at all — it was spotting a tiny
structural fact about lowercase-hex ASCII and converting the search into
linear algebra.

## Files

| File | Role |
|---|---|
| [`exploit.py`](exploit.py) | End-to-end network exploit + `--selftest`; `recover_nonce_checked()`. |
| [`sparse_recover.py`](sparse_recover.py) | The fast sparse-`8`/`9` key enumerator (the key idea). |
| [`solve.py`](solve.py) | `GF(2^128)` arithmetic, GHASH, `recover_h()`, tag/nonce helpers. |
| [`ascii_recover.py`](ascii_recover.py) | Compact five-bit hex-ASCII encoding + tag constraint builder. |
| [`bdd_recover.py`](bdd_recover.py) | Gaussian elimination into the 48-dimensional affine system. |
| [`sat_recover.py`](sat_recover.py) | CNF/XOR + AES Boolean-circuit helpers used by the above. |
| [`prob.py`](prob.py) | Original challenge source. |

> `ascii_recover.py`, `bdd_recover.py` and `sat_recover.py` are the support
> modules the final solver imports; their standalone `__main__` CLIs were part of
> the (ultimately abandoned) SAT experiments and are not needed to run the exploit.

## Key takeaways

* **Reduce** (half-tag leak) + **Reuse** (key *and* nonce) + **Recycle** (key text
  inside the plaintext) — the title literally describes the bug chain.
* Nonce reuse makes GHASH a linear oracle; carefully chosen UTF-8 lengths let you
  pick exactly which linear equations you get.
* When a search space is "small" (`2^16`) but a solver chokes, look for exploitable
  structure in the *representation* — here, a single sparse ASCII bit.
