# BlackHat MEA Qualification CTF 2026

Solutions, exploits, and writeups for challenges I solved at the **BlackHat MEA
Qualification CTF 2026**, hosted on the [FlagYard](https://flagyard.com) platform.

- **Event:** BlackHat MEA 2026 — Qualification round
- **Dates:** September 5–6, 2026
- **Platform:** FlagYard
- **Flag format:** `BHFlagY{...}`
- **Author:** [hax1ng](https://github.com/hax1ng)

## Solved challenges

| Challenge | Category | Solves | Writeup |
|---|---|:--:|---|
| Reduce, Reuse, Recycle | Crypto | 33 | [writeup](crypto/reduce-reuse-recycle/README.md) |
| Teto | Pwn | 17 | [writeup](pwn/teto/README.md) |

Each challenge directory contains a self-contained writeup (`README.md`), the final
exploit/solver, and the relevant challenge artifacts needed to reproduce the solve.

## Highlights

- **Reduce, Reuse, Recycle** *(crypto)* — AES-GCM with a reused key **and** nonce,
  the key echoed inside every plaintext, and only half of each tag leaked. GHASH
  linearity recovers `H` and a large `GF(2)` system for the key; the finishing move
  is a structural observation about lowercase-hex ASCII (one bit is set only for `8`
  and `9`) that turns an intractable SAT enumeration into fast linear algebra, beating
  the server's 300-second alarm.

- **Teto** *(pwn)* — a terminal Tetris game whose only bug is that `set_cell` accepts
  `y == -1`. Combined with a ceiling-pressure kick, an **I** piece becomes a repeatable
  OR-only one-bit stack write. Unseeded `rand()` makes the whole game pre-plannable, so
  deterministic Tetris plays widen `Game.width` (leaking PIE/libc/stack via the
  renderer), re-enter `main` with a `leave; ret` pivot, and assemble an
  `execve("/bin/sh")` gadget pointer one bit at a time — using the program's own stack
  as most of the "ROP chain".

## Repository layout

```
.
├── crypto/
│   └── reduce-reuse-recycle/   # AES-GCM nonce reuse + sparse-ASCII key recovery
└── pwn/
    └── teto/                   # Tetris OR-write → leak → re-enter main → shell
```

## Reproducing

Each writeup has its own instructions. In short:

```bash
# Crypto
cd crypto/reduce-reuse-recycle
python3 -m pip install pycryptodome
python3 exploit.py --selftest --max-weight 4        # offline reproduction

# Pwn (Linux x86-64)
cd pwn/teto
make setup && make check
.venv/bin/python exploit.py --retry                 # local, correct runtime libc
```

## Notes

- Flags shown in the writeups are the ones captured during the event.
- Remote host/port values are assigned per instance by the platform and are supplied on
  the command line rather than hardcoded.
