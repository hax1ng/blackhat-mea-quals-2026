# Teto

**Category:** Pwn &nbsp;|&nbsp; **Author:** FlagYard &nbsp;|&nbsp; **Solves:** 17 &nbsp;|&nbsp; **Flag:** `BHFlagY{7579e13457113e0ecde7b1afdadd71f6}`

> How many tetris pwn have you seen in CTFs?

## TL;DR

`teto` is a terminal Tetris game with a tiny signed-coordinate mistake: `set_cell`
accepts `y == -1`, so under the right conditions a pressure-kicked vertical **I**
piece locks one cell *above* the board and ORs a bit into stack memory just before
`Game.stage`. That's an **OR-only one-bit write** per suitable I piece. The game
never seeds `rand()`, so the piece sequence is identical every run — meaning we can
pre-compute deterministic Tetris plans that play thousands of pieces and reserve
specific I pieces as writes. Those writes first widen `Game.width` (turning the
renderer into a stack leak that defeats PIE/libc/stack ASLR), then edit saved RBP
and the return address to re-enter `main`, and finally build an
`execve("/bin/sh")` gadget pointer one bit at a time — reusing pointers already on
the startup stack as most of the "ROP chain".

## What we're given

A small live Tetris clone plus its source (`challenge/teto.c`), the challenge ELF
(`challenge/teto`), a supplied loader + libc, and a Docker recipe
(`challenge/Dockerfile`, `challenge/compose.yml`). The relevant structures:

```c
typedef struct {
    uint32_t score;
    uint16_t height;
    uint16_t width;      // immediately before stage[]
    uint8_t  stage[40];  // 10 cols * 20 rows, 2 bytes per row
} Game;
```

## Initial analysis

A cell is set like this:

```c
static void set_cell(Game *g, int x, int y) {
    if (x < 0) return;
    if (y < -1) return;                 // <-- rejects -2, deliberately ALLOWS -1
    if ((uint32_t)x >= g->width) return;
    if (y >= (int)g->height) return;
    int idx = y * (int)ROW_BYTES + (x >> 3);
    g->stage[idx] |= (uint8_t)(1u << (x & 7));   // OR-write, bit we choose
}
```

`y == -1` indexes *before* `stage[]`, i.e. into `width` and beyond onto the stack.
Normally pieces above the board aren't locked — but the **ceiling-pressure** mechanic
changes that.

## The vulnerability / core idea

**1. Getting a write out of bounds.** Once the board has held ≥ 60 occupied cells, a
permanent `ceiling_pressure` flag is latched. Rotating a tall piece as it enters the
board triggers special upward kicks (`tall_entry_kicks`), moving a vertical I piece so
three cells sit above the board and the bottom cell locks at `y = -1`. `lock_piece()`
then calls `set_cell()` with the negative index.

**2. It's OR-only.** `g->stage[idx] |= 1 << bit` can only flip a `0` bit to `1`. For a
target qword at byte offset `O` from `stage` and bit `b`, the needed x coordinate is:

```
x = 8 * (O + floor(b/8) + 2) + (b mod 8)       // the +2 absorbs the 2-byte row stride
```

**3. Widening `width` to reach the stack.** Initially `width == 10`, so large x is
rejected by the width check — but `width` sits directly before `stage`. The first
malicious I piece ORs a bit into `width` (`0x000a → 0x008a`); a later one makes it
`0x108a`. Now huge x coordinates pass the check and reach far up the stack.

**4. The renderer becomes a leak.** The draw code computes its row stride from the
mutable width: `stride = (width + 7) / 8`. With `width = 0x8a` the stride is 18 bytes,
but it still prints 10 bytes of bits per row — so rows 1,2,3,… read at `stage+18`,
`stage+36`, … i.e. **stack memory**, rendered as `#`(1)/`.`(0). Decoding gives, with
`S = stage` address:

```
S+112  argv (= S+384)            -> stack base:  S       = leaked_argv - 384
S+128  PIE main pointer          -> PIE base     = leaked_main - 0x2e44
S+256  libc startup (libc+0x2a28b) -> libc base   = leaked - 0x2a28b
```

That defeats PIE, libc and stack ASLR in one shot.

**5. Unseeded RNG → thousands of predictable pieces.** `rand()` is never seeded, so
piece *N* is the same in every process. A beam-search Tetris player (in
[`tools/`](tools/)) produced the checked-in deterministic plans that survive long
enough to reach the needed I pieces.

## Exploitation

Because the primitive is so weak (one chosen bit per I piece), the exploit **reuses
pointers already on the startup stack** instead of writing full addresses:

**First game (18 writes after widening).** Change saved RBP and the return address:

```
[S+88] : S+248        -> S+280          (1 bit, favorable alignment)
[S+96] : libc+0x2a1ca -> libc+0x12a5fe  (5 bits)  ; gadget = `jne; leave; ret`
```

`main()` checks its canary (ZF set → `jne` not taken), does its own `leave` loading our
`S+280` into RBP, then the gadget's `leave; ret` pops `S+400` into RBP and returns into
the existing `main` pointer at `S+288` — **re-entering `main`** without writing a full
PIE pointer. Six writes buy the pivot; the other twelve begin building the final libc
pointer in a conveniently-zero qword at `S+296` (zero start is ideal for an OR-only
write).

**Second game (16 I pieces; 2 widen, 14 data).** The re-entered main saves RBP at
`S+288`; one write bumps it `S+400 → S+464`, and the remaining thirteen finish:

```
[S+296] = libc + 0xef52b
```

When the second `main` returns normally: `RAX = 0`, `RBP = S+464`, return address
`= libc+0xef52b` — a one-shot `execve("/bin/sh", …)` gadget whose constraints line up
(`RBP-0x50 = S+384` scratch for `["/bin/sh", NULL]`, `RBP-0x78 = S+344` zero → `envp =
NULL`, `RAX = 0` → argv terminator). Shell.

**Why it reconnects.** OR-only means an old pointer's set bits must all survive in the
new one, and the new bits must fit the write budget (25 bits total: 12 + 13). Before
committing, the solver checks that `S+248→S+280`, `S+400→S+464`, and
`popcount(libc+0xef52b) ≤ 25` are all satisfiable under the current ASLR layout; if
not, it drops the connection and tries a fresh layout. That's expected, not a crash.

### A sneaky libc mismatch

The **supplied** `challenge/libc.so.6` is *not* the libc used by the Docker image /
remote service:

```
supplied: 328820b908de8ea1ef79afa8995e302e819163d7
runtime:  8e9fd827446c24067541ac5390e6f527fb5947bb
```

Their startup leak offset happens to coincide (so the leak looks perfect) but the
gadgets differ — later gadgets crashed until the real runtime libc was extracted from
the pinned Ubuntu 24.04 image into [`runtime/`](runtime/). The exploit always uses the
`runtime/` offsets.

## Running it

Requirements: Linux x86-64, Python 3.10+, `venv`/`pip`.

```bash
make setup                 # venv + pwntools
make check                 # offline integrity + structural verification

# Local: packaged binary with the correct runtime libc
.venv/bin/python exploit.py --retry

# Automated proof (success marker: TETO_EXPLOIT_DONE)
.venv/bin/python exploit.py --retry --no-interactive --command 'echo PWNED; id'

# Remote service (per-instance host/port from the platform)
.venv/bin/python exploit.py --remote HOST:PORT --retry
```

Optional Docker mode (needs network to build the pinned image):

```bash
make docker-up
.venv/bin/python exploit.py --docker --retry
make docker-down
```

## Flag retrieval

```
GAME OVER
PWNED
BHFlagY{7579e13457113e0ecde7b1afdadd71f6}
EXPLOIT_DONE
```

## Directory layout

```
pwn/teto/
├── exploit.py            self-contained final exploit
├── Makefile              setup / check / local / docker / planners
├── requirements.txt      pwntools
├── SHA256SUMS            integrity manifest
├── challenge/            original ELF + source + SUPPLIED (mismatched) libc + Docker recipe
├── runtime/              libc + loader actually used by Docker/remote (exploit uses these)
├── plans/               deterministic Tetris plans (pieces 0..8405 and 8407..19999)
└── tools/
    ├── verify_bundle.py  offline integrity/structure checks
    ├── plan_exploit.cpp  first-plan beam-search generator
    └── plan_session.cpp  later-session beam-search generator
```

Regenerating the plans is optional and CPU/memory-intensive (`make planners`); the
precomputed plans are checked in and are what the exploit uses.

## Key takeaways

* A single `y == -1` off-by-one becomes a repeatable **OR-only one-bit** stack write.
* A mutable `width` field turns both the **write range** and the **renderer read range**
  into attacker-controlled leaks.
* **Unseeded `rand()`** makes an arbitrarily long game perfectly predictable — pre-plan
  the whole thing offline.
* With a severely limited primitive, **reuse existing stack pointers**: a `leave; ret`
  pivot re-enters `main` for a handful of bits instead of a full address.
* Always confirm the **runtime libc**, even when the first leaked offsets coincidentally
  match the supplied one.
