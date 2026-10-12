#!/usr/bin/env python3
"""Offline integrity and structural checks for the teto solution bundle."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SHA256 = {
    "challenge/teto": "d96615673503a9336ab1de9ae3cfba86735354b06daee16e7accaf208b71bb0d",
    "challenge/teto.c": "d8a593934daf20a751a85127a3d9e6798857be999f911d09f14d7071ff81988b",
    "challenge/libc.so.6": "8db37cf3f2169f59a0f07ef1fea308c35656668c64c8ff294e1860f4121eb161",
    "challenge/ld-linux-x86-64.so.2": "cd4df4f3c7b83673d61189bf2eaebd33ca4f2853ab9772b8a25e025ef99b1e81",
    "runtime/libc.so.6": "d8db8739a1633c972cec6a4fe0566bdcec6fd088f98723492ab0361f66238f75",
    "runtime/ld-linux-x86-64.so.2": "1cd555ac46b7887edeaf3c42aac5408c8135e52f6b37870da2cf82d5fe14e829",
    "plans/exploit_plan.txt": "1b5fb65214dd303a29a868649f05be64858859d6fa9601fcbd82c4e5c520ae84",
    "plans/session2_plan.txt": "ff826f6a36a8bf0b5cd8060de109c2ed94e132453e56f7811c0b230a3ee6b8c3",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_plan(path: Path) -> dict[int, str]:
    plan: dict[int, str] = {}
    for raw_line in path.read_text(encoding="ascii").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        index, command = line.split()
        plan[int(index)] = command
    return plan


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    print("Checking immutable challenge/runtime artifacts...")
    for relative, expected in EXPECTED_SHA256.items():
        path = ROOT / relative
        require(path.is_file(), f"missing {relative}")
        actual = sha256(path)
        require(actual == expected, f"SHA-256 mismatch for {relative}: {actual}")
        print(f"  OK  {relative}")

    for relative in (
        "challenge/teto",
        "challenge/libc.so.6",
        "challenge/ld-linux-x86-64.so.2",
        "runtime/libc.so.6",
        "runtime/ld-linux-x86-64.so.2",
    ):
        require((ROOT / relative).read_bytes()[:4] == b"\x7fELF", f"not ELF: {relative}")

    first = load_plan(ROOT / "plans/exploit_plan.txt")
    second = load_plan(ROOT / "plans/session2_plan.txt")
    require(set(first) == set(range(8406)), "first plan must cover 0..8405")
    require(set(second) == set(range(8407, 20000)), "second plan range is incomplete")
    require(first[15] == "LATCH", "first pressure latch moved")
    require(first[8343] == "EVIL", "first leak marker moved")
    require(sum(command == "EVIL" for command in first.values()) == 20, "bad first EVIL count")
    require(second[8429] == "LATCH", "second pressure latch moved")
    require(second[19962] == "EVIL", "second malicious interval moved")
    require(sum(command == "EVIL" for command in second.values()) == 16, "bad second EVIL count")
    print("  OK  deterministic plan ranges and markers")

    libc = (ROOT / "runtime/libc.so.6").read_bytes()
    require(libc[0x12A5FE : 0x12A602] == b"\x75\x1b\xc9\xc3", "pivot gadget bytes changed")
    require(
        libc[0xEF52B : 0xEF532] == b"\x4c\x8d\x1d\xfd\xbe\x0d\x00",
        "execve gadget bytes changed",
    )
    print("  OK  runtime gadget bytes")
    print("Bundle verification passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
