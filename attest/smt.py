"""Sparse Merkle Tree (depth 256, SHA-256) with compact inclusion and
non-inclusion proofs."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

DEPTH = 256


def H(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def leaf_hash(value: bytes | None) -> bytes:
    return DEFAULTS[0] if value is None else H(b"\x00", value)


# default (empty) hash at each height: DEFAULTS[h] is the root of an empty subtree of height h
DEFAULTS = [H(b"empty")]
for _ in range(DEPTH):
    DEFAULTS.append(H(b"\x01", DEFAULTS[-1], DEFAULTS[-1]))


def path_bits(key: bytes) -> int:
    return int.from_bytes(H(key), "big")


@dataclass
class Proof:
    bitmap: int               # bit h set -> sibling at height h is non-default
    siblings: list[bytes]     # non-default siblings, from leaf level upwards

    def size_bytes(self) -> int:
        return 32 + 32 * len(self.siblings)


class SparseMerkleTree:
    def __init__(self):
        self.nodes: dict[tuple[int, int], bytes] = {}   # (height, prefix) -> hash
        self.values: dict[bytes, bytes] = {}

    def _get(self, height: int, prefix: int) -> bytes:
        return self.nodes.get((height, prefix), DEFAULTS[height])

    def update(self, key: bytes, value: bytes | None):
        idx = path_bits(key)
        if value is None:
            self.values.pop(key, None)
        else:
            self.values[key] = value
        h = leaf_hash(value)
        self.nodes[(0, idx)] = h
        for height in range(1, DEPTH + 1):
            prefix = idx >> height
            child = idx >> (height - 1)
            sib = self._get(height - 1, child ^ 1)
            left, right = (h, sib) if child & 1 == 0 else (sib, h)
            h = H(b"\x01", left, right)
            self.nodes[(height, prefix)] = h

    @property
    def root(self) -> bytes:
        return self._get(DEPTH, 0)

    def get(self, key: bytes) -> bytes | None:
        return self.values.get(key)

    def prove(self, key: bytes) -> Proof:
        idx = path_bits(key)
        bitmap, sibs = 0, []
        for height in range(DEPTH):
            sib = self._get(height, (idx >> height) ^ 1)
            if sib != DEFAULTS[height]:
                bitmap |= 1 << height
                sibs.append(sib)
        return Proof(bitmap, sibs)


def verify(root: bytes, key: bytes, value: bytes | None, proof: Proof) -> bool:
    """True if ``key`` maps to ``value`` under ``root`` (value=None proves absence)."""
    idx = path_bits(key)
    h = leaf_hash(value)
    it = iter(proof.siblings)
    for height in range(DEPTH):
        sib = next(it) if proof.bitmap >> height & 1 else DEFAULTS[height]
        h = H(b"\x01", h, sib) if (idx >> height) & 1 == 0 else H(b"\x01", sib, h)
    return h == root
