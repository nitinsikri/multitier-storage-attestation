"""Three-tier hierarchical attestation.

Layer 3  storage chain: records storage operations in an SMT; each block's hash is
         sent to Layer 2 as an *anchor transaction*.
Layer 2  Plasma-Cash-style chain: SMT of anchors and token balances (storage
         credits); each block's hash is anchored into Layer 1.
Layer 1  immutable ledger (stand-in for a public blockchain): append-only,
         hash-chained list of anchors.

A *Deep Merkle Proof* chains: record -> L3 SMT root -> L3 block hash -> L2 SMT
-> L2 block hash -> L1 ledger entry, so anyone holding the L1 head can verify a
storage record end to end.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .smt import SparseMerkleTree, Proof, verify, H


def block_hash(height: int, prev: bytes, root: bytes) -> bytes:
    return H(b"block", height.to_bytes(8, "big"), prev, root)


class Layer1Ledger:
    def __init__(self):
        self.entries: list[tuple[bytes, bytes]] = []    # (payload, entry_hash)

    def anchor(self, payload: bytes) -> int:
        prev = self.entries[-1][1] if self.entries else b"\x00" * 32
        self.entries.append((payload, H(prev, payload)))
        return len(self.entries) - 1

    @property
    def head(self) -> bytes:
        return self.entries[-1][1]

    def inclusion(self, i: int):
        """Payloads after entry i, enough to recompute the head from entry i."""
        prev = self.entries[i - 1][1] if i else b"\x00" * 32
        return prev, [p for p, _ in self.entries[i + 1:]]


def verify_l1(head: bytes, payload: bytes, prev: bytes, later: list[bytes]) -> bool:
    h = H(prev, payload)
    for p in later:
        h = H(h, p)
    return h == head


class Chain:
    """Generic SMT-backed block chain used for Layers 2 and 3."""

    def __init__(self, name: str):
        self.name, self.smt = name, SparseMerkleTree()
        self.height, self.prev = 0, b"\x00" * 32
        self.pending = 0
        self.blocks: dict[int, tuple[bytes, bytes, bytes]] = {}   # h -> (prev, root, hash)
        self.snapshots: dict[int, SparseMerkleTree] = {}          # h -> tree at seal time

    def put(self, key: bytes, value: bytes):
        self.smt.update(key, value)
        self.pending += 1

    def seal(self) -> tuple[int, bytes]:
        root = self.smt.root
        self.height += 1
        bh = block_hash(self.height, self.prev, root)
        self.blocks[self.height] = (self.prev, root, bh)
        # keep an immutable copy of the tree so proofs can be issued for old blocks
        # (simple but memory-heavy; a production system would use a persistent tree)
        snap = SparseMerkleTree()
        snap.nodes, snap.values = dict(self.smt.nodes), dict(self.smt.values)
        self.snapshots[self.height] = snap
        self.prev, self.pending = bh, 0
        return self.height, bh


@dataclass
class DeepProof:
    record_key: bytes
    record_value: bytes
    l3_height: int
    l3_prev: bytes
    l3_root: bytes
    l3_proof: Proof
    l2_height: int
    l2_prev: bytes
    l2_root: bytes
    l2_proof: Proof
    l1_index: int
    l1_prev: bytes
    l1_later: list

    def size_bytes(self) -> int:
        return (self.l3_proof.size_bytes() + self.l2_proof.size_bytes()
                + 32 * (4 + len(self.l1_later)) + len(self.record_value))


class AttestationSystem:
    def __init__(self, cloudstore, l3_block_size: int = 64, l2_block_size: int = 8):
        self.store = cloudstore
        self.l3, self.l2, self.l1 = Chain("L3"), Chain("L2"), Layer1Ledger()
        self.l3_block_size, self.l2_block_size = l3_block_size, l2_block_size
        self.where: dict[bytes, int] = {}          # record key -> L3 height that sealed it
        self.l3_to_l2: dict[int, int] = {}
        self.l2_to_l1: dict[int, int] = {}
        self.balances: dict[str, int] = {}

    # Layer 2 token accounting (storage credits)
    def deposit(self, user: str, amount: int):
        self.balances[user] = self.balances.get(user, 0) + amount
        self.l2.put(f"bal:{user}".encode(), str(self.balances[user]).encode())

    def write(self, user: str, name: str, data: bytes, price: int = 1) -> str:
        if self.balances.get(user, 0) < price:
            raise PermissionError("insufficient storage credits")
        self.balances[user] -= price
        k = self.store.store_chunk(data)
        rec_key = f"{user}/{name}".encode()
        rec = json.dumps({"chunk": k, "size": len(data)}).encode()
        self.l3.put(rec_key, rec)
        self.where[rec_key] = self.l3.height + 1
        if self.l3.pending >= self.l3_block_size:
            self.flush_l3()
        return k

    def flush_l3(self):
        if not self.l3.pending:
            return
        h, bh = self.l3.seal()
        self.l2.put(f"anchor:L3:{h}".encode(), bh)          # anchor transaction
        self.l3_pending_in_l2 = getattr(self, "l3_pending_in_l2", []) + [h]
        if self.l2.pending >= self.l2_block_size:
            self.flush_l2()

    def flush_l2(self):
        if not self.l2.pending:
            return
        h, bh = self.l2.seal()
        i = self.l1.anchor(bh)
        self.l2_to_l1[h] = i
        for l3h in getattr(self, "l3_pending_in_l2", []):
            self.l3_to_l2[l3h] = h
        self.l3_pending_in_l2 = []

    def finalize(self):
        self.flush_l3()
        self.flush_l2()

    def read(self, user: str, name: str) -> bytes:
        rec = json.loads(self.l3.smt.get(f"{user}/{name}".encode()))
        return self.store.retrieve_chunk(rec["chunk"])

    def deep_proof(self, user: str, name: str) -> DeepProof:
        """Build the proof against the *current* sealed state of each layer."""
        key = f"{user}/{name}".encode()
        l3h = self.where[key]
        l2h = self.l3_to_l2[l3h]
        prev3, root3, _ = self.l3.blocks[l3h]
        prev2, root2, _ = self.l2.blocks[l2h]
        # proofs are produced from snapshots kept at seal time
        p3 = self._snapshot_proof(self.l3, l3h, key)
        p2 = self._snapshot_proof(self.l2, l2h, f"anchor:L3:{l3h}".encode())
        i = self.l2_to_l1[l2h]
        prev1, later = self.l1.inclusion(i)
        return DeepProof(key, self._snapshot_value(self.l3, l3h, key), l3h, prev3, root3, p3,
                         l2h, prev2, root2, p2, i, prev1, later)

    def _snapshot_proof(self, chain, height, key):
        return chain.snapshots[height].prove(key)

    def _snapshot_value(self, chain, height, key):
        return chain.snapshots[height].get(key)


def verify_deep(l1_head: bytes, p: DeepProof) -> bool:
    """Verify a record all the way down to the Layer 1 head."""
    if not verify(p.l3_root, p.record_key, p.record_value, p.l3_proof):
        return False
    l3_hash = block_hash(p.l3_height, p.l3_prev, p.l3_root)
    if not verify(p.l2_root, f"anchor:L3:{p.l3_height}".encode(), l3_hash, p.l2_proof):
        return False
    l2_hash = block_hash(p.l2_height, p.l2_prev, p.l2_root)
    return verify_l1(l1_head, l2_hash, p.l1_prev, p.l1_later)
