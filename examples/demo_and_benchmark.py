"""Store files across two backends, build Deep Merkle Proofs, detect tampering,
and measure proof size and verification time as the number of records grows."""
import os
import tempfile
import time

import numpy as np

from attest import (Cloudstore, MemoryBackend, LocalDirBackend, AttestationSystem,
                    verify_deep, SparseMerkleTree, verify)

tmp = tempfile.mkdtemp()
store = Cloudstore([MemoryBackend("cloud-a"), LocalDirBackend(os.path.join(tmp, "b"), "cloud-b")])
sys_ = AttestationSystem(store, l3_block_size=32, l2_block_size=4)
sys_.deposit("alice", 1000)

for i in range(500):
    sys_.write("alice", f"doc{i}.txt", f"contents of document {i}".encode())
sys_.finalize()

p = sys_.deep_proof("alice", "doc42.txt")
print("Deep proof valid      :", verify_deep(sys_.l1.head, p))
print("Deep proof size       :", p.size_bytes(), "bytes")
print("Read back             :", sys_.read("alice", "doc42.txt"))

p.record_value = p.record_value[:-2] + b"9}"          # change the recorded size
print("Tampered proof valid  :", verify_deep(sys_.l1.head, p))

k = store.key_of(b"contents of document 7")
store.backends[0].blobs[k] = b"corrupted"
print("Read after corrupting one replica:", store.retrieve_chunk(k))

print("\nrecords   SMT update µs   proof bytes   verify µs")
for n in [100, 1_000, 10_000]:
    t = SparseMerkleTree()
    keys = [f"k{i}".encode() for i in range(n)]
    t0 = time.perf_counter()
    for k_ in keys:
        t.update(k_, b"v" + k_)
    upd = (time.perf_counter() - t0) / n * 1e6
    sample = keys[:: max(1, n // 50)]
    sizes, ver = [], []
    for k_ in sample:
        pr = t.prove(k_)
        sizes.append(pr.size_bytes())
        t0 = time.perf_counter()
        assert verify(t.root, k_, b"v" + k_, pr)
        ver.append((time.perf_counter() - t0) * 1e6)
    print(f"{n:>7}   {upd:13.0f}   {np.mean(sizes):11.0f}   {np.mean(ver):9.0f}")
