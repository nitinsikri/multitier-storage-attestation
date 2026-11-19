import pytest

from attest import (SparseMerkleTree, verify, Cloudstore, MemoryBackend, AttestationSystem,
                    verify_deep)


def test_smt_inclusion_and_absence():
    t = SparseMerkleTree()
    for i in range(50):
        t.update(f"k{i}".encode(), f"v{i}".encode())
    assert verify(t.root, b"k7", b"v7", t.prove(b"k7"))
    assert not verify(t.root, b"k7", b"wrong", t.prove(b"k7"))
    assert verify(t.root, b"missing", None, t.prove(b"missing"))


def test_smt_delete_restores_root():
    t = SparseMerkleTree()
    empty = t.root
    t.update(b"a", b"1")
    t.update(b"a", None)
    assert t.root == empty


def test_cloudstore_detects_corruption():
    a, b = MemoryBackend("a"), MemoryBackend("b")
    cs = Cloudstore([a, b], replicas=2)
    k = cs.store_chunk(b"hello")
    a.blobs[k] = b"evil"
    assert cs.retrieve_chunk(k) == b"hello"
    b.blobs[k] = b"evil"
    with pytest.raises(KeyError):
        cs.retrieve_chunk(k)


def test_deep_proof_end_to_end():
    s = AttestationSystem(Cloudstore([MemoryBackend()]), l3_block_size=4, l2_block_size=2)
    s.deposit("u", 100)
    for i in range(20):
        s.write("u", f"f{i}", f"data{i}".encode())
    s.finalize()
    p = s.deep_proof("u", "f13")
    assert verify_deep(s.l1.head, p)
    p.l3_height += 1
    assert not verify_deep(s.l1.head, p)


def test_credits_enforced():
    s = AttestationSystem(Cloudstore([MemoryBackend()]))
    with pytest.raises(PermissionError):
        s.write("nobody", "x", b"1")
