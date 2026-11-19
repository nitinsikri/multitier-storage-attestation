"""Cloudstore abstraction: content-addressed chunks replicated over several backends.

``store_chunk(v)`` returns k = SHA-256(v); ``retrieve_chunk(k)`` checks the hash,
so a tampered or corrupted replica is detected and the next backend is tried.
Real deployments would plug in S3, GCS or a decentralised network; here we ship
an in-memory backend and a local-directory backend.
"""
from __future__ import annotations

import hashlib
import os


class MemoryBackend:
    def __init__(self, name="memory"):
        self.name, self.blobs = name, {}

    def put(self, k: str, v: bytes):
        self.blobs[k] = v

    def get(self, k: str) -> bytes | None:
        return self.blobs.get(k)


class LocalDirBackend:
    def __init__(self, path: str, name="localdir"):
        self.name, self.path = name, path
        os.makedirs(path, exist_ok=True)

    def put(self, k: str, v: bytes):
        with open(os.path.join(self.path, k), "wb") as f:
            f.write(v)

    def get(self, k: str) -> bytes | None:
        p = os.path.join(self.path, k)
        return open(p, "rb").read() if os.path.exists(p) else None


class Cloudstore:
    def __init__(self, backends, replicas: int = 2):
        self.backends, self.replicas = list(backends), replicas

    @staticmethod
    def key_of(v: bytes) -> str:
        return hashlib.sha256(v).hexdigest()

    def store_chunk(self, v: bytes) -> str:
        k = self.key_of(v)
        start = int(k[:8], 16) % len(self.backends)
        for j in range(min(self.replicas, len(self.backends))):
            self.backends[(start + j) % len(self.backends)].put(k, v)
        return k

    def retrieve_chunk(self, k: str) -> bytes:
        for b in self.backends:
            v = b.get(k)
            if v is not None and self.key_of(v) == k:
                return v
        raise KeyError(f"no intact replica of chunk {k[:12]}...")
