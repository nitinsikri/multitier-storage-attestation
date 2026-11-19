# Multi-Tier Cloud Storage Attestation with Sparse Merkle Trees

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.24380952.svg)](https://doi.org/10.5281/zenodo.24380952)

Reference implementation of the method described in:

**Nitin Sikri.** *Multi-Tier Cloud Storage Attestation: A Hierarchical Verification Architecture for Distributed Cloud Integrity.* Proceedings of the 5th International Conference on Big Data and Artificial Intelligence Applications (ICBDAIA'26), Springer, Lecture Notes in Networks and Systems, 2026. *(In press.)*

> **Reference implementation.** This repository was written in November 2026, after the paper was accepted, to illustrate the method described in the paper and to make it easy to reuse. It is **not** the original experimental code, it runs on **synthetic data**, and its numbers will **differ** from the results reported in the paper. Please cite the paper for the method and its reported results.

## What the paper proposes

A three-tier attestation architecture. Layer 3 storage chains record storage operations in Sparse Merkle Trees and anchor their block hashes into a Layer 2 Plasma-Cash-style chain, which manages storage credits and anchors its blocks into a Layer 1 immutable ledger. Data chunks live in a content-addressed **Cloudstore** spanning several providers. A **Deep Merkle Proof** links any storage record to the Layer 1 head.

## What this repository contains

- `attest/smt.py` – 256-level Sparse Merkle Tree (SHA-256) with compact inclusion and non-inclusion proofs
- `attest/cloudstore.py` – content-addressed chunk store replicated over pluggable backends (memory, local directory), with corruption detection
- `attest/layers.py` – Layer 3 / Layer 2 chains, Layer 1 hash-chained ledger, anchoring, storage credits, Deep Merkle Proof construction and verification
- `examples/demo_and_benchmark.py`, `tests/`

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. python examples/demo_and_benchmark.py
python -m pytest -q
```



## How it maps to the paper

| Paper | Code |
|---|---|
| Layer 1 immutable ledger (2.1) | `Layer1Ledger` |
| Layer 2 Plasma Cash chain, tokens (2.2) | `AttestationSystem.l2`, `deposit` |
| Layer 3 storage chains (2.3) | `AttestationSystem.l3`, `write` |
| Cloudstore abstraction (2.4, 3.5) | `Cloudstore.store_chunk`, `retrieve_chunk` |
| Sparse Merkle Tree (3.4) | `SparseMerkleTree`, `verify` |
| Deep Merkle Proof | `deep_proof`, `verify_deep` |

## Limitations

- Layer 1 is a local hash-chained ledger, not Ethereum/Ganache; Layer 2 has no consensus, fraud proofs or exits.
- Cloud backends are in-memory and local-directory stand-ins for S3, GCS or SWARM.
- Old tree states are kept as full copies for proof generation – simple but memory-heavy.
- Latency figures are local measurements and differ from the paper.

## How to cite

If you use this code, please cite the paper:

```bibtex
@inproceedings{sikri2026attestation,
  author    = {Sikri, Nitin},
  title     = {Multi-Tier Cloud Storage Attestation: A Hierarchical Verification Architecture for Distributed Cloud Integrity},
  booktitle = {Proceedings of the 5th International Conference on Big Data and Artificial Intelligence Applications (ICBDAIA'26)},
  publisher = {Springer, Lecture Notes in Networks and Systems},
  year      = {2026}
}
```

To cite this software itself, use its Zenodo DOI: [10.5281/zenodo.24380952](https://doi.org/10.5281/zenodo.24380952).

GitHub also shows a **"Cite this repository"** button generated from `CITATION.cff`.

## Licence

MIT – see [LICENSE](LICENSE).
