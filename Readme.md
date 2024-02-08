# SVM Merkle Tree
An SVM-optimised Merkle tree that makes use of Solana syscalls under the hood. It has the following features:

- Bitcoin merklization parity
- Sha256/Sha256D/Keccak/Keccakd
- A CLI to produce valid Merkle trees/roots/proofs
- Anchor serialization
- Truncated hashes
- Double hashing of leaves by default to prevent length-extension attacks in truncated hashes