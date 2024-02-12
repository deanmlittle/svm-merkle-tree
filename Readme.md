# SVM Merkle Tree
An SVM-optimised Merkle tree that makes use of Solana syscalls under the hood. It has the following features:

- Bitcoin Merkle tree parity
- Sha256/Sha256D/Keccak/Keccakd
- A CLI to produce valid Merkle trees/roots/proofs
- A WASM package
- Full test coverage
- Anchor serialization
- Truncated hashes
- Double hashing of leaves by default to prevent length-extension attacks in truncated hashes

# Caveats
There are some things to keep in mind when using SVM-merkle tree

### Truncated hashes
Due to the transaction size limit of Solana, more complicated programs with larger Merkle trees will often find it preferable to use truncated branch hashes. It is important to consider the security tradeoffs of doing so. The shorter you make your hashes, the greater the potential risk of exposing yourself to length-extension attacks, where an attacker is able to mine a comptaible hash due to the relatively lower bit security of a truncated one.

### Adding leaves
SVM Merkle Tree aims to prevent length-extension attacks by enforcing double-hashing when adding leaves, regardless of whether or not a double-hashing algorithm is selected. Conversely, it also prevents quadruple-hashing in the case that a double-hashing algorithm is selected.

As an example, the pseudocode of sha256 hashing a leaf with a `hash_size` of `20` would be as follows:

```rs
let leaf1_hash = sha256(sha256(leaf1_bytes))[..20].to_vec();
let leaf2_hash = sha256(sha256(leaf2_bytes))[..20].to_vec();
``` 

Branch hashing is as follows:
```rs
sha256([leaf1_hash, leaf2_hash].concat())[..20]
```

As you can see, the first sha256 hash of the leaf is not truncated to provide greater security to the preimage of the second hash. This is a well-known security measure to prevent length-extension attacks. The second hash is then truncated to pair with its branch hashes.

The branches are simply paired, single-hashed and truncated. If you do not wish to truncate branch hashes, simply set the hash size to 0 or 32.

### Adding hashes
If you wish to add a prehashed leaf to the tree, it is possible to do so, however other than checking `hash_size`, it is not possible for SVM Merkle Tree to know whether or not the leaf has been double hashed. If you wish to use the tree in this way, please keep in mind that sanitizing and normalizing the data will then be up to you.

### Odd-numbered trees
If the number of hashes are odd, it is recommended you implement one of the following:
- Include the index number of each leaf in its preimage,
- Add an additional fake final leaf for padding, or
- Keep track of the total leaf count in the tree externally

The reason for this is, if you are using a Bitcoin-compatible Merkle tree for some kind of single-use whitelist functionality, the final leaf of an odd tree will be paired with itself. This means the final leaf actually has two valid positions in an odd-length tree.