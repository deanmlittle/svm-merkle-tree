use crate::errors::Result;
use core::marker::PhantomData;
use std::ops::Sub;

use crate::{MerkleError, MerkleHash};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MerkleNode<const N: usize>([u8; N], bool); // (buffer , is_occupied)

impl<const N: usize> MerkleNode<N> {
    pub fn inner(&self) -> &[u8] {
        &self.0
    }

    pub fn is_occupied(&self) -> bool {
        self.1
    }

    pub fn is_not_occupied(&self) -> bool {
        !self.is_occupied() && self.0 == [0; N]
    }

    pub fn inner_cloned(&self) -> [u8; N] {
        self.0.clone()
    }
}

impl<const N: usize> From<[u8; N]> for MerkleNode<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes, true)
    }
}

impl<const N: usize> Default for MerkleNode<N> {
    fn default() -> Self {
        MerkleNode([0; N], false)
    }
}

pub const fn nodes_from_depth(depth: usize) -> usize {
    (1 << (depth + 1)) - 1
}

pub struct MerkleTree<H: MerkleHash<N>, const N: usize, const NODES: usize, const DEPTH: usize> {
    root: MerkleNode<N>,
    nodes: [MerkleNode<N>; NODES],
    leaf_count: usize,
    _phantom: PhantomData<H>,
}

/// Macro to create a new MerkleTree instance with a given hash function and number of levels.
///
/// # Parameters
/// - `$hash_fn`: The hash function type (must implement a trait providing `HASH_LEN`).
/// - `$levels`: Number of levels in the tree (including the root).
///
/// # Returns
/// A `MerkleTree` instance with all nodes initialized to default.
#[macro_export]
macro_rules! merkle_tree {
    ($hash_fn:ty, $levels:expr) => {{
        // Hash size (in bytes) for the given hash function
        const N: usize = <$hash_fn>::HASH_LEN;

        const DEPTH: usize = $levels - 1;

        // Total number of nodes in a full binary tree of this depth
        const NODES: usize = nodes_from_depth(DEPTH);

        // Construct the MerkleTree struct
        MerkleTree::<$hash_fn, N, NODES, DEPTH> {
            // Root node initialized to default
            root: MerkleNode::default(),

            // Array of all nodes, initially set to default
            nodes: [MerkleNode::default(); NODES],

            // Initially zero leaves
            leaf_count: 0,

            // PhantomData to associate the hash function type with the tree
            _phantom: core::marker::PhantomData::<$hash_fn>,
        }
    }};
}

impl<H: MerkleHash<N>, const N: usize, const NODES: usize, const DEPTH: usize>
    MerkleTree<H, N, NODES, DEPTH>
{
    pub const LEAVES_COUNT: usize = (NODES + 1) / 2;
    // pub const DEPTH: u32 = Self::LEAVES_COUNT.ilog2();

    /// Get Merkle Root
    pub fn get_root(&self) -> Result<&MerkleNode<N>> {
        if self.root == MerkleNode::<N>::default() {
            return Err(MerkleError::TreeNotMerklized.into());
        }
        Ok(&self.root)
    }

    /// Get Merkle Node by index
    pub fn get_node(&self, idx: usize) -> Option<MerkleNode<N>> {
        self.nodes.get(idx).map(|l| l.clone())
    }

    /// Check if Tree is Merklized
    pub fn merklized(&self) -> Result<()> {
        if self.root.inner().eq(&[0u8; 32]) {
            return Err(MerkleError::TreeNotMerklized.into());
        }
        Ok(())
    }

    /// Reset Merkle Tree
    pub fn reset(&mut self) {
        self.nodes = [MerkleNode::<N>::default(); NODES];
        self.leaf_count = 0;
    }

    /// Add a single leaf
    pub fn add_leaf(&mut self, leaf: &[u8]) -> Result<()> {
        if self.leaf_count >= Self::LEAVES_COUNT {
            return Err(MerkleError::LeafOutOfRange.into());
        }
        self.nodes[self.leaf_count] = H::hash(leaf);
        self.leaf_count += 1;
        Ok(())
    }

    /// Add multiple leaves at once
    pub fn add_leaves(&mut self, leaves: &[&[u8]]) -> Result<()> {
        for leaf in leaves {
            self.add_leaf(leaf)?;
        }
        Ok(())
    }

    /// Add a hashes leaf
    pub fn add_hash(&mut self, hash: [u8; N]) -> Result<()> {
        if self.leaf_count >= Self::LEAVES_COUNT {
            return Err(MerkleError::LeafOutOfRange.into());
        }
        self.nodes[self.leaf_count] = MerkleNode::from(hash);
        self.leaf_count += 1;
        Ok(())
    }

    /// Add multiple hashes leaves
    pub fn add_hashes(&mut self, nodes: &[[u8; N]]) -> Result<()> {
        for hash in nodes {
            self.add_hash(*hash)?;
        }
        Ok(())
    }

    /// Merklize
    pub fn merklize(&mut self) {
        let mut offset = 0;

        // Go from deepest level (leaves) up to root
        for level in (0..=DEPTH).rev() {
            let current_level_nodes = 1 << level; // 2^level

            let parent_start = offset + current_level_nodes;
            let mut parent_idx = parent_start;

            // process in pairs
            for i in (0..current_level_nodes - 1).step_by(2) {
                let left_idx = offset + i;
                let right_idx = offset + i + 1;

                let parent = {
                    let left = self.nodes[left_idx];
                    let right = self.nodes[right_idx];

                    match (left.is_not_occupied(), right.is_not_occupied()) {
                        (false, false) => H::merkle_hashv(left.inner(), right.inner(), false),
                        (false, true) => H::merkle_hashv(left.inner(), left.inner(), false),
                        (true, false) => H::merkle_hashv(right.inner(), left.inner(), false), // this case wont occur
                        (true, true) => MerkleNode::default(),
                    }
                };

                self.nodes[parent_idx] = parent;
                parent_idx += 1;
            }

            offset += current_level_nodes; // move offset up for next level
        }

        if let Some(last) = self.nodes.last() {
            self.root = *last;
        }
    }

    /// Total merkle nodes counr
    pub fn nodes_len(&self) -> usize {
        self.nodes.len()
    }

    /// Get parent by index and level
    pub fn get_parent_node(&self, node_level: u32, node_idx: usize) -> Result<&MerkleNode<N>> {
        let parent_idx = self.get_parent_node_idx(node_level, node_idx)?;
        self.nodes.get(parent_idx).ok_or(MerkleError::NodeNotFound)
    }

    pub fn get_parent_node_idx(&self, node_level: u32, node_idx: usize) -> Result<usize> {
        println!("node idx : {}", node_idx);
        if node_level == 0 || node_level > DEPTH as u32 {
            return Err(MerkleError::NodeNotFound); // root has no parent
        }

        let level_start: usize = ((node_level + 1) as usize..=DEPTH).map(|l| 1 << l).sum();

        let relative_idx = node_idx - level_start;

        let parent_level = node_level - 1;
        let parent_start: usize = ((parent_level + 1) as usize..=DEPTH).map(|l| 1 << l).sum();

        let parent_idx = parent_start + (relative_idx >> 1);

        println!("parent idx : {}", parent_idx);

        Ok(parent_idx)
    }

    /// Get Proof path from leaf node to Root
    pub fn get_proof_path_for_leaf_idx(&self, leaf_idx: usize) -> Result<[MerkleNode<N>; DEPTH]> {
        if leaf_idx >= self.leaf_count {
            return Err(MerkleError::LeafOutOfRange);
        }

        let mut index = leaf_idx;

        let mut proof = [MerkleNode::default(); DEPTH];

        for level in (1..=DEPTH).rev() {
            let sibling_index = if index & 1 == 0 { index + 1 } else { index - 1 };

            let sibling = self
                .nodes
                .get(sibling_index)
                .ok_or(MerkleError::NodeNotFound)?;

            proof[DEPTH - level] = *sibling;

            index = self.get_parent_node_idx(level as u32, index)?;
        }

        Ok(proof)
    }
}

#[cfg(test)]
mod tests {

    use crate::{nodes_from_depth, Keccak256, MerkleNode, MerkleProof, Sha256, Sha256d};
    extern crate alloc;
    use alloc::vec::Vec;
    use hex_literal::hex;

    use super::MerkleTree;

    #[test]
    fn merkle_tree_block_9_test() {
        let mut merkle_tree = merkle_tree!(Sha256, 2);

        merkle_tree
            .add_hash(hex!(
                "c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704"
            ))
            .unwrap();

        merkle_tree.merklize();

        assert_eq!(
            &hex!("743f9e7e92165bad517d72503dae64ceba4d831eec8b77e9032cbb70049f1263"),
            merkle_tree.root.inner()
        );
    }

    #[test]
    fn merkle_tree_block_11_test() {
        let mut merkle_tree = merkle_tree!(Sha256, 2);

        merkle_tree
            .add_hash(hex!(
                "c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704"
            ))
            .unwrap();

        merkle_tree
            .add_hash(hex!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ))
            .unwrap();

        merkle_tree.merklize();

        assert_eq!(
            &hex!("02549dd194d947a20a579d0942769759eb726d7a68d15505827260c19ad8260e"),
            merkle_tree.root.inner()
        );
    }

    #[test]
    fn merkle_tree_bitcoin_block_100000_test() {
        let mut merkle_tree = merkle_tree!(Sha256d, 3);

        merkle_tree
            .add_hashes(&[
                hex!("876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c"),
                hex!("c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff"),
                hex!("c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963"),
                hex!("1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9"),
            ])
            .unwrap();

        merkle_tree.merklize();

        assert_eq!(
            &hex!("6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3"),
            merkle_tree.root.inner()
        );
    }
    #[test]
    fn merkle_tree_bitcoin_block_100002_test() {
        let mut merkle_tree = merkle_tree!(Sha256d, 5);

        // Add leaf hashes as slices
        merkle_tree
            .add_hashes(&[
                hex!("a3f3ac605d5e4727f4ea72e9346a5d586f0231460fd52ad9895bc8240d871def"),
                hex!("076d0317ee70ee36cf396a9871ab3bf6f8e6d538d7f8a9062437dcb71c75fcf9"),
                hex!("2ee1e12587e497ada70d9bd10d31e83f0a924825b96cb8d04e8936d793fb60db"),
                hex!("7ad8b910d0c7ba2369bc7f18bb53d80e1869ba2c32274996cebe1ae264bc0e22"),
                hex!("4e3f8ef2e91349a9059cb4f01e54ab2597c1387161d3da89919f7ea6acdbb371"),
                hex!("e0c28dbf9f266a8997e1a02ef44af3a1ee48202253d86161d71282d01e5e30fe"),
                hex!("8719e60a59869e70a7a7a5d4ff6ceb979cd5abe60721d4402aaf365719ebd221"),
                hex!("5310aedf9c8068f1e862ac9186724f7fdedb0aa9819833af4f4016fca6d21fdd"),
                hex!("201f4587ec86b58297edc2dd32d6fcd998aa794308aac802a8af3be0e081d674"),
            ])
            .unwrap();

        // Compute the Merkle root
        merkle_tree.merklize();

        // Compare root as bytes
        assert_eq!(
            &hex!("5275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2f"),
            merkle_tree.root.inner()
        );
    }

    #[test]
    fn merkle_tree_payout_test() {
        let mut merkle_tree = merkle_tree!(Sha256d, 2);

        struct Account {
            chain: u16,
            address: Vec<u8>,
            amount: u64,
        }

        impl Account {
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut m = self.chain.to_le_bytes().to_vec();
                m.push(self.address.len() as u8);
                m.extend_from_slice(&self.address);
                m.extend_from_slice(&self.amount.to_le_bytes());
                m
            }
        }

        let leaf_1 = Account {
            chain: 1,
            address: hex!("c0ffee254729296a45a3885639AC7E10F9d54979").to_vec(),
            amount: 1337,
        }
        .to_bytes();

        let leaf_2 = Account {
            chain: 1,
            address: hex!("999999cf1046e68e36E1aA2E0E07105eDDD1f08E").to_vec(),
            amount: 1337,
        }
        .to_bytes();

        merkle_tree.add_leaf(&leaf_1).unwrap();
        merkle_tree.add_leaf(&leaf_2).unwrap();

        // Check leaves
        assert_eq!(
            &hex!("59f9111666f968b79593c142694cb662"),
            &merkle_tree.nodes[0].inner()[..16]
        );
        assert_eq!(
            &hex!("61ebf6f4d1af532451e53c2d2a303390"),
            &merkle_tree.nodes[1].inner()[..16]
        );

        merkle_tree.merklize();

        // Check root
        assert_eq!(
            &hex!(
                "f612a99a5704cf2b7af93ca9c1299453078a6bfed379486aea1c3d39023c6e8e
"
            ),
            merkle_tree.root.inner()
        );
    }

    #[test]
    fn test_airdrop_sha() {
        let mut merkle_tree = merkle_tree!(Sha256, 3);
        merkle_tree
            .add_leaves(&[
                &hex!("00000000010039050000000000004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"), // Sol
                &hex!("01000000020039050000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf"), // Eth
                &hex!("0200000021003905000000000000d0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af"), // Sui
                &hex!("03000000220039050000000000004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29") // Aptos
            ])
            .unwrap();

        merkle_tree.merklize();

        assert_eq!(
            &hex!("aca7de349035ab227d8edcd02216a17bb9bb381fd278d3b9cef215c8c6ebcddb"),
            merkle_tree.root.inner()
        );
    }

    #[test]
    fn test_airdrop_keccak() {
        let mut merkle_tree = merkle_tree!(Keccak256, 3);
        merkle_tree
            .add_leaves(&[
                &hex!("00000000010039050000000000004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29"), // Sol
                &hex!("01000000020039050000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf"), // Eth
                &hex!("0200000021003905000000000000d0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af"), // Sui
                &hex!("03000000220039050000000000004cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29") // Aptos
            ])
            .unwrap();

        merkle_tree.merklize();

        assert_eq!(
            &hex!("58d09656ee70f84cc104fa8a539a35ab559ed15eb2b4b9e566f396eb583ce7d9"),
            merkle_tree.root.inner()
        );
    }

    #[test]
    fn merkle_tree_8_leaves_proof_test() {
        let mut merkle_tree = merkle_tree!(Sha256d, 4); // DEPTH = 3 → 8 leaves

        // Add leaf hashes as slices
        merkle_tree
            .add_hashes(&[
                hex!("a3f3ac605d5e4727f4ea72e9346a5d586f0231460fd52ad9895bc8240d871def"),
                hex!("076d0317ee70ee36cf396a9871ab3bf6f8e6d538d7f8a9062437dcb71c75fcf9"),
                hex!("2ee1e12587e497ada70d9bd10d31e83f0a924825b96cb8d04e8936d793fb60db"),
                hex!("7ad8b910d0c7ba2369bc7f18bb53d80e1869ba2c32274996cebe1ae264bc0e22"),
                hex!("4e3f8ef2e91349a9059cb4f01e54ab2597c1387161d3da89919f7ea6acdbb371"),
                hex!("e0c28dbf9f266a8997e1a02ef44af3a1ee48202253d86161d71282d01e5e30fe"),
                hex!("8719e60a59869e70a7a7a5d4ff6ceb979cd5abe60721d4402aaf365719ebd221"),
                hex!("5310aedf9c8068f1e862ac9186724f7fdedb0aa9819833af4f4016fca6d21fdd"),
            ])
            .unwrap();

        // Build the Merkle tree
        merkle_tree.merklize();

        // Generate proof for leaf 0
        let proof = merkle_tree.get_proof_path_for_leaf_idx(4).unwrap();

        assert_eq!(proof.len(), 3);

        // Example assertions (adjust according to your actual merklize logic)
        // Leaf sibling
        assert_eq!(proof[0].inner(), merkle_tree.get_node(5).unwrap().inner());

        // Level 2 sibling (parent level)
        assert_eq!(proof[1].inner(), merkle_tree.get_node(11).unwrap().inner());

        // Level 3 sibling
        assert_eq!(proof[2].inner(), merkle_tree.get_node(12).unwrap().inner());

        let proof_verify = MerkleProof::<32>::merklize::<Sha256d>(
            merkle_tree.get_node(4).unwrap().inner(),
            proof.iter().map(|p| p.inner()).collect::<Vec<_>>().as_ref(),
            4,
        );

        for n in merkle_tree.nodes {
            println!("n : {:?}", hex::encode(n.inner()));
        }

        println!(
            "root : {:?}",
            hex::encode(merkle_tree.get_root().unwrap().inner())
        );
        println!("pr {:?}", hex::encode(proof_verify.inner()));
    }
}
