use anchor_lang::prelude::*;
#[cfg(feature = "use_rayon")]
use rayon::{prelude::*, iter::{IntoParallelIterator,ParallelIterator}};
use crate::{HashingAlgorithm, MerkleError};

use super::MerkleProof;

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct MerkleTree {
    algorithm: HashingAlgorithm,
    hash_size: u8,
    root: Vec<u8>,
    hashes: Vec<Vec<Vec<u8>>>
}

// For non-Solana targets, enable use_rayon feature to merklize in parallel
#[cfg(feature = "use_rayon")]
impl MerkleTree {
    fn merklize_unchecked(h: &Vec<Vec<u8>>, a: HashingAlgorithm, s: usize) -> Vec<Vec<u8>> {
        h.par_chunks(2).into_par_iter().map(|h| {
            if h.len() > 1 {
                a.hash(&vec![h[0].clone(),h[1].clone()].concat(), s)
            } else {
                a.hash(&vec![h[0].clone(),h[0].clone()].concat(), s)
            }
        }).collect()
    }
}

// For Solana targets, merklize in serial
#[cfg(not(feature = "use_rayon"))]
impl MerkleTree {
    fn merklize_unchecked(h: &Vec<Vec<u8>>, a: HashingAlgorithm, s: usize) -> Vec<Vec<u8>> {
        h.chunks(2).into_iter().map(|h| {
            if h.len() > 1 {
                a.hash(&vec![h[0].clone(),h[1].clone()].concat(), s)
            } else {
                a.hash(&vec![h[0].clone(),h[0].clone()].concat(), s)
            }
        }).collect()
    }
}

impl MerkleTree {
    pub fn new(hashes: Vec<Vec<u8>>, algorithm: HashingAlgorithm, hash_size: u8) -> Self {
        Self {
            algorithm,
            root: vec![],
            hash_size,
            hashes: vec![hashes]
        }
    }

    // Hash and truncate with algorithm and length of tree instance
    pub fn hash(&self, m: &[u8]) -> Vec<u8> {
        self.algorithm.hash(m, self.hash_size as usize)
    }

    // Double hash and truncate with algorithm and length of tree instance
    pub fn double_hash(&self, m: &[u8]) -> Vec<u8> {
        self.algorithm.double_hash(m, self.hash_size as usize)
    }

    // Hash and appaend a leaf
    pub fn add_leaf(&mut self, leaf: &[u8]) {
        // Double hash to prevent length extension attacks
        // No need for length check
        self.add_hash_unchecked(self.double_hash(leaf))
    }

    // Append a hashed leaf with a length check
    pub fn add_hash(&mut self, hash: Vec<u8>) -> Result<()> {
        if hash.len() != self.hash_size as usize {
            return Err(MerkleError::InvalidHashSize.into())
        }
        self.add_hash_unchecked(hash);
        Ok(())
    }

    // Add a hash without length checking (Only use from a trusted source!)
    pub fn add_hash_unchecked(&mut self, hash: Vec<u8>) {
        self.hashes[0].push(hash);
    }

    // Hash and insert an unhashed leaf
    pub fn insert_leaf(&mut self, index: usize, leaf: &[u8]) -> Result<()> {
        self.insert_hash(index, self.double_hash(leaf))
    }

    pub fn insert_hash(&mut self, index: usize, hash: Vec<u8>) -> Result<()> {
        if hash.len() != self.hash_size as usize {
            return Err(MerkleError::InvalidHashSize.into())
        }
        if index > self.hashes[0].len() {
            return Err(MerkleError::LeafOutOfRange.into());
        }
        self.reset();
        self.hashes[0].insert(index, hash);
        Ok(())
    }

    pub fn merklize(&mut self) -> Result<()> {
        let len = self.hashes[0].len();
        match len {
            0 => Err(MerkleError::TreeEmpty.into()),
            1 => {
                self.reset();
                self.root = self.hashes[0][0].clone();
                Ok(())
            }, 
            _ => {
                self.reset();
                let mut count = self.hashes[0].len();
                while count > 1 {
                    let h: Vec<Vec<u8>> = Self::merklize_unchecked(self.hashes.last().ok_or(MerkleError::BranchOutOfRange)?, self.algorithm.clone(), self.hash_size as usize);
                    count = h.len();
                    if count > 1 {
                        self.hashes.push(h);
                    } else {
                        self.root = h[0].clone()
                    }
                }
                Ok(())
            }
        }
    }

    pub fn reset(&mut self) {
        self.hashes.truncate(1);
    }

    fn merklized(&self) -> Result<()> {
        if self.root.eq(&[0u8;32]) {
            return Err(MerkleError::TreeNotMerklized.into())
        }
        Ok(())
    }

    fn within_range(&self, index: usize) -> Result<()> {
        let len = self.hashes[0].len();
        if index > len {
            return Err(MerkleError::LeafOutOfRange.into())
        }
        Ok(())
    }

    fn get_hash_index(&self, hash: Vec<u8>) -> Result<usize> {
        match self.hashes[0].binary_search(&hash) {
            Ok(i) => Ok(i),
            Err(_) => Err(MerkleError::LeafNotFound.into())
        }
    }

    pub fn merkle_proof_hash(&self, hash: Vec<u8>) -> Result<MerkleProof> {
        self.merklized()?;
        let i = self.get_hash_index(hash)?;
        self.merkle_proof_index_unchecked(i)
    }

    pub fn merkle_proof_index(&self, i: usize) -> Result<MerkleProof> {
        self.merklized()?;
        self.within_range(i)?;
        self.merkle_proof_index_unchecked(i)
    }

    fn merkle_proof_index_unchecked(&self, i: usize) -> Result<MerkleProof> {
        let len = self.hashes[0].len();
        match len {
            // We can't have zero leaves in a Merkle tree
            0 => Err(MerkleError::TreeEmpty.into()),
            // If we only have one leaf, the 0th hash is the root
            1 => Ok(MerkleProof::new(
                self.algorithm.clone(),
                i as u32,
                self.hash_size,
                vec![],
            )),
            _ => {
                let mut hashes: Vec<Vec<u8>> = vec![self.hashes[0][i].clone()];
                let mut n = i;
                // 0, 1, 2, 3
                for x in 0..self.hashes.len() {
                    n = match n%2 == 0 {
                        true => usize::min(n+1, self.hashes[x].len()),
                        false => n-1
                    };
                    
                    match self.hashes[x].get(n) {
                        Some(h) => {
                            hashes.push(h.clone())
                        },
                        None => hashes.push(self.hashes[x][n-1].clone())
                    }
                    n = n.saturating_div(2);
                }
                Ok(MerkleProof::new(
                    self.algorithm.clone(),
                    i as u32,
                    self.hash_size,
                    hashes.concat()
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::MerkleTree;

    #[test]
    fn merkle_tree_block_9_test() {
        let mut merkle_tree = MerkleTree::new(
            vec![
                hex!("c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704").to_vec()
            ],
            crate::HashingAlgorithm::Sha256d,
            32
        );
        merkle_tree.merklize().unwrap();
        assert_eq!(hex!("c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704").to_vec(), merkle_tree.root);
        for n in 0..merkle_tree.hashes[0].len() {
            let proof = merkle_tree.merkle_proof_index(n).unwrap();
            assert_eq!(merkle_tree.root, proof.merklize().unwrap());
        }
    }

    #[test]
    fn merkle_tree_bitcoin_block_100000_test() {
        let mut merkle_tree = MerkleTree::new(
            vec![
                hex!("876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c").to_vec(),
                hex!("c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff").to_vec(),
                hex!("c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963").to_vec(),
                hex!("1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9").to_vec()
            ],
            crate::HashingAlgorithm::Sha256d,
            32
        );
        merkle_tree.merklize().unwrap();
        assert_eq!(hex!("6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3").to_vec(), merkle_tree.root);
        for n in 0..merkle_tree.hashes[0].len() {
            let proof = merkle_tree.merkle_proof_index(n).unwrap();
            assert_eq!(merkle_tree.root, proof.merklize().unwrap());
        }
    }

    #[test]
    fn merkle_tree_bitcoin_block_100002_test() {
        let mut merkle_tree = MerkleTree::new(
            vec![
                hex!("a3f3ac605d5e4727f4ea72e9346a5d586f0231460fd52ad9895bc8240d871def").to_vec(),
                hex!("076d0317ee70ee36cf396a9871ab3bf6f8e6d538d7f8a9062437dcb71c75fcf9").to_vec(),
                hex!("2ee1e12587e497ada70d9bd10d31e83f0a924825b96cb8d04e8936d793fb60db").to_vec(),
                hex!("7ad8b910d0c7ba2369bc7f18bb53d80e1869ba2c32274996cebe1ae264bc0e22").to_vec(),
                hex!("4e3f8ef2e91349a9059cb4f01e54ab2597c1387161d3da89919f7ea6acdbb371").to_vec(),
                hex!("e0c28dbf9f266a8997e1a02ef44af3a1ee48202253d86161d71282d01e5e30fe").to_vec(),
                hex!("8719e60a59869e70a7a7a5d4ff6ceb979cd5abe60721d4402aaf365719ebd221").to_vec(),
                hex!("5310aedf9c8068f1e862ac9186724f7fdedb0aa9819833af4f4016fca6d21fdd").to_vec(),
                hex!("201f4587ec86b58297edc2dd32d6fcd998aa794308aac802a8af3be0e081d674").to_vec()
            ],
            crate::HashingAlgorithm::Sha256d,
            32
        );
        merkle_tree.merklize().unwrap();

        assert_eq!(hex!("5275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2f").to_vec(), merkle_tree.root);

        for n in 0..merkle_tree.hashes[0].len() {
            let proof = merkle_tree.merkle_proof_index(n).unwrap();
            assert_eq!(merkle_tree.root, proof.merklize().unwrap());
        }
    }

    #[test]
    fn merkle_tree_payout_test() {
        let mut merkle_tree = MerkleTree::new(
            vec![],
            crate::HashingAlgorithm::Sha256,
            16
        );

        struct Account {
            chain: u16,
            address: Vec<u8>,
            amount: u64,
        }

        impl Account {
            pub fn to_bytes(&self) -> Vec<u8> {
                let mut m = self.chain.to_le_bytes().to_vec();
                m.extend_from_slice(&[self.address.len() as u8]);
                m.extend_from_slice(&self.address);
                m.extend_from_slice(&self.amount.to_le_bytes());
                m
            }
        }

        let leaf_1 = Account { chain: 1, address: hex!("c0ffee254729296a45a3885639AC7E10F9d54979").to_vec(), amount: 1337 }.to_bytes();
        let leaf_2 = Account { chain: 1, address: hex!("999999cf1046e68e36E1aA2E0E07105eDDD1f08E").to_vec(), amount: 1337 }.to_bytes();

        merkle_tree.add_leaf(&leaf_1);
        merkle_tree.add_leaf(&leaf_2);

        merkle_tree.merklize().unwrap();

        assert_eq!(hex!("59f9111666f968b79593c142694cb662").to_vec(), merkle_tree.hashes[0][0]);
        assert_eq!(hex!("61ebf6f4d1af532451e53c2d2a303390").to_vec(), merkle_tree.hashes[0][1]);
        assert_eq!(hex!("ed89c53c2635102579a7a002249f7c97").to_vec(), merkle_tree.root);

        for n in 0..merkle_tree.hashes[0].len() {
            let proof = merkle_tree.merkle_proof_index(n).unwrap();
            assert_eq!(merkle_tree.root, proof.merklize().unwrap());
        }
    }
}