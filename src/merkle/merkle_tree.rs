#[cfg(not(target_os = "solana"))]
use rayon::{prelude::*, iter::{IntoParallelIterator,ParallelIterator}};
use crate::{HashingAlgorithm, MerkleError};
use anchor_lang::Result;
use super::MerkleProof;

#[derive(Debug, Clone)]
pub struct MerkleTree {
    algorithm: HashingAlgorithm,
    hash_size: u8,
    root: Vec<u8>,
    hashes: Vec<Vec<Vec<u8>>>
}

// For non-Solana targets, use Rayon to hash/merklize in parallel
#[cfg(not(target_os = "solana"))]
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

    fn add_leaves(&mut self, leaves: &Vec<Vec<u8>>) -> Result<()> {
        let hashes: Vec<Vec<u8>> = leaves.into_par_iter().map(|leaf| {
            self.double_hash(leaf)
        }).collect();
        self.add_hashes_unchecked(hashes)
    }
}

// For Solana targets, merklize in serial
#[cfg(target_os = "solana")]
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

    fn add_leaves(&mut self, leaves: &Vec<Vec<u8>>) -> Result<()> {
        let hashes: Vec<Vec<u8>> = leaves.into_iter().map(|leaf| {
            self.double_hash(leaf)
        }).collect();
        self.add_hashes_unchecked(hashes)
    }
}

impl MerkleTree {
    // Initialize a new tree with configurable size and hashing params
    pub fn new(algorithm: HashingAlgorithm, hash_size: u8) -> Self {
        let mut hash_size = hash_size;
        if hash_size == 0 || hash_size > 32 {
            hash_size = 32
        }
        Self {
            algorithm,
            root: vec![],
            hash_size,
            hashes: vec![vec![]]
        }
    }

    // Append multiple hashes with a length check. Use with unnormalized data
    pub fn add_hashes(&mut self, hashes: Vec<Vec<u8>>) -> Result<()> {
        for hash in hashes.iter() {
            if hash.len() != self.hash_size as usize {
                return Err(MerkleError::InvalidHashSize.into());
            }
        }
        self.hashes[0].extend_from_slice(&hashes);
        Ok(())
    }

    // Append multiple hashes without a length check. Use with normalized data
    pub fn add_hashes_unchecked(&mut self, hashes: Vec<Vec<u8>>) -> Result<()> {
        self.hashes[0].extend_from_slice(&hashes);
        Ok(())
    }

    // Hash with defined hashing algorithm and truncate to defined length
    fn hash(&self, m: &[u8]) -> Vec<u8> {
        self.algorithm.hash(m, self.hash_size as usize)
    }

    // Double hash with defined hashing algorithm and truncate to defined length
    fn double_hash(&self, m: &[u8]) -> Vec<u8> {
        self.algorithm.double_hash(m, self.hash_size as usize)
    }

    // Hash and append a leaf
    pub fn add_leaf(&mut self, leaf: &[u8]) {
        // Double hash to prevent length extension attacks
        // No need for length check
        self.add_hash_unchecked(self.double_hash(leaf))
    }

    // Append a hash with a length check. Use with unnormalized data
    pub fn add_hash(&mut self, hash: Vec<u8>) -> Result<()> {
        if hash.len() != self.hash_size as usize {
            return Err(MerkleError::InvalidHashSize.into())
        }
        self.add_hash_unchecked(hash);
        Ok(())
    }

    // Append a hash without a length check. Use with normalized data
    pub fn add_hash_unchecked(&mut self, hash: Vec<u8>) {
        self.hashes[0].push(hash);
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
                while count > 2 {
                    let h: Vec<Vec<u8>> = Self::merklize_unchecked(self.hashes.last().ok_or(MerkleError::BranchOutOfRange)?, self.algorithm.clone(), self.hash_size as usize);
                    count = h.len();
                    self.hashes.push(h);
                }
                self.root = Self::merklize_unchecked(self.hashes.last().ok_or(MerkleError::BranchOutOfRange)?, self.algorithm.clone(), 32 as usize)[0].clone();
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

    // pub fn pairing_hashes_hash(&self, hash: Vec<u8>) -> Result<Vec<u8>> {
    //     let proof = self.merkle_proof_hash(hash)?;
    //     proof.to_pairing_hashes()
    // }

    // pub fn pairing_hashes_index(&self, index: usize) -> Result<Vec<u8>> {
    //     let proof = self.merkle_proof_index(index)?;
    //     proof.to_pairing_hashes()
    // }

    pub fn get_merkle_root(&self) -> Result<Vec<u8>> {
        self.merklized()?;
        Ok(self.root.clone())
    }

    pub fn get_leaf_hash(&self, i: usize) -> Result<Vec<u8>> {
        self.within_range(i)?;
        Ok(self.hashes[0][i].clone())
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
                self.hash_size,
                i as u32,
                vec![],
            )),
            _ => {
                let mut hashes: Vec<Vec<u8>> = vec![];
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
                    self.hash_size,
                    i as u32,
                    hashes.concat()
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use crate::merkle;

    use super::MerkleTree;

    #[test]
    fn merkle_tree_block_9_test() {
        let mut merkle_tree = MerkleTree::new(
            crate::HashingAlgorithm::Sha256d,
            32
        );
        merkle_tree.add_hash(hex!("c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704").to_vec()).unwrap();
        merkle_tree.merklize().unwrap();
        assert_eq!(hex!("c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704").to_vec(), merkle_tree.root);
        for n in 0..merkle_tree.hashes[0].len() {
            let proof = merkle_tree.merkle_proof_index(n).unwrap();
            assert_eq!(merkle_tree.root, proof.merklize_hash(&merkle_tree.get_leaf_hash(n).unwrap()).unwrap());
        }
    }

    #[test]
    fn merkle_tree_bitcoin_block_100000_test() {
        let mut merkle_tree = MerkleTree::new(
            crate::HashingAlgorithm::Sha256d,
            32
        );

        merkle_tree.add_hashes(vec![
            hex!("876dd0a3ef4a2816ffd1c12ab649825a958b0ff3bb3d6f3e1250f13ddbf0148c").to_vec(),
            hex!("c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff").to_vec(),
            hex!("c46e239ab7d28e2c019b6d66ad8fae98a56ef1f21aeecb94d1b1718186f05963").to_vec(),
            hex!("1d0cb83721529a062d9675b98d6e5c587e4a770fc84ed00abc5a5de04568a6e9").to_vec()
        ]).unwrap();

        merkle_tree.merklize().unwrap();
        assert_eq!(hex!("6657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f3").to_vec(), merkle_tree.root);
        for n in 0..merkle_tree.hashes[0].len() {
            let proof = merkle_tree.merkle_proof_index(n).unwrap();
            assert_eq!(merkle_tree.root, proof.merklize_hash(&merkle_tree.get_leaf_hash(n).unwrap()).unwrap());
        }
    }

    #[test]
    fn merkle_tree_bitcoin_block_100002_test() {
        let mut merkle_tree = MerkleTree::new(
            crate::HashingAlgorithm::Sha256d,
            32
        );

        merkle_tree.add_hashes(vec![
            hex!("a3f3ac605d5e4727f4ea72e9346a5d586f0231460fd52ad9895bc8240d871def").to_vec(),
            hex!("076d0317ee70ee36cf396a9871ab3bf6f8e6d538d7f8a9062437dcb71c75fcf9").to_vec(),
            hex!("2ee1e12587e497ada70d9bd10d31e83f0a924825b96cb8d04e8936d793fb60db").to_vec(),
            hex!("7ad8b910d0c7ba2369bc7f18bb53d80e1869ba2c32274996cebe1ae264bc0e22").to_vec(),
            hex!("4e3f8ef2e91349a9059cb4f01e54ab2597c1387161d3da89919f7ea6acdbb371").to_vec(),
            hex!("e0c28dbf9f266a8997e1a02ef44af3a1ee48202253d86161d71282d01e5e30fe").to_vec(),
            hex!("8719e60a59869e70a7a7a5d4ff6ceb979cd5abe60721d4402aaf365719ebd221").to_vec(),
            hex!("5310aedf9c8068f1e862ac9186724f7fdedb0aa9819833af4f4016fca6d21fdd").to_vec(),
            hex!("201f4587ec86b58297edc2dd32d6fcd998aa794308aac802a8af3be0e081d674").to_vec()
        ]).unwrap();

        merkle_tree.merklize().unwrap();

        assert_eq!(hex!("5275289558f51c9966699404ae2294730c3c9f9bda53523ce50e9b95e558da2f").to_vec(), merkle_tree.root);

        for n in 0..merkle_tree.hashes[0].len() {
            let proof = merkle_tree.merkle_proof_index(n).unwrap();          
            assert_eq!(merkle_tree.root, proof.merklize_hash(&merkle_tree.hashes[0][n]).unwrap());
        }
    }

    #[test]
    fn merkle_tree_payout_test() {
        let mut merkle_tree = MerkleTree::new(
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
        assert_eq!(hex!("ed89c53c2635102579a7a002249f7c97460d31ef72baaafd6960be39546c6002").to_vec(), merkle_tree.root);

        let proof = merkle_tree.merkle_proof_index(0).unwrap();
        assert_eq!(merkle_tree.root, proof.merklize(&leaf_1).unwrap());
        let proof2 = merkle_tree.merkle_proof_index(1).unwrap();
        assert_eq!(merkle_tree.root, proof2.merklize(&leaf_2).unwrap());
    }
}