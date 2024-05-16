#[cfg(not(target_arch = "wasm32"))]
use anchor_lang::prelude::*;
use crate::{MerkleError, Result};
use super::HashingAlgorithm;

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
pub struct MerkleProof {
    algorithm: HashingAlgorithm,
    hash_size: u8,
    index: u32,
    hashes: Vec<u8>
}
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct MerkleProof {
    algorithm: HashingAlgorithm,
    hash_size: u8,
    index: u32,
    hashes: Vec<u8>
}

impl MerkleProof {
    pub fn new(algorithm: HashingAlgorithm, hash_size: u8, index: u32, hashes: Vec<u8>) -> Self {
        let mut hash_size = hash_size;
        if hash_size == 0 || hash_size > 32 {
            hash_size = 32
        }
        Self {
            algorithm,
            index,
            hash_size,
            hashes
        }
    }

    // Hash with defined hashing algorithm and truncate to defined length
    pub fn hash(&self, m: &[u8]) -> Vec<u8> {
        self.algorithm.hash(m, self.hash_size as usize)
    }

    // Double hash with defined hashing algorithm and truncate to defined length
    pub fn double_hash(&self, m: &[u8]) -> Vec<u8> {
        self.algorithm.double_hash(m, self.hash_size as usize)
    }

    // Merklize from a leaf
    pub fn merklize(&self, leaf: &[u8]) -> Result<Vec<u8>> {
        // If our pairing hashes are empty, return the untruncated hash
        match self.hashes.len() == 0 {
            true => Ok(self.algorithm.double_hash(leaf, 0)),
            false => self.merklize_hash_unchecked(&self.double_hash(leaf))
        }
    }

    // Merklize from a leaf
    pub fn merklize_hash(&self, hash: &[u8]) -> Result<Vec<u8>> {
        // If pairing hashes are empty and our hash is 32 bytes long, return early
        if hash.len() != self.hash_size as usize {
            match self.hashes.is_empty() && hash.len() == 32 {
                true => return Ok(hash.to_vec()),
                false => return Err(MerkleError::InvalidHashSize.into())
            }
        }
        self.merklize_hash_unchecked(hash)
    }

    // Merklize from a hash. NOTE: There are no length checks being performed here.
    fn merklize_hash_unchecked(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let size = self.hash_size as usize;
        // If the pairing hashes are not a valid length, return an invalid size error
        if self.hashes.len() % size != 0 {
            return Err(MerkleError::InvalidHashSize.into());
        }
        // If there are no pairing hashes, simply return the hashed data
        if self.hashes.len() == 0 {
            return Ok(hash.to_vec())
        }
        let hash_count = self.hashes.len() / size;
        let mut index = self.index;
        let mut h = hash.to_vec();
        let mut m = vec![0u8;size*2];
        for i in 0..hash_count {
            match index%2 == 0 {
                true => {
                    m[..size].copy_from_slice(&h);
                    m[size..].copy_from_slice(&self.hashes[i*size..size*(i+1)]);
                },
                false => {
                    m[..size].copy_from_slice(&self.hashes[i*size..size*(i+1)]);
                    m[size..].copy_from_slice(&h);
                }
            }
            h = match i == hash_count-1 {
                true => self.algorithm.hash(&m, 32),
                false => self.hash(&m)
            };
            index = index/2;
        }
        Ok(h)
    }

    pub fn get_pairing_hashes(&self) -> Vec<u8> {
        self.hashes.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::merkle::HashingAlgorithm;

    use super::MerkleProof;
    use hex_literal::hex;

    #[test]
    fn test_spv_proof() {
        let spv = MerkleProof::new(
            HashingAlgorithm::Sha256d,
            32,
            0x2f,
            vec![
                hex!("780f39009c90be8cc62b1729569b5c8d50b59bad4489e95ac7a839555c1ee795").to_vec(),
                hex!("5503c702bc9ac972d2dbb46d2534559d2a268a7b06872b279015809a323f3d53").to_vec(),
                hex!("c7dfdb01537035a4ef485275a727aeb29328e49c1afc4fedac87d9333f059963").to_vec(),
                hex!("f54a333d21b4faa9f912ab2af2e72f6941c3d1c979331e34f62fa7dac23daf29").to_vec(),
                hex!("f24c049d3395fea0e77ad4dfdf496844cf289390364ce2defdab1e2b9bc4a935").to_vec(),
                hex!("d030d9cf05fb2c79325c80ab426d6ed274d5440464d7074bdbbf47551d91dc99").to_vec(),
                hex!("93a8935eb4f4ec9378102a8a32d1768221ee7ba35cefcd91d1e90d39ae8de541").to_vec(),
                hex!("cddb8cab43a01a960e09d820fc6c1a35cbe372d0121d22fd1938cda5f89861be").to_vec(),
                hex!("9a587173dbd8c5e232ce766ea43e1dc46754b18ecc7eceb34f3e87d41db9a48b").to_vec(),
                hex!("efefd46134b1144963ede9b117ef7556857fb9cd4ad6f0a6a050a45bc7e3698c").to_vec(),
                hex!("169149cacf761b5533d74e9c7f2c6e01ec0fba86466c86e62c3fd9fbd1462fdd").to_vec(),
                hex!("558d9e2aedfc65fc8d583ddca868fa29acebaa190e42f35b8912fe353d331e64").to_vec(),
                hex!("fd0ae5310b7ef3e52b1c4d2cd7e99dd0553259394f44b8b71a0ad36918c6b2d9").to_vec(),
                hex!("941e1c1872daf9351606edd68bf125246b99d2cf44ecd1c526fdc06fbfa3d9c9").to_vec()
            ].concat()
        );
        assert_eq!(
            hex!("e43a1de4dd9c526274b8ea9e4bf01fe8928649f8e5b94abc4e05d83b8abeb924").to_vec(), 
            spv.merklize(&hex!("01000000017125b04467dc2e3e766a0dae2b7a2f74211c7aa7bf796d47fbf44c259be23462661100006b483045022100f1e5fdfd36837a2e84225e157d25f4d341cad49bfdc909e0332e5e5a58e849a102203b5c59d2f5cf4c6f84b2bc189a03ed802d48784f335b712f73e80f807d4cdd714121037d53430715b2bc8463847e79d7e259c11a7d81bf7d6166e003e1b103b65731ffffffffff0123020000000000001976a9140ec56960e83cd3c03c8882e0fd34d462a34c653888ac00000000").to_vec()).unwrap()
        );
    }
}