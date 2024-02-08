use anchor_lang::prelude::*;

use crate::MerkleError;

use super::HashingAlgorithm;

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct MerkleProof {
    algorithm: HashingAlgorithm,
    index: u32,
    hash_size: u8,
    pub hashes: Vec<u8>
}

impl MerkleProof {
    pub fn new(algorithm: HashingAlgorithm, index: u32, hash_size: u8, hashes: Vec<u8>) -> Self {
        Self {
            algorithm,
            index,
            hash_size,
            hashes
        }
    }

    pub fn merklize(&self) -> Result<Vec<u8>> {
        let size = self.hash_size as usize;
        if self.hashes.len() == 0 || self.hashes.len() % size != 0 {
            return Err(MerkleError::InvalidHashSize.into());
        }
        let hash_count = self.hashes.len() / size;
        if hash_count == 1 {
            return Ok(self.hashes.clone())
        }
        let mut index = self.index;
        let mut h: Vec<u8> = self.hashes[0..self.hash_size as usize].to_vec();
        let mut m = vec![0u8;self.hash_size as usize*2];
        for i in 1..hash_count {
            match index%2 == 0 {
                true => {
                    m[..self.hash_size as usize].copy_from_slice(&h);
                    m[self.hash_size as usize..].copy_from_slice(&self.hashes[i*size..size*(i+1)]);
                },
                false => {
                    m[..self.hash_size as usize].copy_from_slice(&self.hashes[i*size..size*(i+1)]);
                    m[self.hash_size as usize..].copy_from_slice(&h);
                }
            }
            h = self.algorithm.hash(&m, self.hash_size as usize);
            index = index/2
        }
        Ok(h)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut m = self.index.to_le_bytes().to_vec();
        m.extend_from_slice(&[u8::from(self.algorithm.clone()), self.hash_size]);
        m.extend_from_slice(&self.hashes);
        m
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
            0x2f,
            32,
            vec![
                hex!("cd1c00c1726e76669911c9ffbd2975f9966fa8bb23e32bfd33bc439eb4e41167").to_vec(),
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
        let merkle = spv.merklize().unwrap();
        assert_eq!(hex!("e43a1de4dd9c526274b8ea9e4bf01fe8928649f8e5b94abc4e05d83b8abeb924").to_vec(), merkle);
    }
}