use anchor_lang::prelude::*;
use solana_program::{blake3::Hash, hash, keccak};

#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, PartialEq)]
pub enum HashingAlgorithm {
    Sha256 = 0,
    Sha256d = 1,
    Keccak = 2,
    Keccakd = 3
}

impl From<HashingAlgorithm> for u8 {
    fn from(value: HashingAlgorithm) -> Self {
        match value {
            HashingAlgorithm::Sha256 => 0,
            HashingAlgorithm::Sha256d => 1,
            HashingAlgorithm::Keccak => 2,
            HashingAlgorithm::Keccakd => 3,
        }
    }
}

impl From<u8> for HashingAlgorithm {
    fn from(value: u8) -> HashingAlgorithm {
        match value {
            1 => HashingAlgorithm::Sha256d,
            2 => HashingAlgorithm::Keccak,
            3 => HashingAlgorithm::Keccakd,
            _ => HashingAlgorithm::Sha256,
        }
    }
}

impl HashingAlgorithm {
    pub fn hash(&self, b: &[u8], s: usize) -> Vec<u8> {
        let mut s = match s == 0 || s > 32 {
            true => 32,
            false => s
        };
        match self {
            HashingAlgorithm::Sha256 => hash::hash(b).to_bytes()[..s].to_vec(),
            HashingAlgorithm::Keccak => keccak::hash(b).to_bytes()[..s].to_vec(),
            HashingAlgorithm::Sha256d | HashingAlgorithm::Keccakd => self.double_hash(b, s)
        }
    }

    pub fn double_hash(&self, b: &[u8], s: usize) -> Vec<u8> {
        let mut s = match s == 0 || s > 32 {
            true => 32,
            false => s
        };
        match self {
            HashingAlgorithm::Sha256 | HashingAlgorithm::Sha256d => hash::hash(&hash::hash(b).to_bytes()).to_bytes()[..s].to_vec(),
            HashingAlgorithm::Keccak | HashingAlgorithm::Keccakd => keccak::hash(&keccak::hash(b).to_bytes()).to_bytes()[..s].to_vec(),
        }
    }
}
