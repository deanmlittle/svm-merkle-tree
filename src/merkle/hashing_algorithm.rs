#[cfg(target_arch = "wasm32")]
pub mod hashing_wasm {
    use sha2::{Sha256, Digest};
    use sha3::Keccak256;

    pub fn sha256(val: &[u8]) -> [u8;32] {
        let mut hasher = Sha256::new();
        hasher.update(val);
        hasher.finalize().into()
    }

    pub fn keccak256(val: &[u8]) -> [u8;32] {
        let mut hasher = Keccak256::new();
        hasher.update(val);
        hasher.finalize().into()
    }
}
#[cfg(target_arch = "wasm32")]
use hashing_wasm::{sha256, keccak256};

#[cfg(not(target_arch = "wasm32"))]
use anchor_lang::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
mod hashing {
    use solana_program::{hash, keccak};

    pub fn sha256(val: &[u8]) -> [u8;32] {
        hash::hash(val).to_bytes()
    }

    pub fn keccak256(val: &[u8]) -> [u8;32] {
        keccak::hash(val).to_bytes()
    }
}
#[cfg(not(target_arch = "wasm32"))]
use hashing::{sha256, keccak256};

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, AnchorSerialize, AnchorDeserialize, PartialEq)]
pub enum HashingAlgorithm {
    Sha256 = 0,
    Sha256d = 1,
    Keccak = 2,
    Keccakd = 3
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, PartialEq)]
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
            HashingAlgorithm::Sha256 => sha256(b)[..s].to_vec(),
            HashingAlgorithm::Keccak => keccak256(b)[..s].to_vec(),
            HashingAlgorithm::Sha256d | HashingAlgorithm::Keccakd => self.double_hash(b, s)
        }
    }

    pub fn double_hash(&self, b: &[u8], s: usize) -> Vec<u8> {
        let mut s = match s == 0 || s > 32 {
            true => 32,
            false => s
        };
        match self {
            HashingAlgorithm::Sha256 | HashingAlgorithm::Sha256d => sha256(&sha256(b))[..s].to_vec(),
            HashingAlgorithm::Keccak | HashingAlgorithm::Keccakd => keccak256(&keccak256(b))[..s].to_vec(),
        }
    }
}
