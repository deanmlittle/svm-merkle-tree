use wasm_bindgen::prelude::*;

use crate::{
    HashingAlgorithm as RustHashingAlgorithm, 
    MerkleProof as RustMerkleProof,
    MerkleTree as RustMerkleTree
};

#[wasm_bindgen]
pub enum HashingAlgorithm {
    Sha256 = 0,
    Sha256d = 1,
    Keccak = 2,
    Keccakd = 3
}

impl From<HashingAlgorithm> for RustHashingAlgorithm {
    fn from(value: HashingAlgorithm) -> Self {
        match value {
            HashingAlgorithm::Sha256 => RustHashingAlgorithm::Sha256 ,
            HashingAlgorithm::Sha256d => RustHashingAlgorithm::Sha256d,
            HashingAlgorithm::Keccak => RustHashingAlgorithm::Keccak,
            HashingAlgorithm::Keccakd => RustHashingAlgorithm::Keccakd,
        }
    }
}

#[wasm_bindgen]
pub struct MerkleTree(RustMerkleTree);


#[wasm_bindgen]
pub struct MerkleProof(RustMerkleProof);

#[wasm_bindgen]
impl MerkleTree {
    #[wasm_bindgen(constructor)]
    pub fn new(algorithm: HashingAlgorithm, hash_size: u8) -> Self {
        Self(RustMerkleTree::new(
            RustHashingAlgorithm::from(algorithm),
            hash_size
        ))
    }

    pub fn add_leaf(&mut self, leaf: &[u8]) {
        self.0.add_leaf(leaf);
    }

    pub fn merklize(&mut self) -> Result<(), JsError> {
        self.0.merklize().map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn get_merkle_root(&self) -> Result<Vec<u8>, JsError> {
        self.0.get_merkle_root().map_err(|e| JsError::new(&e.to_string()))
    }

    pub fn merkle_proof_hash(&self, hash: Vec<u8>) -> Result<MerkleProof, JsError> {
        Ok(MerkleProof(self.0.merkle_proof_hash(hash).map_err(|e| JsError::new(&e.to_string()))?))
    }

    pub fn merkle_proof_index(&self, i: usize) -> Result<MerkleProof, JsError> {
        Ok(MerkleProof(self.0.merkle_proof_index(i).map_err(|e| JsError::new(&e.to_string()))?))
    }
}

#[wasm_bindgen]
impl MerkleProof {
    #[wasm_bindgen(constructor)]
    pub fn new(algorithm: HashingAlgorithm, hash_size: u8, index: u32, hashes: Vec<u8>) -> Self {
        Self(RustMerkleProof::new(
            RustHashingAlgorithm::from(algorithm),
            hash_size,
            index,
            hashes
        ))
    }

    pub fn merklize(&self, leaf: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.0.merklize(leaf).map_err(|e| JsError::new(&e.to_string()))?)
    }

    pub fn merklize_hash(&self, hash: &[u8]) -> Result<Vec<u8>, JsError> {
        Ok(self.0.merklize_hash(hash).map_err(|e| JsError::new(&e.to_string()))?)
    }
}