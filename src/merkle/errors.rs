#[cfg(not(target_arch = "wasm32"))]
use anchor_lang::error::{AnchorError, Error, ERROR_CODE_OFFSET};
use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
pub type Result<T> = anchor_lang::Result<T>;
#[cfg(target_arch = "wasm32")]
pub type Result<T> = anyhow::Result<T, MerkleError>;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("Leaf out of range")]
    LeafOutOfRange,
    #[error("Branch out of range")]
    BranchOutOfRange,
    #[error("Leaf not found")]
    LeafNotFound,
    #[error("Merkle tree not merklized")]
    TreeNotMerklized,
    #[error("Merkle tree is empty")]
    TreeEmpty,
    #[error("Invalid hash size")]
    InvalidHashSize,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<MerkleError> for anchor_lang::error::Error {
    fn from(value: MerkleError) -> Self {
        let e = match value {
            MerkleError::LeafOutOfRange => AnchorError {
                error_name: "LeafOutOfRange".to_string(),
                error_code_number: ERROR_CODE_OFFSET + 1337 + 0,
                error_msg: value.to_string(),
                error_origin: None,
                compared_values: None
            },
            MerkleError::BranchOutOfRange => AnchorError {
                error_name: "BranchOutOfRange".to_string(),
                error_code_number: ERROR_CODE_OFFSET + 1337 + 1,
                error_msg: value.to_string(),
                error_origin: None,
                compared_values: None
            },
            MerkleError::LeafNotFound => AnchorError {
                error_name: "LeafNotFound".to_string(),
                error_code_number: ERROR_CODE_OFFSET + 1337 + 2,
                error_msg: value.to_string(),
                error_origin: None,
                compared_values: None
            },
            MerkleError::TreeNotMerklized => AnchorError {
                error_name: "TreeNotMerklized".to_string(),
                error_code_number: ERROR_CODE_OFFSET + 1337 + 3,
                error_msg: value.to_string(),
                error_origin: None,
                compared_values: None
            },
            MerkleError::TreeEmpty => AnchorError {
                error_name: "TreeEmpty".to_string(),
                error_code_number: ERROR_CODE_OFFSET + 1337 + 4,
                error_msg: value.to_string(),
                error_origin: None,
                compared_values: None
            },
            MerkleError::InvalidHashSize => AnchorError {
                error_name: "InvalidHashSize".to_string(),
                error_code_number: ERROR_CODE_OFFSET + 1337 + 5,
                error_msg: value.to_string(),
                error_origin: None,
                compared_values: None
            },
        };
        Error::AnchorError(Box::new(e))
    }
}