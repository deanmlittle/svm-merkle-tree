pub type Result<T> = core::result::Result<T, MerkleError>;

#[derive(Debug)]
pub enum MerkleError {
    LeafOutOfRange,
    BranchOutOfRange,
    LeafNotFound,
    TreeNotMerklized,
    TreeEmpty,
    InvalidHashSize,
    NodeNotFound,
}

impl MerkleError {
    pub fn as_str(&self) -> &str {
        match self {
            MerkleError::LeafOutOfRange => "LeafOutOfRange",
            MerkleError::BranchOutOfRange => "BranchOutOfRange",
            MerkleError::LeafNotFound => "LeafNotFound",
            MerkleError::TreeNotMerklized => "TreeNotMerklized",
            MerkleError::TreeEmpty => "TreeEmpty",
            MerkleError::InvalidHashSize => "InvalidHashSize",
            MerkleError::NodeNotFound => "NodeNotFound",
        }
    }
}
