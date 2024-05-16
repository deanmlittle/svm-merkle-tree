/* tslint:disable */
/* eslint-disable */
/**
* @param {Uint8Array} val
* @returns {Uint8Array}
*/
export function sha256(val: Uint8Array): Uint8Array;
/**
* @param {Uint8Array} val
* @returns {Uint8Array}
*/
export function keccak256(val: Uint8Array): Uint8Array;
/**
*/
export enum HashingAlgorithm {
  Sha256 = 0,
  Sha256d = 1,
  Keccak = 2,
  Keccakd = 3,
}
/**
*/
export class MerkleProof {
  free(): void;
/**
* @param {HashingAlgorithm} algorithm
* @param {number} hash_size
* @param {number} index
* @param {Uint8Array} hashes
*/
  constructor(algorithm: HashingAlgorithm, hash_size: number, index: number, hashes: Uint8Array);
/**
* @param {Uint8Array} leaf
* @returns {Uint8Array}
*/
  merklize(leaf: Uint8Array): Uint8Array;
/**
* @param {Uint8Array} hash
* @returns {Uint8Array}
*/
  merklize_hash(hash: Uint8Array): Uint8Array;
/**
* @returns {Uint8Array}
*/
  get_pairing_hashes(): Uint8Array;
}
/**
*/
export class MerkleTree {
  free(): void;
/**
* @param {HashingAlgorithm} algorithm
* @param {number} hash_size
*/
  constructor(algorithm: HashingAlgorithm, hash_size: number);
/**
* @param {Uint8Array} leaf
*/
  add_leaf(leaf: Uint8Array): void;
/**
*/
  merklize(): void;
/**
* @returns {Uint8Array}
*/
  get_merkle_root(): Uint8Array;
/**
* @param {Uint8Array} hash
* @returns {MerkleProof}
*/
  merkle_proof_hash(hash: Uint8Array): MerkleProof;
/**
* @param {number} i
* @returns {MerkleProof}
*/
  merkle_proof_index(i: number): MerkleProof;
}
