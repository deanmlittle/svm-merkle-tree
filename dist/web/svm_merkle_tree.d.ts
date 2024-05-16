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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly sha256: (a: number, b: number, c: number) => void;
  readonly keccak256: (a: number, b: number, c: number) => void;
  readonly __wbg_merkletree_free: (a: number) => void;
  readonly __wbg_merkleproof_free: (a: number) => void;
  readonly merkletree_new: (a: number, b: number) => number;
  readonly merkletree_add_leaf: (a: number, b: number, c: number) => void;
  readonly merkletree_merklize: (a: number, b: number) => void;
  readonly merkletree_get_merkle_root: (a: number, b: number) => void;
  readonly merkletree_merkle_proof_hash: (a: number, b: number, c: number, d: number) => void;
  readonly merkletree_merkle_proof_index: (a: number, b: number, c: number) => void;
  readonly merkleproof_new: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly merkleproof_merklize: (a: number, b: number, c: number, d: number) => void;
  readonly merkleproof_merklize_hash: (a: number, b: number, c: number, d: number) => void;
  readonly merkleproof_get_pairing_hashes: (a: number, b: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
