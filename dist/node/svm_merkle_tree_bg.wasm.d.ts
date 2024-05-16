/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export function sha256(a: number, b: number, c: number): void;
export function keccak256(a: number, b: number, c: number): void;
export function __wbg_merkletree_free(a: number): void;
export function __wbg_merkleproof_free(a: number): void;
export function merkletree_new(a: number, b: number): number;
export function merkletree_add_leaf(a: number, b: number, c: number): void;
export function merkletree_merklize(a: number, b: number): void;
export function merkletree_get_merkle_root(a: number, b: number): void;
export function merkletree_merkle_proof_hash(a: number, b: number, c: number, d: number): void;
export function merkletree_merkle_proof_index(a: number, b: number, c: number): void;
export function merkleproof_new(a: number, b: number, c: number, d: number, e: number): number;
export function merkleproof_merklize(a: number, b: number, c: number, d: number): void;
export function merkleproof_merklize_hash(a: number, b: number, c: number, d: number): void;
export function merkleproof_get_pairing_hashes(a: number, b: number): void;
export function __wbindgen_add_to_stack_pointer(a: number): number;
export function __wbindgen_malloc(a: number, b: number): number;
export function __wbindgen_free(a: number, b: number, c: number): void;
