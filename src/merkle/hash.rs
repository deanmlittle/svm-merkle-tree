use core::{mem::MaybeUninit, ptr};

use crate::MerkleNode;

pub trait MerkleHash<const N: usize>: Default + Clone + Copy {
    fn hash(bytes: &[u8]) -> MerkleNode<N>;
    fn merkle_hashv(l: &[u8], r: &[u8], swap: bool) -> MerkleNode<N>;
}

#[inline(always)]
pub unsafe fn trunc32_to_n<const N: usize>(src32: *const u8) -> MerkleNode<N> {
    debug_assert!(N <= 32);
    let mut out = MaybeUninit::<[u8; N]>::uninit();
    unsafe {
        ptr::copy_nonoverlapping(src32, out.as_mut_ptr() as *mut u8, N);
        MerkleNode::from(out.assume_init())
    }
}

#[inline(always)]
pub unsafe fn first_n<const N: usize>(src: &[u8]) -> MerkleNode<N> {
    debug_assert!(src.len() >= N);
    let mut out = MaybeUninit::<[u8; N]>::uninit();
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), out.as_mut_ptr() as *mut u8, N);
        MerkleNode::from(out.assume_init())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256;

impl Sha256 {
    pub const HASH_LEN: usize = 32;
}

impl<const N: usize> MerkleHash<N> for Sha256 {
    #[inline(always)]
    fn hash(bytes: &[u8]) -> MerkleNode<N> {
        let h: [u8; 32] = solana_nostd_sha256::hash(bytes);
        unsafe { trunc32_to_n::<N>(h.as_ptr()) }
    }

    #[inline(always)]
    fn merkle_hashv(l: &[u8], r: &[u8], swap: bool) -> MerkleNode<N> {
        let (a, b) = if swap { (r, l) } else { (l, r) };

        // Grab first N bytes of each child
        let left_n = unsafe { first_n::<N>(a) };
        let right_n = unsafe { first_n::<N>(b) };

        // Hash concatenated slices using hashv
        let h: [u8; 32] = solana_nostd_sha256::hashv(&[left_n.inner(), &right_n.inner()]);
        unsafe { trunc32_to_n::<N>(h.as_ptr()) }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256d;

impl Sha256d {
    pub const HASH_LEN: usize = 32;
}

impl<const N: usize> MerkleHash<N> for Sha256d {
    #[inline(always)]
    fn hash(bytes: &[u8]) -> MerkleNode<N> {
        let h1: [u8; 32] = solana_nostd_sha256::hash(bytes);
        let h2: [u8; 32] = solana_nostd_sha256::hash(&h1);
        unsafe { trunc32_to_n::<N>(h2.as_ptr()) }
    }

    #[inline(always)]
    fn merkle_hashv(l: &[u8], r: &[u8], swap: bool) -> MerkleNode<N> {
        let (a, b) = if swap { (r, l) } else { (l, r) };

        let left_n = unsafe { first_n::<N>(a) };
        let right_n = unsafe { first_n::<N>(b) };

        // Double SHA-256
        let h1: [u8; 32] = solana_nostd_sha256::hashv(&[left_n.inner(), &right_n.inner()]);
        let h2: [u8; 32] = solana_nostd_sha256::hash(&h1);
        unsafe { trunc32_to_n::<N>(h2.as_ptr()) }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Keccak256;

impl Keccak256 {
    pub const HASH_LEN: usize = 32;
}

impl<const N: usize> MerkleHash<N> for Keccak256 {
    #[inline(always)]
    fn hash(bytes: &[u8]) -> MerkleNode<N> {
        let h: [u8; 32] = solana_nostd_keccak::hash(bytes);
        unsafe { trunc32_to_n::<N>(h.as_ptr()) }
    }

    #[inline(always)]
    fn merkle_hashv(l: &[u8], r: &[u8], swap: bool) -> MerkleNode<N> {
        let (a, b) = if swap { (r, l) } else { (l, r) };

        // Grab first N bytes of each child
        let left_n = unsafe { first_n::<N>(a) };
        let right_n = unsafe { first_n::<N>(b) };

        // Hash concatenated slices using hashv
        let h: [u8; 32] = solana_nostd_keccak::hashv(&[left_n.inner(), &right_n.inner()]);
        unsafe { trunc32_to_n::<N>(h.as_ptr()) }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Keccak256d;

impl Keccak256d {
    pub const HASH_LEN: usize = 32;
}

impl<const N: usize> MerkleHash<N> for Keccak256d {
    #[inline(always)]
    fn hash(bytes: &[u8]) -> MerkleNode<N> {
        let h1: [u8; 32] = solana_nostd_keccak::hash(bytes);
        let h2: [u8; 32] = solana_nostd_keccak::hash(&h1);
        unsafe { trunc32_to_n::<N>(h2.as_ptr()) }
    }

    #[inline(always)]
    fn merkle_hashv(l: &[u8], r: &[u8], swap: bool) -> MerkleNode<N> {
        let (a, b) = if swap { (r, l) } else { (l, r) };

        let left_n = unsafe { first_n::<N>(a) };
        let right_n = unsafe { first_n::<N>(b) };

        // Double Keccak-256
        let h1: [u8; 32] = solana_nostd_keccak::hashv(&[left_n.inner(), &right_n.inner()]);
        let h2: [u8; 32] = solana_nostd_keccak::hash(&h1);
        unsafe { trunc32_to_n::<N>(h2.as_ptr()) }
    }
}
