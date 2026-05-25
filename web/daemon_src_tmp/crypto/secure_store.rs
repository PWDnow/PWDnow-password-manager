use std::num::NonZeroUsize;
use std::ptr::NonNull;
use std::ops::{Deref, DerefMut};
use nix::sys::mman::{mlock, mmap_anonymous, mprotect, munlock, munmap, MapFlags, ProtFlags};
use zeroize::Zeroize;
use crate::error::VaultError;

/// Page size on Linux/macOS (constant for all supported targets).
const PAGE_SIZE: usize = 4096;

/// A key held in mlock'd, page-aligned memory.
///
/// The page is kept `PROT_NONE` (no read, no write) except during the brief
/// window when `as_bytes` / `as_bytes_mut` is called.  This defeats
/// cross-process memory scrapers that try to read the key from `/proc/mem` or
/// via ptrace between vault operations.
///
/// # Safety
/// Internally uses `mmap_anonymous` + `mprotect` (Linux only).  The page is
/// zeroized and `munmap`'d in `Drop`.
pub struct LockedKey {
    ptr: NonNull<std::ffi::c_void>,
    len: usize, // actual key length in bytes
}

// SAFETY: The raw pointer is never aliased outside the controlled guard
// methods.  `LockedKey` owns the mapping exclusively.
unsafe impl Send for LockedKey {}
unsafe impl Sync for LockedKey {}

pub struct LockedKeyGuard<'a> {
    key: &'a LockedKey,
}

impl<'a> Deref for LockedKeyGuard<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            std::slice::from_raw_parts(self.key.ptr.as_ptr() as *const u8, self.key.len)
        }
    }
}

impl<'a> Drop for LockedKeyGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            let _ = mprotect(self.key.ptr, PAGE_SIZE, ProtFlags::PROT_NONE);
        }
    }
}

pub struct LockedKeyMutGuard<'a> {
    key: &'a mut LockedKey,
}

impl<'a> Deref for LockedKeyMutGuard<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe {
            std::slice::from_raw_parts(self.key.ptr.as_ptr() as *const u8, self.key.len)
        }
    }
}

impl<'a> DerefMut for LockedKeyMutGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            std::slice::from_raw_parts_mut(self.key.ptr.as_ptr() as *mut u8, self.key.len)
        }
    }
}

impl<'a> Drop for LockedKeyMutGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            let _ = mprotect(self.key.ptr, PAGE_SIZE, ProtFlags::PROT_NONE);
        }
    }
}

impl LockedKey {
    pub fn new(len: usize) -> Result<Self, VaultError> {
        assert!(len <= PAGE_SIZE, "LockedKey: key length exceeds one page");
        let page = NonZeroUsize::new(PAGE_SIZE)
            .ok_or_else(|| VaultError::Crypto("zero page size".into()))?;

        // Allocate one private anonymous page (readable + writable initially).
        let ptr = unsafe {
            mmap_anonymous(None, page, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE, MapFlags::MAP_PRIVATE)
                .map_err(|e| VaultError::Crypto(format!("mmap failed: {e}")))?
        };

        // mlock the page so the OS never swaps it to disk.
        unsafe {
            mlock(ptr, PAGE_SIZE)
                .map_err(|e| VaultError::Crypto(format!("mlock failed: {e}")))?;
        }

        // Seal the page immediately — callers must use as_bytes/as_bytes_mut
        // which open/close the PROT_READ window.
        unsafe {
            mprotect(ptr, PAGE_SIZE, ProtFlags::PROT_NONE)
                .map_err(|e| VaultError::Crypto(format!("mprotect(PROT_NONE) failed: {e}")))?;
        }

        Ok(Self { ptr, len })
    }

    /// Read the key bytes.  Temporarily opens a `PROT_READ` window.
    pub fn as_bytes(&self) -> LockedKeyGuard<'_> {
        unsafe {
            mprotect(self.ptr, PAGE_SIZE, ProtFlags::PROT_READ).expect("mprotect(PROT_READ)");
        }
        LockedKeyGuard { key: self }
    }

    /// Write into the key bytes.  Temporarily opens a `PROT_READ | PROT_WRITE` window.
    pub fn as_bytes_mut(&mut self) -> LockedKeyMutGuard<'_> {
        unsafe {
            mprotect(self.ptr, PAGE_SIZE, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE)
                .expect("mprotect(PROT_READ|PROT_WRITE)");
        }
        LockedKeyMutGuard { key: self }
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        unsafe {
            // Open write access so we can zeroize.
            let _ = mprotect(self.ptr, PAGE_SIZE, ProtFlags::PROT_READ | ProtFlags::PROT_WRITE);
            let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, PAGE_SIZE);
            slice.zeroize();
            let _ = munlock(self.ptr, PAGE_SIZE);
            let _ = munmap(self.ptr, PAGE_SIZE);
        }
    }
}
