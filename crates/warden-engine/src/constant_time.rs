//! Constant-time comparison utilities — prevents timing attacks.
//!
//! @implements FR53

use subtle::ConstantTimeEq;

/// Compare two byte slices in constant time.
/// Both length and content comparison are constant-time — no early return on length mismatch.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_eq: subtle::Choice = (a.len() as u64).ct_eq(&(b.len() as u64));
    let min_len = a.len().min(b.len());
    let content_eq: subtle::Choice = a[..min_len].ct_eq(&b[..min_len]);
    (len_eq & content_eq).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equal_values() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_different_values() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn test_different_lengths() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn test_nearly_identical() {
        assert!(!constant_time_eq(
            b"abcdefghijklmnopqrstuvwxyz0",
            b"abcdefghijklmnopqrstuvwxyz1"
        ));
    }
}
