//! # warden-engine
//!
//! Rust-native crypto primitives for the Warden auth package.
//! JWT HS256, HMAC, constant-time comparison.
//!
//! Argon2id and bcrypt hashing used to live here; they were dropped in
//! Story 52.1 (2026-05-08). Sigil (`@c9up/sigil` / `sigil-engine`) is the
//! canonical password-hashing service since Story 40.1 — warden's own
//! argon2/bcrypt copies were never wired through the NAPI surface and
//! kept the warden-engine crate carrying redundant dependencies.
//!
//! @implements FR49, FR52, FR53

pub mod constant_time;
pub mod crypto;
pub mod jwt;

pub use constant_time::{constant_time_eq, constant_time_str_eq};
pub use jwt::{sign as jwt_sign, verify as jwt_verify};
