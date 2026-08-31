//! NAPI bindings for warden-engine crypto primitives.

use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::panic::catch_unwind;

fn wrap<
    T: Send + 'static,
    F: FnOnce() -> std::result::Result<T, String> + std::panic::UnwindSafe,
>(
    f: F,
) -> Result<T> {
    match catch_unwind(f) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(Error::from_reason(e)),
        Err(_) => Err(Error::from_reason("Internal panic in warden engine")),
    }
}

#[napi]
pub fn jwt_sign(payload: String, secret: String) -> Result<String> {
    wrap(|| warden_engine::jwt_sign(&payload, secret.as_bytes()))
}

#[napi]
pub fn jwt_verify(token: String, secret: String) -> Result<String> {
    wrap(|| warden_engine::jwt_verify(&token, secret.as_bytes()))
}

#[napi]
pub fn constant_time_eq(a: String, b: String) -> Result<bool> {
    wrap(|| Ok(warden_engine::constant_time_eq(a.as_bytes(), b.as_bytes())))
}

#[napi]
pub fn hmac_sign(data: String, secret: String) -> Result<String> {
    wrap(|| warden_engine::crypto::hmac_sign(&data, secret.as_bytes()))
}

#[napi]
pub fn hmac_verify(data: String, signature: String, secret: String) -> Result<bool> {
    wrap(|| warden_engine::crypto::hmac_verify(&data, &signature, secret.as_bytes()))
}

#[napi]
pub fn random_bytes(len: u32) -> Result<String> {
    wrap(|| warden_engine::crypto::random_bytes(len as usize))
}

#[napi]
pub fn random_hex(len: u32) -> Result<String> {
    wrap(|| warden_engine::crypto::random_hex(len as usize))
}
