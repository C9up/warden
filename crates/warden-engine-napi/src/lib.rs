//! NAPI bindings for warden-engine: JWT HS256 signing and verification.

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
