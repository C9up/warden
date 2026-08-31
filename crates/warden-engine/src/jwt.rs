//! JWT signing and verification — Rust-native HMAC-SHA256.
//!
//! @implements FR52

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// JWT header (always HS256).
const JWT_HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

/// Sign a JWT payload with HMAC-SHA256.
/// Secret must be at least 32 bytes. Returns the complete JWT string.
pub fn sign(payload: &str, secret: &[u8]) -> Result<String, String> {
    if secret.len() < 32 {
        return Err("JWT secret must be at least 32 bytes".to_string());
    }
    let header_b64 = URL_SAFE_NO_PAD.encode(JWT_HEADER);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let message = format!("{}.{}", header_b64, payload_b64);

    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(message.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    Ok(format!("{}.{}", message, signature))
}

/// Verify a JWT token and return the decoded payload.
/// Validates signature (constant-time) and `exp` claim if present.
/// Secret must be at least 32 bytes.
pub fn verify(token: &str, secret: &[u8]) -> Result<String, String> {
    if secret.len() < 32 {
        return Err("JWT secret must be at least 32 bytes".to_string());
    }
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format: expected 3 parts".to_string());
    }

    // Verify the algorithm claim before checking the signature — prevents
    // algorithm confusion attacks where an attacker sends `{"alg":"none"}`.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| "Invalid header encoding".to_string())?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| "Invalid header JSON".to_string())?;
    if header["alg"].as_str() != Some("HS256") {
        return Err(format!(
            "Unsupported JWT algorithm: {:?}. Only HS256 is accepted.",
            header["alg"]
        ));
    }

    let message = format!("{}.{}", parts[0], parts[1]);

    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| format!("HMAC key error: {}", e))?;
    mac.update(message.as_bytes());

    let provided_sig = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "Invalid signature encoding".to_string())?;

    mac.verify_slice(&provided_sig)
        .map_err(|_| "Invalid signature".to_string())?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| "Invalid payload encoding".to_string())?;

    let payload_str =
        String::from_utf8(payload_bytes).map_err(|_| "Payload is not valid UTF-8".to_string())?;

    // Validate exp claim — MANDATORY (aligned with TS fallback path).
    // A token without exp is rejected to prevent indefinitely-valid tokens.
    if let Ok(claims) = serde_json::from_str::<serde_json::Value>(&payload_str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        match claims["exp"].as_i64() {
            Some(exp) if now > exp => return Err("Token expired".to_string()),
            Some(_) => {} // valid
            None => return Err("Token missing exp claim".to_string()),
        }
        if let Some(nbf) = claims["nbf"].as_i64() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            if now < nbf {
                return Err("Token not yet valid".to_string());
            }
        }
    }

    Ok(payload_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        let payload = r#"{"sub":"user-123","role":"admin","exp":9999999999}"#;

        let token = sign(payload, secret).unwrap();

        // Token has 3 parts
        assert_eq!(token.split('.').count(), 3);

        // Verify returns the payload
        let decoded = verify(&token, secret).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_verify_wrong_secret() {
        let token = sign(r#"{"sub":"1"}"#, b"secret-aaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let result = verify(&token, b"wrong-aaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid signature"));
    }

    #[test]
    fn test_verify_tampered_payload() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        let token = sign(r#"{"sub":"user-1","role":"user"}"#, secret).unwrap();

        // Tamper: replace payload part
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"user-1","role":"admin"}"#);
        let tampered = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = verify(&tampered, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_invalid_format() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        let result = verify("not.a.jwt.token", secret);
        assert!(result.is_err());

        let result = verify("onlyonepart", secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_expired_token() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        let payload = r#"{"sub":"1","exp":0}"#; // expired at epoch
        let token = sign(payload, secret).unwrap();
        let result = verify(&token, secret);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_short_secret_rejected() {
        let result = sign("{}", b"short");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("32 bytes"));
    }

    #[test]
    fn test_sign_produces_different_tokens_for_different_payloads() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        let t1 = sign(r#"{"sub":"1"}"#, secret).unwrap();
        let t2 = sign(r#"{"sub":"2"}"#, secret).unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn test_header_is_hs256() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        let token = sign("{}", secret).unwrap();
        let header_b64 = token.split('.').next().unwrap();
        let header = String::from_utf8(URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        assert!(header.contains("HS256"));
    }

    #[test]
    fn test_alg_none_rejected() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        // Craft a token with alg:none header
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"1"}"#);
        let fake_token = format!("{}.{}.", header, payload);
        let result = verify(&fake_token, secret);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported JWT algorithm"));
    }

    #[test]
    fn test_nbf_future_rejected() {
        let secret = b"my-secret-key-at-least-32-bytes!";
        // nbf = far in the future, exp = also far future (so exp check passes)
        let payload = r#"{"sub":"1","exp":9999999999,"nbf":9999999999}"#;
        let token = sign(payload, secret).unwrap();
        let result = verify(&token, secret);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet valid"));
    }
}
