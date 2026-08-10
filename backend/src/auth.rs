use std::collections::HashMap;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::{api::ApiError, config::Config, db, now_seconds};

pub const SESSION_COOKIE: &str = "totem_session";
pub const CSRF_HEADER: &str = "x-totem-request";

#[derive(Default)]
pub struct LoginLimiter {
    attempts: HashMap<String, Vec<i64>>,
}

impl LoginLimiter {
    pub fn allow(&mut self, key: &str, now: i64) -> bool {
        let attempts = self.attempts.entry(key.to_owned()).or_default();
        attempts.retain(|timestamp| *timestamp > now - 60);
        if attempts.len() >= 5 {
            return false;
        }
        attempts.push(now);
        true
    }

    pub fn prune(&mut self, now: i64) {
        self.attempts.retain(|_, timestamps| {
            timestamps.retain(|timestamp| *timestamp > now - 60);
            !timestamps.is_empty()
        });
    }
}

pub fn hash_password(password: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ApiError::internal("password hashing failed"))
}

pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

pub fn ensure_admin(connection: &Connection, initial_password: Option<&str>) -> anyhow::Result<()> {
    if db::admin_password_hash(connection)?.is_some() {
        return Ok(());
    }
    let password = initial_password
        .filter(|password| !password.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("ADMIN_PASSWORD is required for first-time initialization")
        })?;
    let password_hash = hash_password(password).map_err(|error| anyhow::anyhow!(error.message))?;
    db::insert_admin(connection, &password_hash, now_seconds())?;
    Ok(())
}

pub fn reset_admin_password(connection: &Connection, password: &str) -> anyhow::Result<()> {
    if password.is_empty() {
        return Err(anyhow::anyhow!("password cannot be empty"));
    }
    let password_hash = hash_password(password).map_err(|error| anyhow::anyhow!(error.message))?;
    if db::admin_password_hash(connection)?.is_some() {
        db::update_admin_password(connection, &password_hash, now_seconds())?;
    } else {
        db::insert_admin(connection, &password_hash, now_seconds())?;
    }
    Ok(())
}

pub fn extract_session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (name, value) = part.trim().split_once('=')?;
        (name == SESSION_COOKIE && !value.is_empty()).then(|| value.to_owned())
    })
}

pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub fn new_session(connection: &Connection, config: &Config) -> Result<String, ApiError> {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ApiError::internal("failed to create session"))?;
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let now = now_seconds();
    let expires_at = now.saturating_add((config.session_ttl_hours * 60 * 60) as i64);
    db::create_session(connection, &token_hash(&token), now, expires_at)
        .map_err(|_| ApiError::internal("failed to create session"))?;
    Ok(token)
}

pub fn require_session(connection: &Connection, headers: &HeaderMap) -> Result<(), ApiError> {
    let token = extract_session_token(headers)
        .ok_or_else(|| ApiError::unauthorized("authentication_required", "Please log in first"))?;
    let valid = db::session_is_valid(connection, &token_hash(&token), now_seconds())
        .map_err(|_| ApiError::internal("failed to validate session"))?;
    if valid {
        Ok(())
    } else {
        Err(ApiError::unauthorized(
            "session_expired",
            "Your session has expired",
        ))
    }
}

pub fn delete_current_session(
    connection: &Connection,
    headers: &HeaderMap,
) -> rusqlite::Result<()> {
    if let Some(token) = extract_session_token(headers) {
        db::delete_session(connection, &token_hash(&token))?;
    }
    Ok(())
}

pub fn session_cookie(token: &str, config: &Config) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        config.session_ttl_hours.saturating_mul(60 * 60)
    );
    if config.cookie_secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_session_cookie(config: &Config) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    );
    if config.cookie_secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn require_csrf(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        == Some("1")
    {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "csrf_check_failed",
            "This request is missing the Totem request header",
        ))
    }
}

pub fn client_key(headers: &HeaderMap) -> String {
    headers
        .get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::{hash_password, verify_password, LoginLimiter};

    #[test]
    fn argon2_hashes_verify_without_storing_plaintext() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert_ne!(hash, "correct horse battery staple");
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn login_limiter_allows_five_attempts_per_minute() {
        let mut limiter = LoginLimiter::default();
        for _ in 0..5 {
            assert!(limiter.allow("127.0.0.1", 100));
        }
        assert!(!limiter.allow("127.0.0.1", 100));
        assert!(limiter.allow("127.0.0.1", 161));
    }
}
