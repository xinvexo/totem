use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{anyhow, Context, Result};

#[derive(Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub database_path: PathBuf,
    pub master_key: [u8; 32],
    pub cookie_secure: bool,
    pub session_ttl_hours: u64,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
        let port: u16 = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_owned())
            .parse()
            .context("PORT must be a valid port number")?;
        let bind_addr = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
        .parse()
        .context("HOST and PORT do not form a valid bind address")?;

        let database_path =
            PathBuf::from(env::var("DATABASE_PATH").unwrap_or_else(|_| "./totem.db".to_owned()));
        let master_key =
            parse_master_key(&env::var("MASTER_KEY").context("MASTER_KEY is required")?)?;
        let cookie_secure = parse_bool("COOKIE_SECURE", false)?;
        let session_ttl_hours: u64 = env::var("SESSION_TTL_HOURS")
            .unwrap_or_else(|_| "168".to_owned())
            .parse()
            .context("SESSION_TTL_HOURS must be a positive integer")?;
        if session_ttl_hours == 0 {
            return Err(anyhow!("SESSION_TTL_HOURS must be greater than zero"));
        }

        Ok(Self {
            bind_addr,
            database_path,
            master_key,
            cookie_secure,
            session_ttl_hours,
        })
    }

    pub fn database_path_from_env() -> PathBuf {
        PathBuf::from(env::var("DATABASE_PATH").unwrap_or_else(|_| "./totem.db".to_owned()))
    }
}

pub fn parse_master_key(value: &str) -> Result<[u8; 32]> {
    let value = value.trim();
    let decoded = hex::decode(value).context("MASTER_KEY must be hexadecimal")?;
    if decoded.len() != 32 {
        return Err(anyhow!(
            "MASTER_KEY must contain exactly 32 bytes (64 hexadecimal characters)"
        ));
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn parse_bool(name: &str, default: bool) -> Result<bool> {
    let Some(value) = env::var(name).ok() else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(anyhow!("{name} must be true or false")),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_master_key;

    #[test]
    fn parses_a_256_bit_hex_key() {
        let key = parse_master_key(&"ab".repeat(32)).unwrap();
        assert_eq!(key, [0xab; 32]);
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(parse_master_key("abcd").is_err());
    }
}
