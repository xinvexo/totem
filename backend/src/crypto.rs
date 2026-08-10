use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, Payload},
    XChaCha20Poly1305, XNonce,
};

#[derive(Clone)]
pub struct Crypto {
    key: [u8; 32],
}

impl Crypto {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 24]), String> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| "invalid encryption key".to_owned())?;
        let mut nonce = [0_u8; 24];
        aead_random_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: b"totem/totp",
                },
            )
            .map_err(|_| "secret encryption failed".to_owned())?;
        Ok((ciphertext, nonce))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
        if nonce.len() != 24 {
            return Err("invalid secret nonce".to_owned());
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| "invalid encryption key".to_owned())?;
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: b"totem/totp",
                },
            )
            .map_err(|_| "secret decryption failed".to_owned())
    }
}

fn aead_random_bytes(bytes: &mut [u8]) {
    use chacha20poly1305::aead::rand_core::RngCore;
    OsRng.fill_bytes(bytes);
}

#[cfg(test)]
mod tests {
    use super::Crypto;

    #[test]
    fn encrypts_and_decrypts_with_a_random_nonce() {
        let crypto = Crypto::new([7; 32]);
        let (ciphertext, nonce) = crypto.encrypt(b"secret-value").unwrap();
        assert_ne!(ciphertext, b"secret-value");
        assert_eq!(
            crypto.decrypt(&ciphertext, &nonce).unwrap(),
            b"secret-value"
        );
        assert!(crypto.decrypt(&ciphertext, &[0; 24]).is_err());
    }
}
