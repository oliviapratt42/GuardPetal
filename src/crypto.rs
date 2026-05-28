use anyhow::{anyhow, Result};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use sha2::Sha256;
use std::io::{Read, Write};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_LEN: usize = 32;

pub fn new_salt() -> Vec<u8> {
    let mut salt = vec![0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|error| anyhow!("Could not derive vault key: {error}"))?;
    Ok(key)
}

pub fn encrypt_to_base64(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<String> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow!("Encryption failed"))?;

    let mut packed = Vec::with_capacity(nonce.len() + ciphertext.len());
    packed.extend_from_slice(&nonce);
    packed.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(packed))
}

pub fn decrypt_from_base64(key: &[u8; KEY_LEN], encoded: &str) -> Result<Vec<u8>> {
    let packed = BASE64.decode(encoded)?;
    if packed.len() < 13 {
        return Err(anyhow!("Encrypted value is too short"));
    }

    let (nonce, ciphertext) = packed.split_at(12);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("Decryption failed"))
}

pub fn compress_then_encrypt_to_base64(key: &[u8; KEY_LEN], text: &str) -> Result<String> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(text.as_bytes())?;
    let compressed = encoder.finish()?;
    encrypt_to_base64(key, &compressed)
}

pub fn decrypt_then_decompress_from_base64(key: &[u8; KEY_LEN], encoded: &str) -> Result<String> {
    let compressed = decrypt_from_base64(key, encoded)?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut text = String::new();
    decoder.read_to_string(&mut text)?;
    Ok(text)
}

pub fn keyed_hash_hex(key: &[u8; KEY_LEN], value: &str) -> Result<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)?;
    mac.update(value.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}
