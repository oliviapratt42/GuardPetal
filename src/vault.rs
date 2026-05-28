use crate::crypto;
use crate::settings::AppPaths;
use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use zeroize::Zeroizing;

const CHECK_PLAINTEXT: &str = "guardpetal-vault-check-v1";

pub struct Vault {
    database_path: PathBuf,
}

pub struct UnlockedVault {
    key: Zeroizing<[u8; crypto::KEY_LEN]>,
}

impl UnlockedVault {
    pub fn key(&self) -> &[u8; crypto::KEY_LEN] {
        &self.key
    }
}

impl Vault {
    pub fn open_or_setup(paths: &AppPaths) -> Result<Self> {
        let vault = Self {
            database_path: paths.database_path.clone(),
        };

        if !paths.database_path.exists() {
            println!("No GuardPetal vault found. Starting first-boot setup.");
            vault.setup()?;
        }

        Ok(vault)
    }

    pub fn unlock(&self) -> Result<UnlockedVault> {
        let connection = Connection::open(&self.database_path)?;
        let salt = read_metadata(&connection, "vault_salt")?.context("Vault is missing salt")?;
        let encrypted_check =
            read_metadata(&connection, "vault_check")?.context("Vault is missing check value")?;

        let passphrase = rpassword::prompt_password("Passphrase: ")?;
        let key = crypto::derive_key(&passphrase, &BASE64.decode(salt)?)?;
        let decrypted = crypto::decrypt_from_base64(&key, &encrypted_check)?;

        if decrypted != CHECK_PLAINTEXT.as_bytes() {
            anyhow::bail!("Incorrect passphrase");
        }

        Ok(UnlockedVault { key })
    }

    fn setup(&self) -> Result<()> {
        println!("GuardPetal stores network metadata locally.");
        println!("There is no passphrase recovery in v1. If this passphrase is lost, the vault cannot be unlocked.");

        let passphrase = rpassword::prompt_password("Create passphrase: ")?;
        let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
        if passphrase != confirm {
            anyhow::bail!("Passphrases did not match");
        }

        let connection = Connection::open(&self.database_path)
            .with_context(|| format!("Could not create {}", self.database_path.display()))?;
        create_metadata_schema(&connection)?;

        let salt = crypto::new_salt();
        let key = crypto::derive_key(&passphrase, &salt)?;
        let encrypted_check = crypto::encrypt_to_base64(&key, CHECK_PLAINTEXT.as_bytes())?;

        write_metadata(&connection, "vault_salt", &BASE64.encode(salt))?;
        write_metadata(&connection, "vault_check", &encrypted_check)?;

        println!("Vault created.");
        Ok(())
    }
}

pub fn create_metadata_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL
        );
        ",
    )?;
    Ok(())
}

fn read_metadata(connection: &Connection, key: &str) -> Result<Option<String>> {
    let value = connection
        .query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value)
}

fn write_metadata(connection: &Connection, key: &str, value: &str) -> Result<()> {
    connection.execute(
        "
        INSERT INTO metadata (key, value)
        VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        ",
        params![key, value],
    )?;
    Ok(())
}
