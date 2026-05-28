use crate::crypto;
use crate::scanner::{ScanResult, ScannedDevice};
use crate::vault::{create_metadata_schema, UnlockedVault};
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

#[derive(Debug)]
pub struct DeviceRow {
    pub display_id: usize,
    pub stable_id: String,
    pub status: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<u16>,
    pub identity_confidence: u8,
    pub tags: String,
}

pub struct Storage {
    connection: Connection,
}

impl Storage {
    pub fn open(path: &Path, vault: &UnlockedVault) -> Result<Self> {
        let connection = Connection::open(path)?;
        create_metadata_schema(&connection)?;
        let storage = Self { connection };
        storage.migrate()?;
        storage.ensure_key_marker(vault)?;
        Ok(storage)
    }

    pub fn store_scan(&self, vault: &UnlockedVault, result: &ScanResult) -> Result<()> {
        let raw_json = serde_json::to_string_pretty(&result.raw_evidence)?;
        let encrypted_raw = crypto::compress_then_encrypt_to_base64(vault.key(), &raw_json)?;

        self.connection.execute(
            "
            INSERT INTO scans (id, started_at, completed_at, subnet, profile, raw_evidence)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ",
            params![
                &result.scan_id,
                result.started_at.to_rfc3339(),
                result.completed_at.to_rfc3339(),
                &result.subnet,
                &result.profile,
                encrypted_raw
            ],
        )?;

        for (index, device) in result.devices.iter().enumerate() {
            self.store_device(vault, &result.scan_id, index + 1, device)?;
        }

        Ok(())
    }

    pub fn latest_devices(&self, vault: &UnlockedVault) -> Result<Vec<DeviceRow>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Vec::new());
        };

        let mut statement = self.connection.prepare(
            "
            SELECT display_id, stable_id, status, ip_address, encrypted_mac, encrypted_hostname,
                   vendor, open_ports, identity_confidence, tags
            FROM scan_devices
            WHERE scan_id = ?1
            ORDER BY display_id
            ",
        )?;

        let rows = statement
            .query_map(params![scan_id], |row| {
                Ok(EncryptedDeviceRow {
                    display_id: row.get::<_, i64>(0)? as usize,
                    stable_id: row.get(1)?,
                    status: row.get(2)?,
                    ip_address: row.get(3)?,
                    encrypted_mac: row.get(4)?,
                    encrypted_hostname: row.get(5)?,
                    vendor: row.get(6)?,
                    open_ports: row.get(7)?,
                    identity_confidence: row.get::<_, i64>(8)? as u8,
                    tags: row.get(9)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        rows.into_iter()
            .map(|row| row.decrypt(vault))
            .collect::<Result<Vec<_>>>()
    }

    pub fn latest_raw_evidence(&self, vault: &UnlockedVault) -> Result<Option<String>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(None);
        };

        let encrypted: Option<String> = self
            .connection
            .query_row(
                "SELECT raw_evidence FROM scans WHERE id = ?1",
                params![scan_id],
                |row| row.get(0),
            )
            .optional()?;

        encrypted
            .map(|value| crypto::decrypt_then_decompress_from_base64(vault.key(), &value))
            .transpose()
    }

    pub fn device_by_display_id(
        &self,
        vault: &UnlockedVault,
        display_id: usize,
    ) -> Result<Option<DeviceRow>> {
        Ok(self
            .latest_devices(vault)?
            .into_iter()
            .find(|device| device.display_id == display_id))
    }

    pub fn wipe_scan_data(&self) -> Result<()> {
        self.connection.execute("DELETE FROM scan_devices", [])?;
        self.connection.execute("DELETE FROM scans", [])?;
        Ok(())
    }

    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                subnet TEXT NOT NULL,
                profile TEXT NOT NULL,
                raw_evidence TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                display_id INTEGER NOT NULL,
                stable_id TEXT NOT NULL,
                status TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                encrypted_mac TEXT,
                encrypted_hostname TEXT,
                vendor TEXT,
                open_ports TEXT NOT NULL,
                identity_confidence INTEGER NOT NULL,
                tags TEXT NOT NULL DEFAULT '',
                UNIQUE(scan_id, display_id)
            );
            ",
        )?;
        Ok(())
    }

    fn ensure_key_marker(&self, _vault: &UnlockedVault) -> Result<()> {
        Ok(())
    }

    fn store_device(
        &self,
        vault: &UnlockedVault,
        scan_id: &str,
        display_id: usize,
        device: &ScannedDevice,
    ) -> Result<()> {
        let stable_id = match &device.mac_address {
            Some(mac) => crypto::keyed_hash_hex(vault.key(), mac)?[..12].to_string(),
            None => format!("ip-{}", device.ip_address.replace('.', "-")),
        };
        let encrypted_mac = device
            .mac_address
            .as_deref()
            .map(|mac| crypto::encrypt_to_base64(vault.key(), mac.as_bytes()))
            .transpose()?;
        let encrypted_hostname = device
            .hostname
            .as_deref()
            .map(|hostname| crypto::encrypt_to_base64(vault.key(), hostname.as_bytes()))
            .transpose()?;
        let open_ports = serde_json::to_string(&device.open_ports)?;
        let identity_confidence = identity_confidence(device);

        self.connection.execute(
            "
            INSERT INTO scan_devices (
                scan_id, display_id, stable_id, status, ip_address, encrypted_mac,
                encrypted_hostname, vendor, open_ports, identity_confidence, tags
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, '')
            ",
            params![
                scan_id,
                display_id,
                stable_id,
                &device.status,
                &device.ip_address,
                encrypted_mac,
                encrypted_hostname,
                device.vendor.as_deref(),
                open_ports,
                identity_confidence
            ],
        )?;
        Ok(())
    }

    fn latest_scan_id(&self) -> Result<Option<String>> {
        let scan_id = self
            .connection
            .query_row(
                "SELECT id FROM scans ORDER BY completed_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        Ok(scan_id)
    }
}

struct EncryptedDeviceRow {
    display_id: usize,
    stable_id: String,
    status: String,
    ip_address: String,
    encrypted_mac: Option<String>,
    encrypted_hostname: Option<String>,
    vendor: Option<String>,
    open_ports: String,
    identity_confidence: u8,
    tags: String,
}

impl EncryptedDeviceRow {
    fn decrypt(self, vault: &UnlockedVault) -> Result<DeviceRow> {
        let mac_address = self
            .encrypted_mac
            .as_deref()
            .map(|value| decrypt_string(vault, value))
            .transpose()?;
        let hostname = self
            .encrypted_hostname
            .as_deref()
            .map(|value| decrypt_string(vault, value))
            .transpose()?;
        let open_ports = serde_json::from_str(&self.open_ports)?;

        Ok(DeviceRow {
            display_id: self.display_id,
            stable_id: self.stable_id,
            status: self.status,
            ip_address: self.ip_address,
            mac_address,
            hostname,
            vendor: self.vendor,
            open_ports,
            identity_confidence: self.identity_confidence,
            tags: self.tags,
        })
    }
}

fn decrypt_string(vault: &UnlockedVault, value: &str) -> Result<String> {
    let bytes = crypto::decrypt_from_base64(vault.key(), value)?;
    Ok(String::from_utf8(bytes)?)
}

fn identity_confidence(device: &ScannedDevice) -> u8 {
    let mut score = 0;
    if device.mac_address.is_some() {
        score += 40;
    }
    if device.hostname.is_some() {
        score += 30;
    }
    if !device.open_ports.is_empty() {
        score += 30;
    }
    score
}
