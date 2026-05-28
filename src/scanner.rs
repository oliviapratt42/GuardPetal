use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Default)]
pub struct FakeScanner;

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub subnet: String,
    pub profile: String,
    pub devices: Vec<ScannedDevice>,
    pub raw_evidence: Vec<RawEvidenceRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScannedDevice {
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub open_ports: Vec<u16>,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RawEvidenceRecord {
    pub source: String,
    pub summary: String,
    pub device_ip: Option<String>,
    pub fields: serde_json::Value,
}

impl FakeScanner {
    pub fn detect_subnet(&self) -> String {
        "192.168.1.0/24".to_string()
    }

    pub fn scan(&self, subnet: &str) -> ScanResult {
        let started_at = Utc::now();
        let devices = vec![
            ScannedDevice {
                ip_address: "192.168.1.1".to_string(),
                mac_address: Some("a8:5e:45:10:00:01".to_string()),
                hostname: Some("home-router.local".to_string()),
                vendor: Some("Example Networks".to_string()),
                open_ports: vec![53, 80, 443],
                status: "present".to_string(),
            },
            ScannedDevice {
                ip_address: "192.168.1.42".to_string(),
                mac_address: Some("b8:27:eb:22:44:66".to_string()),
                hostname: Some("raspberrypi.local".to_string()),
                vendor: Some("Raspberry Pi Foundation".to_string()),
                open_ports: vec![22],
                status: "present".to_string(),
            },
            ScannedDevice {
                ip_address: "192.168.1.87".to_string(),
                mac_address: None,
                hostname: None,
                vendor: None,
                open_ports: vec![],
                status: "present".to_string(),
            },
        ];

        let raw_evidence = devices
            .iter()
            .map(|device| RawEvidenceRecord {
                source: "fake_scanner".to_string(),
                summary: format!(
                    "Observed {} with {} open ports",
                    device.ip_address,
                    device.open_ports.len()
                ),
                device_ip: Some(device.ip_address.clone()),
                fields: serde_json::json!({
                    "ip_address": device.ip_address.clone(),
                    "mac_address_present": device.mac_address.is_some(),
                    "hostname_present": device.hostname.is_some(),
                    "open_ports": device.open_ports.clone(),
                }),
            })
            .collect();

        ScanResult {
            scan_id: Uuid::new_v4().to_string(),
            started_at,
            completed_at: Utc::now(),
            subnet: subnet.to_string(),
            profile: "medium_manual_fake_v0".to_string(),
            devices,
            raw_evidence,
        }
    }
}
