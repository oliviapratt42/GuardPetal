use crate::settings::Settings;
use crate::storage::DeviceRow;
use comfy_table::{Cell, Table};

pub fn help() {
    println!("Available commands:");
    println!("  help          Show this command list");
    println!("  settings      Show current local settings");
    println!("  scope         Show visibility and data-handling scope");
    println!("  scan          Run the configured manual scan");
    println!("  run scan      Alias for scan");
    println!("  devices       Show latest scan results");
    println!("  raw           Show normalized raw evidence from latest scan");
    println!("  device <id>   Inspect one device from the latest scan");
    println!("  wipe          Delete stored scan data; settings remain");
    println!("  exit          Lock and exit");
}

pub fn settings(settings: &Settings) {
    let mut table = Table::new();
    table.set_header(vec!["Setting", "Value"]);
    table.add_row(vec![Cell::new("Reverse DNS"), Cell::new(format!("{:?}", settings.reverse_dns))]);
    table.add_row(vec![Cell::new("Scan profile"), Cell::new(&settings.scan_profile)]);
    table.add_row(vec![Cell::new("Subnet detection"), Cell::new(&settings.subnet_detection)]);
    table.add_row(vec![Cell::new("Vault path"), Cell::new(settings.vault_path.display().to_string())]);
    table.add_row(vec![Cell::new("Logging mode"), Cell::new(&settings.logging_mode)]);
    println!("{table}");
}

pub fn scope() {
    println!("GuardPetal v1 visibility scope:");
    println!("- Runs locally on this machine.");
    println!("- Assumes this machine is on the same flat LAN being scanned.");
    println!("- Can discover local device presence and visible metadata.");
    println!("- Cannot claim whole-network packet or DNS visibility from a normal laptop on a switched network.");
    println!("- Reverse DNS can contact outside infrastructure and requires explicit consent before use.");
    println!("- Sensitive scan fields are encrypted before storage.");
}

pub fn devices(devices: &[DeviceRow]) {
    if devices.is_empty() {
        println!("No scan results stored yet. Type `scan` first.");
        return;
    }

    let mut table = Table::new();
    table.set_header(vec![
        "ID",
        "Status",
        "IP",
        "Hostname",
        "MAC",
        "Vendor",
        "Open Ports",
        "Confidence",
        "Tags",
    ]);

    for device in devices {
        table.add_row(vec![
            Cell::new(device.display_id),
            Cell::new(&device.status),
            Cell::new(&device.ip_address),
            Cell::new(device.hostname.as_deref().unwrap_or("-")),
            Cell::new(device.mac_address.as_deref().unwrap_or("-")),
            Cell::new(device.vendor.as_deref().unwrap_or("-")),
            Cell::new(format_ports(&device.open_ports)),
            Cell::new(format!("{}%", device.identity_confidence)),
            Cell::new(if device.tags.is_empty() { "-" } else { device.tags.as_str() }),
        ]);
    }

    println!("{table}");
}

pub fn raw_evidence(evidence: Option<&str>) {
    match evidence {
        Some(evidence) => println!("{evidence}"),
        None => println!("No raw evidence stored yet. Type `scan` first."),
    }
}

pub fn device_detail(device: Option<&DeviceRow>) {
    let Some(device) = device else {
        println!("No device found with that ID in the latest scan.");
        return;
    };

    let mut table = Table::new();
    table.set_header(vec!["Field", "Value"]);
    table.add_row(vec![Cell::new("Session ID"), Cell::new(device.display_id)]);
    table.add_row(vec![Cell::new("Stable ID"), Cell::new(&device.stable_id)]);
    table.add_row(vec![Cell::new("Status"), Cell::new(&device.status)]);
    table.add_row(vec![Cell::new("IP address"), Cell::new(&device.ip_address)]);
    table.add_row(vec![Cell::new("MAC address"), Cell::new(device.mac_address.as_deref().unwrap_or("-"))]);
    table.add_row(vec![Cell::new("Hostname"), Cell::new(device.hostname.as_deref().unwrap_or("-"))]);
    table.add_row(vec![Cell::new("Vendor"), Cell::new(device.vendor.as_deref().unwrap_or("-"))]);
    table.add_row(vec![Cell::new("Open ports"), Cell::new(format_ports(&device.open_ports))]);
    table.add_row(vec![Cell::new("Identity confidence"), Cell::new(format!("{}%", device.identity_confidence))]);
    table.add_row(vec![Cell::new("Tags"), Cell::new(if device.tags.is_empty() { "-" } else { device.tags.as_str() })]);
    println!("{table}");
}

fn format_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return "-".to_string();
    }

    ports
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
