# GuardPetal

GuardPetal v1 is a local-first Rust CLI for understanding a home network from the perspective of the machine running it. It is a learning-first architecture project, but the result should still feel serious, professional, and careful with sensitive network data.

Core question:

> Who is on my network, and what does it look like right now?

## V1 Direction

- User: technical homeowner.
- Interface: interactive terminal session.
- Binary: `guardpetal`.
- Data posture: local-first, no cloud, no AI enrichment.
- First milestone: securely house scans.
- First usable flow: run GuardPetal, unlock it, type `scan` or `run scan`, and trust that it is scanning according to configured settings.

V1 is not a frontend dashboard anymore. The old Vite prototype was removed so the repo can focus on the Rust CLI architecture.

## Observation Model

GuardPetal v1 runs on a laptop on the same flat LAN as the devices being scanned. It can usually observe:

- Device presence through ARP table data, ping/ARP scans, local subnet scans, mDNS/Bonjour, and sometimes NetBIOS/LLMNR.
- Device metadata such as IP address, MAC address, hostname when available, vendor/OUI, open ports, service names, latency, reachability, and scan confidence.
- Internet performance from the laptop's perspective, such as gateway reachability, DNS latency, external reachability, and speed-test-style metrics if explicitly chosen later.

On a normal switched home network, a laptop generally cannot see every other device's unicast traffic by default. It may see its own traffic, broadcasts, multicasts, and some discovery chatter. Whole-network DNS or connection analytics require a later architecture choice, such as router integration, DNS proxying, gateway placement, mirror-port capture, or another deliberate traffic-visibility setup.

The v1 observation model is therefore:

> Manual scan from laptop, same LAN, one flat subnet. GuardPetal discovers devices, enriches identities, stores scan data securely, shows current discovery results, and measures network/internet performance from the laptop's perspective. DNS and connection analytics are later architecture branches unless traffic is deliberately routed through GuardPetal or another collector.

## CLI Shape

Running `guardpetal` should:

- Detect whether a vault already exists.
- Enter first-boot setup if no vault exists.
- Otherwise prompt for the passphrase.
- Open an interactive prompt after unlock, such as `guardpetal>`.

Initial commands:

- `help`: show available next steps.
- `settings`: show reverse DNS permission, scan profile, subnet behavior, vault path, and logging mode.
- `scope`: show visibility and data-handling scope.
- `scan` / `run scan`: run the configured manual scan.
- `devices`: show latest scan results.
- `raw`: show normalized raw evidence from the latest scan.
- `device <id>`: inspect one device from the latest scan.
- `wipe`: delete stored scan data after confirmation.
- `exit`: lock and leave the session.

`wipe` deletes scan data only. Settings remain.

## Security Direction

GuardPetal uses SQLite for local structured storage and field-level encryption for selected sensitive values.

Encrypted in v1:

- MAC address.
- Hostname.
- User nickname.
- Reverse DNS cache.
- Raw scan evidence.

Plain in v1:

- Local IP address.
- Vendor.
- User tags.
- Scan timestamps and scan IDs.
- Port numbers and lightweight port evidence.

GuardPetal stores a keyed HMAC of MAC addresses for device matching while encrypting the original MAC address for unlocked display. Raw evidence is structured, compressed, then encrypted.

The passphrase derives an in-memory key using Argon2. If the passphrase is forgotten, v1 has no recovery path.

## Scanning Direction

V1 uses a single manual medium scan profile:

- Ping/ARP discovery.
- Common TCP port checks.
- Light service identification.
- Manual only.
- Rate-limited.
- Elevated permissions allowed when needed.
- Lower-permission fallback when possible.

Before each scan, GuardPetal should detect the subnet, display it, display the scan profile, and ask for confirmation. Manual subnet override is out of scope for v1.

Reverse DNS should use explicit consent. If a scan path would use reverse DNS and no permission choice exists, GuardPetal asks yes/no and then asks whether to remember the choice.

## Architecture

Module boundaries:

- `main`: startup and top-level error handling.
- `cli`: interactive prompt and command parsing.
- `app`: unlocked session orchestration.
- `settings`: settings file and app paths.
- `vault`: first boot, unlock, passphrase-derived key handling.
- `storage`: SQLite schema and persistence.
- `crypto`: encryption, compression, and keyed hashing.
- `scanner`: scanner interface and current fake scan implementation.
- `render`: terminal tables and readable output.

The current scanner is intentionally fake. It exercises the secure storage path before real network scanning is introduced.

## Development

Install Rust, then run:

```bash
cargo run
```

For tests and development, set `GUARDPETAL_HOME` to point at disposable app data:

```bash
GUARDPETAL_HOME=.guardpetal cargo run
```

This lets development runs avoid touching the real macOS application-support directory.
