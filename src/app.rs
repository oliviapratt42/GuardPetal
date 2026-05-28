use crate::cli::{Command, CommandReader};
use crate::render;
use crate::scanner::FakeScanner;
use crate::settings::{AppPaths, Settings};
use crate::storage::Storage;
use crate::vault::{UnlockedVault, Vault};
use anyhow::Result;

pub fn run() -> Result<()> {
    let paths = AppPaths::load()?;
    let mut settings = Settings::load_or_create(&paths)?;
    let vault = Vault::open_or_setup(&paths)?;
    let unlocked = vault.unlock()?;
    let storage = Storage::open(&paths.database_path, &unlocked)?;

    println!();
    println!("GuardPetal is unlocked.");
    println!("Type `help` to see available commands.");

    let mut session = AppSession {
        settings: &mut settings,
        storage,
        scanner: FakeScanner::default(),
        unlocked,
    };

    CommandReader::new().run(|command| session.handle(command))
}

struct AppSession<'a> {
    settings: &'a mut Settings,
    storage: Storage,
    scanner: FakeScanner,
    unlocked: UnlockedVault,
}

impl AppSession<'_> {
    fn handle(&mut self, command: Command) -> Result<bool> {
        match command {
            Command::Help => render::help(),
            Command::Settings => render::settings(self.settings),
            Command::Scope => render::scope(),
            Command::Scan => self.scan()?,
            Command::Devices => {
                let devices = self.storage.latest_devices(&self.unlocked)?;
                render::devices(&devices);
            }
            Command::Raw => {
                let evidence = self.storage.latest_raw_evidence(&self.unlocked)?;
                render::raw_evidence(evidence.as_deref());
            }
            Command::Device(id) => {
                let device = self.storage.device_by_display_id(&self.unlocked, id)?;
                render::device_detail(device.as_ref());
            }
            Command::Wipe => self.wipe()?,
            Command::Exit => return Ok(false),
            Command::Unknown(input) => {
                println!("Unknown command `{input}`. Type `help` for available commands.");
            }
            Command::Empty => {}
        }

        Ok(true)
    }

    fn scan(&mut self) -> Result<()> {
        let detected_subnet = self.scanner.detect_subnet();

        println!("Detected subnet: {detected_subnet}");
        println!("Scan profile: medium manual scan");
        println!("Includes: ping/ARP discovery, common TCP ports, light service identification.");
        println!("This milestone uses a fake scanner to prove secure scan storage before real LAN scanning.");

        if !crate::cli::confirm("Run scan with these settings?")? {
            println!("Scan cancelled.");
            return Ok(());
        }

        let result = self.scanner.scan(&detected_subnet);
        self.storage.store_scan(&self.unlocked, &result)?;

        println!("Scan complete. Stored {} device observations.", result.devices.len());
        println!("Type `devices` to view the latest scan or `raw` to inspect normalized evidence.");
        Ok(())
    }

    fn wipe(&mut self) -> Result<()> {
        println!("This deletes stored scan data. Settings remain.");
        println!("Type `delete my GuardPetal data` to continue.");

        let confirmation = crate::cli::read_line("> ")?;
        if confirmation.trim() != "delete my GuardPetal data" {
            println!("Wipe cancelled.");
            return Ok(());
        }

        self.storage.wipe_scan_data()?;
        println!("Stored scan data wiped.");
        Ok(())
    }
}
