use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct AppPaths {
    pub home_dir: PathBuf,
    pub settings_path: PathBuf,
    pub database_path: PathBuf,
}

impl AppPaths {
    pub fn load() -> Result<Self> {
        let home_dir = match env::var_os("GUARDPETAL_HOME") {
            Some(path) => PathBuf::from(path),
            None => dirs::data_dir()
                .context("Could not find a platform data directory")?
                .join("GuardPetal"),
        };

        fs::create_dir_all(&home_dir)
            .with_context(|| format!("Could not create {}", home_dir.display()))?;

        Ok(Self {
            settings_path: home_dir.join("settings.toml"),
            database_path: home_dir.join("guardpetal.sqlite"),
            home_dir,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    pub reverse_dns: ReverseDnsSetting,
    pub scan_profile: String,
    pub subnet_detection: String,
    pub logging_mode: String,
    #[serde(skip)]
    pub vault_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReverseDnsSetting {
    NotConfigured,
    Enabled,
    Disabled,
}

impl Settings {
    pub fn load_or_create(paths: &AppPaths) -> Result<Self> {
        if paths.settings_path.exists() {
            let raw = fs::read_to_string(&paths.settings_path)?;
            let mut settings: Settings = toml::from_str(&raw)?;
            settings.vault_path = paths.database_path.clone();
            return Ok(settings);
        }

        let settings = Settings {
            reverse_dns: ReverseDnsSetting::NotConfigured,
            scan_profile: "medium_manual_fake_v0".to_string(),
            subnet_detection: "detect_every_scan".to_string(),
            logging_mode: "minimal_sensitive".to_string(),
            vault_path: paths.database_path.clone(),
        };
        settings.save(paths)?;
        Ok(settings)
    }

    fn save(&self, paths: &AppPaths) -> Result<()> {
        let serializable = self.clone_for_save();
        let raw = toml::to_string_pretty(&serializable)?;
        fs::write(&paths.settings_path, raw)?;
        Ok(())
    }

    fn clone_for_save(&self) -> Self {
        Self {
            reverse_dns: match self.reverse_dns {
                ReverseDnsSetting::NotConfigured => ReverseDnsSetting::NotConfigured,
                ReverseDnsSetting::Enabled => ReverseDnsSetting::Enabled,
                ReverseDnsSetting::Disabled => ReverseDnsSetting::Disabled,
            },
            scan_profile: self.scan_profile.clone(),
            subnet_detection: self.subnet_detection.clone(),
            logging_mode: self.logging_mode.clone(),
            vault_path: self.vault_path.clone(),
        }
    }
}
