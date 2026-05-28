use anyhow::Result;
use std::io::{self, Write};

pub enum Command {
    Help,
    Settings,
    Scope,
    Scan,
    Devices,
    Raw,
    Device(usize),
    Wipe,
    Exit,
    Unknown(String),
    Empty,
}

pub struct CommandReader;

impl CommandReader {
    pub fn new() -> Self {
        Self
    }

    pub fn run<F>(&self, mut handle: F) -> Result<()>
    where
        F: FnMut(Command) -> Result<bool>,
    {
        loop {
            let input = read_line("guardpetal> ")?;
            let command = parse_command(&input);
            if !handle(command)? {
                println!("Locked. Goodbye.");
                return Ok(());
            }
        }
    }
}

pub fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim_end().to_string())
}

pub fn confirm(question: &str) -> Result<bool> {
    loop {
        let answer = read_line(&format!("{question} [y/n] "))?;
        match answer.trim().to_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Please answer y or n."),
        }
    }
}

fn parse_command(input: &str) -> Command {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Command::Empty;
    }

    let mut parts = trimmed.split_whitespace();
    let Some(command) = parts.next() else {
        return Command::Empty;
    };

    match command {
        "help" | "h" | "?" => Command::Help,
        "settings" => Command::Settings,
        "scope" => Command::Scope,
        "scan" => Command::Scan,
        "run" if parts.next() == Some("scan") => Command::Scan,
        "devices" => Command::Devices,
        "raw" => Command::Raw,
        "wipe" => Command::Wipe,
        "exit" | "quit" => Command::Exit,
        "device" => match parts.next().and_then(|id| id.parse::<usize>().ok()) {
            Some(id) => Command::Device(id),
            None => Command::Unknown(trimmed.to_string()),
        },
        _ => Command::Unknown(trimmed.to_string()),
    }
}
