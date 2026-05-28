mod app;
mod cli;
mod crypto;
mod render;
mod scanner;
mod settings;
mod storage;
mod vault;

fn main() {
    if let Err(error) = app::run() {
        eprintln!("GuardPetal error: {error:?}");
        std::process::exit(1);
    }
}
