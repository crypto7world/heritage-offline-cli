mod commands;
mod handlers;
mod utils;

use log::error;

use clap::Parser;
use commands::CliOpts;
use handlers::handle_command;

fn main() {
    env_logger::init();

    let cli_opts = CliOpts::parse();

    match handle_command(cli_opts) {
        Ok(result) => println!("{}", result),
        Err(e) => {
            error!("{}", e.to_string())
        }
    }
}
