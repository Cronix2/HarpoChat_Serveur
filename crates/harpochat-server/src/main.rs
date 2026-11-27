// SPDX-License-Identifier: Apache-2.0
//! Entry point.

use clap::Parser;

fn main() {
    let cli = harpochat_server::cli::Cli::parse();
    std::process::exit(harpochat_server::cli::run_cli(cli));
}
