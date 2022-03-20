mod cli;
mod client;

use std::io::Error;

use clap::Parser;

fn main() -> Result<(), Error> {
    let args = cli::Args::parse();
    let client = client::Wcb::new(args);
    client.run()
}
