use std::env;
use std::io::Error;

use clap::CommandFactory;
use clap_complete::{generate_to, shells::Bash};

include!("src/cli.rs");

fn main() -> Result<(), Error> {
    let outdir = match env::var_os("OUT_DIR") {
        None => return Ok(()),
        Some(outdir) => outdir,
    };

    let mut app = Args::command();
    let path = generate_to(Bash, &mut app, "wcb", outdir)?;

    println!("cargo:warning=completion file is generated: {:?}", path);

    Ok(())
}
