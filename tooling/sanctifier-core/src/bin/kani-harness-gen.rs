#[path = "../kani_harness.rs"]
mod kani_harness;

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::Write;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(args.len() == 3, "usage: kani-harness-gen SOURCE_RS CRATE_NAME OUTPUT_RS");
    let input = std::fs::read_to_string(&args[0])
        .with_context(|| format!("read {}", &args[0]))?;
    let output = kani_harness::generate_kani_harnesses(&input, &args[1])?;
    let target = std::path::Path::new(&args[2]);
    if let Some(dir) = target.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut file = OpenOptions::new().create_new(true).write(true).open(target)
        .context("output already exists; preserve manual proof refinements")?;
    file.write_all(output.as_bytes())?;
    println!("Generated unverified Kani skeleton at {}", target.display());
    Ok(())
}
