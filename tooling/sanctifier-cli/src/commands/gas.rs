//! Static cost-proxy reporting; values are not measured Soroban fees.
use anyhow::{bail, Context, Result};
use clap::Args;
use sanctifier_core::gas_estimator::{GasEstimationReport, GasEstimator};
use serde::Serialize;
use std::{fs, path::{Path, PathBuf}};

#[derive(Args, Debug)]
pub struct GasArgs {
    /// Contract directory, its Cargo.toml, or a Rust source file
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Output format: text or json
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}
#[derive(Serialize)]
struct Row {
    file: String,
    #[serde(flatten)]
    estimate: GasEstimationReport,
}
#[derive(Serialize)]
struct Report {
    schema: &'static str,
    methodology: &'static str,
    caveat: &'static str,
    functions: Vec<Row>,
}

pub fn exec(args: GasArgs) -> Result<()> {
    let (root, files) = source_files(&args.path)?;
    let mut functions = Vec::new();
    let estimator = GasEstimator::new();
    for file in files {
        let source = fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let relative = file.strip_prefix(&root).unwrap_or(&file)
            .to_string_lossy().replace('\\', "/");
        for estimate in estimator.estimate_contract(&source) {
            functions.push(Row { file: relative.clone(), estimate });
        }
    }
    functions.sort_by(|a, b| {
        (&a.file, &a.estimate.function_name).cmp(&(&b.file, &b.estimate.function_name))
    });
    let report = Report {
        schema: "sanctifier-function-cost-v1",
        methodology: "Static syn AST weights: function base 50; binary op +5; direct call +20; storage method +1000; require_auth +500; other method +25; loops assume 10 iterations.",
        caveat: "Relative source-level weights, NOT measured Soroban CPU instructions, gas, transaction fees or precise memory. Dynamic inputs, host calls, compile optimizations and network charges are unknown.",
        functions,
    };
    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Per-function static cost weights (not measured fees)");
        for row in &report.functions {
            println!("{}::{}\t{} instructions*\t{} bytes*",
                row.file, row.estimate.function_name,
                row.estimate.estimated_instructions,
                row.estimate.estimated_memory_bytes);
        }
        println!("Functions: {}\n* {}", report.functions.len(), report.caveat);
    }
    Ok(())
}

fn source_files(input: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    let meta = fs::symlink_metadata(input)
        .with_context(|| format!("opening {}", input.display()))?;
    if meta.file_type().is_symlink() {
        bail!("input may not be a symlink");
    }
    let root = if meta.is_file() {
        if input.file_name().and_then(|s| s.to_str()) == Some("Cargo.toml") {
            input.parent().unwrap_or(Path::new(".")).to_path_buf()
        } else if input.extension().and_then(|s| s.to_str()) == Some("rs") {
            return Ok((input.parent().unwrap_or(Path::new(".")).to_path_buf(),
                vec![input.to_path_buf()]));
        } else { bail!("expected a directory, Cargo.toml, or .rs"); }
    } else { input.to_path_buf() };
    let scan = if root.join("Cargo.toml").is_file() && root.join("src").is_dir() {
        root.join("src")
    } else { root.clone() };
    let mut files = Vec::new();
    collect_rs(&scan, &mut files)?;
    files.sort();
    if files.is_empty() { bail!("no Rust files in {}", scan.display()); }
    Ok((root, files))
}
fn collect_rs(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries = fs::read_dir(dir)?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let kind = entry.file_type()?;
        if kind.is_symlink() { continue; }
        let path = entry.path();
        if kind.is_dir() {
            if matches!(entry.file_name().to_string_lossy().as_ref(),
                    ".git" | "target" | "vendor" | "node_modules") { continue; }
            collect_rs(&path, files)?;
        } else if kind.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(())
}
