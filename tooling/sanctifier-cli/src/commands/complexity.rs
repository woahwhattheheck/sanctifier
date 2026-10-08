use anyhow::{bail, Context, Result};
use clap::Args;
use sanctifier_core::complexity::{analyze_source, ContractMetrics};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args, Debug)]
pub struct ComplexityArgs {
    /// Rust source file or directory containing Rust sources
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Output format (text or json)
    #[arg(short, long, value_parser = ["text", "json"], default_value = "text")]
    pub format: String,
    /// Maximum acceptable cyclomatic complexity per function
    #[arg(long, default_value_t = 10)]
    pub max_cyclomatic: u32,
    /// Maximum acceptable function nesting depth
    #[arg(long, default_value_t = 4)]
    pub max_nesting: u32,
    /// Maximum acceptable function length in source lines
    #[arg(long, default_value_t = 50)]
    pub max_function_lines: usize,
    /// Maximum acceptable number of parameters per function
    #[arg(long, default_value_t = 5)]
    pub max_params: usize,
    /// Exit unsuccessfully if any function exceeds a configured limit
    #[arg(long)]
    pub fail_on_exceed: bool,
}

pub fn exec(args: ComplexityArgs) -> Result<()> {
    let mut files = Vec::new();
    collect_rs_files(&args.path, &mut files)?;
    files.sort();
    if files.is_empty() {
        bail!("no Rust source files found at {}", args.path.display());
    }
    let mut contracts: Vec<ContractMetrics> = Vec::new();
    for path in &files {
        let source = fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let mut metrics = analyze_source(&source, &path.display().to_string())
            .with_context(|| format!("parsing {}", path.display()))?;
        for f in &mut metrics.functions {
            f.warnings.clear();
            if f.cyclomatic_complexity > args.max_cyclomatic {
                f.warnings.push(format!("cyclomatic complexity {} exceeds {}", f.cyclomatic_complexity, args.max_cyclomatic));
            }
            if f.max_nesting_depth > args.max_nesting {
                f.warnings.push(format!("nesting depth {} exceeds {}", f.max_nesting_depth, args.max_nesting));
            }
            if f.loc > args.max_function_lines {
                f.warnings.push(format!("function length {} exceeds {} lines", f.loc, args.max_function_lines));
            }
            if f.param_count > args.max_params {
                f.warnings.push(format!("parameter count {} exceeds {}", f.param_count, args.max_params));
            }
        }
        contracts.push(metrics);
    }
    let fn_count: usize = contracts.iter().map(|m| m.functions.len()).sum();
    let flagged: usize = contracts.iter().flat_map(|m| &m.functions)
        .filter(|f| !f.warnings.is_empty()).count();
    if args.format == "json" {
        let value = serde_json::json!({
            "schema_version": 1,
            "thresholds": {
                "max_cyclomatic": args.max_cyclomatic,
                "max_nesting": args.max_nesting,
                "max_function_lines": args.max_function_lines,
                "max_params": args.max_params
            },
            "summary": {
                "files": contracts.len(),
                "functions": fn_count,
                "flagged_functions": flagged
            },
            "contracts": contracts
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("Sanctifier complexity: {} files, {} functions, {} above limits",
            contracts.len(), fn_count, flagged);
        println!("Limits: CC={} nesting={} lines={} params={}",
            args.max_cyclomatic, args.max_nesting, args.max_function_lines, args.max_params);
        for report in &contracts {
            if report.functions.is_empty() { continue; }
            println!("\n{}", report.contract_path);
            for f in &report.functions {
                println!("  {}: CC={} nesting={} lines={} params={}",
                    f.name, f.cyclomatic_complexity, f.max_nesting_depth, f.loc, f.param_count);
                for w in &f.warnings { println!("    WARN: {}", w); }
            }
        }
    }
    if args.fail_on_exceed && flagged > 0 {
        bail!("{} functions exceeded complexity limits", flagged);
    }
    Ok(())
}

fn collect_rs_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("reading path {}", path.display()))?;
    if meta.file_type().is_symlink() { return Ok(()); }
    if meta.is_file() {
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            bail!("expected Rust .rs file or directory: {}", path.display());
        }
        out.push(path.to_path_buf());
        return Ok(());
    }
    if !meta.is_dir() { bail!("expected source file or directory: {}", path.display()); }
    for entry in fs::read_dir(path)
        .with_context(|| format!("listing {}", path.display()))?
    {
        let entry = entry?;
        let child = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if child.is_dir() && (name == ".git" || name == "target" || name == "node_modules") {
            continue;
        }
        collect_rs_files(&child, out)?;
    }
    Ok(())
}
