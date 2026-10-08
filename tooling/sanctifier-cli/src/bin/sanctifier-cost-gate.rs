//! Deterministic, fail-closed cost regression checks for source-backed Soroban contracts.
//! Uses the existing sanctifier-core heuristic estimator. These are not on-chain gas units.
use anyhow::{bail, ensure, Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand};
use sanctifier_core::gas_estimator::GasEstimator;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(name = "sanctifier-cost-gate", about = "Record and check per-function Sanctifier cost baselines")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Record a reviewed baseline. Commit the resulting JSON to the repository.
    Record {
        #[command(flatten)]
        inputs: Inputs,
        #[arg(long)]
        baseline: PathBuf,
    },
    /// Exit nonzero when metrics grow beyond the approved percentage, or coverage changes.
    Check {
        #[command(flatten)]
        inputs: Inputs,
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long, default_value_t = 10)]
        max_regression_percent: u32,
    },
}

#[derive(Debug, ClapArgs)]
struct Inputs {
    /// Repository root; source paths must resolve within this directory.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// Contract Rust file; repeat --source for additional files.
    #[arg(long = "source", required = true)]
    sources: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cost {
    instructions: u64,
    memory_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    schema_version: u32,
    estimates: BTreeMap<String, Cost>,
}

fn collect(inputs: &Inputs) -> Result<Baseline> {
    let root = fs::canonicalize(&inputs.root)
        .with_context(|| format!("cannot open --root {}", inputs.root.display()))?;
    ensure!(root.is_dir(), "--root is not a directory: {}", root.display());

    let mut estimates = BTreeMap::new();
    for source in &inputs.sources {
        let resolved = if source.is_absolute() {
            source.clone()
        } else {
            root.join(source)
        };
        let resolved = fs::canonicalize(&resolved)
            .with_context(|| format!("cannot open source {}", source.display()))?;
        ensure!(resolved.is_file(), "source is not a regular file: {}", source.display());
        ensure!(
            resolved.extension().and_then(|ext| ext.to_str()) == Some("rs"),
            "expected a Rust source file: {}",
            source.display()
        );
        let relative = resolved.strip_prefix(&root).with_context(|| {
            format!("source {} escapes --root {}", resolved.display(), root.display())
        })?;
        let relative = stable_path(relative)?;
        let source_text = fs::read_to_string(&resolved)
            .with_context(|| format!("cannot read {}", source.display()))?;
        let reports = GasEstimator::new().estimate_contract(&source_text);
        // This estimator returns an empty list on parse errors; never treat that
        // as a successful zero-cost result or silently drop an input contract.
        ensure!(
            !reports.is_empty(),
            "{} has no parsable public impl functions; refusing incomplete cost coverage",
            relative
        );
        for report in reports {
            let key = format!("{}::{}", relative, report.function_name);
            let cost = Cost {
                instructions: report.estimated_instructions as u64,
                memory_bytes: report.estimated_memory_bytes as u64,
            };
            ensure!(
                estimates.insert(key.clone(), cost).is_none(),
                "ambiguous duplicate public function key: {}",
                key
            );
        }
    }
    ensure!(!estimates.is_empty(), "no public functions were estimated");
    Ok(Baseline {
        schema_version: 1,
        estimates,
    })
}

fn stable_path(path: &Path) -> Result<String> {
    let text = path.to_str().context("non-UTF-8 source path is unsupported")?;
    Ok(text.replace('\\', "/"))
}

fn record(inputs: &Inputs, baseline_path: &Path) -> Result<()> {
    let snapshot = collect(inputs)?;
    let mut data = serde_json::to_string_pretty(&snapshot)?;
    data.push('\n');
    fs::write(baseline_path, data)
        .with_context(|| format!("cannot write baseline {}", baseline_path.display()))?;
    println!(
        "RECORDED {} public function estimates in {}; review and commit this change",
        snapshot.estimates.len(),
        baseline_path.display()
    );
    Ok(())
}

fn check(inputs: &Inputs, baseline_path: &Path, max_percent: u32) -> Result<()> {
    ensure!(
        max_percent <= 100,
        "--max-regression-percent must be between 0 and 100"
    );
    let bytes = fs::read(baseline_path)
        .with_context(|| format!("cannot read baseline {}", baseline_path.display()))?;
    let baseline: Baseline = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid cost baseline {}", baseline_path.display()))?;
    ensure!(baseline.schema_version == 1, "unsupported cost baseline schema");
    ensure!(!baseline.estimates.is_empty(), "empty cost baseline is not a valid gate");
    for (key, cost) in &baseline.estimates {
        ensure!(
            !key.is_empty() && cost.instructions > 0 && cost.memory_bytes > 0,
            "invalid or zero-cost baseline for {}",
            key
        );
    }

    let current = collect(inputs)?;
    let mut failures = Vec::new();
    for key in baseline.estimates.keys() {
        if !current.estimates.contains_key(key) {
            failures.push(format!("missing baseline function in current sources: {}", key));
        }
    }
    for (key, observed) in &current.estimates {
        match baseline.estimates.get(key) {
            None => failures.push(format!("new public function is not baselined: {}", key)),
            Some(previous) => {
                for (metric, before, after) in [
                    ("instructions", previous.instructions, observed.instructions),
                    ("memory_bytes", previous.memory_bytes, observed.memory_bytes),
                ] {
                    // Integer arithmetic avoids floating-point boundary errors and
                    // prevents large-value overflow in threshold comparisons.
                    if (u128::from(after) * 100)
                        > (u128::from(before) * (100 + u128::from(max_percent)))
                    {
                        failures.push(format!(
                            "{} {} regressed {} -> {} (max +{}%)",
                            key, metric, before, after, max_percent
                        ));
                    }
                }
            }
        }
    }

    if !failures.is_empty() {
        for finding in &failures {
            eprintln!("COST REGRESSION: {}", finding);
        }
        bail!(
            "cost gate failed with {} finding(s); review the source change before rebaselining",
            failures.len()
        );
    }
    println!(
        "PASS: {} public functions within +{}% of committed baseline",
        current.estimates.len(),
        max_percent
    );
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Record { inputs, baseline } => record(&inputs, &baseline),
        Command::Check {
            inputs,
            baseline,
            max_regression_percent,
        } => check(&inputs, &baseline, max_regression_percent),
    }
}
