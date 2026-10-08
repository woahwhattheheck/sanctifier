//! Cost-only CI executable sharing the production estimator, without the CLI's SMT dependencies.
#[path = "../../sanctifier-core/src/gas_estimator.rs"]
mod gas_estimator;

use quote::ToTokens;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fs, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cost {
    estimated_instructions: u64,
    estimated_memory_bytes: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    schema_version: u32,
    sources: Vec<String>,
    functions: BTreeMap<String, Cost>,
}

fn snapshot(sources: &[String]) -> Result<Baseline> {
    let root = std::env::current_dir()?.canonicalize()?;
    let mut functions = BTreeMap::new();
    let mut normalized = Vec::new();
    for source in sources {
        let path = Path::new(source).canonicalize()?;
        let relative = path.strip_prefix(&root)?;
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            return Err(format!("source is not a Rust file: {source}").into());
        }
        let label = relative
            .to_str()
            .ok_or("non-UTF-8 source path")?
            .replace('\\', "/");
        if normalized.contains(&label) {
            return Err(format!("duplicate source: {label}").into());
        }
        let text = fs::read_to_string(&path)?;
        let parsed = syn::parse_file(&text).map_err(|e| format!("invalid Rust in {label}: {e}"))?;
        for item in parsed.items {
            if let syn::Item::Impl(implementation) = item {
                let owner = implementation.self_ty.to_token_stream().to_string();
                let trait_name = implementation
                    .trait_
                    .as_ref()
                    .map(|(_, name, _)| format!(" as {}", name.to_token_stream()))
                    .unwrap_or_default();
                // Per-impl estimation keeps same-named methods on different types separate.
                let reports = gas_estimator::GasEstimator::new()
                    .estimate_contract(&implementation.to_token_stream().to_string());
                for report in reports {
                    let key = format!("{label}::{owner}{trait_name}::{}", report.function_name);
                    let cost = Cost {
                        estimated_instructions: report.estimated_instructions as u64,
                        estimated_memory_bytes: report.estimated_memory_bytes as u64,
                    };
                    if functions.insert(key.clone(), cost).is_some() {
                        return Err(format!("ambiguous function identity: {key}").into());
                    }
                }
            }
        }
        normalized.push(label);
    }
    normalized.sort();
    if functions.is_empty() {
        return Err("no public impl methods found; refusing an empty cost baseline".into());
    }
    Ok(Baseline {
        schema_version: 1,
        sources: normalized,
        functions,
    })
}

fn regressions(baseline: &Baseline, current: &Baseline, percent: u64) -> Vec<String> {
    let mut failures = Vec::new();
    for (name, old) in &baseline.functions {
        let Some(new) = current.functions.get(name) else {
            failures.push(format!("missing baseline function: {name}"));
            continue;
        };
        for (metric, before, after) in [
            (
                "estimated_instructions",
                old.estimated_instructions,
                new.estimated_instructions,
            ),
            (
                "estimated_memory_bytes",
                old.estimated_memory_bytes,
                new.estimated_memory_bytes,
            ),
        ] {
            // Exact integer comparison includes the threshold; zero-to-positive always fails.
            // The CLI accepts any u64 threshold. A large baseline multiplied
            // by a large threshold can exceed u128, while after * 100
            // cannot. Saturating the unrepresentably high allowed limit
            // preserves the exact inequality without panicking or wrapping.
            let permitted_scaled = u128::from(before)
                .checked_mul(100 + u128::from(percent))
                .unwrap_or(u128::MAX);
            if u128::from(after) * 100 > permitted_scaled {
                failures.push(format!(
                    "{name}: {metric} {before} -> {after} exceeds {percent}%"
                ));
            }
        }
    }
    for name in current.functions.keys() {
        if !baseline.functions.contains_key(name) {
            failures.push(format!(
                "new function needs an explicitly reviewed baseline: {name}"
            ));
        }
    }
    failures
}

fn run() -> Result<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 || !matches!(args[0].as_str(), "update" | "check") {
        return Err("usage: sanctifier-cost-gate update BASELINE SOURCE.rs [SOURCE.rs ...]\n       sanctifier-cost-gate check BASELINE MAX_REGRESSION_PERCENT".into());
    }
    if args[0] == "update" {
        let baseline = snapshot(&args[2..])?;
        let content = serde_json::to_string_pretty(&baseline)? + "\n";
        fs::write(&args[1], content)?;
        eprintln!(
            "stored {} function estimates in {}",
            baseline.functions.len(),
            args[1]
        );
        return Ok(true);
    }
    if args.len() != 3 {
        return Err("check expects exactly BASELINE and MAX_REGRESSION_PERCENT".into());
    }
    let percent: u64 = args[2]
        .parse()
        .map_err(|_| "threshold must be a non-negative integer percent")?;
    let baseline: Baseline = serde_json::from_str(&fs::read_to_string(&args[1])?)?;
    if baseline.schema_version != 1 || baseline.sources.is_empty() || baseline.functions.is_empty()
    {
        return Err("unsupported or empty baseline".into());
    }
    let current = snapshot(&baseline.sources)?;
    let failures = regressions(&baseline, &current, percent);
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "passed": failures.is_empty(),
            "max_regression_percent": percent,
            "checked_functions": current.functions.len(),
            "regressions": failures,
        }))?
    );
    Ok(failures.is_empty())
}

fn main() {
    match run() {
        Ok(true) => (),
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("cost gate: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maximum_valid_threshold_does_not_overflow() {
        let name = "contract.rs::Token::transfer".to_string();
        let source = "contract.rs".to_string();
        let baseline = Baseline {
            schema_version: 1,
            sources: vec![source.clone()],
            functions: BTreeMap::from([(
                name.clone(),
                Cost {
                    estimated_instructions: u64::MAX - 1,
                    estimated_memory_bytes: u64::MAX - 1,
                },
            )]),
        };
        let current = Baseline {
            schema_version: 1,
            sources: vec![source],
            functions: BTreeMap::from([(
                name,
                Cost {
                    estimated_instructions: u64::MAX,
                    estimated_memory_bytes: u64::MAX,
                },
            )]),
        };

        // A mathematically enormous allowed threshold permits this tiny
        // increase. Debug and release builds must never overflow/wrap.
        assert!(regressions(&baseline, &current, u64::MAX).is_empty());
    }
}
