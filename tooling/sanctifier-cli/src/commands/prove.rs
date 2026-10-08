use anyhow::Context as _;
use clap::Args;
use colored::*;
use sanctifier_core::smt::{
    configured_z3_config, BalanceTransition, ProofResult, ProofStatus, SmtProver,
    TokenInvariant, DEFAULT_Z3_TIMEOUT_MS,
};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use z3::Context;

#[derive(Args)]
pub struct ProveArgs {
    /// Path to the contract directory or file to verify
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Invariant to prove: balance_non_negative | supply_conserved | no_unauthorized_mint | all
    #[arg(long)]
    pub invariant: String,

    /// Prove balance transitions for transfer, mint, burn, or all (with --invariant balance_non_negative)
    #[arg(long)]
    pub transition: Option<String>,

    /// Demonstrate an unchecked transfer's negative balance with a Z3 SAT witness
    #[arg(long, requires = "transition")]
    pub unsafe_transfer: bool,

    /// Directory to write proof certificates (default: <path>/.sanctifier/proofs)
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Skip saving proof certificates to disk (useful for CI smoke checks)
    #[arg(long)]
    pub no_save: bool,

    /// Emit results as JSON
    #[arg(long)]
    pub json: bool,
}

/// On-disk proof certificate.
#[derive(Debug, Serialize)]
struct ProofCertificate {
    invariant: String,
    status: ProofStatus,
    message: String,
    counterexample: Option<sanctifier_core::smt::Counterexample>,
    duration_ms: u64,
    contract_path: String,
    timestamp_secs: u64,
}

pub fn exec(args: ProveArgs) -> anyhow::Result<()> {
    let invariants = resolve_invariants(&args.invariant)?;

    let transitions = match args.transition.as_deref() {
        None => None,
        Some("all") => Some(vec![
            BalanceTransition::Transfer,
            BalanceTransition::Mint,
            BalanceTransition::Burn,
        ]),
        Some(s) => Some(vec![
            BalanceTransition::parse(s).ok_or_else(|| {
                anyhow::anyhow!("Unknown balance transition '{s}'. Use transfer, mint, burn, or all")
            })?,
        ]),
    };
    if transitions.is_some()
        && (invariants.len() != 1 || invariants[0] != TokenInvariant::BalanceNonNegative)
    {
        anyhow::bail!("--transition requires --invariant balance_non_negative");
    }
    if args.unsafe_transfer && args.transition.as_deref() != Some("transfer") {
        anyhow::bail!("--unsafe-transfer requires --transition transfer");
    }

    let cfg = configured_z3_config(DEFAULT_Z3_TIMEOUT_MS);
    let ctx = Context::new(&cfg);
    let prover = SmtProver::new(&ctx);

    let contract_path = args
        .path
        .canonicalize()
        .unwrap_or_else(|_| args.path.clone());

    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| contract_path.join(".sanctifier").join("proofs"));

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut any_violated = false;

    let results: Vec<ProofResult> = match &transitions {
        Some(operations) => operations
            .iter()
            .map(|op| prover.prove_balance_transition(*op, !args.unsafe_transfer))
            .collect(),
        None => invariants
            .iter()
            .map(|invariant| prover.prove_invariant(invariant))
            .collect(),
    };

    for result in &results {

        if result.status == ProofStatus::Violated {
            any_violated = true;
        }

        if args.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            print_result(&result);
        }

        if !args.no_save {
            let cert = ProofCertificate {
                invariant: result.invariant.clone(),
                status: result.status.clone(),
                message: result.message.clone(),
                counterexample: result.counterexample.clone(),
                duration_ms: result.duration_ms,
                contract_path: contract_path.display().to_string(),
                timestamp_secs: timestamp,
            };
            save_certificate(&cert, &output_dir)
                .with_context(|| format!("saving certificate for {}", result.invariant))?;
        }
    }

    // Exit 1 when any invariant is violated so CI catches regressions.
    if any_violated {
        std::process::exit(1);
    }

    Ok(())
}

fn resolve_invariants(s: &str) -> anyhow::Result<Vec<TokenInvariant>> {
    if s == "all" {
        return Ok(TokenInvariant::all());
    }
    TokenInvariant::parse(s).map(|i| vec![i]).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown invariant '{s}'. Valid options: \
                balance_non_negative, supply_conserved, no_unauthorized_mint, all"
        )
    })
}

fn print_result(r: &ProofResult) {
    let (icon, label) = match r.status {
        ProofStatus::Proved => ("✅".green(), "PROVED".green().bold()),
        ProofStatus::Violated => ("❌".red(), "VIOLATED".red().bold()),
        ProofStatus::Unknown => ("❓".yellow(), "UNKNOWN".yellow().bold()),
    };
    println!("\n{icon} [{label}] {}", r.invariant.bold());
    println!("   {}", r.message);
    println!("   Solved in {}ms", r.duration_ms);

    if let Some(ce) = &r.counterexample {
        println!("\n   {}", "Counterexample:".yellow().bold());
        println!("   Call: {}", ce.call_sequence.italic());
        println!("   Variables:");
        for (k, v) in &ce.variables {
            println!("     {k} = {v}");
        }
    }
}

fn save_certificate(cert: &ProofCertificate, dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;
    let file = dir.join(format!("{}.json", cert.invariant));
    let json = serde_json::to_string_pretty(cert)?;
    fs::write(&file, json).with_context(|| format!("writing {}", file.display()))?;
    println!(
        "   {} Proof certificate saved → {}",
        "📄".cyan(),
        file.display()
    );
    Ok(())
}
