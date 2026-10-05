use crate::commands::analyze::AnalyzeArgs;
use clap::Args;
use colored::*;
use notify::{recommended_watcher, EventKind, RecursiveMode, Watcher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Arguments for `sanctifier watch`.
#[derive(Args)]
pub struct WatchArgs {
    /// Path to a contract directory, workspace, or single `.rs` file to watch
    #[arg(short, long, default_value = ".")]
    pub path: PathBuf,

    /// Debounce window in milliseconds before re-running after a change
    #[arg(short, long, default_value = "300")]
    pub debounce: u64,

    /// Output format passed through to `analyze` (text | json)
    #[arg(short, long, default_value = "text")]
    pub format: String,
}

type WatchEvent = notify::Result<notify::Event>;

/// Returns true when an event represents a created/modified/removed `.rs` file.
/// Access (read) events and non-Rust paths are ignored so the watcher only
/// reacts to actual source edits.
fn is_rs_event(event: &notify::Event) -> bool {
    let is_mutation = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    is_mutation
        && event
            .paths
            .iter()
            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("rs"))
}

/// Run `sanctifier watch`: re-run analysis whenever a `.rs` file under `path`
/// changes, debounced, until interrupted with Ctrl-C.
pub fn exec(args: WatchArgs) -> anyhow::Result<()> {
    let path = args.path.clone();
    watch_loop(&path, args.debounce, || run_analysis(&args))
}

/// Run analyze --watch using the same watcher/debounce loop while preserving
/// the complete analyze invocation across each child-process rerun.
pub fn exec_analyze(args: AnalyzeArgs) -> anyhow::Result<()> {
    let watch_path = analyze_watch_target(&args.path).to_path_buf();
    watch_loop(&watch_path, args.debounce, || run_analyze_args(&args))
}

/// Analyze accepts a Cargo.toml path as well as a directory or Rust file.
/// Watching only the manifest would miss source edits, so watch its containing
/// project directory while preserving the original path for each analysis run.
fn analyze_watch_target(path: &Path) -> &Path {
    if path.file_name().and_then(|name| name.to_str()) == Some("Cargo.toml") {
        path.parent().unwrap_or(path)
    } else {
        path
    }
}

fn watch_loop<F>(path: &Path, debounce_ms: u64, mut run: F) -> anyhow::Result<()>
where
    F: FnMut(),
{
    if !path.exists() {
        anyhow::bail!("path {:?} does not exist", path);
    }

    let (tx, rx) = channel::<WatchEvent>();
    let mut watcher = recommended_watcher(move |res| {
        let _ = tx.send(res);
    })?;
    watcher.watch(path, RecursiveMode::Recursive)?;

    // Ctrl-C flips this flag; the loop polls it so shutdown is cooperative and
    // the watcher/Drop runs cleanly instead of the process being hard-killed.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = Arc::clone(&shutdown);
        ctrlc::set_handler(move || shutdown.store(true, Ordering::SeqCst))
            .map_err(|e| anyhow::anyhow!("failed to install Ctrl-C handler: {e}"))?;
    }

    // Show results immediately, before the first change.
    run();
    print_watching(path);

    while !shutdown.load(Ordering::SeqCst) {
        // Poll so Ctrl-C is observed even while idle.
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(Ok(event)) if is_rs_event(&event) => {
                debounce(&rx, debounce_ms, &shutdown);
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                run();
                print_watching(path);
            }
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    println!("\n{} Watch stopped.", "✓".green());
    Ok(())
}

/// Wait until source files have been quiet for `debounce_ms`. Each new `.rs`
/// change resets the timer, so a burst of saves coalesces into a single run and
/// a change arriving mid-window cancels the pending run.
fn debounce(rx: &Receiver<WatchEvent>, debounce_ms: u64, shutdown: &AtomicBool) {
    let window = Duration::from_millis(debounce_ms);
    let mut deadline = Instant::now() + window;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        match rx.recv_timeout(remaining) {
            Ok(Ok(event)) if is_rs_event(&event) => {
                deadline = Instant::now() + window;
            }
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Clear the screen and re-run `sanctifier analyze` as a child process.
///
/// Running analysis in a subprocess keeps the watcher alive: `analyze` calls
/// `std::process::exit` on findings / invalid projects, which would otherwise
/// terminate the whole watch session.
fn run_analysis(args: &WatchArgs) {
    clear_screen();

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("{} could not locate sanctifier binary: {e}", "❌".red());
            return;
        }
    };

    let status = Command::new(exe)
        .arg("analyze")
        .arg(&args.path)
        .arg("--format")
        .arg(&args.format)
        .status();

    if let Err(e) = status {
        eprintln!("{} failed to run analysis: {e}", "❌".red());
    }
}

fn run_analyze_args(args: &AnalyzeArgs) {
    clear_screen();

    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("{} could not locate sanctifier binary: {e}", "❌".red());
            return;
        }
    };

    let mut command = Command::new(exe);
    command
        .arg("analyze")
        .arg(&args.path)
        .arg("--format")
        .arg(&args.format)
        .arg("--limit")
        .arg(args.limit.to_string());

    if let Some(vuln_db) = &args.vuln_db {
        command.arg("--vuln-db").arg(vuln_db);
    }
    for webhook_url in &args.webhook_urls {
        command.arg("--webhook-url").arg(webhook_url);
    }
    if args.no_baseline {
        command.arg("--no-baseline");
    }
    if args.profile {
        command.arg("--profile");
    }
    if let Some(max_memory) = args.max_memory {
        command.arg("--max-memory").arg(max_memory.to_string());
    }

    if let Err(e) = command.status() {
        eprintln!("{} failed to run analysis: {e}", "❌".red());
    }
}

fn clear_screen() {
    // ANSI: clear screen + move cursor to home.
    print!("\x1B[2J\x1B[1;1H");
    let _ = std::io::stdout().flush();
}

fn print_watching(path: &Path) {
    println!(
        "\n👀 Watching {} for .rs changes — press Ctrl-C to stop.",
        path.display().to_string().cyan()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{AccessKind, Event, EventKind, ModifyKind};

    #[test]
    fn manifest_watch_targets_project_directory() {
        assert_eq!(
            analyze_watch_target(Path::new("contracts/token/Cargo.toml")),
            Path::new("contracts/token")
        );
        assert_eq!(
            analyze_watch_target(Path::new("contracts/token/src/lib.rs")),
            Path::new("contracts/token/src/lib.rs")
        );
    }

    #[test]
    fn detects_rs_modifications() {
        let event =
            Event::new(EventKind::Modify(ModifyKind::Any)).add_path(PathBuf::from("lib.rs"));
        assert!(is_rs_event(&event));
    }

    #[test]
    fn detects_rs_creation_and_removal() {
        let created = Event::new(EventKind::Create(notify::event::CreateKind::File))
            .add_path("new.rs".into());
        let removed = Event::new(EventKind::Remove(notify::event::RemoveKind::File))
            .add_path("old.rs".into());
        assert!(is_rs_event(&created));
        assert!(is_rs_event(&removed));
    }

    #[test]
    fn ignores_non_rs_files() {
        let event = Event::new(EventKind::Modify(ModifyKind::Any)).add_path("notes.txt".into());
        assert!(!is_rs_event(&event));
    }

    #[test]
    fn ignores_access_events() {
        let event = Event::new(EventKind::Access(AccessKind::Read)).add_path("lib.rs".into());
        assert!(!is_rs_event(&event));
    }
}
