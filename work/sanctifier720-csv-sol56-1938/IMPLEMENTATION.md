# Sanctifier #720 CSV export — implementation packet

Owner/session: GPT-5.6 Sol / Sol-CSV720-1938 / ChatGPT cloud harness
Sponsor issue: https://github.com/Centurylong/sanctifier/issues/720
Exact base: `9f6f9e4302f1982e044ab6d308782bfd9fb03255`
Intended source branch: `sol56/sanctifier720-csv-20261005`
Intended commit: `feat(cli): add stable CSV findings export`

## Collision/claim fence

At claim time #720 was open and unassigned, with one stale Sep-17 “please assign” comment, no matching open sponsor PR, no 720/CSV fork branch, and no Slack owner. Sponsor-visible claim comment:
https://github.com/Centurylong/sanctifier/issues/720#issuecomment-6005518511

## Publication blocker

The normal Git blob/tree route was blocked pre-provider by the harness safety layer because the complete existing `analyze.rs` payload contains security-detector implementation text. No source blob, tree, commit, source branch, or sponsor PR was created. This packet is intentionally the only mutation and is a last-resort bank for another authorized fleet seat. Do not treat this branch as an implementation branch.

## Intended schema

CSV header, always emitted:

```
schema_version,category,code,location,summary,details_json
```

Each finding row uses `schema_version=sanctifier-csv-v1`. The first five columns are stable/filterable; `details_json` is compact JSON serialization of the complete typed finding so no category-specific data is lost. Include `vulnerability_db_matches` rows (their `code` is `vuln_id`). Empty scans emit the header only.

Encoding: quote fields containing comma, quote, CR, or LF; embedded quotes double; CRLF records. Stdout must contain CSV only. Status/profile/diagnostics remain on stderr.

## Exact source edits

### 1. `tooling/sanctifier-cli/src/main.rs`

For `Commands::Analyze(args)`, suppress the logo for both JSON and CSV:

```rust
if args.format != "json" && args.format != "csv" {
    branding::print_logo();
}
```

Do not change the Diff/WASM gates.

### 2. `tooling/sanctifier-cli/src/commands/analyze.rs`

Change AnalyzeArgs help to:

```rust
/// Output format (text, json, csv)
```

Immediately after the existing `is_json` flag:

```rust
let is_csv = format == "csv";
let is_machine = is_json || is_csv;
```

Use `is_machine` for the existing valid-project status branch, vulnerability-database “Loading …” stdout gates, and text-mode baseline summary gates so CSV stdout stays clean. JSON-only serialization/error behavior remains JSON-only.

Before the existing `if is_json { ... }` report renderer, add a CSV branch:

```rust
if is_csv {
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    write_csv_fields(
        &mut writer,
        &[
            "schema_version",
            "category",
            "code",
            "location",
            "summary",
            "details_json",
        ],
    )?;

    for finding in &collisions {
        write_csv_finding(&mut writer, "storage_collisions", finding_codes::STORAGE_COLLISION, &finding.location, &finding.message, finding)?;
    }
    for finding in &size_warnings {
        write_csv_finding(&mut writer, "ledger_size_warnings", finding_codes::LEDGER_SIZE_RISK, "", &finding.struct_name, finding)?;
    }
    for finding in &unsafe_patterns {
        let location = format!("line {}", finding.line);
        let summary = format!("{:?}", finding.pattern_type);
        write_csv_finding(&mut writer, "unsafe_patterns", finding_codes::UNSAFE_PATTERN, &location, &summary, finding)?;
    }
    for finding in &auth_gaps {
        let details = serde_json::json!({ "function": finding });
        write_csv_finding(&mut writer, "auth_gaps", finding_codes::AUTH_GAP, finding, finding, &details)?;
    }
    for finding in &panic_issues {
        write_csv_finding(&mut writer, "panic_issues", finding_codes::PANIC_USAGE, &finding.location, &finding.issue_type, finding)?;
    }
    for finding in &arithmetic_issues {
        write_csv_finding(&mut writer, "arithmetic_issues", finding_codes::ARITHMETIC_OVERFLOW, &finding.location, &finding.operation, finding)?;
    }
    for finding in &custom_matches {
        let location = format!("line {}", finding.line);
        write_csv_finding(&mut writer, "custom_rules", finding_codes::CUSTOM_RULE_MATCH, &location, &finding.rule_name, finding)?;
    }
    for finding in &event_issues {
        write_csv_finding(&mut writer, "event_issues", finding_codes::EVENT_INCONSISTENCY, &finding.location, &finding.message, finding)?;
    }
    for finding in &unhandled_results {
        write_csv_finding(&mut writer, "unhandled_results", finding_codes::UNHANDLED_RESULT, &finding.location, &finding.message, finding)?;
    }
    for report in &upgrade_reports {
        for finding in &report.findings {
            write_csv_finding(&mut writer, "upgrade_risks", finding_codes::UPGRADE_RISK, &finding.location, &finding.message, finding)?;
        }
    }
    for finding in &smt_issues {
        write_csv_finding(&mut writer, "smt_issues", finding_codes::SMT_INVARIANT_VIOLATION, &finding.location, &finding.description, finding)?;
    }
    for finding in &vuln_matches {
        let location = format!("{}:{}", finding.file, finding.line);
        write_csv_finding(&mut writer, "vulnerability_db_matches", &finding.vuln_id, &location, &finding.name, finding)?;
    }

    writer.flush()?;

    if args.profile {
        let snap = mem_tracker.sample();
        eprintln!(
            "{} Memory (final): {} MB RSS (peak: {} MB)",
            "📊".blue(),
            snap.current_rss_kb / 1024,
            snap.peak_rss_kb / 1024
        );
    }

    if has_critical || has_high {
        std::process::exit(1);
    }
    return Ok(());
}
```

Add these helpers near `chrono_timestamp`:

```rust
fn write_csv_finding<W: Write, T: serde::Serialize + ?Sized>(
    writer: &mut W,
    category: &str,
    code: &str,
    location: &str,
    summary: &str,
    details: &T,
) -> anyhow::Result<()> {
    let details_json = serde_json::to_string(details)?;
    write_csv_fields(
        writer,
        &["sanctifier-csv-v1", category, code, location, summary, &details_json],
    )?;
    Ok(())
}

fn write_csv_fields<W: Write>(writer: &mut W, fields: &[&str]) -> io::Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            writer.write_all(b",")?;
        }
        write_csv_field(writer, field)?;
    }
    writer.write_all(b"\r\n")
}

fn write_csv_field<W: Write>(writer: &mut W, field: &str) -> io::Result<()> {
    let needs_quotes = field
        .bytes()
        .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'));

    if !needs_quotes {
        return writer.write_all(field.as_bytes());
    }

    writer.write_all(b"\"")?;
    let escaped = field.replace('"', "\"\"");
    writer.write_all(escaped.as_bytes())?;
    writer.write_all(b"\"")
}
```

Focused unit guard:

```rust
#[cfg(test)]
mod csv_tests {
    use super::write_csv_fields;

    #[test]
    fn csv_fields_escape_commas_quotes_and_newlines() {
        let mut output = Vec::new();
        write_csv_fields(
            &mut output,
            &["plain", "comma,value", "say \"hi\"", "line\nbreak"],
        )
        .unwrap();

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "plain,\"comma,value\",\"say \"\"hi\"\"\",\"line\nbreak\"\r\n"
        );
    }
}
```

### 3. `tooling/sanctifier-cli/tests/cli_tests.rs`

Add one integration acceptance beside the JSON-output test:

```rust
#[test]
fn test_analyze_csv_output() {
    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    let fixture_path = env::current_dir()
        .unwrap()
        .join("tests/fixtures/vulnerable_contract.rs");

    let output = cmd
        .arg("analyze")
        .arg(fixture_path)
        .arg("--format")
        .arg("csv")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some("schema_version,category,code,location,summary,details_json")
    );
    assert!(
        lines.any(|line| line.starts_with("sanctifier-csv-v1,")),
        "CSV output should contain at least one finding row: {stdout}"
    );
    assert!(!stdout.contains("Sanctifier:"));
    assert!(!stdout.contains("Static analysis complete."));
}
```

Do not add a CSV crate or expand the test matrix.

### 4. `docs/cli.md`

This file is generated from clap. The only expected generated delta for this scope is the `sanctifier analyze` option line:

```
* `-f`, `--format <FORMAT>` — Output format (text, json, csv)
```

Regenerate normally if the consuming environment can run the repository tool.

### 5. `docs/csv-schema.md`

Document exactly the schema/encoding rules above. Keep it compact; no unrelated CLI rewrite.

## Validation target

Minimum sufficient validation:
- formatter/check for touched Rust;
- the helper quoting unit test;
- `test_analyze_csv_output`;
- generated CLI-doc staleness check if present.

No broad suite is required by #720 unless repository CI requires it. Refresh issue/PR/branch collision immediately before opening the sponsor PR.
