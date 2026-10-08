use anyhow::{bail, Context, Result};
use clap::Args;
// Reuse the already-implemented core complexity engine without duplicating
// its AST scoring. That source has no public crate export yet.
#[path = "../../../sanctifier-core/src/complexity.rs"]
mod core_complexity;
use core_complexity::{analyze_complexity, ContractMetrics};
use syn::spanned::Spanned;
use syn::visit::Visit;
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
        let ast = syn::parse_file(&source)
            .with_context(|| format!("parsing {}", path.display()))?;
        let mut metrics = analyze_complexity(&ast, &path.display().to_string());
        // The legacy core parser measured quote!(tokens).to_string().lines(),
        // which strips whitespace and reports LOC=1 for every function.
        // Match its visitor order and restore physical source-span lengths.
        let mut spans = FunctionSpans::default();
        spans.visit_file(&ast);
        if metrics.functions.len() != spans.lines.len() {
            bail!("function source-span mismatch for {}", path.display());
        }
        for (function, physical_lines) in metrics.functions.iter_mut().zip(spans.lines) {
            function.loc = physical_lines;
        }
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

#[derive(Default)]
struct FunctionSpans {
    lines: Vec<usize>,
}

impl<'ast> Visit<'ast> for FunctionSpans {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if matches!(node.vis, syn::Visibility::Public(_)) {
            self.lines.push(node.span().end().line.saturating_sub(node.span().start().line) + 1);
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.lines.push(node.span().end().line.saturating_sub(node.span().start().line) + 1);
        syn::visit::visit_impl_item_fn(self, node);
    }
}

#[cfg(test)]
mod issue_696_regression {
    use super::*;
    #[test]
    fn nested_declarations_do_not_inflate_outer_function_complexity() {
        let source = r#"
            pub fn outer() {
                fn helper() { if true { panic!("unused"); } }
                struct Inner;
                impl Inner {
                    fn method() { for _ in 0..3 { work(); } }
                }
                if true { work(); }
            }
        "#;
        let parsed = syn::parse_file(source).unwrap();
        let metrics = analyze_complexity(&parsed, "nested.rs");
        let outer = metrics.functions.iter().find(|f| f.name == "outer").unwrap();
        let method = metrics.functions.iter().find(|f| f.name == "method").unwrap();
        assert_eq!(outer.cyclomatic_complexity, 2);
        assert_eq!(outer.max_nesting_depth, 1);
        assert_eq!(method.cyclomatic_complexity, 2);
        let mut spans = FunctionSpans::default();
        spans.visit_file(&parsed);
        assert_eq!(metrics.functions.len(), spans.lines.len());
    }

    #[test]
    fn nested_function_spans_preserve_actual_line_counts() {
        let source = "pub fn first() {\n    if true {\n        work();\n    }\n}\n\npub fn second() {}\n";
        let parsed = syn::parse_file(source).unwrap();
        let mut spans = FunctionSpans::default();
        spans.visit_file(&parsed);
        assert_eq!(spans.lines, vec![5, 1]);
        let metrics = analyze_complexity(&parsed, "example.rs");
        assert_eq!(metrics.functions.len(), 2);
        assert_eq!(metrics.functions[0].cyclomatic_complexity, 2);
    }
}
