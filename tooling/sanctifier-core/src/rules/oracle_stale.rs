use crate::finding_codes::ORACLE_STALE;
use crate::rules::{Rule, RuleViolation, Severity};
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

/// Advisory: price-bearing oracle output consumed without a visible freshness guard.
/// This is intentionally a local, syntax-based check, not interprocedural proof.
pub struct OracleStaleRule;

impl OracleStaleRule {
    pub fn new() -> Self { Self }
}
impl Default for OracleStaleRule {
    fn default() -> Self { Self::new() }
}

impl Rule for OracleStaleRule {
    fn name(&self) -> &str { "oracle_stale" }
    fn description(&self) -> &str {
        "Detects oracle price use without a visible timestamp freshness check"
    }
    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let Some(file) = crate::parse_cache::parse_cached(source) else {
            return Vec::new();
        };
        let mut visitor = OracleFunctionVisitor { findings: Vec::new() };
        visitor.visit_file(&file);
        visitor.findings
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

struct OracleFunctionVisitor {
    findings: Vec<RuleViolation>,
}

impl OracleFunctionVisitor {
    fn scan(&mut self, name: &str, block: &syn::Block) {
        let mut reads = PriceReadVisitor { reads: Vec::new() };
        reads.visit_block(block);
        if reads.reads.is_empty() { return; }
        let mut uses = PriceUseVisitor { used: Vec::new() };
        uses.visit_block(block);
        let mut guards = FreshnessGuardVisitor { guarded: Vec::new() };
        guards.visit_block(block);
        for (var, line) in reads.reads {
            if !uses.used.contains(&var) || guards.guarded.contains(&var) {
                continue;
            }
            self.findings.push(
                RuleViolation::new(
                    ORACLE_STALE,
                    Severity::Warning,
                    format!("{ORACLE_STALE}: oracle result '{var}' is used as a price without a visible freshness check"),
                    format!("{name}:{line}"),
                )
                .with_suggestion(
                    "Compare the oracle response timestamp with env.ledger().timestamp() and a bounded maximum age; reject stale observations before using the price."
                        .to_string(),
                ),
            );
        }
    }
}

impl<'ast> Visit<'ast> for OracleFunctionVisitor {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if matches!(item.vis, syn::Visibility::Public(_)) {
            self.scan(&item.sig.ident.to_string(), &item.block);
        }
        visit::visit_item_fn(self, item);
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if matches!(item.vis, syn::Visibility::Public(_)) {
            self.scan(&item.sig.ident.to_string(), &item.block);
        }
        visit::visit_impl_item_fn(self, item);
    }
}

struct PriceReadVisitor {
    reads: Vec<(String, usize)>,
}
impl<'ast> Visit<'ast> for PriceReadVisitor {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(binding), Some(init)) = (&node.pat, &node.init) {
            let expression = init.expr.to_token_stream().to_string().to_lowercase();
            let oracle = expression.contains("oracle")
                && ["lastprice", "last_price", "latest_price", "get_price", "price"]
                    .iter()
                    .any(|n| expression.contains(n));
            if oracle {
                self.reads.push((binding.ident.to_string(), node.span().start().line));
            }
        }
        visit::visit_local(self, node);
    }
}

struct PriceUseVisitor {
    used: Vec<String>,
}
impl<'ast> Visit<'ast> for PriceUseVisitor {
    fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
        if let (syn::Expr::Path(p), syn::Member::Named(member)) =
            (&*node.base, &node.member)
        {
            if member == "price" {
                if let Some(name) = p.path.get_ident() {
                    self.used.push(name.to_string());
                }
            }
        }
        visit::visit_expr_field(self, node);
    }
}

struct FreshnessGuardVisitor {
    guarded: Vec<String>,
}
impl<'ast> Visit<'ast> for FreshnessGuardVisitor {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let cond = node.cond.to_token_stream().to_string();
        let action = node.then_branch.to_token_stream().to_string();
        if [">", "<", ">=", "<="].iter().any(|c| cond.contains(c))
            && (action.contains("panic") || action.contains("return") || action.contains("assert"))
        {
            mark_timestamp_guards(&cond, &mut self.guarded);
        }
        visit::visit_expr_if(self, node);
    }
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node.path.segments.last().map(|s| s.ident.to_string());
        if matches!(name.as_deref(), Some("assert" | "ensure")) {
            mark_timestamp_guards(&node.tokens.to_string(), &mut self.guarded);
        }
        visit::visit_macro(self, node);
    }
}
fn mark_timestamp_guards(tokens: &str, guarded: &mut Vec<String>) {
    // Guard must tie the specific oracle response's timestamp to now/age.
    if !(tokens.contains("ledger") || tokens.contains("now") || tokens.contains("max_age")) {
        return;
    }
    let pieces: Vec<&str> = tokens.split_whitespace().collect();
    for window in pieces.windows(3) {
        if window[1] == "." && window[2] == "timestamp" {
            guarded.push(window[0].to_string());
        }
    }
}
