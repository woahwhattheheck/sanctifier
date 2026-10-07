use crate::finding_codes::WEAK_RANDOM;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

const FINDING_CODE: &str = WEAK_RANDOM;

/// Detects predictable ledger metadata used as a randomness source for
/// participant/outcome selection.
///
/// Soroban ledger timestamp and sequence are public, predictable metadata. They
/// are useful for deadlines and ordering, but not for entropy. This rule tracks
/// values derived from `env.ledger().timestamp()` / `.sequence()` through local
/// bindings and reports them only when they become a selection sink: a
/// modulo-reduced collection index, `get`-style lookup, or an explicitly
/// selection-named function call.
pub struct WeakRandomRule;

impl WeakRandomRule {
    pub fn new() -> Self {
        Self
    }

    fn check_fn(&self, name: &str, block: &syn::Block) -> Vec<RuleViolation> {
        let mut visitor = WeakRandomVisitor {
            fn_name: name.to_string(),
            tainted: HashSet::new(),
            reduced: HashSet::new(),
            seen_lines: HashSet::new(),
            violations: Vec::new(),
        };
        visitor.visit_block(block);
        visitor.violations
    }
}

impl Default for WeakRandomRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for WeakRandomRule {
    fn name(&self) -> &str {
        "weak_random"
    }

    fn description(&self) -> &str {
        "Detects predictable ledger timestamp/sequence values used to select participants or outcomes"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return vec![],
        };

        let mut visitor = FnVisitor {
            rule: self,
            violations: Vec::new(),
        };
        visitor.visit_file(&file);
        visitor.violations
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct FnVisitor<'rule> {
    rule: &'rule WeakRandomRule,
    violations: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for FnVisitor<'_> {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.violations
            .extend(self.rule.check_fn(&node.sig.ident.to_string(), &node.block));
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.violations
            .extend(self.rule.check_fn(&node.sig.ident.to_string(), &node.block));
        visit::visit_item_fn(self, node);
    }
}

struct WeakRandomVisitor {
    fn_name: String,
    tainted: HashSet<String>,
    reduced: HashSet<String>,
    seen_lines: HashSet<usize>,
    violations: Vec<RuleViolation>,
}

impl WeakRandomVisitor {
    fn report(&mut self, line: usize) {
        if !self.seen_lines.insert(line) {
            return;
        }

        self.violations.push(
            RuleViolation::new(
                FINDING_CODE,
                Severity::Error,
                format!(
                    "{FINDING_CODE}: ledger timestamp/sequence-derived value is used as a selection index; ledger metadata is predictable and not a secure randomness source"
                ),
                format!("{}:{line}", self.fn_name),
            )
            .with_suggestion(
                "Use commit-reveal or a verifiable randomness source (VRF/oracle), and derive the selection index from that unpredictable value instead of ledger timestamp/sequence."
                    .to_string(),
            ),
        );
    }
}

impl<'ast> Visit<'ast> for WeakRandomVisitor {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(name) = pat_ident(&node.pat) {
            // A new binding with the same identifier shadows the old one. Compute
            // the initializer against the pre-shadow state first (so `let x = x`
            // can propagate taint), then replace rather than accumulate state.
            let (is_tainted, is_reduced) = node
                .init
                .as_ref()
                .map(|init| {
                    let is_tainted = expr_is_tainted(&init.expr, &self.tainted);
                    (is_tainted, is_tainted && contains_modulo(&init.expr))
                })
                .unwrap_or((false, false));

            self.tainted.remove(&name);
            self.reduced.remove(&name);
            if is_tainted {
                self.tainted.insert(name.clone());
            }
            if is_reduced {
                self.reduced.insert(name);
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(name) = path_ident(&node.left) {
            // Assignment replaces the variable's previous value. Evaluate the
            // RHS before clearing so self-derived assignments still propagate.
            let is_tainted = expr_is_tainted(&node.right, &self.tainted);
            let is_reduced = is_tainted && contains_modulo(&node.right);

            self.tainted.remove(&name);
            self.reduced.remove(&name);
            if is_tainted {
                self.tainted.insert(name.clone());
            }
            if is_reduced {
                self.reduced.insert(name);
            }
        }
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(node.op, syn::BinOp::RemAssign(_)) {
            if let Some(name) = path_ident(&node.left) {
                let is_tainted = self.tainted.contains(&name)
                    || expr_is_tainted(&node.right, &self.tainted);
                if is_tainted {
                    self.tainted.insert(name.clone());
                    self.reduced.insert(name);
                } else {
                    self.tainted.remove(&name);
                    self.reduced.remove(&name);
                }
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_index(&mut self, node: &'ast syn::ExprIndex) {
        if expr_is_reduced(&node.index, &self.tainted, &self.reduced) {
            self.report(node.span().start().line);
        }
        visit::visit_expr_index(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let reduced_index_sink = matches!(
            method.as_str(),
            "get" | "get_mut" | "get_unchecked" | "get_unchecked_mut" | "swap_remove" | "remove"
        ) && node
            .args
            .first()
            .is_some_and(|arg| expr_is_reduced(arg, &self.tainted, &self.reduced));

        let named_selection_sink = is_selection_name(&method)
            && node
                .args
                .iter()
                .any(|arg| expr_is_tainted(arg, &self.tainted));

        if reduced_index_sink || named_selection_sink {
            self.report(node.span().start().line);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let selection_call = match &*node.func {
            syn::Expr::Path(path) => path
                .path
                .segments
                .last()
                .is_some_and(|segment| is_selection_name(&segment.ident.to_string())),
            _ => false,
        };

        if selection_call
            && node
                .args
                .iter()
                .any(|arg| expr_is_tainted(arg, &self.tainted))
        {
            self.report(node.span().start().line);
        }
        visit::visit_expr_call(self, node);
    }
}

fn expr_is_reduced(
    expr: &syn::Expr,
    tainted: &HashSet<String>,
    reduced: &HashSet<String>,
) -> bool {
    if let Some(name) = path_ident(expr) {
        if reduced.contains(&name) {
            return true;
        }
    }
    expr_is_tainted(expr, tainted) && contains_modulo(expr)
}

fn expr_is_tainted(expr: &syn::Expr, tainted: &HashSet<String>) -> bool {
    struct TaintProbe<'names> {
        tainted: &'names HashSet<String>,
        found: bool,
    }

    impl<'ast> Visit<'ast> for TaintProbe<'_> {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if is_ledger_metadata_call(node) {
                self.found = true;
                return;
            }
            visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if node.path.segments.len() == 1
                && node
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| self.tainted.contains(&segment.ident.to_string()))
            {
                self.found = true;
                return;
            }
            visit::visit_expr_path(self, node);
        }
    }

    let mut probe = TaintProbe {
        tainted,
        found: false,
    };
    probe.visit_expr(expr);
    probe.found
}

fn contains_modulo(expr: &syn::Expr) -> bool {
    struct ModuloProbe {
        found: bool,
    }

    impl<'ast> Visit<'ast> for ModuloProbe {
        fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
            if matches!(node.op, syn::BinOp::Rem(_)) {
                self.found = true;
                return;
            }
            visit::visit_expr_binary(self, node);
        }
    }

    let mut probe = ModuloProbe { found: false };
    probe.visit_expr(expr);
    probe.found
}

fn is_ledger_metadata_call(node: &syn::ExprMethodCall) -> bool {
    matches!(node.method.to_string().as_str(), "timestamp" | "sequence")
        && node.args.is_empty()
        && receiver_is_ledger(&node.receiver)
}

fn receiver_is_ledger(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(call) => call.method == "ledger" && call.args.is_empty(),
        syn::Expr::Paren(paren) => receiver_is_ledger(&paren.expr),
        syn::Expr::Group(group) => receiver_is_ledger(&group.expr),
        syn::Expr::Reference(reference) => receiver_is_ledger(&reference.expr),
        _ => false,
    }
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        syn::Pat::Type(typed) => pat_ident(&typed.pat),
        _ => None,
    }
}

fn path_ident(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) if path.path.segments.len() == 1 => {
            path.path.segments.last().map(|segment| segment.ident.to_string())
        }
        syn::Expr::Paren(paren) => path_ident(&paren.expr),
        syn::Expr::Group(group) => path_ident(&group.expr),
        syn::Expr::Reference(reference) => path_ident(&reference.expr),
        syn::Expr::Cast(cast) => path_ident(&cast.expr),
        _ => None,
    }
}

fn is_selection_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "winner", "select", "choose", "choice", "pick", "lottery", "random", "rand",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remainder_assignment_marks_tainted_index_as_reduced() {
        let source = r#"
fn choose(env: Env, players: Vec<u64>) -> u64 {
    let mut idx = env.ledger().timestamp();
    idx %= players.len() as u64;
    players[idx as usize]
}
"#;

        let findings = WeakRandomRule::new().check(source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, FINDING_CODE);
    }

    #[test]
    fn clean_reassignment_clears_previous_ledger_taint() {
        let source = r#"
fn choose(env: Env, players: Vec<u64>, reveal: u64) -> u64 {
    let mut idx = env.ledger().timestamp() % players.len() as u64;
    idx = reveal % players.len() as u64;
    players[idx as usize]
}
"#;

        assert!(WeakRandomRule::new().check(source).is_empty());
    }

    #[test]
    fn clean_shadowing_binding_clears_previous_ledger_taint() {
        let source = r#"
fn choose(env: Env, players: Vec<u64>, reveal: u64) -> u64 {
    let idx = env.ledger().sequence() % players.len() as u32;
    let idx = reveal % players.len() as u64;
    players[idx as usize]
}
"#;

        assert!(WeakRandomRule::new().check(source).is_empty());
    }
}
