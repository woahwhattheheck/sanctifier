use crate::finding_codes::UNBOUNDED_RECURSION;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, FnArg, Pat, Signature};

/// Detects direct self-recursion that has no explicit depth bound.
///
/// This rule is deliberately intraprocedural. It flags a function only when it
/// can see that function call itself, and treats recursion as bounded only when
/// a depth-like parameter is both checked by a comparison and changed
/// monotonically at the recursive call site.
pub struct UnboundedRecursionRule;

impl UnboundedRecursionRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UnboundedRecursionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnboundedRecursionRule {
    fn name(&self) -> &str {
        "unbounded_recursion"
    }

    fn description(&self) -> &str {
        "Detects direct self-recursion without an explicit monotonic depth bound"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return Vec::new(),
        };

        let mut visitor = FunctionVisitor {
            violations: Vec::new(),
            test_depth: 0,
        };
        visitor.visit_file(&file);
        visitor.violations
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct FunctionVisitor {
    violations: Vec<RuleViolation>,
    test_depth: usize,
}

impl FunctionVisitor {
    fn check_function(&mut self, sig: &Signature, block: &syn::Block) {
        if self.test_depth > 0 {
            return;
        }

        let fn_name = sig.ident.to_string();
        let depth_params = depth_parameter_names(sig);
        let mut facts = RecursionFacts {
            fn_name: &fn_name,
            depth_params: &depth_params,
            recursive_calls: 0,
            guarded_depth_params: HashSet::new(),
            stepped_depth_params: HashSet::new(),
        };
        facts.visit_block(block);

        if facts.recursive_calls == 0 {
            return;
        }

        let bounded = depth_params.iter().any(|param| {
            facts.guarded_depth_params.contains(param)
                && facts.stepped_depth_params.contains(param)
        });
        if bounded {
            return;
        }

        self.violations.push(
            RuleViolation::new(
                UNBOUNDED_RECURSION,
                Severity::High,
                format!(
                    "{UNBOUNDED_RECURSION}: `{fn_name}` directly recurses without an explicit depth bound carried through the recursive call"
                ),
                format!("{fn_name}:{}", sig.ident.span().start().line),
            )
            .with_suggestion(
                "Add a depth/remaining parameter, stop at an explicit bound, and change that parameter monotonically on every recursive call (for example depth + 1 toward MAX_DEPTH or remaining - 1 toward zero)."
                    .to_string(),
            ),
        );
    }
}

impl<'ast> Visit<'ast> for FunctionVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let was_test = has_cfg_test(&node.attrs);
        if was_test {
            self.test_depth += 1;
        }
        visit::visit_item_mod(self, node);
        if was_test {
            self.test_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.check_function(&node.sig, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.check_function(&node.sig, &node.block);
    }
}

struct RecursionFacts<'a> {
    fn_name: &'a str,
    depth_params: &'a HashSet<String>,
    recursive_calls: usize,
    guarded_depth_params: HashSet<String>,
    stepped_depth_params: HashSet<String>,
}

impl RecursionFacts<'_> {
    fn record_guard(&mut self, condition: &Expr) {
        let mut collector = GuardCollector {
            depth_params: self.depth_params,
            guarded: HashSet::new(),
        };
        collector.visit_expr(condition);
        self.guarded_depth_params.extend(collector.guarded);
    }

    fn record_recursive_args(
        &mut self,
        args: &syn::punctuated::Punctuated<Expr, syn::Token![,]>,
    ) {
        self.recursive_calls += 1;
        for param in self.depth_params {
            if args.iter().any(|arg| is_monotonic_step(arg, param)) {
                self.stepped_depth_params.insert(param.clone());
            }
        }
    }
}

impl<'ast> Visit<'ast> for RecursionFacts<'_> {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.record_guard(&node.cond);
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.record_guard(&node.cond);
        visit::visit_expr_while(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if is_direct_self_call(&node.func, self.fn_name) {
            self.record_recursive_args(&node.args);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == self.fn_name && expr_is_ident(&node.receiver, "self") {
            self.record_recursive_args(&node.args);
        }
        visit::visit_expr_method_call(self, node);
    }
}

struct GuardCollector<'a> {
    depth_params: &'a HashSet<String>,
    guarded: HashSet<String>,
}

impl<'ast> Visit<'ast> for GuardCollector<'_> {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if is_comparison(&node.op) {
            for param in self.depth_params {
                if expr_mentions_ident(&node.left, param)
                    || expr_mentions_ident(&node.right, param)
                {
                    self.guarded.insert(param.clone());
                }
            }
        }
        visit::visit_expr_binary(self, node);
    }
}

fn depth_parameter_names(sig: &Signature) -> HashSet<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(typed) => match typed.pat.as_ref() {
                Pat::Ident(ident) => {
                    let name = ident.ident.to_string();
                    let lower = name.to_ascii_lowercase();
                    (lower.contains("depth")
                        || lower == "remaining"
                        || lower.ends_with("_remaining")
                        || lower.ends_with("_left"))
                    .then_some(name)
                }
                _ => None,
            },
            FnArg::Receiver(_) => None,
        })
        .collect()
}

fn is_direct_self_call(expr: &Expr, fn_name: &str) -> bool {
    let Expr::Path(path) = peel(expr) else {
        return false;
    };
    let segments: Vec<_> = path.path.segments.iter().collect();
    match segments.as_slice() {
        [only] => only.ident == fn_name,
        [first, last] => first.ident == "Self" && last.ident == fn_name,
        _ => false,
    }
}

fn is_monotonic_step(expr: &Expr, param: &str) -> bool {
    match peel(expr) {
        Expr::Binary(binary) => match &binary.op {
            syn::BinOp::Add(_) => {
                (expr_is_ident(&binary.left, param) && is_positive_int(&binary.right))
                    || (is_positive_int(&binary.left) && expr_is_ident(&binary.right, param))
            }
            syn::BinOp::Sub(_) => {
                expr_is_ident(&binary.left, param) && is_positive_int(&binary.right)
            }
            _ => false,
        },
        Expr::MethodCall(call) => {
            let method = call.method.to_string();
            matches!(
                method.as_str(),
                "saturating_add" | "saturating_sub" | "checked_add" | "checked_sub"
            ) && expr_is_ident(&call.receiver, param)
                && call.args.first().is_some_and(is_positive_int)
        }
        _ => false,
    }
}

fn is_positive_int(expr: &Expr) -> bool {
    match peel(expr) {
        Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(value) => value.base10_parse::<u64>().is_ok_and(|value| value > 0),
            _ => false,
        },
        _ => false,
    }
}

fn expr_is_ident(expr: &Expr, name: &str) -> bool {
    match peel(expr) {
        Expr::Path(path) => path.path.is_ident(name),
        _ => false,
    }
}

fn expr_mentions_ident(expr: &Expr, name: &str) -> bool {
    struct IdentUse<'a> {
        name: &'a str,
        found: bool,
    }

    impl<'ast> Visit<'ast> for IdentUse<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if node.path.is_ident(self.name) {
                self.found = true;
                return;
            }
            visit::visit_expr_path(self, node);
        }
    }

    let mut visitor = IdentUse { name, found: false };
    visitor.visit_expr(expr);
    visitor.found
}

fn peel(expr: &Expr) -> &Expr {
    match expr {
        Expr::Paren(paren) => peel(&paren.expr),
        Expr::Group(group) => peel(&group.expr),
        _ => expr,
    }
}

fn is_comparison(op: &syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::Eq(_)
            | syn::BinOp::Ne(_)
            | syn::BinOp::Lt(_)
            | syn::BinOp::Le(_)
            | syn::BinOp::Gt(_)
            | syn::BinOp::Ge(_)
    )
}

fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        match &attr.meta {
            syn::Meta::List(list) => list
                .tokens
                .to_string()
                .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
                .any(|part| part == "test"),
            _ => false,
        }
    })
}
