use crate::finding_codes::MAP_ITERATION_ORDER;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::BTreeSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

/// Detects observable outcomes that depend on map iteration order.
///
/// Ordinary per-entry work and order-insensitive reductions are left alone.
/// Findings are limited to positional selection or to loops that make traversal
/// order observable through a returned value, outer overwrite, or ordered sink.
pub struct MapIterationOrderRule;

impl MapIterationOrderRule {
    pub fn new() -> Self {
        Self
    }

    fn check_function(
        &self,
        fn_name: &str,
        sig: &syn::Signature,
        block: &syn::Block,
    ) -> Vec<RuleViolation> {
        let mut maps = map_parameters(sig);
        let mut bindings = MapBindingCollector {
            maps: BTreeSet::new(),
        };
        bindings.visit_block(block);
        maps.extend(bindings.maps);

        if maps.is_empty() {
            return vec![];
        }

        let mut visitor = MapOrderVisitor {
            fn_name,
            maps: &maps,
            violations: Vec::new(),
        };
        visitor.visit_block(block);
        visitor.violations
    }
}

impl Default for MapIterationOrderRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MapIterationOrderRule {
    fn name(&self) -> &str {
        "map_iteration_order"
    }

    fn description(&self) -> &str {
        "Detects observable outcomes that depend on Map/HashMap iteration order"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return vec![],
        };

        let mut visitor = FunctionVisitor {
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

struct FunctionVisitor<'rule> {
    rule: &'rule MapIterationOrderRule,
    violations: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_> {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.violations.extend(self.rule.check_function(
            &node.sig.ident.to_string(),
            &node.sig,
            &node.block,
        ));
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.violations.extend(self.rule.check_function(
            &node.sig.ident.to_string(),
            &node.sig,
            &node.block,
        ));
        visit::visit_item_fn(self, node);
    }
}

struct MapOrderVisitor<'a> {
    fn_name: &'a str,
    maps: &'a BTreeSet<String>,
    violations: Vec<RuleViolation>,
}

impl MapOrderVisitor<'_> {
    fn push_finding(&mut self, map_name: &str, line: usize, reason: &str) {
        self.violations.push(
            RuleViolation::new(
                MAP_ITERATION_ORDER,
                Severity::Warning,
                format!(
                    "{MAP_ITERATION_ORDER}: map {map_name} iteration in {} {reason}; the result can change when map iteration order changes",
                    self.fn_name
                ),
                format!("{}:{line}", self.fn_name),
            )
            .with_suggestion(
                "Make ordering explicit before selecting or emitting entries, or use an order-insensitive reduction."
                    .to_string(),
            ),
        );
    }
}

impl<'ast> Visit<'ast> for MapOrderVisitor<'_> {
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        if let Some(map_name) = map_iteration_source(&node.expr, self.maps) {
            let loop_vars = pattern_idents(&node.pat);
            if let Some(reason) = order_sensitive_body_reason(&node.body, &loop_vars) {
                self.push_finding(&map_name, node.span().start().line, &reason);
            }
        }

        visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(
            method.as_str(),
            "next" | "nth" | "last" | "find" | "find_map" | "position"
        ) {
            if let Some(map_name) = map_iterator_expr(&node.receiver, self.maps) {
                self.push_finding(
                    &map_name,
                    node.method.span().start().line,
                    &format!("selects an entry with order-sensitive iterator method {method}()"),
                );
            }
        }

        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
}

fn map_parameters(sig: &syn::Signature) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for input in &sig.inputs {
        let syn::FnArg::Typed(pat_type) = input else {
            continue;
        };
        if is_unordered_map_type(&pat_type.ty) {
            out.extend(pattern_idents(&pat_type.pat));
        }
    }
    out
}

struct MapBindingCollector {
    maps: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for MapBindingCollector {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        match &node.pat {
            syn::Pat::Type(pat_type) if is_unordered_map_type(&pat_type.ty) => {
                self.maps.extend(pattern_idents(&pat_type.pat));
            }
            pat => {
                if node
                    .init
                    .as_ref()
                    .is_some_and(|init| is_map_constructor(&init.expr))
                {
                    self.maps.extend(pattern_idents(pat));
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
}

fn is_unordered_map_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| matches!(segment.ident.to_string().as_str(), "Map" | "HashMap")),
        syn::Type::Reference(reference) => is_unordered_map_type(&reference.elem),
        syn::Type::Paren(paren) => is_unordered_map_type(&paren.elem),
        _ => false,
    }
}

fn is_map_constructor(expr: &syn::Expr) -> bool {
    let syn::Expr::Call(call) = expr else {
        return false;
    };
    let syn::Expr::Path(path) = call.func.as_ref() else {
        return false;
    };
    path.path
        .segments
        .iter()
        .any(|segment| matches!(segment.ident.to_string().as_str(), "Map" | "HashMap"))
}

fn map_iteration_source(expr: &syn::Expr, maps: &BTreeSet<String>) -> Option<String> {
    if method_chain_contains_ordering(expr) {
        return None;
    }

    match expr {
        syn::Expr::Path(path) => {
            let name = path.path.get_ident()?.to_string();
            maps.contains(&name).then_some(name)
        }
        syn::Expr::Reference(reference) => map_iteration_source(&reference.expr, maps),
        syn::Expr::Paren(paren) => map_iteration_source(&paren.expr, maps),
        syn::Expr::MethodCall(call) => {
            let method = call.method.to_string();
            if matches!(
                method.as_str(),
                "iter"
                    | "into_iter"
                    | "keys"
                    | "values"
                    | "enumerate"
                    | "filter"
                    | "filter_map"
                    | "map"
                    | "take"
                    | "skip"
                    | "peekable"
                    | "fuse"
                    | "rev"
            ) {
                map_iteration_source(&call.receiver, maps)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn map_iterator_expr(expr: &syn::Expr, maps: &BTreeSet<String>) -> Option<String> {
    let syn::Expr::MethodCall(call) = expr else {
        return None;
    };
    if matches!(
        call.method.to_string().as_str(),
        "iter"
            | "into_iter"
            | "keys"
            | "values"
            | "enumerate"
            | "filter"
            | "filter_map"
            | "map"
            | "take"
            | "skip"
            | "peekable"
            | "fuse"
            | "rev"
    ) {
        map_iteration_source(expr, maps)
    } else {
        None
    }
}

fn method_chain_contains_ordering(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(call) => {
            let method = call.method.to_string();
            matches!(
                method.as_str(),
                "sorted" | "sorted_by" | "sorted_by_key" | "sort" | "sort_by" | "sort_by_key"
            ) || method_chain_contains_ordering(&call.receiver)
        }
        syn::Expr::Reference(reference) => method_chain_contains_ordering(&reference.expr),
        syn::Expr::Paren(paren) => method_chain_contains_ordering(&paren.expr),
        _ => false,
    }
}

fn order_sensitive_body_reason(
    block: &syn::Block,
    loop_vars: &BTreeSet<String>,
) -> Option<String> {
    let mut locals = LocalBindingCollector {
        names: BTreeSet::new(),
    };
    locals.visit_block(block);

    let mut visitor = OutcomeVisitor {
        loop_vars,
        inner_locals: &locals.names,
        reason: None,
    };
    visitor.visit_block(block);
    visitor.reason
}

struct LocalBindingCollector {
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for LocalBindingCollector {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        self.names.extend(pattern_idents(&node.pat));
        visit::visit_local(self, node);
    }

    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
}

struct OutcomeVisitor<'a> {
    loop_vars: &'a BTreeSet<String>,
    inner_locals: &'a BTreeSet<String>,
    reason: Option<String>,
}

impl OutcomeVisitor<'_> {
    fn set_reason(&mut self, reason: String) {
        if self.reason.is_none() {
            self.reason = Some(reason);
        }
    }
}

impl<'ast> Visit<'ast> for OutcomeVisitor<'_> {
    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if node
            .expr
            .as_ref()
            .is_some_and(|expr| expr_uses_any(expr, self.loop_vars))
        {
            self.set_reason("returns a value derived from the first matching map entry".to_string());
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        let outer_target = base_ident(&node.left)
            .is_some_and(|name| !self.inner_locals.contains(&name));
        if outer_target && expr_uses_any(&node.right, self.loop_vars) {
            self.set_reason(
                "overwrites outer state from map entries, making the final value depend on which entry is visited last"
                    .to_string(),
            );
        }
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(
            method.as_str(),
            "push" | "push_back" | "append" | "extend" | "publish"
        ) {
            let external_receiver = base_ident(&node.receiver)
                .is_some_and(|name| !self.inner_locals.contains(&name));
            let carries_loop_value = node
                .args
                .iter()
                .any(|arg| expr_uses_any(arg, self.loop_vars));
            if external_receiver && carries_loop_value {
                self.set_reason(format!(
                    "emits map entries through order-preserving {method}()"
                ));
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}
}

fn pattern_idents(pat: &syn::Pat) -> BTreeSet<String> {
    struct Collector {
        names: BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for Collector {
        fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
            self.names.insert(node.ident.to_string());
            visit::visit_pat_ident(self, node);
        }
    }

    let mut collector = Collector {
        names: BTreeSet::new(),
    };
    collector.visit_pat(pat);
    collector.names
}

fn expr_uses_any(expr: &syn::Expr, names: &BTreeSet<String>) -> bool {
    struct IdentUse<'a> {
        names: &'a BTreeSet<String>,
        found: bool,
    }
    impl<'ast> Visit<'ast> for IdentUse<'_> {
        fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
            if self.names.contains(&node.to_string()) {
                self.found = true;
            }
        }
        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
    }

    let mut visitor = IdentUse {
        names,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
}

fn base_ident(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => path.path.get_ident().map(|ident| ident.to_string()),
        syn::Expr::Reference(reference) => base_ident(&reference.expr),
        syn::Expr::Paren(paren) => base_ident(&paren.expr),
        syn::Expr::Field(field) => base_ident(&field.base),
        syn::Expr::Index(index) => base_ident(&index.expr),
        syn::Expr::MethodCall(call) => base_ident(&call.receiver),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_returning_first_matching_map_entry() {
        let source = r#"
            fn first_positive(scores: Map<Address, i128>) -> Option<Address> {
                for (addr, score) in scores.iter() {
                    if score > 0 {
                        return Some(addr);
                    }
                }
                None
            }
        "#;
        let findings = MapIterationOrderRule::new().check(source);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_name, MAP_ITERATION_ORDER);
    }

    #[test]
    fn flags_ordered_output_built_from_map_iteration() {
        let source = r#"
            fn keys(env: Env, scores: Map<Address, i128>) -> Vec<Address> {
                let mut out = Vec::new(&env);
                for (addr, _) in scores.iter() {
                    out.push_back(addr);
                }
                out
            }
        "#;
        let findings = MapIterationOrderRule::new().check(source);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].message.contains("push_back"));
    }

    #[test]
    fn flags_positional_iterator_selection() {
        let source = r#"
            fn first(scores: Map<Address, i128>) -> Option<(Address, i128)> {
                scores.iter().next()
            }
        "#;
        let findings = MapIterationOrderRule::new().check(source);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert!(findings[0].message.contains("next()"));
    }

    #[test]
    fn ignores_order_insensitive_reduction() {
        let source = r#"
            fn total(scores: Map<Address, i128>) -> i128 {
                let mut sum = 0i128;
                for (_, score) in scores.iter() {
                    sum += score;
                }
                sum
            }
        "#;
        let findings = MapIterationOrderRule::new().check(source);
        assert!(findings.is_empty(), "{findings:#?}");
    }
}
