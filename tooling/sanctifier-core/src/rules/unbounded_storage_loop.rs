use crate::finding_codes::UNBOUNDED_LOOP;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashSet;
use syn::visit::Visit;
use syn::{Attribute, BinOp, Expr};

/// Detects loops whose iteration count is derived from a Soroban storage-backed
/// Vec/Map and is not constrained by a fixed guard or inline pagination.
///
/// A collection that can grow in storage can eventually make an otherwise
/// valid entrypoint exceed Soroban's metered execution budget if the entrypoint
/// processes every element in one invocation.
pub struct UnboundedStorageLoopRule;

impl UnboundedStorageLoopRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UnboundedStorageLoopRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UnboundedStorageLoopRule {
    fn name(&self) -> &str {
        "unbounded_storage_loop"
    }

    fn description(&self) -> &str {
        "Detects loops over storage-sourced Vec/Map collections without a fixed cap or pagination"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return Vec::new(),
        };

        let mut visitor = ContractVisitor {
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

struct ContractVisitor {
    violations: Vec<RuleViolation>,
    test_depth: usize,
}

impl ContractVisitor {
    fn in_test_module(&self) -> bool {
        self.test_depth > 0
    }
}

impl<'ast> Visit<'ast> for ContractVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let was_test = has_cfg_test(&node.attrs);
        if was_test {
            self.test_depth += 1;
        }

        syn::visit::visit_item_mod(self, node);

        if was_test {
            self.test_depth -= 1;
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if self.in_test_module() || !has_attr(&node.attrs, "contractimpl") {
            syn::visit::visit_item_impl(self, node);
            return;
        }

        for item in &node.items {
            if let syn::ImplItem::Fn(function) = item {
                if !matches!(function.vis, syn::Visibility::Public(_)) {
                    continue;
                }

                self.violations.extend(check_function(
                    &function.sig.ident.to_string(),
                    &function.block,
                ));
            }
        }
    }
}

fn check_function(fn_name: &str, block: &syn::Block) -> Vec<RuleViolation> {
    let mut visitor = LoopVisitor {
        fn_name,
        storage_collections: HashSet::new(),
        capped_collections: HashSet::new(),
        violations: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.violations
}

struct LoopVisitor<'a> {
    fn_name: &'a str,
    storage_collections: HashSet<String>,
    capped_collections: HashSet<String>,
    violations: Vec<RuleViolation>,
}

impl LoopVisitor<'_> {
    fn emit(&mut self, collection: String, line: usize) {
        if self.capped_collections.contains(&collection) {
            return;
        }

        self.violations.push(
            RuleViolation::new(
                UNBOUNDED_LOOP,
                Severity::Error,
                format!(
                    "{UNBOUNDED_LOOP}: `{}` iterates storage-sourced collection `{}` without a fixed cap or pagination",
                    self.fn_name, collection
                ),
                format!("{}:{}", self.fn_name, line),
            )
            .with_suggestion(format!(
                "Reject oversized `{collection}` before the loop or paginate the iteration with a fixed page size (for example `.take(MAX_PAGE_SIZE)`)"
            )),
        );
    }
}

impl<'ast> Visit<'ast> for LoopVisitor<'_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (Some(name), Some(init)) = (pat_ident(&node.pat), &node.init) {
            let storage_read = local_collection_compatible(&node.pat)
                && expression_reads_storage(&init.expr);
            let storage_alias = alias_of_storage_collection(&init.expr, &self.storage_collections)
                .is_some();

            if storage_read || storage_alias {
                self.storage_collections.insert(name);
            }
        }

        syn::visit::visit_local(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if block_terminates(&node.then_branch) {
            if let Some(name) =
                oversize_guard_collection(&node.cond, &self.storage_collections)
            {
                self.capped_collections.insert(name);
            }
        }

        syn::visit::visit_expr_if(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if is_assert_macro(node) {
            let tokens = node.tokens.to_string();
            for name in &self.storage_collections {
                if tokens_mentions_len(&tokens, name) && tokens_has_fixed_bound(&tokens) {
                    self.capped_collections.insert(name.clone());
                }
            }
        }

        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        if let Some(source) = for_loop_source(&node.expr, &self.storage_collections) {
            if !source.inline_bounded {
                self.emit(source.collection, node.for_token.span.start().line);
            }
        }

        syn::visit::visit_expr_for_loop(self, node);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        if let Some(collection) =
            len_collection_in_expr(&node.cond, &self.storage_collections)
        {
            self.emit(collection, node.while_token.span.start().line);
        }

        syn::visit::visit_expr_while(self, node);
    }
}

struct LoopSource {
    collection: String,
    inline_bounded: bool,
}

fn for_loop_source(expr: &Expr, storage_collections: &HashSet<String>) -> Option<LoopSource> {
    if let Some(collection) = iter_base_ident(expr)
        .filter(|name| storage_collections.contains(name))
    {
        return Some(LoopSource {
            collection,
            inline_bounded: has_inline_bound(expr),
        });
    }

    if let Some(collection) = len_collection_in_expr(expr, storage_collections) {
        return Some(LoopSource {
            collection,
            inline_bounded: has_inline_bound(expr),
        });
    }

    if expression_reads_storage(expr) {
        return Some(LoopSource {
            collection: "<storage-read>".to_string(),
            inline_bounded: has_inline_bound(expr),
        });
    }

    None
}

fn iter_base_ident(expr: &Expr) -> Option<String> {
    match strip_expr(expr) {
        Expr::Path(path) if path.path.segments.len() == 1 => {
            path.path.segments.last().map(|seg| seg.ident.to_string())
        }
        Expr::MethodCall(call) => iter_base_ident(&call.receiver),
        _ => None,
    }
}

fn alias_of_storage_collection(
    expr: &Expr,
    storage_collections: &HashSet<String>,
) -> Option<String> {
    iter_base_ident(expr).filter(|name| storage_collections.contains(name))
}

fn expression_reads_storage(expr: &Expr) -> bool {
    let mut visitor = StorageReadVisitor { found: false };
    visitor.visit_expr(expr);
    visitor.found
}

struct StorageReadVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for StorageReadVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(node.method.to_string().as_str(), "get" | "try_get")
            && is_storage_chain(&node.receiver)
        {
            self.found = true;
            return;
        }

        syn::visit::visit_expr_method_call(self, node);
    }
}

fn is_storage_chain(expr: &Expr) -> bool {
    match strip_expr(expr) {
        Expr::MethodCall(call)
            if matches!(
                call.method.to_string().as_str(),
                "persistent" | "instance" | "temporary"
            ) =>
        {
            true
        }
        Expr::MethodCall(call) => is_storage_chain(&call.receiver),
        _ => false,
    }
}

fn len_collection_in_expr(
    expr: &Expr,
    storage_collections: &HashSet<String>,
) -> Option<String> {
    let mut visitor = LenCollectionVisitor {
        storage_collections,
        found: None,
    };
    visitor.visit_expr(expr);
    visitor.found
}

struct LenCollectionVisitor<'a> {
    storage_collections: &'a HashSet<String>,
    found: Option<String>,
}

impl<'ast> Visit<'ast> for LenCollectionVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.found.is_none() && node.method == "len" {
            if let Some(name) = simple_path_ident(&node.receiver) {
                if self.storage_collections.contains(&name) {
                    self.found = Some(name);
                    return;
                }
            }
        }

        syn::visit::visit_expr_method_call(self, node);
    }
}

fn oversize_guard_collection(
    expr: &Expr,
    storage_collections: &HashSet<String>,
) -> Option<String> {
    let Expr::Binary(binary) = strip_expr(expr) else {
        return None;
    };

    match &binary.op {
        BinOp::Gt(_) | BinOp::Ge(_) if fixed_bound(&binary.right) => {
            exact_len_collection(&binary.left, storage_collections)
        }
        BinOp::Lt(_) | BinOp::Le(_) if fixed_bound(&binary.left) => {
            exact_len_collection(&binary.right, storage_collections)
        }
        _ => None,
    }
}

fn exact_len_collection(
    expr: &Expr,
    storage_collections: &HashSet<String>,
) -> Option<String> {
    match strip_expr(expr) {
        Expr::MethodCall(call) if call.method == "len" => {
            simple_path_ident(&call.receiver)
                .filter(|name| storage_collections.contains(name))
        }
        _ => None,
    }
}

fn has_inline_bound(expr: &Expr) -> bool {
    let mut visitor = InlineBoundVisitor { found: false };
    visitor.visit_expr(expr);
    visitor.found
}

struct InlineBoundVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for InlineBoundVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(method.as_str(), "take" | "min")
            && node.args.iter().any(fixed_bound)
        {
            self.found = true;
            return;
        }

        syn::visit::visit_expr_method_call(self, node);
    }
}

fn fixed_bound(expr: &Expr) -> bool {
    match strip_expr(expr) {
        Expr::Lit(lit) => matches!(&lit.lit, syn::Lit::Int(_)),
        Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
            let ident = segment.ident.to_string();
            ident.chars().any(|ch| ch.is_ascii_uppercase())
                && ident
                    .chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        }),
        _ => false,
    }
}

fn block_terminates(block: &syn::Block) -> bool {
    let mut visitor = ExitVisitor { found: false };
    visitor.visit_block(block);
    visitor.found
}

struct ExitVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for ExitVisitor {
    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.found = true;
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "panic" | "panic_any" | "unreachable"
            )
        }) {
            self.found = true;
            return;
        }

        syn::visit::visit_macro(self, node);
    }
}

fn local_collection_compatible(pat: &syn::Pat) -> bool {
    match pat {
        syn::Pat::Type(pat_type) => is_vec_or_map_type(&pat_type.ty),
        _ => true,
    }
}

fn is_vec_or_map_type(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .is_some_and(|segment| matches!(segment.ident.to_string().as_str(), "Vec" | "Map")),
        syn::Type::Reference(reference) => is_vec_or_map_type(&reference.elem),
        _ => false,
    }
}

fn pat_ident(pat: &syn::Pat) -> Option<String> {
    match pat {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        syn::Pat::Type(pat_type) => pat_ident(&pat_type.pat),
        _ => None,
    }
}

fn simple_path_ident(expr: &Expr) -> Option<String> {
    match strip_expr(expr) {
        Expr::Path(path) if path.path.segments.len() == 1 => {
            path.path.segments.last().map(|segment| segment.ident.to_string())
        }
        _ => None,
    }
}

fn strip_expr(expr: &Expr) -> &Expr {
    match expr {
        Expr::Reference(reference) => strip_expr(&reference.expr),
        Expr::Paren(paren) => strip_expr(&paren.expr),
        Expr::Group(group) => strip_expr(&group.expr),
        _ => expr,
    }
}

fn is_assert_macro(node: &syn::Macro) -> bool {
    node.path.segments.last().is_some_and(|segment| {
        matches!(
            segment.ident.to_string().as_str(),
            "assert" | "assert_eq" | "debug_assert" | "debug_assert_eq"
        )
    })
}

fn tokens_mentions_len(tokens: &str, name: &str) -> bool {
    let compact: String = tokens.chars().filter(|ch| !ch.is_whitespace()).collect();
    compact.contains(&format!("{name}.len()"))
}

fn tokens_has_fixed_bound(tokens: &str) -> bool {
    tokens.chars().any(|ch| ch.is_ascii_digit())
        || tokens.split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_').any(|word| {
            !word.is_empty()
                && word.chars().any(|ch| ch.is_ascii_uppercase())
                && word
                    .chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        })
}

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name)
    })
}

fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }

        attr.meta
            .require_list()
            .map(|list| list.tokens.to_string().contains("test"))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unbounded_loop_over_storage_collection() {
        let source = r#"
            use soroban_sdk::{contractimpl, Address, Env, Vec};

            #[contractimpl]
            impl Contract {
                pub fn pay_all(env: Env) {
                    let holders: Vec<Address> =
                        env.storage().persistent().get(&DataKey::Holders).unwrap();

                    for holder in holders.iter() {
                        pay(&env, &holder);
                    }
                }
            }
        "#;

        let findings = UnboundedStorageLoopRule::new().check(source);

        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_name, UNBOUNDED_LOOP);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].location.contains("pay_all"));
    }

    #[test]
    fn accepts_storage_collection_with_fixed_cap() {
        let source = r#"
            use soroban_sdk::{contractimpl, Address, Env, Vec};

            const MAX_HOLDERS: u32 = 100;

            #[contractimpl]
            impl Contract {
                pub fn pay_all(env: Env) {
                    let holders: Vec<Address> =
                        env.storage().persistent().get(&DataKey::Holders).unwrap();

                    if holders.len() > MAX_HOLDERS {
                        return;
                    }

                    for holder in holders.iter() {
                        pay(&env, &holder);
                    }
                }
            }
        "#;

        let findings = UnboundedStorageLoopRule::new().check(source);
        assert!(findings.is_empty(), "{findings:#?}");
    }
}
