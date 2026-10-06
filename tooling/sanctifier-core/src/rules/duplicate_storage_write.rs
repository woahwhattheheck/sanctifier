use crate::finding_codes::DUPLICATE_STORAGE_WRITE;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::Attribute;

/// Detects redundant Soroban storage writes in one straight-line sequence.
///
/// The rule is intentionally conservative. It reports only when two storage
/// `set` calls target the same storage kind/key with the same stable value
/// expression and no non-`set` statement occurs between them. Writing a new
/// value, mutating a local first, or crossing a control-flow boundary is treated
/// as an intentional update and is not reported.
pub struct DuplicateStorageWriteRule;

impl DuplicateStorageWriteRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DuplicateStorageWriteRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DuplicateStorageWriteRule {
    fn name(&self) -> &str {
        "duplicate_storage_write"
    }

    fn description(&self) -> &str {
        "Detects redundant repeated writes of the same value to the same Soroban storage key"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return Vec::new(),
        };

        let mut visitor = DuplicateWriteVisitor {
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

struct DuplicateWriteVisitor {
    violations: Vec<RuleViolation>,
    test_depth: usize,
}

impl DuplicateWriteVisitor {
    fn in_test_module(&self) -> bool {
        self.test_depth > 0
    }

    fn analyze_function(&mut self, fn_name: &str, block: &syn::Block) {
        let mut blocks = BlockVisitor {
            function_name: fn_name,
            violations: &mut self.violations,
        };
        blocks.visit_block(block);
    }
}

impl<'ast> Visit<'ast> for DuplicateWriteVisitor {
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

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if !self.in_test_module() {
            self.analyze_function(&node.sig.ident.to_string(), &node.block);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if !self.in_test_module() {
            self.analyze_function(&node.sig.ident.to_string(), &node.block);
        }
    }
}

struct BlockVisitor<'a> {
    function_name: &'a str,
    violations: &'a mut Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for BlockVisitor<'_> {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        analyze_direct_statements(self.function_name, node, self.violations);
        visit::visit_block(self, node);
    }
}

struct StorageWrite {
    kind: &'static str,
    key: String,
    display_key: String,
    value: String,
    line: usize,
}

fn analyze_direct_statements(
    fn_name: &str,
    block: &syn::Block,
    violations: &mut Vec<RuleViolation>,
) {
    let mut last_by_target: HashMap<(String, String), StorageWrite> = HashMap::new();

    for statement in &block.stmts {
        let Some(write) = direct_storage_set(statement) else {
            last_by_target.clear();
            continue;
        };

        let target = (write.kind.to_string(), write.key.clone());
        if let Some(previous) = last_by_target.get(&target) {
            if previous.value == write.value {
                violations.push(
                    RuleViolation::new(
                        DUPLICATE_STORAGE_WRITE,
                        Severity::Warning,
                        format!(
                            "{DUPLICATE_STORAGE_WRITE}: `{fn_name}` writes the same value to storage key `{}` more than once without an intervening state/value change",
                            write.display_key
                        ),
                        format!("{fn_name}:{}", write.line),
                    )
                    .with_suggestion(
                        "Keep one write when the key/value pair is unchanged. If the second write is an intentional update, compute or mutate the new value before writing it.".to_string(),
                    ),
                );
            }
        }

        last_by_target.insert(target, write);
    }
}

fn direct_storage_set(statement: &syn::Stmt) -> Option<StorageWrite> {
    let syn::Stmt::Expr(syn::Expr::MethodCall(call), _) = statement else {
        return None;
    };
    if call.method != "set" || call.args.len() != 2 {
        return None;
    }

    let kind = storage_kind(&call.receiver)?;
    let mut args = call.args.iter();
    let key_expr = args.next()?;
    let value_expr = args.next()?;

    if !is_stable_expr(key_expr) || !is_stable_expr(value_expr) {
        return None;
    }

    Some(StorageWrite {
        kind,
        key: canonical_expr(key_expr),
        display_key: display_expr(key_expr),
        value: canonical_expr(value_expr),
        line: call.method.span().start().line,
    })
}

fn storage_kind(expr: &syn::Expr) -> Option<&'static str> {
    match expr {
        syn::Expr::MethodCall(call) if call.method == "persistent" => Some("persistent"),
        syn::Expr::MethodCall(call) if call.method == "temporary" => Some("temporary"),
        syn::Expr::MethodCall(call) if call.method == "instance" => Some("instance"),
        syn::Expr::MethodCall(call) => storage_kind(&call.receiver),
        _ => None,
    }
}

fn is_stable_expr(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Reference(reference) => is_stable_expr(&reference.expr),
        syn::Expr::Path(_) | syn::Expr::Lit(_) => true,
        syn::Expr::Paren(paren) => is_stable_expr(&paren.expr),
        syn::Expr::Group(group) => is_stable_expr(&group.expr),
        syn::Expr::Field(field) => is_stable_expr(&field.base),
        syn::Expr::Index(index) => is_stable_expr(&index.expr) && is_stable_expr(&index.index),
        syn::Expr::Unary(unary) => is_stable_expr(&unary.expr),
        syn::Expr::Binary(binary) => {
            is_stable_expr(&binary.left) && is_stable_expr(&binary.right)
        }
        syn::Expr::Cast(cast) => is_stable_expr(&cast.expr),
        syn::Expr::Tuple(tuple) => tuple.elems.iter().all(is_stable_expr),
        syn::Expr::Array(array) => array.elems.iter().all(is_stable_expr),
        syn::Expr::Struct(struct_expr) => {
            struct_expr.fields.iter().all(|field| is_stable_expr(&field.expr))
                && struct_expr.rest.as_deref().map_or(true, is_stable_expr)
        }
        _ => false,
    }
}

fn canonical_expr(expr: &syn::Expr) -> String {
    quote::quote!(#expr)
        .to_string()
        .split_whitespace()
        .collect::<String>()
}

fn display_expr(expr: &syn::Expr) -> String {
    let rendered = quote::quote!(#expr).to_string();
    rendered
        .strip_prefix("& ")
        .unwrap_or(rendered.as_str())
        .to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_redundant_write_to_same_key_and_value() {
        let source = r#"
            impl Contract {
                pub fn save(env: Env, key: Symbol, value: i128) {
                    env.storage().persistent().set(&key, &value);
                    env.storage().persistent().set(&key, &value);
                }
            }
        "#;

        let findings = DuplicateStorageWriteRule::new().check(source);
        assert_eq!(findings.len(), 1, "{findings:#?}");
        assert_eq!(findings[0].rule_name, DUPLICATE_STORAGE_WRITE);
    }

    #[test]
    fn ignores_intentional_update_to_new_value() {
        let source = r#"
            impl Contract {
                pub fn save(env: Env, key: Symbol, first: i128, second: i128) {
                    env.storage().persistent().set(&key, &first);
                    env.storage().persistent().set(&key, &second);
                }
            }
        "#;

        assert!(DuplicateStorageWriteRule::new().check(source).is_empty());
    }

    #[test]
    fn ignores_write_after_value_mutation() {
        let source = r#"
            impl Contract {
                pub fn save(env: Env, key: Symbol, mut value: i128) {
                    env.storage().persistent().set(&key, &value);
                    value += 1;
                    env.storage().persistent().set(&key, &value);
                }
            }
        "#;

        assert!(DuplicateStorageWriteRule::new().check(source).is_empty());
    }
}
