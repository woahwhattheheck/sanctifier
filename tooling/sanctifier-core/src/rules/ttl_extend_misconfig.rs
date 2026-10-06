use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

const FINDING_CODE: &str = "SANCT_TTL_EXTEND_MISCONFIG";

pub struct TtlExtendMisconfigRule;

impl TtlExtendMisconfigRule {
    pub fn new() -> Self { Self }
}

impl Default for TtlExtendMisconfigRule {
    fn default() -> Self { Self::new() }
}

impl Rule for TtlExtendMisconfigRule {
    fn name(&self) -> &str { "ttl_extend_misconfig" }

    fn description(&self) -> &str {
        "Detects storage extend_ttl calls whose constant threshold is greater than or equal to extend_to"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return vec![],
        };
        let mut visitor = TtlVisitor {
            findings: Vec::new(),
            current_fn: None,
            env_bindings: HashSet::new(),
        };
        visitor.visit_file(&file);
        visitor.findings
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

struct TtlVisitor {
    findings: Vec<RuleViolation>,
    current_fn: Option<String>,
    env_bindings: HashSet<String>,
}

impl<'ast> Visit<'ast> for TtlVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let previous_fn = self.current_fn.replace(node.sig.ident.to_string());
        let previous_envs = std::mem::replace(&mut self.env_bindings, env_bindings(&node.sig));
        syn::visit::visit_item_fn(self, node);
        self.env_bindings = previous_envs;
        self.current_fn = previous_fn;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let previous_fn = self.current_fn.replace(node.sig.ident.to_string());
        let previous_envs = std::mem::replace(&mut self.env_bindings, env_bindings(&node.sig));
        syn::visit::visit_impl_item_fn(self, node);
        self.env_bindings = previous_envs;
        self.current_fn = previous_fn;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "extend_ttl" {
            if let Some((kind, threshold, extend_to)) = ttl_args(node, &self.env_bindings) {
                if let (Some(threshold), Some(extend_to)) =
                    (const_u128(threshold), const_u128(extend_to))
                {
                    if threshold >= extend_to {
                        let function = self.current_fn.clone().unwrap_or_else(|| "<unknown>".into());
                        self.findings.push(
                            RuleViolation::new(
                                FINDING_CODE,
                                Severity::Warning,
                                format!(
                                    "{}.extend_ttl uses threshold {threshold} >= extend_to {extend_to}; the renewal window is misconfigured",
                                    kind
                                ),
                                format!("{}:{}", function, node.span().start().line),
                            )
                            .with_suggestion(
                                "Use constants with threshold < extend_to so renewal moves the entry to a later ledger".into(),
                            ),
                        );
                    }
                }
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn ttl_args<'a>(
    call: &'a syn::ExprMethodCall,
    env_bindings: &HashSet<String>,
) -> Option<(&'static str, &'a syn::Expr, &'a syn::Expr)> {
    let kind = storage_kind(&call.receiver, env_bindings)?;
    let args: Vec<&syn::Expr> = call.args.iter().collect();
    match (kind, args.len()) {
        ("instance", 2) => Some((kind, args[0], args[1])),
        ("persistent" | "temporary", 3) => Some((kind, args[1], args[2])),
        _ => None,
    }
}

fn storage_kind(expr: &syn::Expr, env_bindings: &HashSet<String>) -> Option<&'static str> {
    let syn::Expr::MethodCall(call) = unwrap(expr) else { return None };
    let kind = match call.method.to_string().as_str() {
        "persistent" => "persistent",
        "instance" => "instance",
        "temporary" => "temporary",
        _ => return None,
    };
    storage_root(&call.receiver, env_bindings).then_some(kind)
}

fn storage_root(expr: &syn::Expr, env_bindings: &HashSet<String>) -> bool {
    match unwrap(expr) {
        syn::Expr::MethodCall(call) if call.method == "storage" && call.args.is_empty() => {
            is_env_binding(&call.receiver, env_bindings)
        }
        syn::Expr::MethodCall(call) => storage_root(&call.receiver, env_bindings),
        _ => false,
    }
}

fn is_env_binding(expr: &syn::Expr, env_bindings: &HashSet<String>) -> bool {
    match unwrap(expr) {
        syn::Expr::Path(path) if path.path.segments.len() == 1 => {
            env_bindings.contains(&path.path.segments[0].ident.to_string())
        }
        syn::Expr::Reference(reference) => is_env_binding(&reference.expr, env_bindings),
        _ => false,
    }
}

fn env_bindings(signature: &syn::Signature) -> HashSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|argument| {
            let syn::FnArg::Typed(argument) = argument else {
                return None;
            };
            if !type_is_env(&argument.ty) {
                return None;
            }
            let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
                return None;
            };
            Some(binding.ident.to_string())
        })
        .collect()
}

fn type_is_env(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Env"),
        syn::Type::Reference(reference) => type_is_env(&reference.elem),
        syn::Type::Paren(paren) => type_is_env(&paren.elem),
        syn::Type::Group(group) => type_is_env(&group.elem),
        _ => false,
    }
}

fn unwrap(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Paren(p) => unwrap(&p.expr),
        syn::Expr::Group(g) => unwrap(&g.expr),
        _ => expr,
    }
}

fn const_u128(expr: &syn::Expr) -> Option<u128> {
    match unwrap(expr) {
        syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(n), .. }) => {
            n.base10_parse::<u128>().ok()
        }
        syn::Expr::Cast(c) => const_u128(&c.expr),
        syn::Expr::Binary(b) => {
            let left = const_u128(&b.left)?;
            let right = const_u128(&b.right)?;
            match &b.op {
                syn::BinOp::Add(_) => left.checked_add(right),
                syn::BinOp::Sub(_) => left.checked_sub(right),
                syn::BinOp::Mul(_) => left.checked_mul(right),
                syn::BinOp::Div(_) if right != 0 => left.checked_div(right),
                syn::BinOp::Rem(_) if right != 0 => left.checked_rem(right),
                syn::BinOp::Shl(_) => u32::try_from(right).ok().and_then(|n| left.checked_shl(n)),
                syn::BinOp::Shr(_) => u32::try_from(right).ok().and_then(|n| left.checked_shr(n)),
                syn::BinOp::BitAnd(_) => Some(left & right),
                syn::BinOp::BitOr(_) => Some(left | right),
                syn::BinOp::BitXor(_) => Some(left ^ right),
                _ => None,
            }
        }
        _ => None,
    }
}


#[cfg(test)]
mod receiver_tests {
    use super::*;

    #[test]
    fn accepts_renamed_env_binding() {
        let source = r#"
            fn renew(ctx: Env) {
                ctx.storage().instance().extend_ttl(200, 100);
            }
        "#;
        assert_eq!(TtlExtendMisconfigRule::new().check(source).len(), 1);
    }

    #[test]
    fn ignores_unrelated_storage_api() {
        let source = r#"
            fn renew(cache: Cache) {
                cache.storage().persistent().extend_ttl(&KEY, 200, 100);
            }
        "#;
        assert!(TtlExtendMisconfigRule::new().check(source).is_empty());
    }
}
