use crate::rules::{Rule, RuleViolation, Severity};
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
        let mut visitor = TtlVisitor { findings: Vec::new(), current_fn: None };
        visitor.visit_file(&file);
        visitor.findings
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

struct TtlVisitor {
    findings: Vec<RuleViolation>,
    current_fn: Option<String>,
}

impl<'ast> Visit<'ast> for TtlVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let previous = self.current_fn.replace(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.current_fn = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let previous = self.current_fn.replace(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.current_fn = previous;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == "extend_ttl" {
            if let Some((kind, threshold, extend_to)) = ttl_args(node) {
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

fn ttl_args(call: &syn::ExprMethodCall) -> Option<(&'static str, &syn::Expr, &syn::Expr)> {
    let kind = storage_kind(&call.receiver)?;
    let args: Vec<&syn::Expr> = call.args.iter().collect();
    match (kind, args.len()) {
        ("instance", 2) => Some((kind, args[0], args[1])),
        ("persistent" | "temporary", 3) => Some((kind, args[1], args[2])),
        _ => None,
    }
}

fn storage_kind(expr: &syn::Expr) -> Option<&'static str> {
    let syn::Expr::MethodCall(call) = unwrap(expr) else { return None };
    let kind = match call.method.to_string().as_str() {
        "persistent" => "persistent",
        "instance" => "instance",
        "temporary" => "temporary",
        _ => return None,
    };
    storage_root(&call.receiver).then_some(kind)
}

fn storage_root(expr: &syn::Expr) -> bool {
    match unwrap(expr) {
        syn::Expr::MethodCall(call) if call.method == "storage" => true,
        syn::Expr::MethodCall(call) => storage_root(&call.receiver),
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
