use crate::finding_codes::HARDCODED_DECIMALS;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// Detects fixed token-decimal assumptions that can mis-scale assets whose
/// precision differs from the value hardcoded by the contract.
pub struct HardcodedDecimalsRule;

impl HardcodedDecimalsRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HardcodedDecimalsRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for HardcodedDecimalsRule {
    fn name(&self) -> &str {
        "hardcoded_decimals"
    }

    fn description(&self) -> &str {
        "Detects hardcoded token decimal counts and powers-of-ten used as fixed asset precision"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return vec![],
        };

        let mut visitor = HardcodedDecimalsVisitor {
            fn_name: String::new(),
            seen_lines: HashSet::new(),
            violations: Vec::new(),
        };
        visitor.visit_file(&file);
        visitor.violations
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct HardcodedDecimalsVisitor {
    fn_name: String,
    seen_lines: HashSet<usize>,
    violations: Vec<RuleViolation>,
}

impl HardcodedDecimalsVisitor {
    fn report_binding(&mut self, name: &str, value: u128, line: usize) {
        if !self.seen_lines.insert(line) {
            return;
        }

        let location = if self.fn_name.is_empty() {
            format!("<module>:{line}")
        } else {
            format!("{}:{line}", self.fn_name)
        };

        self.violations.push(
            RuleViolation::new(
                HARDCODED_DECIMALS,
                Severity::Warning,
                format!(
                    "Hardcoded precision `{name} = {value}` assumes a fixed asset decimal configuration"
                ),
                location,
            )
            .with_suggestion(
                "Read the asset's decimals at runtime and derive the scale from that value instead of assuming a fixed precision"
                    .to_string(),
            ),
        );
    }

    fn report_scale(&mut self, value: u128, line: usize) {
        if !self.seen_lines.insert(line) {
            return;
        }

        let location = if self.fn_name.is_empty() {
            format!("<module>:{line}")
        } else {
            format!("{}:{line}", self.fn_name)
        };

        self.violations.push(
            RuleViolation::new(
                HARDCODED_DECIMALS,
                Severity::Warning,
                format!(
                    "Token amount conversion uses hardcoded decimal scale `{value}`, assuming every asset has the same precision"
                ),
                location,
            )
            .with_suggestion(
                "Read the asset's decimals at runtime and derive the scale from that value instead of assuming a fixed precision"
                    .to_string(),
            ),
        );
    }
}

impl<'ast> Visit<'ast> for HardcodedDecimalsVisitor {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let previous = std::mem::replace(&mut self.fn_name, node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.fn_name = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let previous = std::mem::replace(&mut self.fn_name, node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.fn_name = previous;
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        let name = node.ident.to_string();
        if let Some(value) = hardcoded_precision_binding(&name, &node.expr) {
            self.report_binding(&name, value, node.ident.span().start().line);
        }
        syn::visit::visit_item_const(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        let name = match &node.pat {
            syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
            syn::Pat::Type(typed) => match typed.pat.as_ref() {
                syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
            _ => None,
        };

        if let (Some(name), Some(init)) = (name.as_deref(), node.init.as_ref()) {
            let line = node.pat.span().start().line;

            if let Some(value) = hardcoded_precision_binding(name, &init.expr) {
                self.report_binding(name, value, line);
            } else if !is_rate_context(name)
                && !is_rate_context(&self.fn_name)
                && is_conversion_context(name)
            {
                if let Some(value) = hardcoded_scale_arithmetic(&init.expr) {
                    self.report_scale(value, line);
                }
            }
        }

        syn::visit::visit_local(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if is_conversion_context(&self.fn_name) && !is_rate_context(&self.fn_name) {
            if let Some(value) = hardcoded_scale_binary(node) {
                self.report_scale(value, node.span().start().line);
            }
        }
        syn::visit::visit_expr_binary(self, node);
    }
}

fn hardcoded_precision_binding(name: &str, expr: &syn::Expr) -> Option<u128> {
    if is_rate_context(name) || !is_precision_binding_name(name) {
        return None;
    }

    let value = integer_literal(expr)?;
    let lower = name.to_ascii_lowercase();

    if lower.contains("decimal") || lower.contains("precision") {
        if value <= 38 || is_power_of_ten(value) {
            return Some(value);
        }
    }

    if is_scale_name(&lower) && is_power_of_ten(value) {
        return Some(value);
    }

    None
}

fn hardcoded_scale_arithmetic(expr: &syn::Expr) -> Option<u128> {
    match expr {
        syn::Expr::Binary(binary) => hardcoded_scale_binary(binary),
        syn::Expr::Paren(paren) => hardcoded_scale_arithmetic(&paren.expr),
        syn::Expr::Group(group) => hardcoded_scale_arithmetic(&group.expr),
        syn::Expr::Cast(cast) => hardcoded_scale_arithmetic(&cast.expr),
        _ => None,
    }
}

fn hardcoded_scale_binary(binary: &syn::ExprBinary) -> Option<u128> {
    if !matches!(binary.op, syn::BinOp::Mul(_) | syn::BinOp::Div(_)) {
        return None;
    }

    if contains_rate_identifier(binary) {
        return None;
    }

    if let Some(value) = power_of_ten_literal(&binary.right) {
        if contains_token_quantity_identifier(&binary.left) {
            return Some(value);
        }
    }

    if matches!(binary.op, syn::BinOp::Mul(_)) {
        if let Some(value) = power_of_ten_literal(&binary.left) {
            if contains_token_quantity_identifier(&binary.right) {
                return Some(value);
            }
        }
    }

    None
}

fn integer_literal(expr: &syn::Expr) -> Option<u128> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(value),
            ..
        }) => value.base10_parse::<u128>().ok(),
        syn::Expr::Paren(paren) => integer_literal(&paren.expr),
        syn::Expr::Group(group) => integer_literal(&group.expr),
        syn::Expr::Cast(cast) => integer_literal(&cast.expr),
        _ => None,
    }
}

fn power_of_ten_literal(expr: &syn::Expr) -> Option<u128> {
    let value = integer_literal(expr)?;
    is_power_of_ten(value).then_some(value)
}

fn is_power_of_ten(mut value: u128) -> bool {
    if value < 100 {
        return false;
    }

    while value % 10 == 0 {
        value /= 10;
    }

    value == 1
}

fn is_precision_binding_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("decimal") || lower.contains("precision") || is_scale_name(&lower)
}

fn is_scale_name(lower: &str) -> bool {
    lower == "scale"
        || lower.ends_with("_scale")
        || lower.starts_with("scale_")
        || lower.contains("unit_scale")
}

fn is_conversion_context(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "decimal",
        "precision",
        "scale",
        "normalize",
        "denormalize",
        "display",
        "human",
        "convert",
        "units",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword))
}

fn is_rate_context(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "bps",
        "basis",
        "rate",
        "fee",
        "interest",
        "percent",
        "commission",
        "royalty",
        "tax",
        "ratio",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword))
}

fn contains_token_quantity_identifier(expr: &syn::Expr) -> bool {
    contains_identifier_matching(expr, |name| {
        [
            "amount",
            "balance",
            "supply",
            "token",
            "asset",
            "price",
            "reserve",
            "liquidity",
            "share",
            "quantity",
        ]
        .iter()
        .any(|keyword| name.contains(keyword))
    })
}

fn contains_rate_identifier(expr: &syn::ExprBinary) -> bool {
    contains_identifier_matching(&syn::Expr::Binary(expr.clone()), is_rate_context)
}

fn contains_identifier_matching(
    expr: &syn::Expr,
    predicate: impl Fn(&str) -> bool,
) -> bool {
    struct Finder<F> {
        predicate: F,
        found: bool,
    }

    impl<'ast, F> Visit<'ast> for Finder<F>
    where
        F: Fn(&str) -> bool,
    {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if let Some(segment) = node.path.segments.last() {
                if (self.predicate)(&segment.ident.to_string().to_ascii_lowercase()) {
                    self.found = true;
                }
            }
            if !self.found {
                syn::visit::visit_expr_path(self, node);
            }
        }
    }

    let mut finder = Finder {
        predicate,
        found: false,
    };
    finder.visit_expr(expr);
    finder.found
}
