use crate::finding_codes::SIGNED_QUANTITY;
use crate::rules::{Rule, RuleViolation, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;

/// Advises when a clearly non-negative quantity is represented by a signed
/// primitive integer without an explicit non-negative guard.
pub struct SignedNonnegativeQuantityRule;

impl SignedNonnegativeQuantityRule {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SignedNonnegativeQuantityRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for SignedNonnegativeQuantityRule {
    fn name(&self) -> &str {
        "signed_nonnegative_quantity"
    }

    fn description(&self) -> &str {
        "Detects signed integer balance/amount fields and unguarded parameters where negative values are invalid"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return vec![],
        };

        let mut visitor = QuantityVisitor {
            violations: Vec::new(),
        };
        visitor.visit_file(&file);
        visitor.violations
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct QuantityVisitor {
    violations: Vec<RuleViolation>,
}

impl QuantityVisitor {
    fn record(&mut self, owner: &str, name: &str, ty: &syn::Type, line: usize, guarded: bool) {
        if guarded || !is_quantity_name(name) || !is_signed_integer(ty) {
            return;
        }

        let ty_text = quote::quote!(#ty).to_string();
        self.violations.push(
            RuleViolation::new(
                SIGNED_QUANTITY,
                Severity::Info,
                format!(
                    "{SIGNED_QUANTITY}: signed integer `{name}: {ty_text}` represents a non-negative balance/amount without an explicit non-negative guard"
                ),
                format!("{owner}:{line}"),
            )
            .with_suggestion(format!(
                "Prefer an unsigned integer when `{name}` cannot be negative, or reject `{name} < 0` before using the value"
            )),
        );
    }

    fn inspect_signature(&mut self, owner: &str, sig: &syn::Signature, block: &syn::Block) {
        for input in &sig.inputs {
            let syn::FnArg::Typed(pat_ty) = input else {
                continue;
            };
            let syn::Pat::Ident(ident) = &*pat_ty.pat else {
                continue;
            };

            let name = ident.ident.to_string();
            if !is_quantity_name(&name) || !is_signed_integer(&pat_ty.ty) {
                continue;
            }

            self.record(
                owner,
                &name,
                &pat_ty.ty,
                pat_ty.span().start().line,
                has_nonnegative_guard(block, &name),
            );
        }
    }
}

impl<'ast> Visit<'ast> for QuantityVisitor {
    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        let owner = node.ident.to_string();
        for field in &node.fields {
            if let Some(ident) = &field.ident {
                self.record(
                    &owner,
                    &ident.to_string(),
                    &field.ty,
                    field.span().start().line,
                    false,
                );
            }
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.inspect_signature(&node.sig.ident.to_string(), &node.sig, &node.block);
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.inspect_signature(&node.sig.ident.to_string(), &node.sig, &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }
}

fn is_quantity_name(name: &str) -> bool {
    let normalized = name.trim_start_matches("r#").to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split('_').filter(|part| !part.is_empty()).collect();

    if parts.iter().any(|part| {
        matches!(
            *part,
            "delta" | "diff" | "difference" | "change" | "offset" | "net"
        )
    }) {
        return false;
    }

    parts
        .iter()
        .any(|part| matches!(*part, "amount" | "amounts" | "balance" | "balances"))
}

fn is_signed_integer(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };

    matches!(
        segment.ident.to_string().as_str(),
        "i8" | "i16" | "i32" | "i64" | "i128" | "isize"
    )
}

fn has_nonnegative_guard(block: &syn::Block, target: &str) -> bool {
    let mut visitor = GuardVisitor {
        target,
        guarded: false,
    };
    visitor.visit_block(block);
    visitor.guarded
}

struct GuardVisitor<'a> {
    target: &'a str,
    guarded: bool,
}

impl<'ast> Visit<'ast> for GuardVisitor<'_> {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.guarded {
            return;
        }

        let name = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();

        if matches!(name.as_str(), "assert" | "debug_assert" | "require" | "ensure") {
            let compact = node.tokens.to_string().replace(' ', "");
            let ge_zero = format!("{}>=0", self.target);
            let zero_le = format!("0<={}", self.target);
            if compact.contains(&ge_zero) || compact.contains(&zero_le) {
                self.guarded = true;
                return;
            }
        }

        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if !self.guarded
            && condition_rejects_negative(&node.cond, self.target)
            && block_terminates(&node.then_branch)
        {
            self.guarded = true;
            return;
        }

        syn::visit::visit_expr_if(self, node);
    }
}

fn condition_rejects_negative(expr: &syn::Expr, target: &str) -> bool {
    let expr = unwrap_parens(expr);
    let syn::Expr::Binary(binary) = expr else {
        return false;
    };

    match (
        simple_ident(&binary.left),
        zero_literal(&binary.right),
        &binary.op,
    ) {
        (Some(name), true, syn::BinOp::Lt(_)) if name == target => return true,
        _ => {}
    }

    matches!(
        (
            zero_literal(&binary.left),
            simple_ident(&binary.right),
            &binary.op,
        ),
        (true, Some(name), syn::BinOp::Gt(_)) if name == target
    )
}

fn unwrap_parens(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Paren(paren) => unwrap_parens(&paren.expr),
        other => other,
    }
}

fn simple_ident(expr: &syn::Expr) -> Option<String> {
    match unwrap_parens(expr) {
        syn::Expr::Path(path) if path.path.segments.len() == 1 => {
            Some(path.path.segments[0].ident.to_string())
        }
        _ => None,
    }
}

fn zero_literal(expr: &syn::Expr) -> bool {
    matches!(
        unwrap_parens(expr),
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(value),
            ..
        }) if value.base10_parse::<i128>().ok() == Some(0)
    )
}

fn block_terminates(block: &syn::Block) -> bool {
    let mut visitor = RejectVisitor { rejects: false };
    visitor.visit_block(block);
    visitor.rejects
}

struct RejectVisitor {
    rejects: bool,
}

impl<'ast> Visit<'ast> for RejectVisitor {
    fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
        self.rejects = true;
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_default();
        if matches!(name.as_str(), "panic" | "panic_with_error" | "bail") {
            self.rejects = true;
            return;
        }
        syn::visit::visit_macro(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_signed_quantity_field_and_unguarded_parameter() {
        let source = r#"
            struct VaultState {
                balance: i128,
                balance_delta: i128,
            }

            fn withdraw(amount: i128, fee: i128) {
                consume(amount, fee);
            }
        "#;

        let findings = SignedNonnegativeQuantityRule::new().check(source);
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert!(findings.iter().any(|finding| finding.message.contains("balance")));
        assert!(findings.iter().any(|finding| finding.message.contains("amount")));
    }

    #[test]
    fn accepts_explicit_nonnegative_guards() {
        let source = r#"
            fn transfer(amount: i128) {
                assert!(amount >= 0);
                consume(amount);
            }

            fn mint(balance: i64) -> Result<(), Error> {
                if balance < 0 {
                    return Err(Error::Negative);
                }
                consume(balance);
                Ok(())
            }
        "#;

        assert!(SignedNonnegativeQuantityRule::new()
            .check(source)
            .is_empty());
    }

    #[test]
    fn ignores_unsigned_and_negative_semantic_names() {
        let source = r#"
            struct State {
                balance: u128,
                amount_delta: i128,
                net_balance: i64,
            }
        "#;

        assert!(SignedNonnegativeQuantityRule::new()
            .check(source)
            .is_empty());
    }
}
