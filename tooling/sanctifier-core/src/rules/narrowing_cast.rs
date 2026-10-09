use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashMap;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// Reports numeric casts with a known source type that can truncate bits or
/// change sign. Unknown expression types and pointer-sized integers are not
/// guessed at, keeping the results reproducible for Soroban/WASM32.
pub struct NarrowingCastRule;

impl NarrowingCastRule {
    pub fn new() -> Self {
        Self
    }
}
impl Default for NarrowingCastRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for NarrowingCastRule {
    fn name(&self) -> &str { "narrowing_cast" }
    fn description(&self) -> &str {
        "Detects lossy integer as-casts that may truncate value amounts or change sign"
    }
    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let Some(file) = crate::parse_cache::parse_cached(source) else { return vec![]; };
        let mut scanner = FunctionScanner { violations: vec![] };
        scanner.visit_file(&file);
        scanner.violations
    }
    fn as_any(&self) -> &dyn std::any::Any { self }
}

#[derive(Copy, Clone)]
struct IntType { name: &'static str, bits: u32, signed: bool }

fn primitive(name: &str) -> Option<IntType> {
    let (bits, signed, name) = match name {
        "u8" => (8, false, "u8"), "u16" => (16, false, "u16"),
        "u32" => (32, false, "u32"), "u64" => (64, false, "u64"),
        "u128" => (128, false, "u128"), "i8" => (8, true, "i8"),
        "i16" => (16, true, "i16"), "i32" => (32, true, "i32"),
        "i64" => (64, true, "i64"), "i128" => (128, true, "i128"),
        _ => return None,
    };
    Some(IntType { name, bits, signed })
}

fn integer_type(ty: &syn::Type) -> Option<IntType> {
    let syn::Type::Path(path) = ty else { return None; };
    if path.qself.is_some() || path.path.segments.len() != 1 { return None; }
    primitive(&path.path.segments[0].ident.to_string())
}

fn lossy(src: IntType, dst: IntType) -> bool {
    src.bits > dst.bits
        || (src.signed && !dst.signed)
        || (!src.signed && dst.signed && src.bits >= dst.bits)
}

fn safe_literal(expr: &syn::Expr, dst: IntType) -> bool {
    let (negative, magnitude) = match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(n) => match n.base10_parse::<u128>() {
                Ok(m) => (false, m), Err(_) => return false,
            },
            _ => return false,
        },
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Neg(_)) => {
            let syn::Expr::Lit(lit) = &*unary.expr else { return false; };
            let syn::Lit::Int(n) = &lit.lit else { return false; };
            match n.base10_parse::<u128>() {
                Ok(m) => (true, m), Err(_) => return false,
            }
        }
        _ => return false,
    };
    if negative { return dst.signed && magnitude <= (1u128 << (dst.bits - 1)); }
    if dst.signed { magnitude <= (1u128 << (dst.bits - 1)) - 1 }
    else if dst.bits == 128 { true }
    else { magnitude <= (1u128 << dst.bits) - 1 }
}

fn expr_type(expr: &syn::Expr, known: &HashMap<String, IntType>) -> Option<IntType> {
    match expr {
        syn::Expr::Paren(p) => expr_type(&p.expr, known),
        syn::Expr::Group(g) => expr_type(&g.expr, known),
        syn::Expr::Path(p) => known.get(&p.path.get_ident()?.to_string()).copied(),
        syn::Expr::Cast(c) => integer_type(&c.ty),
        syn::Expr::Lit(l) => match &l.lit {
            syn::Lit::Int(n) => primitive(n.suffix()), _ => None,
        },
        syn::Expr::Unary(u) if matches!(u.op, syn::UnOp::Neg(_)) => expr_type(&u.expr, known),
        _ => None,
    }
}

struct FunctionScanner { violations: Vec<RuleViolation> }

impl FunctionScanner {
    fn scan(&mut self, name: &str, sig: &syn::Signature, block: &syn::Block) {
        let mut known = HashMap::new();
        for arg in &sig.inputs {
            if let syn::FnArg::Typed(t) = arg {
                if let (syn::Pat::Ident(id), Some(kind)) = (&*t.pat, integer_type(&t.ty)) {
                    known.insert(id.ident.to_string(), kind);
                }
            }
        }
        let mut visitor = CastVisitor {
            function: name, known, violations: Vec::new(),
        };
        visitor.visit_block(block);
        self.violations.append(&mut visitor.violations);
    }
}

impl<'ast> Visit<'ast> for FunctionScanner {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.scan(&node.sig.ident.to_string(), &node.sig, &node.block);
        syn::visit::visit_item_fn(self, node);
    }
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.scan(&node.sig.ident.to_string(), &node.sig, &node.block);
        syn::visit::visit_impl_item_fn(self, node);
    }
}

struct CastVisitor<'a> {
    function: &'a str,
    known: HashMap<String, IntType>,
    violations: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for CastVisitor<'_> {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        let outer = self.known.clone();
        syn::visit::visit_block(self, block);
        self.known = outer;
    }
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init { self.visit_expr(&init.expr); }
        let (name, declared) = match &local.pat {
            syn::Pat::Type(t) => {
                let syn::Pat::Ident(id) = &*t.pat else { return; };
                (id.ident.to_string(), integer_type(&t.ty))
            }
            syn::Pat::Ident(id) => (id.ident.to_string(), None),
            _ => return,
        };
        let inferred = local.init.as_ref()
            .and_then(|i| expr_type(&i.expr, &self.known));
        if let Some(t) = declared.or(inferred) {
            self.known.insert(name, t);
        } else {
            self.known.remove(&name);
        }
    }
    fn visit_expr_cast(&mut self, cast: &'ast syn::ExprCast) {
        if let (Some(src), Some(dst)) =
            (expr_type(&cast.expr, &self.known), integer_type(&cast.ty))
        {
            if lossy(src, dst) && !safe_literal(&cast.expr, dst) {
                self.violations.push(
                    RuleViolation::new(
                        "SANCT_NARROWING_CAST", Severity::Warning,
                        format!(
                            "Integer cast from {} to {} using 'as' can wrap, truncate or change sign",
                            src.name, dst.name
                        ),
                        format!("{}:{}", self.function, cast.span().start().line),
                    ).with_suggestion(format!(
                        "Replace 'as' with checked TryInto::<{}>::try_into(value) and handle the conversion error",
                        dst.name
                    ))
                );
            }
        }
        syn::visit::visit_expr_cast(self, cast);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flags_signed_and_unsigned_amount_narrowing() {
        let source = "fn pay(amount: i128, value: u128) { let _a = amount as u64; let _b = value as u32; }";
        let found = NarrowingCastRule::new().check(source);
        assert_eq!(found.len(), 2);
        assert!(found[0].message.contains("i128 to u64"));
        assert!(found[1].message.contains("u128 to u32"));
    }
    #[test]
    fn flags_sign_flip_and_chained_casts() {
        let source = "fn pay(value: u64) { let _a = value as i64; let _b = (value as i128) as u32; }";
        let found = NarrowingCastRule::new().check(source);
        assert_eq!(found.len(), 2);
    }
    #[test]
    fn ignores_safe_widening_and_fitting_literals() {
        let source = "fn pay(value: u32) { let _a = value as u128; let _b = 12u128 as u64; let _c = -2i128 as i64; }";
        assert!(NarrowingCastRule::new().check(source).is_empty());
    }
    #[test]
    fn keeps_lexical_scopes_and_ignores_unknown_sources() {
        let source = "fn pay(value: u128) { { let value: u8 = 2; let _a = value as u64; } let _b = value as u64; let _c = unknown() as u64; }";
        let found = NarrowingCastRule::new().check(source);
        assert_eq!(found.len(), 1);
        assert!(found[0].message.contains("u128 to u64"));
    }
}
