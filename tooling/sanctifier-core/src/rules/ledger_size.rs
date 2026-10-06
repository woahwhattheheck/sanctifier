use crate::rules::{Rule, RuleViolation, Severity};
use syn::{Fields, Item, Meta, Type};

const DEFAULT_LEDGER_LIMIT_BYTES: usize = 64_000;
const DEFAULT_APPROACHING_THRESHOLD: f64 = 0.80;
const SERIALIZATION_MARGIN_PERCENT: usize = 10;
const SCVAL_TAG_BYTES: usize = 4;
const XDR_WORD_BYTES: usize = 4;
const SCVAL_VARLEN_OVERHEAD_BYTES: usize = SCVAL_TAG_BYTES + XDR_WORD_BYTES;
const SCVAL_CONTAINER_OVERHEAD_BYTES: usize = SCVAL_TAG_BYTES + XDR_WORD_BYTES * 2;
const DYNAMIC_PROXY_PAYLOAD_BYTES: usize = 64;
const UNKNOWN_UDT_ESTIMATE_BYTES: usize = 40;

pub struct LedgerSizeRule {
    ledger_limit: usize,
    approaching_threshold: f64,
    strict_mode: bool,
}

impl LedgerSizeRule {
    pub fn new() -> Self {
        Self {
            ledger_limit: DEFAULT_LEDGER_LIMIT_BYTES,
            approaching_threshold: DEFAULT_APPROACHING_THRESHOLD,
            strict_mode: false,
        }
    }
}

impl Default for LedgerSizeRule {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerSizeRule {
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.ledger_limit = limit;
        self
    }

    pub fn with_approaching_threshold(mut self, threshold: f64) -> Self {
        self.approaching_threshold = threshold;
        self
    }

    pub fn with_strict_mode(mut self, strict: bool) -> Self {
        self.strict_mode = strict;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeWarningLevel {
    ExceedsLimit,
    ApproachingLimit,
}

impl Rule for LedgerSizeRule {
    fn name(&self) -> &str {
        "ledger_size"
    }

    fn description(&self) -> &str {
        "Analyzes contracttype structs and enums for ledger entry size limits"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(f) => (*f).clone(),
            None => return vec![],
        };

        let mut violations = Vec::new();
        let strict_threshold = (self.ledger_limit as f64 * 0.5) as usize;

        for item in &file.items {
            match item {
                Item::Struct(s) if has_contracttype(&s.attrs) => {
                    let size = self.estimate_struct_size(s);
                    if let Some(level) = self.classify_size(size, strict_threshold) {
                        let severity = match level {
                            SizeWarningLevel::ExceedsLimit => Severity::Error,
                            SizeWarningLevel::ApproachingLimit => Severity::Warning,
                        };
                        let budgeted = self.size_with_margin(size);
                        let remaining = self.ledger_limit.saturating_sub(budgeted);
                        violations.push(RuleViolation::new(
                            self.name(),
                            severity,
                            format!(
                                "Struct '{}' estimated XDR size {} bytes ({}% safety budget: {} bytes) exceeds or approaches limit",
                                s.ident, size, SERIALIZATION_MARGIN_PERCENT, budgeted
                            ),
                            format!(
                                "{}:estimated {} bytes, budgeted {} bytes, remaining {} bytes, limit {} bytes",
                                s.ident, size, budgeted, remaining, self.ledger_limit
                            ),
                        ));
                    }
                }
                Item::Enum(e) if has_contracttype(&e.attrs) => {
                    let size = self.estimate_enum_size(e);
                    if let Some(level) = self.classify_size(size, strict_threshold) {
                        let severity = match level {
                            SizeWarningLevel::ExceedsLimit => Severity::Error,
                            SizeWarningLevel::ApproachingLimit => Severity::Warning,
                        };
                        let budgeted = self.size_with_margin(size);
                        let remaining = self.ledger_limit.saturating_sub(budgeted);
                        violations.push(RuleViolation::new(
                            self.name(),
                            severity,
                            format!(
                                "Enum '{}' estimated XDR size {} bytes ({}% safety budget: {} bytes) exceeds or approaches limit",
                                e.ident, size, SERIALIZATION_MARGIN_PERCENT, budgeted
                            ),
                            format!(
                                "{}:estimated {} bytes, budgeted {} bytes, remaining {} bytes, limit {} bytes",
                                e.ident, size, budgeted, remaining, self.ledger_limit
                            ),
                        ));
                    }
                }
                _ => {}
            }
        }

        violations
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl LedgerSizeRule {
    fn classify_size(&self, size: usize, strict_threshold: usize) -> Option<SizeWarningLevel> {
        let budgeted = self.size_with_margin(size);
        if budgeted >= self.ledger_limit || (self.strict_mode && budgeted >= strict_threshold) {
            Some(SizeWarningLevel::ExceedsLimit)
        } else if budgeted as f64 >= self.ledger_limit as f64 * self.approaching_threshold {
            Some(SizeWarningLevel::ApproachingLimit)
        } else {
            None
        }
    }

    fn size_with_margin(&self, size: usize) -> usize {
        let margin = size
            .saturating_mul(SERIALIZATION_MARGIN_PERCENT)
            .saturating_add(99)
            / 100;
        size.saturating_add(margin)
    }

    fn estimate_struct_size(&self, s: &syn::ItemStruct) -> usize {
        let mut total = 0;
        match &s.fields {
            Fields::Named(fields) => {
                for f in &fields.named {
                    total += self.estimate_type_size(&f.ty);
                }
            }
            Fields::Unnamed(fields) => {
                for f in &fields.unnamed {
                    total += self.estimate_type_size(&f.ty);
                }
            }
            Fields::Unit => {}
        }
        total
    }

    fn estimate_enum_size(&self, e: &syn::ItemEnum) -> usize {
        // Contract enums are serialized as tagged ScVals; budget one XDR
        // discriminant plus the scalar tag rather than a bare Rust discriminant.
        const DISCRIMINANT_SIZE: usize = 8;
        let mut max_variant = 0usize;
        for v in &e.variants {
            let mut variant_size = 0;
            match &v.fields {
                syn::Fields::Named(fields) => {
                    for f in &fields.named {
                        variant_size += self.estimate_type_size(&f.ty);
                    }
                }
                syn::Fields::Unnamed(fields) => {
                    for f in &fields.unnamed {
                        variant_size += self.estimate_type_size(&f.ty);
                    }
                }
                syn::Fields::Unit => {}
            }
            max_variant = max_variant.max(variant_size);
        }
        DISCRIMINANT_SIZE + max_variant
    }

    // These are XDR-shaped payload estimates, not Rust in-memory sizes. Fixed
    // width values include the ScVal discriminant. Dynamic containers use one
    // representative element/payload and are intentionally documented as
    // lower-confidence growth floors.
    #[allow(clippy::only_used_in_recursion)]
    fn estimate_type_size(&self, ty: &Type) -> usize {
        match ty {
            Type::Path(tp) => {
                if let Some(seg) = tp.path.segments.last() {
                    match seg.ident.to_string().as_str() {
                        // Soroban XDR has no u8/u16 scalar variants; SDK values
                        // widen these to a 32-bit ScVal representation.
                        "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "bool" => 8,
                        "u64" | "i64" => 12,
                        "u128" | "i128" | "I128" | "U128" => 20,
                        "u256" | "i256" | "I256" | "U256" => 36,
                        // Account addresses are slightly larger than contract
                        // addresses in XDR; use the larger representation.
                        "Address" => 44,
                        "BytesN" => {
                            if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                                if let Some(n) = args.args.iter().find_map(|arg| {
                                    if let syn::GenericArgument::Const(syn::Expr::Lit(expr)) = arg {
                                        if let syn::Lit::Int(lit) = &expr.lit {
                                            return lit.base10_parse::<usize>().ok();
                                        }
                                    }
                                    None
                                }) {
                                    return SCVAL_VARLEN_OVERHEAD_BYTES
                                        .saturating_add(round_up_xdr_word(n));
                                }
                            }
                            SCVAL_VARLEN_OVERHEAD_BYTES + DYNAMIC_PROXY_PAYLOAD_BYTES
                        }
                        "Bytes" | "String" | "Symbol" => {
                            SCVAL_VARLEN_OVERHEAD_BYTES + DYNAMIC_PROXY_PAYLOAD_BYTES
                        }
                        "Vec" => {
                            if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                                if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                                    return SCVAL_CONTAINER_OVERHEAD_BYTES
                                        .saturating_add(self.estimate_type_size(inner));
                                }
                            }
                            SCVAL_CONTAINER_OVERHEAD_BYTES + DYNAMIC_PROXY_PAYLOAD_BYTES
                        }
                        "Map" => {
                            if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                                let one_entry: usize = args
                                    .args
                                    .iter()
                                    .filter_map(|arg| {
                                        if let syn::GenericArgument::Type(inner) = arg {
                                            Some(self.estimate_type_size(inner))
                                        } else {
                                            None
                                        }
                                    })
                                    .sum();
                                if one_entry > 0 {
                                    return SCVAL_CONTAINER_OVERHEAD_BYTES
                                        .saturating_add(one_entry);
                                }
                            }
                            SCVAL_CONTAINER_OVERHEAD_BYTES + DYNAMIC_PROXY_PAYLOAD_BYTES
                        }
                        "Option" => {
                            if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                                if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                                    return SCVAL_TAG_BYTES
                                        .saturating_add(self.estimate_type_size(inner));
                                }
                            }
                            SCVAL_TAG_BYTES + UNKNOWN_UDT_ESTIMATE_BYTES
                        }
                        _ => UNKNOWN_UDT_ESTIMATE_BYTES,
                    }
                } else {
                    UNKNOWN_UDT_ESTIMATE_BYTES
                }
            }
            Type::Array(arr) => {
                if let syn::Expr::Lit(expr_lit) = &arr.len {
                    if let syn::Lit::Int(lit) = &expr_lit.lit {
                        if let Ok(n) = lit.base10_parse::<usize>() {
                            return SCVAL_CONTAINER_OVERHEAD_BYTES.saturating_add(
                                n.saturating_mul(self.estimate_type_size(&arr.elem)),
                            );
                        }
                    }
                }
                SCVAL_CONTAINER_OVERHEAD_BYTES + DYNAMIC_PROXY_PAYLOAD_BYTES
            }
            Type::Tuple(tuple) => SCVAL_CONTAINER_OVERHEAD_BYTES.saturating_add(
                tuple
                    .elems
                    .iter()
                    .map(|elem| self.estimate_type_size(elem))
                    .sum::<usize>(),
            ),
            Type::Reference(reference) => self.estimate_type_size(&reference.elem),
            Type::Paren(paren) => self.estimate_type_size(&paren.elem),
            Type::Group(group) => self.estimate_type_size(&group.elem),
            _ => UNKNOWN_UDT_ESTIMATE_BYTES,
        }
    }

}

fn round_up_xdr_word(bytes: usize) -> usize {
    bytes.saturating_add(XDR_WORD_BYTES - 1) / XDR_WORD_BYTES * XDR_WORD_BYTES
}

fn has_contracttype(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if let Meta::Path(path) = &attr.meta {
            path.is_ident("contracttype") || path.segments.iter().any(|s| s.ident == "contracttype")
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_width_estimates_follow_xdr_shape() {
        let rule = LedgerSizeRule::new();
        let u8_ty: Type = syn::parse_quote!(u8);
        let u64_ty: Type = syn::parse_quote!(u64);
        let address_ty: Type = syn::parse_quote!(Address);
        let bytes_n_ty: Type = syn::parse_quote!(BytesN<32>);
        let array_ty: Type = syn::parse_quote!([u8; 4096]);

        assert_eq!(rule.estimate_type_size(&u8_ty), 8);
        assert_eq!(rule.estimate_type_size(&u64_ty), 12);
        assert_eq!(rule.estimate_type_size(&address_ty), 44);
        assert_eq!(rule.estimate_type_size(&bytes_n_ty), 40);
        assert_eq!(rule.estimate_type_size(&array_ty), 32_780);
    }

    #[test]
    fn serialization_margin_is_one_sided_and_rounded_up() {
        let rule = LedgerSizeRule::new();
        assert_eq!(rule.size_with_margin(51_256), 56_382);
        assert_eq!(rule.size_with_margin(64_056), 70_462);
    }

    #[test]
    fn reports_near_cap_warning_and_over_cap_error_with_per_struct_budget() {
        let source = r#"
            use soroban_sdk::{contracttype, Address};

            #[contracttype]
            pub struct NearCapState {
                pub admin: Address,
                pub blob: [u8; 6400],
            }

            #[contracttype]
            pub struct OversizedState {
                pub admin: Address,
                pub blob: [u8; 8000],
            }
        "#;

        let findings = LedgerSizeRule::new().check(source);
        assert_eq!(findings.len(), 2, "{findings:#?}");
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[1].severity, Severity::Error);
        assert!(findings[0].message.contains("10% safety budget"));
        assert!(findings[0].location.contains("remaining 7618 bytes"));
        assert!(findings[1].location.contains("remaining 0 bytes"));
    }
}
