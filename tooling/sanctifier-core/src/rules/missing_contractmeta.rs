use crate::finding_codes::MISSING_CONTRACTMETA;
use crate::rules::{Rule, RuleViolation, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;

/// Advisory detector for Soroban contract roots that omit discoverability metadata.
pub struct MissingContractmetaRule;

impl MissingContractmetaRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MissingContractmetaRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingContractmetaRule {
    fn name(&self) -> &str {
        "missing_contractmeta"
    }

    fn description(&self) -> &str {
        "Detects Soroban contract declarations without contractmeta! discoverability metadata"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return vec![],
        };

        let mut visitor = ContractMetadataVisitor::default();
        visitor.visit_file(&file);

        if visitor.has_contractmeta {
            return vec![];
        }

        let Some(marker) = visitor.contract_marker else {
            return vec![];
        };

        vec![
            RuleViolation::new(
                MISSING_CONTRACTMETA,
                Severity::Info,
                format!(
                    "Soroban contract '{}' does not declare contractmeta! discoverability metadata",
                    marker.name
                ),
                format!("{}:{}", marker.name, marker.line),
            )
            .with_suggestion(
                "Add a contractmeta! entry with concise public metadata (for example a Description) so explorers and tooling can identify the contract."
                    .to_string(),
            ),
        ]
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Default)]
struct ContractMetadataVisitor {
    contract_marker: Option<ContractMarker>,
    has_contractmeta: bool,
    test_depth: usize,
}

#[derive(Debug)]
struct ContractMarker {
    name: String,
    line: usize,
}

impl<'ast> Visit<'ast> for ContractMetadataVisitor {
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

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        if self.test_depth == 0
            && self.contract_marker.is_none()
            && has_attribute(&node.attrs, "contract")
        {
            self.contract_marker = Some(ContractMarker {
                name: node.ident.to_string(),
                line: node.ident.span().start().line,
            });
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if self.test_depth == 0
            && self.contract_marker.is_none()
            && has_attribute(&node.attrs, "contract")
        {
            self.contract_marker = Some(ContractMarker {
                name: node.ident.to_string(),
                line: node.ident.span().start().line,
            });
        }
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if self.test_depth == 0
            && node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "contractmeta")
        {
            self.has_contractmeta = true;
        }
        syn::visit::visit_macro(self, node);
    }
}

fn has_attribute(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attribute| {
        attribute
            .path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == name)
    })
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
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
    fn flags_contract_root_without_contractmeta() {
        let source = r#"
            #[contract]
            pub struct Token;
        "#;

        let findings = MissingContractmetaRule::new().check(source);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, MISSING_CONTRACTMETA);
        assert_eq!(findings[0].severity, Severity::Info);
    }

    #[test]
    fn accepts_contract_root_with_contractmeta() {
        let source = r#"
            #[contract]
            pub struct Token;

            contractmeta!(key = "Description", val = "Example token");
        "#;

        assert!(MissingContractmetaRule::new().check(source).is_empty());
    }

    #[test]
    fn test_only_contractmeta_does_not_satisfy_contract_root() {
        let source = r#"
            #[contract]
            pub struct Token;

            #[cfg(test)]
            mod tests {
                contractmeta!(key = "Description", val = "test-only metadata");
            }
        "#;

        let findings = MissingContractmetaRule::new().check(source);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_name, MISSING_CONTRACTMETA);
    }

    #[test]
    fn ignores_non_contract_rust_source() {
        let source = r#"
            pub struct Helper;
            impl Helper {
                pub fn value() -> u32 { 1 }
            }
        "#;

        assert!(MissingContractmetaRule::new().check(source).is_empty());
    }
}
