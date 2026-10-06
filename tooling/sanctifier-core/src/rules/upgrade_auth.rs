use crate::finding_codes::UPGRADE_RISK;
use crate::rules::{Rule, RuleViolation, Severity};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

const FINDING_CODE: &str = UPGRADE_RISK;

/// Detects public contract-upgrade paths that reach the Soroban WASM upgrade
/// primitive without both an administrator-shaped authorization guard and
/// nonce-shaped replay protection.
pub struct UpgradeAuthRule;

impl UpgradeAuthRule {
    pub fn new() -> Self {
        Self
    }

    fn check_function(
        &self,
        name: &str,
        visibility: &syn::Visibility,
        sig: &syn::Signature,
        block: &syn::Block,
    ) -> Vec<RuleViolation> {
        if !matches!(visibility, syn::Visibility::Public(_)) {
            return Vec::new();
        }

        let mut guard = UpgradeGuardVisitor::default();
        guard.visit_block(block);

        if !guard.has_upgrade_call {
            return Vec::new();
        }

        let has_admin_auth = guard.has_auth && guard.has_admin_marker;
        if has_admin_auth && guard.has_nonce {
            return Vec::new();
        }

        let missing = match (has_admin_auth, guard.has_nonce) {
            (false, false) => "administrator authorization and nonce replay protection",
            (false, true) => "administrator authorization",
            (true, false) => "nonce replay protection",
            (true, true) => unreachable!(),
        };

        vec![RuleViolation::new(
            FINDING_CODE,
            Severity::Error,
            format!(
                "{FINDING_CODE}: public upgrade path calls `update_current_contract_wasm` without {missing}"
            ),
            format!("{}:{}", name, sig.span().start().line),
        )
        .with_suggestion(
            "Authenticate the current administrator and validate/consume a nonce before calling the contract WASM upgrade primitive."
                .to_string(),
        )]
    }
}

impl Default for UpgradeAuthRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for UpgradeAuthRule {
    fn name(&self) -> &str {
        "upgrade_auth"
    }

    fn description(&self) -> &str {
        "Detects public contract-upgrade paths missing administrator authorization or nonce replay protection."
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

struct FunctionVisitor<'a> {
    rule: &'a UpgradeAuthRule,
    violations: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.violations.extend(self.rule.check_function(
            &node.sig.ident.to_string(),
            &node.vis,
            &node.sig,
            &node.block,
        ));
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.violations.extend(self.rule.check_function(
            &node.sig.ident.to_string(),
            &node.vis,
            &node.sig,
            &node.block,
        ));
        visit::visit_impl_item_fn(self, node);
    }
}

#[derive(Default)]
struct UpgradeGuardVisitor {
    has_upgrade_call: bool,
    has_auth: bool,
    has_admin_marker: bool,
    has_nonce: bool,
}

impl UpgradeGuardVisitor {
    fn inspect_name(&mut self, name: &str) {
        let lower = name.to_ascii_lowercase();
        if lower.contains("admin")
            || lower.contains("owner")
            || lower.contains("authority")
            || lower.contains("govern")
        {
            self.has_admin_marker = true;
        }
        if lower.contains("nonce") {
            self.has_nonce = true;
        }
    }

    fn inspect_call_name(&mut self, name: &str) {
        if name == "update_current_contract_wasm" {
            self.has_upgrade_call = true;
        }
        if matches!(name, "require_auth" | "require_auth_for_args") {
            self.has_auth = true;
        }
        self.inspect_name(name);
    }
}

impl<'ast> Visit<'ast> for UpgradeGuardVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.inspect_call_name(&node.method.to_string());
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if let Some(segment) = path.path.segments.last() {
                self.inspect_call_name(&segment.ident.to_string());
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(segment) = node.path.segments.last() {
            self.inspect_call_name(&segment.ident.to_string());
        }
        visit::visit_macro(self, node);
    }

    fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
        self.inspect_name(&node.to_string());
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        self.inspect_name(&node.value());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_unguarded_upgrade() {
        let source = r#"
pub struct Contract;
impl Contract {
    pub fn upgrade(env: Env, wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(wasm_hash);
    }
}
"#;

        let findings = UpgradeAuthRule::new().check(source);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        let rendered = format!(
            "{}|{:?}|{}",
            finding.rule_name, finding.severity, finding.message
        );
        insta::assert_snapshot!(
            rendered,
            @"S010|Error|S010: public upgrade path calls `update_current_contract_wasm` without administrator authorization and nonce replay protection"
        );
    }

    #[test]
    fn accepts_admin_auth_plus_nonce_guard() {
        let source = r#"
pub struct Contract;
impl Contract {
    pub fn upgrade(
        env: Env,
        admin: Address,
        expected_nonce: u64,
        wasm_hash: BytesN<32>,
    ) {
        admin.require_auth_for_args((expected_nonce, wasm_hash.clone()));
        let stored_nonce: u64 = env.storage().instance().get(&"upgrade_nonce").unwrap_or(0);
        assert_eq!(stored_nonce, expected_nonce);
        env.storage().instance().set(&"upgrade_nonce", &(stored_nonce + 1));
        env.deployer().update_current_contract_wasm(wasm_hash);
    }
}
"#;

        assert!(UpgradeAuthRule::new().check(source).is_empty());
    }

    #[test]
    fn flags_partial_guards() {
        let auth_only = r#"
pub fn upgrade(env: Env, admin: Address, wasm_hash: BytesN<32>) {
    admin.require_auth();
    env.deployer().update_current_contract_wasm(wasm_hash);
}
"#;
        let nonce_only = r#"
pub fn upgrade(env: Env, nonce: u64, wasm_hash: BytesN<32>) {
    assert!(nonce > 0);
    env.deployer().update_current_contract_wasm(wasm_hash);
}
"#;

        assert_eq!(UpgradeAuthRule::new().check(auth_only).len(), 1);
        assert_eq!(UpgradeAuthRule::new().check(nonce_only).len(), 1);
    }

    #[test]
    fn ignores_non_upgrade_and_private_helpers() {
        let source = r#"
pub fn configure(admin: Address) {
    admin.require_auth();
}
fn hidden_upgrade(env: Env, wasm_hash: BytesN<32>) {
    env.deployer().update_current_contract_wasm(wasm_hash);
}
"#;

        assert!(UpgradeAuthRule::new().check(source).is_empty());
    }
}
