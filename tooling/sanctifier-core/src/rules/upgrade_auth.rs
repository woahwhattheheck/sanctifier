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

        if guard.has_admin_auth && guard.has_nonce_guard {
            return Vec::new();
        }

        let missing = match (guard.has_admin_auth, guard.has_nonce_guard) {
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
    has_admin_auth: bool,
    has_nonce_guard: bool,
}

fn is_admin_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("admin")
        || lower.contains("owner")
        || lower.contains("authority")
        || lower.contains("govern")
}

fn is_nonce_marker(value: &str) -> bool {
    value.to_ascii_lowercase().contains("nonce")
}

#[derive(Default)]
struct MarkerVisitor {
    has_admin: bool,
    has_nonce: bool,
}

impl<'ast> Visit<'ast> for MarkerVisitor {
    fn visit_ident(&mut self, node: &'ast proc_macro2::Ident) {
        let value = node.to_string();
        self.has_admin |= is_admin_marker(&value);
        self.has_nonce |= is_nonce_marker(&value);
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        let value = node.value();
        self.has_admin |= is_admin_marker(&value);
        self.has_nonce |= is_nonce_marker(&value);
    }
}

fn expr_has_admin_marker(expr: &syn::Expr) -> bool {
    let mut marker = MarkerVisitor::default();
    marker.visit_expr(expr);
    marker.has_admin
}

fn expr_has_nonce_marker(expr: &syn::Expr) -> bool {
    let mut marker = MarkerVisitor::default();
    marker.visit_expr(expr);
    marker.has_nonce
}

fn is_admin_auth_helper(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_admin_marker(&lower)
        && (lower.contains("auth")
            || lower.contains("require")
            || lower.contains("verify")
            || lower.contains("check"))
}

fn is_nonce_guard_helper(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    is_nonce_marker(&lower)
        && (lower.contains("assert")
            || lower.contains("check")
            || lower.contains("consume")
            || lower.contains("increment")
            || lower.contains("advance")
            || lower.contains("validate")
            || lower.contains("verify"))
}

impl<'ast> Visit<'ast> for UpgradeGuardVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();

        if name == "update_current_contract_wasm" {
            self.has_upgrade_call = true;
        }

        if matches!(name.as_str(), "require_auth" | "require_auth_for_args")
            && expr_has_admin_marker(&node.receiver)
        {
            self.has_admin_auth = true;
        }

        if matches!(name.as_str(), "set" | "insert" | "put" | "replace")
            && (expr_has_nonce_marker(&node.receiver)
                || node.args.iter().any(expr_has_nonce_marker))
        {
            self.has_nonce_guard = true;
        }

        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if let Some(segment) = path.path.segments.last() {
                let name = segment.ident.to_string();

                if name == "update_current_contract_wasm" {
                    self.has_upgrade_call = true;
                }

                if matches!(name.as_str(), "require_auth" | "require_auth_for_args")
                    && node.args.iter().any(expr_has_admin_marker)
                {
                    self.has_admin_auth = true;
                }

                if is_admin_auth_helper(&name) {
                    self.has_admin_auth = true;
                }

                if is_nonce_guard_helper(&name) {
                    self.has_nonce_guard = true;
                }
            }
        }

        visit::visit_expr_call(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(
            &node.op,
            syn::BinOp::Eq(_)
                | syn::BinOp::Ne(_)
                | syn::BinOp::Lt(_)
                | syn::BinOp::Le(_)
                | syn::BinOp::Gt(_)
                | syn::BinOp::Ge(_)
        ) && (expr_has_nonce_marker(&node.left) || expr_has_nonce_marker(&node.right))
        {
            self.has_nonce_guard = true;
        }

        visit::visit_expr_binary(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(segment) = node.path.segments.last() {
            let name = segment.ident.to_string();
            if matches!(
                name.as_str(),
                "assert" | "assert_eq" | "assert_ne" | "debug_assert" | "debug_assert_eq" | "debug_assert_ne"
            ) && is_nonce_marker(&node.tokens.to_string())
            {
                self.has_nonce_guard = true;
            }

            if is_admin_auth_helper(&name) {
                self.has_admin_auth = true;
            }
            if is_nonce_guard_helper(&name) {
                self.has_nonce_guard = true;
            }
        }

        visit::visit_macro(self, node);
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
    fn bare_nonce_name_does_not_count_as_replay_protection() {
        let source = r#"
pub fn upgrade(env: Env, admin: Address, nonce: u64, wasm_hash: BytesN<32>) {
    admin.require_auth();
    let _unused_nonce = nonce;
    env.deployer().update_current_contract_wasm(wasm_hash);
}
"#;

        let findings = UpgradeAuthRule::new().check(source);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("nonce replay protection"));
    }

    #[test]
    fn unrelated_admin_name_does_not_bind_another_principals_auth() {
        let source = r#"
pub fn upgrade(
    env: Env,
    user: Address,
    admin_hint: Address,
    nonce: u64,
    wasm_hash: BytesN<32>,
) {
    user.require_auth();
    assert!(nonce > 0);
    let _ = admin_hint;
    env.deployer().update_current_contract_wasm(wasm_hash);
}
"#;

        let findings = UpgradeAuthRule::new().check(source);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("administrator authorization"));
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