use crate::finding_codes::MIGRATE_AUTH;
use crate::rules::{Rule, RuleViolation, Severity};
use syn::spanned::Spanned;
use syn::visit::Visit;

const FINDING_CODE: &str = MIGRATE_AUTH;

pub struct MigrateAuthRule;

impl MigrateAuthRule {
    pub fn new() -> Self { Self }

    fn check_function(
        &self,
        name: &str,
        visibility: &syn::Visibility,
        sig: &syn::Signature,
        block: &syn::Block,
    ) -> Vec<RuleViolation> {
        if name != "migrate" || !matches!(visibility, syn::Visibility::Public(_)) {
            return Vec::new();
        }

        let mut guard = AuthGuardVisitor { found: false };
        guard.visit_block(block);
        if guard.found { return Vec::new(); }

        vec![RuleViolation::new(
            FINDING_CODE,
            Severity::Error,
            format!("{FINDING_CODE}: public `migrate` entrypoint has no authorization guard"),
            format!("migrate:{}", sig.span().start().line),
        )
        .with_suggestion(
            "Authenticate the migration administrator with `require_auth()` or `require_auth_for_args()` before changing schema or contract state.".to_string(),
        )]
    }
}

impl Default for MigrateAuthRule {
    fn default() -> Self { Self::new() }
}

impl Rule for MigrateAuthRule {
    fn name(&self) -> &str { "migrate_auth" }

    fn description(&self) -> &str {
        "Detects public migrate entrypoints that do not contain an authorization guard."
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => (*file).clone(),
            None => return vec![],
        };
        let mut visitor = FunctionVisitor { rule: self, violations: Vec::new() };
        visitor.visit_file(&file);
        visitor.violations
    }

    fn as_any(&self) -> &dyn std::any::Any { self }
}

struct FunctionVisitor<'a> {
    rule: &'a MigrateAuthRule,
    violations: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.violations.extend(self.rule.check_function(
            &node.sig.ident.to_string(), &node.vis, &node.sig, &node.block,
        ));
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.violations.extend(self.rule.check_function(
            &node.sig.ident.to_string(), &node.vis, &node.sig, &node.block,
        ));
        syn::visit::visit_impl_item_fn(self, node);
    }
}

struct AuthGuardVisitor { found: bool }

impl AuthGuardVisitor {
    fn is_guard(name: &str) -> bool {
        matches!(name, "require_auth" | "require_auth_for_args")
    }
}

impl<'ast> Visit<'ast> for AuthGuardVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if Self::is_guard(&node.method.to_string()) { self.found = true; }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if path.path.segments.last().is_some_and(|segment| Self::is_guard(&segment.ident.to_string())) {
                self.found = true;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|segment| Self::is_guard(&segment.ident.to_string())) {
            self.found = true;
        }
        syn::visit::visit_macro(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_unauthenticated_public_migrate_and_snapshots_finding() {
        let source = r#"
pub struct Contract;
impl Contract {
    pub fn migrate(env: Env) {
        env.storage().instance().set(&1, &2);
    }
}
"#;
        let findings = MigrateAuthRule::new().check(source);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        let rendered = format!("{}|{:?}|{}", finding.rule_name, finding.severity, finding.message);
        insta::assert_snapshot!(
            rendered,
            @"SANCT_MIGRATE_AUTH|Error|SANCT_MIGRATE_AUTH: public `migrate` entrypoint has no authorization guard"
        );
    }

    #[test]
    fn accepts_method_path_and_macro_auth_guards() {
        let source = r#"
pub struct MethodGuard;
impl MethodGuard { pub fn migrate(admin: Address) { admin.require_auth(); } }

pub struct ArgsGuard;
impl ArgsGuard { pub fn migrate(admin: Address) { admin.require_auth_for_args((1,)); } }

pub struct PathGuard;
impl PathGuard { pub fn migrate(admin: Address) { Address::require_auth(&admin); } }

pub struct MacroGuard;
impl MacroGuard { pub fn migrate(admin: Address) { require_auth!(admin); } }
"#;
        assert!(MigrateAuthRule::new().check(source).is_empty());
    }

    #[test]
    fn ignores_private_migrate_and_other_public_functions() {
        let source = r#"
fn migrate() {}
pub fn migration() {}
pub struct Contract;
impl Contract { fn migrate() {} pub fn remigrate() {} }
"#;
        assert!(MigrateAuthRule::new().check(source).is_empty());
    }
}
