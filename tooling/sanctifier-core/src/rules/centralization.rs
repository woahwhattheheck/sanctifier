//! Inventory publicly reachable, privileged Soroban contract powers.
//!
//! This is a centralization inventory, not a claim that an authorized action is
//! exploitable. Only entrypoints with an explicit privileged signer or a
//! recognizable role-assertion are reported. Ordinary user authorization does
//! not by itself establish admin control.

use crate::finding_codes::CENTRALIZATION_RISK;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::BTreeSet;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

pub struct CentralizationRule;

impl CentralizationRule {
    pub fn new() -> Self {
        Self
    }

    fn check_entrypoint(
        &self,
        visibility: &syn::Visibility,
        name: &syn::Ident,
        block: &syn::Block,
    ) -> Vec<RuleViolation> {
        if !matches!(visibility, syn::Visibility::Public(_)) {
            return Vec::new();
        }

        let mut evidence = AdminEvidence::default();
        evidence.visit_block(block);

        // Calling a privileged method without an authorization guard belongs
        // to the auth-gap detector, not to an inventory of *admin-gated* powers.
        let explicit_admin = evidence.signers.iter().any(|s| is_admin_identity(s));
        let owner_signed = evidence.signers.iter().any(|s| is_owner_identity(s));
        let role_gated = !evidence.roles.is_empty();
        if !explicit_admin && !owner_signed && !role_gated {
            return Vec::new();
        }

        let mut powers = evidence.powers;
        if let Some(power) = classify_power(&name.to_string()) {
            powers.insert(power);
        }

        // "owner.require_auth()" on ordinary transfers, allowances, and other
        // user-level calls is not evidence of contract centralization.
        if !explicit_admin && !role_gated && powers.is_empty() {
            return Vec::new();
        }

        let high_impact = powers.iter().any(|p| {
            matches!(*p, "contract upgrade" | "token mint" | "treasury drain")
        });
        let severity = if high_impact {
            Severity::Error
        } else if powers.is_empty() {
            Severity::Info
        } else {
            Severity::Warning
        };
        let controls = evidence
            .signers
            .into_iter()
            .chain(evidence.roles)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        let capabilities = if powers.is_empty() {
            "other privileged entrypoint".to_string()
        } else {
            powers.into_iter().collect::<Vec<_>>().join(", ")
        };
        let function_name = name.to_string();

        vec![
            RuleViolation::new(
                CENTRALIZATION_RISK,
                severity,
                format!(
                    "Admin-gated `{function_name}` can perform: {capabilities}; controlling authority: {controls}"
                ),
                format!("{function_name}:{}", name.span().start().line),
            )
            .with_suggestion(if high_impact {
                "Disclose privileged ownership, consider multisig/timelock controls, and bound or remove unilateral mint, upgrade, or fund-extraction powers.".to_string()
            } else {
                "Document this role and its scope; consider multisig, governance, or time-delayed changes where appropriate.".to_string()
            }),
        ]
    }
}

impl Default for CentralizationRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for CentralizationRule {
    fn name(&self) -> &str {
        "centralization"
    }

    fn description(&self) -> &str {
        "Enumerates public admin- or role-gated entrypoints, highlights upgrade, mint, and drain powers"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(file) => file,
            None => return Vec::new(),
        };
        let mut collector = EntryPointVisitor {
            rule: self,
            findings: Vec::new(),
        };
        collector.visit_file(&file);
        collector.findings.sort_by(|a, b| {
            (&a.location, &a.message).cmp(&(&b.location, &b.message))
        });
        collector.findings
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct EntryPointVisitor<'r> {
    rule: &'r CentralizationRule,
    findings: Vec<RuleViolation>,
}

impl<'ast> Visit<'ast> for EntryPointVisitor<'_> {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.findings.extend(
            self.rule
                .check_entrypoint(&node.vis, &node.sig.ident, &node.block),
        );
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.findings.extend(
            self.rule
                .check_entrypoint(&node.vis, &node.sig.ident, &node.block),
        );
        visit::visit_item_fn(self, node);
    }
}

#[derive(Default)]
struct AdminEvidence {
    signers: BTreeSet<String>,
    roles: BTreeSet<String>,
    powers: BTreeSet<&'static str>,
}

impl<'ast> Visit<'ast> for AdminEvidence {
    // The outer entrypoint's inventory must not inherit authorization or
    // capability names from local function declarations. Their bodies are
    // separate scopes, not executed merely because they are declared here.
    fn visit_item_fn(&mut self, _node: &'ast syn::ItemFn) {}

    fn visit_impl_item_fn(&mut self, _node: &'ast syn::ImplItemFn) {}

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(method.as_str(), "require_auth" | "require_auth_for_args") {
            let receiver = &node.receiver;
            let identity = quote::quote!(#receiver)
                .to_string()
                .split_whitespace()
                .collect::<String>()
                .to_ascii_lowercase();
            if is_admin_identity(&identity) || is_owner_identity(&identity) {
                self.signers.insert(identity);
            }
        }
        if is_role_assertion(&method) && role_mentions_admin(&quote::quote!(#node).to_string()) {
            self.roles.insert(method);
        }
        if let Some(power) = classify_power(&method) {
            self.powers.insert(power);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref() {
            if let Some(segment) = path.path.segments.last() {
                let callee = segment.ident.to_string();
                if is_role_assertion(&callee) && role_mentions_admin(&quote::quote!(#node).to_string()) {
                    self.roles.insert(callee.clone());
                }
                if let Some(power) = classify_power(&callee) {
                    self.powers.insert(power);
                }
            }
        }
        visit::visit_expr_call(self, node);
    }
}

fn is_admin_identity(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "admin", "governor", "governance", "guardian", "authority",
        "multisig", "council", "controller", "superuser",
    ]
    .iter()
    .any(|term| name.contains(term))
}

fn is_owner_identity(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.contains("owner") || name.contains("operator")
}

fn is_role_assertion(name: &str) -> bool {
    matches!(
        name,
        "require_admin" | "assert_admin" | "ensure_admin" | "only_admin"
            | "require_owner" | "assert_owner" | "ensure_owner"
            | "require_role" | "assert_role" | "ensure_role" | "only_role"
    )
}

fn role_mentions_admin(call: &str) -> bool {
    let s = call.to_ascii_lowercase();
    // Named admin/owner guard helpers are assertions by definition. A generic
    // require_role call only qualifies when its requested role is privileged.
    s.contains("admin")
        || s.contains("owner")
        || s.contains("governor")
        || s.contains("guardian")
        || s.contains("authority")
        || s.contains("multisig")
        || s.contains("operator")
}

fn classify_power(raw: &str) -> Option<&'static str> {
    let s = raw.to_ascii_lowercase();
    if s.contains("update_current_contract_wasm")
        || s.contains("upgrade")
        || s.contains("set_wasm")
        || s.contains("replace_code")
    {
        Some("contract upgrade")
    } else if s.contains("mint") || s.contains("issue_tokens") {
        Some("token mint")
    } else if s.contains("drain")
        || s.contains("sweep")
        || s.contains("withdraw_all")
        || s.contains("emergency_withdraw")
        || s.contains("rescue_funds")
    {
        Some("treasury drain")
    } else if s.contains("pause")
        || s.contains("unpause")
        || s.contains("freeze")
        || s.contains("unfreeze")
    {
        Some("pause/freeze")
    } else if s.contains("set_fee")
        || s.contains("update_fee")
        || s.contains("change_fee")
        || s.contains("set_tax")
    {
        Some("fee control")
    } else if s.contains("set_admin")
        || s.contains("change_admin")
        || s.contains("set_owner")
        || s.contains("transfer_ownership")
        || s.contains("grant_role")
        || s.contains("revoke_role")
    {
        Some("role/ownership change")
    } else if s.contains("set_config")
        || s.contains("set_oracle")
        || s.contains("set_treasury")
        || s.contains("update_config")
    {
        Some("configuration control")
    } else {
        None
    }
}

/// Stable report fragment that the CLI can embed in a dedicated section.
/// One entry per function makes auditors aware of the single signer who holds
/// multiple powers; it is not an exploit finding on its own.
pub fn markdown_section(findings: &[RuleViolation]) -> String {
    let mut output = String::from("## Centralization — admin powers\n");
    if findings.is_empty() {
        output.push_str("No explicit privileged entrypoints identified.\n");
    } else {
        for finding in findings {
            output.push_str(&format!(
                "- [{:?}] {} ({})\n",
                finding.severity, finding.message, finding.location
            ));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_upgrades_mint_and_pause_across_templates() {
        let upgrade = r#"
            #[contractimpl]
            impl Vault {
                pub fn upgrade(env: Env, admin: Address, hash: BytesN<32>) {
                    admin.require_auth();
                    env.deployer().update_current_contract_wasm(hash);
                }
            }
        "#;
        let token = r#"
            impl Token {
                pub fn mint(e: Env, governor: Address, to: Address, amount: i128) {
                    governor.require_auth();
                    e.storage().persistent().set(&to, &amount);
                }
                pub fn pause(owner: Address) {
                    owner.require_auth();
                }
            }
        "#;
        let findings = CentralizationRule::new().check(upgrade);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Error);
        assert!(findings[0].message.contains("contract upgrade"));

        let token_findings = CentralizationRule::new().check(token);
        assert_eq!(token_findings.len(), 2);
        assert!(token_findings.iter().any(|f| f.message.contains("token mint")));
        assert!(token_findings.iter().any(|f| f.message.contains("pause/freeze")));

        // Report snapshot: fixed entry order, explicit privileges and severities.
        let preview = markdown_section(&findings);
        assert!(preview.starts_with("## Centralization — admin powers\n"));
        assert!(preview.contains("[Error] Admin-gated `upgrade`"));
        assert_eq!(markdown_section(&[]), "## Centralization — admin powers\nNo explicit privileged entrypoints identified.\n");
    }

    #[test]
    fn excludes_user_auth_and_ungated_code() {
        let source = r#"
            impl Token {
                pub fn transfer(from: Address, to: Address, amount: i128) {
                    from.require_auth();
                }
                pub fn approve(owner: Address, spender: Address, amount: i128) {
                    owner.require_auth();
                }
                pub fn mint(to: Address, amount: i128) {
                    // No guard; report via auth_gap instead.
                }
                fn admin_helper(admin: Address) {
                    admin.require_auth();
                }
            }
        "#;
        assert!(CentralizationRule::new().check(source).is_empty());
    }

    #[test]
    fn report_markdown_matches_committed_snapshot() {
        let findings = vec![
            RuleViolation::new(
                CENTRALIZATION_RISK,
                Severity::Error,
                "Admin-gated `upgrade` can perform: contract upgrade; controlling authority: admin".to_string(),
                "src/vault.rs:upgrade:12".to_string(),
            ),
            RuleViolation::new(
                CENTRALIZATION_RISK,
                Severity::Warning,
                "Admin-gated `set_fee` can perform: fee control; controlling authority: governor".to_string(),
                "src/token.rs:set_fee:34".to_string(),
            ),
        ];
        assert_eq!(
            markdown_section(&findings),
            include_str!("../../tests/fixtures/centralization-report.md"),
        );
    }

    #[test]
    fn reports_admin_role_guard_and_low_impact_custom_power() {
        let source = r#"
            impl Contract {
                pub fn set_fee(env: Env) {
                    require_role(Role::Admin);
                    env.storage().instance().set(&1, &2);
                }
                pub fn rescue(env: Env, authority: Address) {
                    authority.clone().require_auth();
                    emergency_withdraw(env);
                }
                pub fn read_audit(admin: Address) {
                    admin.require_auth();
                }
            }
        "#;
        let findings = CentralizationRule::new().check(source);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().any(|f| f.message.contains("fee control") && f.severity == Severity::Warning));
        assert!(findings.iter().any(|f| f.message.contains("treasury drain") && f.severity == Severity::Error));
        assert!(findings.iter().any(|f| f.message.contains("other privileged entrypoint") && f.severity == Severity::Info));
    }
}
