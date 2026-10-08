use crate::finding_codes::MISSING_REENTRANCY_GUARD;
use crate::rules::{Rule, RuleViolation, Severity};
use quote::ToTokens;
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// Advises on unguarded value-moving entrypoints that interact with other contracts.
///
/// This is intentionally intra-procedural: it requires an observable external
/// call, not merely a suspicious function name. A guarded transfer, a function
/// that only changes local storage, and a read-only cross-contract query are
/// not findings. The separate CEI detector examines ordering of state effects.
pub struct MissingReentrancyGuardRule;

impl MissingReentrancyGuardRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MissingReentrancyGuardRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for MissingReentrancyGuardRule {
    fn name(&self) -> &str {
        "missing_reentrancy_guard"
    }

    fn description(&self) -> &str {
        "Finds value-moving contract entrypoints that make external calls without an active reentrancy guard"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let Some(file) = crate::parse_cache::parse_cached(source) else {
            return Vec::new();
        };
        let mut visitor = ContractVisitor::default();
        visitor.visit_file(&file);
        visitor.findings
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Default)]
struct ContractVisitor {
    test_depth: usize,
    findings: Vec<RuleViolation>,
}

impl ContractVisitor {
    fn inspect(&mut self, name: &str, line: usize, block: &syn::Block) {
        let mut facts = EntryFacts::default();
        facts.visit_block(block);
        if !(is_value_moving(name) || facts.has_value_move) {
            return;
        }
        if let Some(call_line) = facts.first_unguarded_external {
            self.findings.push(
                RuleViolation::new(
                    MISSING_REENTRANCY_GUARD,
                    Severity::Warning,
                    format!(
                        "{MISSING_REENTRANCY_GUARD}: value-moving entrypoint `{name}` makes a cross-contract call without an active reentrancy guard"
                    ),
                    format!("{name}:{call_line}"),
                )
                .with_suggestion(
                    "Acquire a SanctifiedGuard or ReentrancyGuard before the external call and keep it active until state transitions finish; also consider checks-effects-interactions".into(),
                ),
            );
        }
        let _ = line; // source location is the actionable external call, not the signature
    }
}

impl<'ast> Visit<'ast> for ContractVisitor {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let is_test = test_cfg(&node.attrs);
        if is_test {
            self.test_depth += 1;
        }
        syn::visit::visit_item_mod(self, node);
        if is_test {
            self.test_depth -= 1;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if self.test_depth == 0
            && !test_cfg(&node.attrs)
            && matches!(node.vis, syn::Visibility::Public(_))
        {
            self.inspect(
                &node.sig.ident.to_string(),
                node.sig.ident.span().start().line,
                &node.block,
            );
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if self.test_depth == 0
            && !test_cfg(&node.attrs)
            && matches!(node.vis, syn::Visibility::Public(_))
        {
            self.inspect(
                &node.sig.ident.to_string(),
                node.sig.ident.span().start().line,
                &node.block,
            );
        }
    }
}

fn test_cfg(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && {
                let meta = attr.meta.to_token_stream().to_string().replace(' ', "");
                meta.contains("(test)") && !meta.contains("not(test)")
            }
    })
}

fn is_value_moving(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "transfer", "withdraw", "redeem", "payout", "send", "mint",
        "burn", "swap", "drain", "claim", "unstake", "liquidate",
    ]
    .iter()
    .any(|word| lower.contains(word))
}

fn moves_value(method: &str) -> bool {
    ["transfer", "transfer_from", "mint", "burn", "swap", "send", "payout"]
        .iter()
        .any(|word| method == *word || method.starts_with(&format!("{word}_")))
}

#[derive(Default)]
struct EntryFacts {
    guard_vars: HashSet<String>,
    client_vars: HashSet<String>,
    guard_active: bool,
    first_unguarded_external: Option<usize>,
    has_value_move: bool,
}

impl EntryFacts {
    fn is_guard(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(path) => path.path.get_ident().is_some_and(|id| {
                self.guard_vars.contains(&id.to_string())
            }),
            syn::Expr::Reference(r) => self.is_guard(&r.expr),
            syn::Expr::Paren(p) => self.is_guard(&p.expr),
            syn::Expr::MethodCall(m) => self.is_guard(&m.receiver),
            _ => is_guard_type(expr),
        }
    }

    fn is_client(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(path) => path.path.get_ident().is_some_and(|id| {
                self.client_vars.contains(&id.to_string())
            }),
            syn::Expr::Reference(r) => self.is_client(&r.expr),
            syn::Expr::Paren(p) => self.is_client(&p.expr),
            syn::Expr::MethodCall(m) => self.is_client(&m.receiver),
            _ => is_client_constructor(expr),
        }
    }
}

fn is_guard_type(expr: &syn::Expr) -> bool {
    let tokens = expr.to_token_stream().to_string();
    tokens.contains("SanctifiedGuard") || tokens.contains("ReentrancyGuard")
}

fn is_client_constructor(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Call(call) => match &*call.func {
            syn::Expr::Path(path) => {
                path.path.segments.iter().any(|s| s.ident.to_string().ends_with("Client"))
            }
            _ => false,
        },
        _ => false,
    }
}

impl<'ast> Visit<'ast> for EntryFacts {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(ident), Some(init)) = (&node.pat, &node.init) {
            let name = ident.ident.to_string();
            if is_guard_type(&init.expr) {
                self.guard_vars.insert(name.clone());
            }
            if is_client_constructor(&init.expr) {
                self.client_vars.insert(name);
            }
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            let segments: Vec<_> = path.path.segments.iter().map(|s| s.ident.to_string()).collect();
            let guard = segments.iter().any(|s| s == "SanctifiedGuard" || s == "ReentrancyGuard");
            let action = segments.last().map(String::as_str).unwrap_or("");
            if guard && matches!(action, "enter" | "try_enter" | "acquire") {
                self.guard_active = true;
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if self.is_guard(&node.receiver) {
            if matches!(method.as_str(), "enter" | "try_enter" | "acquire") {
                self.guard_active = true;
            } else if matches!(method.as_str(), "exit" | "release" | "unlock") {
                self.guard_active = false;
            }
        }

        let client = self.is_client(&node.receiver);
        let external = method == "invoke_contract"
            || (client && !matches!(method.as_str(), "clone" | "address" | "new"));
        if client && moves_value(&method) {
            self.has_value_move = true;
        }
        if external && !self.guard_active && self.first_unguarded_external.is_none() {
            self.first_unguarded_external = Some(node.method.span().start().line);
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_flags_unguarded_token_transfer() {
        let src = r#"
            impl Vault {
                pub fn withdraw(env: Env, token: Address, to: Address, amount: i128) {
                    TokenClient::new(&env, &token).transfer(&env.current_contract_address(), &to, &amount);
                }
            }
        "#;
        let findings = MissingReentrancyGuardRule::new().check(src);
        let report = findings
            .iter()
            .map(|f| format!("{} | {:?}", f.rule_name, f.severity))
            .collect::<Vec<_>>()
            .join("\n");
        insta::assert_snapshot!(report, @"SANCT_MISSING_REENTRANCY_GUARD | Warning");
        assert_eq!(findings.len(), 1);
        assert!(findings[0].location.starts_with("withdraw:"));
    }

    #[test]
    fn respects_active_reentrancy_guard() {
        let src = r#"
            impl Vault {
                pub fn withdraw(env: Env, token: Address, amount: i128) {
                    let guard = ReentrancyGuard::new(&env);
                    guard.enter();
                    TokenClient::new(&env, &token).transfer(&to, &amount);
                    guard.exit();
                }
            }
        "#;
        assert!(MissingReentrancyGuardRule::new().check(src).is_empty());
    }

    #[test]
    fn recognizes_sanctified_guard_and_detects_early_release() {
        let secure = r#"
            impl Vault {
                pub fn drain(env: Env, target: Address) {
                    let _guard = SanctifiedGuard::enter(&env);
                    env.invoke_contract::<()>(&target, &symbol_short!("drain"), vec![&env]);
                }
            }
        "#;
        let unsafe_src = r#"
            impl Vault {
                pub fn drain(env: Env, target: Address) {
                    let g = SanctifiedGuard::new(&env);
                    g.enter();
                    g.exit();
                    env.invoke_contract::<()>(&target, &symbol_short!("drain"), vec![&env]);
                }
            }
        "#;
        let rule = MissingReentrancyGuardRule::new();
        assert!(rule.check(secure).is_empty());
        assert_eq!(rule.check(unsafe_src).len(), 1);
    }

    #[test]
    fn ignores_read_only_queries_and_local_only_transfers() {
        let src = r#"
            impl Vault {
                pub fn query_remote(env: Env, target: Address) {
                    env.invoke_contract::<()>(&target, &symbol_short!("balance"), vec![&env]);
                }
                pub fn withdraw_local(env: Env, key: DataKey) {
                    env.storage().persistent().set(&key, &0_i128);
                }
            }
        "#;
        assert!(MissingReentrancyGuardRule::new().check(src).is_empty());
    }

    #[test]
    fn handles_named_clients_and_excludes_test_modules() {
        let src = r#"
            impl Vault {
                pub fn execute(env: Env, token: Address, to: Address, amount: i128) {
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&to, &amount);
                }
            }
            #[cfg(test)]
            mod tests {
                impl Mock {
                    pub fn withdraw(env: Env, t: Address) {
                        env.invoke_contract::<()>(&t, &sym, vec![&env]);
                    }
                }
            }
        "#;
        let findings = MissingReentrancyGuardRule::new().check(src);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].location.starts_with("execute:"));
    }
}
