use crate::finding_codes::DEPRECATED_SDK;
use crate::rules::{Rule, RuleViolation, Severity};
use std::collections::HashSet;
use syn::spanned::Spanned;
use syn::visit::Visit;

const FINDING_CODE: &str = DEPRECATED_SDK;

#[derive(Clone, Copy)]
enum ApiShape {
    EnvMethod(&'static str),
    EnvAccessorMethod {
        accessor: &'static str,
        method: &'static str,
    },
    DeployerAddressMethod(&'static str),
    AssociatedFn {
        ty: &'static str,
        function: &'static str,
    },
    Macro(&'static str),
}

#[derive(Clone, Copy)]
struct DeprecatedApi {
    display: &'static str,
    replacement: &'static str,
    shape: ApiShape,
}

// Maintained from the public #[deprecated] annotations in soroban-sdk.
// Generic names such as publish and deploy are matched only when their
// receiver has a syntax-distinctive Soroban accessor chain rooted at env.
const DEPRECATED_APIS: &[DeprecatedApi] = &[
    DeprecatedApi {
        display: "Env::logger()",
        replacement: "Env::logs()",
        shape: ApiShape::EnvMethod("logger"),
    },
    DeprecatedApi {
        display: "Logs::log(..)",
        replacement: "Logs::add(..) (or the log! macro)",
        shape: ApiShape::EnvAccessorMethod {
            accessor: "logs",
            method: "log",
        },
    },
    DeprecatedApi {
        display: "Events::publish(..)",
        replacement: "#[contractevent] plus Events::publish_event(..)",
        shape: ApiShape::EnvAccessorMethod {
            accessor: "events",
            method: "publish",
        },
    },
    DeprecatedApi {
        display: "Ledger::protocol_version()",
        replacement: "remove protocol-version branching; the SDK no longer guarantees this value",
        shape: ApiShape::EnvAccessorMethod {
            accessor: "ledger",
            method: "protocol_version",
        },
    },
    DeprecatedApi {
        display: "Deployer::update_current_contract_wasm(..)",
        replacement: "Deployer::update_current_contract(..)",
        shape: ApiShape::EnvAccessorMethod {
            accessor: "deployer",
            method: "update_current_contract_wasm",
        },
    },
    DeprecatedApi {
        display: "DeployerWithAddress::deploy(..)",
        replacement: "DeployerWithAddress::deploy_contract(..)",
        shape: ApiShape::DeployerAddressMethod("deploy"),
    },
    DeprecatedApi {
        display: "Env::register_contract(..)",
        replacement: "Env::register(..)",
        shape: ApiShape::EnvMethod("register_contract"),
    },
    DeprecatedApi {
        display: "Prng::u64_in_range(..)",
        replacement: "Prng::gen_range(..)",
        shape: ApiShape::EnvAccessorMethod {
            accessor: "prng",
            method: "u64_in_range",
        },
    },
    DeprecatedApi {
        display: "Symbol::short(..)",
        replacement: "the symbol_short! macro",
        shape: ApiShape::AssociatedFn {
            ty: "Symbol",
            function: "short",
        },
    },
    DeprecatedApi {
        display: "String::from_slice(..)",
        replacement: "String::from_str(..)",
        shape: ApiShape::AssociatedFn {
            ty: "String",
            function: "from_slice",
        },
    },
    DeprecatedApi {
        display: "panic_error!(..)",
        replacement: "panic_with_error!(..)",
        shape: ApiShape::Macro("panic_error"),
    },
    DeprecatedApi {
        display: "assert_in_contract!(..)",
        replacement: "debug_assert_in_contract!(..) for debug-only assertions",
        shape: ApiShape::Macro("assert_in_contract"),
    },
];

pub struct DeprecatedSdkRule;

impl DeprecatedSdkRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DeprecatedSdkRule {
    fn default() -> Self {
        Self::new()
    }
}

impl Rule for DeprecatedSdkRule {
    fn name(&self) -> &str {
        "deprecated_sdk"
    }

    fn description(&self) -> &str {
        "Detects known-deprecated soroban_sdk API calls and points to supported replacements"
    }

    fn check(&self, source: &str) -> Vec<RuleViolation> {
        let file = match crate::parse_cache::parse_cached(source) {
            Some(f) => (*f).clone(),
            None => return vec![],
        };
        let mut visitor = DeprecatedSdkVisitor {
            fn_name: String::new(),
            seen: HashSet::new(),
            violations: Vec::new(),
        };
        visitor.visit_file(&file);
        visitor.violations
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

struct DeprecatedSdkVisitor {
    fn_name: String,
    seen: HashSet<(usize, &'static str)>,
    violations: Vec<RuleViolation>,
}

impl DeprecatedSdkVisitor {
    fn record(&mut self, api: &'static DeprecatedApi, line: usize) {
        if !self.seen.insert((line, api.display)) {
            return;
        }
        self.violations.push(
            RuleViolation::new(
                FINDING_CODE,
                Severity::Warning,
                format!(
                    "{FINDING_CODE}: deprecated soroban_sdk API '{}' is still in use",
                    api.display
                ),
                format!("{}:{}", self.fn_name, line),
            )
            .with_suggestion(format!("Use {} instead.", api.replacement)),
        );
    }
}

impl<'ast> Visit<'ast> for DeprecatedSdkVisitor {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let prev = std::mem::replace(&mut self.fn_name, node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.fn_name = prev;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let prev = std::mem::replace(&mut self.fn_name, node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.fn_name = prev;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        for api in DEPRECATED_APIS {
            let matched = match api.shape {
                ApiShape::EnvMethod(method) => {
                    node.method == method && receiver_is_env(&node.receiver)
                }
                ApiShape::EnvAccessorMethod { accessor, method } => {
                    node.method == method && receiver_is_env_accessor(&node.receiver, accessor)
                }
                ApiShape::DeployerAddressMethod(method) => {
                    node.method == method && receiver_is_deployer_address(&node.receiver)
                }
                ApiShape::AssociatedFn { .. } | ApiShape::Macro(_) => false,
            };
            if matched {
                self.record(api, node.span().start().line);
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            for api in DEPRECATED_APIS {
                if let ApiShape::AssociatedFn { ty, function } = api.shape {
                    if path_ends_with(&path.path, ty, function) {
                        self.record(api, node.span().start().line);
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(name) = node.path.segments.last().map(|segment| segment.ident.to_string()) {
            for api in DEPRECATED_APIS {
                if let ApiShape::Macro(macro_name) = api.shape {
                    if name == macro_name {
                        self.record(api, node.span().start().line);
                    }
                }
            }
        }
        syn::visit::visit_macro(self, node);
    }
}

fn receiver_is_env(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Path(p) => p.path.get_ident().map(|i| i == "env").unwrap_or(false),
        syn::Expr::Field(f) => match &f.member {
            syn::Member::Named(name) => name == "env",
            syn::Member::Unnamed(_) => false,
        },
        syn::Expr::Paren(p) => receiver_is_env(&p.expr),
        _ => false,
    }
}

fn receiver_is_env_accessor(expr: &syn::Expr, accessor: &str) -> bool {
    match expr {
        syn::Expr::MethodCall(call) => {
            call.method == accessor && call.args.is_empty() && receiver_is_env(&call.receiver)
        }
        syn::Expr::Paren(p) => receiver_is_env_accessor(&p.expr, accessor),
        _ => false,
    }
}

fn receiver_is_deployer_address(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::MethodCall(call)
            if (call.method == "with_current_contract" || call.method == "with_address")
                && receiver_is_env_accessor(&call.receiver, "deployer") =>
        {
            true
        }
        syn::Expr::Paren(p) => receiver_is_deployer_address(&p.expr),
        _ => false,
    }
}

fn path_ends_with(path: &syn::Path, ty: &str, function: &str) -> bool {
    let mut segments = path.segments.iter().rev();
    matches!(
        (segments.next(), segments.next()),
        (Some(last), Some(prev)) if last.ident == function && prev.ident == ty
    )
}
