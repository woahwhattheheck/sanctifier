use serde::Serialize;
use syn::visit::{self, Visit};
use syn::{parse_str, File, Item, Type};

#[derive(Debug, Serialize, Clone, Default)]
pub struct GasEstimationReport {
    pub function_name: String,
    pub estimated_instructions: usize,
    pub estimated_memory_bytes: usize,
}

pub struct GasEstimator {}

impl Default for GasEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl GasEstimator {
    pub fn new() -> Self {
        Self {}
    }

    /// Returns source-level instruction-weight proxies for public endpoints.
    /// These weights are not measured Wasm CPU instructions or network fees.
    pub fn estimate_contract(&self, source: &str) -> Vec<GasEstimationReport> {
        let file = match parse_str::<File>(source) {
            Ok(file) => file,
            Err(_) => return vec![],
        };
        let mut reports = Vec::new();
        self.collect_public_functions(&file.items, "", &mut reports);
        reports
    }

    fn collect_public_functions(
        &self,
        items: &[Item],
        prefix: &str,
        reports: &mut Vec<GasEstimationReport>,
    ) {
        for item in items {
            match item {
                Item::Fn(f) if matches!(f.vis, syn::Visibility::Public(_)) => {
                    let mut visitor = GasEstimationVisitor::new(format!("{}{}", prefix, f.sig.ident));
                    visitor.visit_item_fn(f);
                    reports.push(visitor.into_report());
                }
                Item::Impl(i) => {
                    let self_ty = &i.self_ty;
                    let owner = quote::quote!(#self_ty).to_string().replace(' ', "");
                    for impl_item in &i.items {
                        if let syn::ImplItem::Fn(f) = impl_item {
                            if matches!(f.vis, syn::Visibility::Public(_)) {
                                let name = format!("{}{}::{}", prefix, owner, f.sig.ident);
                                let mut visitor = GasEstimationVisitor::new(name);
                                visitor.visit_impl_item_fn(f);
                                reports.push(visitor.into_report());
                            }
                        }
                    }
                }
                Item::Mod(module) => {
                    if let Some((_, nested)) = &module.content {
                        let nested_prefix = format!("{}{}::", prefix, module.ident);
                        self.collect_public_functions(nested, &nested_prefix, reports);
                    }
                }
                _ => {}
            }
        }
    }

}
struct GasEstimationVisitor {
    function_name: String,
    instruction_count: usize,
    memory_bytes: usize,
}

impl GasEstimationVisitor {
    fn new(function_name: String) -> Self {
        Self {
            function_name,
            instruction_count: 50, // Base cost for function entry
            memory_bytes: 32,      // Base stack usage
        }
    }

    fn into_report(self) -> GasEstimationReport {
        GasEstimationReport {
            function_name: self.function_name,
            estimated_instructions: self.instruction_count,
            estimated_memory_bytes: self.memory_bytes,
        }
    }

    fn estimate_type_size(&self, ty: &Type) -> usize {
        match ty {
            Type::Path(tp) => {
                if let Some(seg) = tp.path.segments.last() {
                    match seg.ident.to_string().as_str() {
                        "u32" | "i32" | "bool" => 4,
                        "u64" | "i64" => 8,
                        "u128" | "i128" | "I128" | "U128" => 16,
                        "Address" => 32,
                        "Bytes" | "BytesN" | "String" | "Symbol" => 64,
                        "Vec" | "Map" => 128,
                        _ => 32,
                    }
                } else {
                    8
                }
            }
            _ => 8,
        }
    }
}

impl<'ast> Visit<'ast> for GasEstimationVisitor {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        self.instruction_count += 5;
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        self.instruction_count += 20;
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if method == "get"
            || method == "set"
            || method == "has"
            || method == "update"
            || method == "remove"
        {
            // Storage operations are expensive cross-host calls
            self.instruction_count += 1000;
        } else if method == "require_auth" {
            self.instruction_count += 500;
        } else {
            self.instruction_count += 25;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.instruction_count += 50;
        let mut inner_visitor = GasEstimationVisitor::new(String::new());
        inner_visitor.visit_block(&node.body);

        self.instruction_count += inner_visitor.instruction_count * 10;
        self.memory_bytes += inner_visitor.memory_bytes * 10;

        visit::visit_expr(&mut *self, &node.expr);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.instruction_count += 50;
        let mut inner_visitor = GasEstimationVisitor::new(String::new());
        inner_visitor.visit_block(&node.body);

        self.instruction_count += inner_visitor.instruction_count * 10;
        self.memory_bytes += inner_visitor.memory_bytes * 10;

        visit::visit_expr(&mut *self, &node.cond);
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.instruction_count += 50;
        let mut inner_visitor = GasEstimationVisitor::new(String::new());
        inner_visitor.visit_block(&node.body);

        self.instruction_count += inner_visitor.instruction_count * 10;
        self.memory_bytes += inner_visitor.memory_bytes * 10;
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Type(pat_type) = &node.pat {
            self.memory_bytes += self.estimate_type_size(&pat_type.ty);
        } else {
            self.memory_bytes += 8;
        }
        self.instruction_count += 2;
        visit::visit_local(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        let mac = &node.mac.path;
        if mac.is_ident("vec") || mac.is_ident("map") {
            self.memory_bytes += 128;
            self.instruction_count += 50;
        } else if mac.is_ident("symbol_short") || mac.is_ident("String") {
            self.memory_bytes += 32;
            self.instruction_count += 10;
        } else {
            self.instruction_count += 10;
        }
        visit::visit_expr_macro(self, node);
    }
}

#[cfg(test)]
mod focused_tests {
    use super::*;
    #[test]
    fn public_functions_include_nested_modules_but_not_helpers() {
        let src = r#"
            pub fn api(x: u32) -> u32 { x + 1 }
            fn helper() {}
            struct Contract;
            impl Contract {
                pub fn send(x: u32) -> u32 { x + 2 }
                fn private() {}
            }
            mod nested { pub fn entry() { let x = 1 + 2; } }
        "#;
        let reports = GasEstimator::new().estimate_contract(src);
        let names: Vec<&str> = reports.iter().map(|r| r.function_name.as_str()).collect();
        assert_eq!(names, ["api", "Contract::send", "nested::entry"]);
        assert!(reports.iter().all(|r| r.estimated_instructions >= 50));
    }
}
