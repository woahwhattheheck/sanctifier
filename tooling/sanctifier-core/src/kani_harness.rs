//! Generate deliberately unfinished Kani proof harnesses from Soroban #[contractimpl] signatures.
//! This is source analysis only. It does NOT certify a property or model Soroban Host behavior.

use anyhow::{anyhow, bail, Context, Result};
use quote::ToTokens;
use std::collections::BTreeSet;
use syn::{FnArg, GenericArgument, ImplItem, Item, Pat, PathArguments, Type, Visibility};

/// Parse actual Rust entrypoints and emit a standalone integration-test skeleton.
/// Unsupported types produce an error rather than a broken or silently skipped proof.
pub fn generate_kani_harnesses(source: &str, crate_name: &str) -> Result<String> {
    let file = syn::parse_file(source).context("cannot parse input Rust source")?;
    let crate_ident = crate_name.replace('-', "_");
    syn::parse_str::<syn::Ident>(&crate_ident)
        .context("crate name must be a single Rust identifier")?;

    let mut proofs = Vec::new();
    let mut names = BTreeSet::new();
    let mut need_address = false;

    for item in &file.items {
        let Item::Impl(contract_impl) = item else { continue };
        if !contract_impl.attrs.iter().any(|attr| {
            attr.path().segments.last().is_some_and(|seg| seg.ident == "contractimpl")
        }) {
            continue;
        }
        if contract_impl.trait_.is_some() {
            continue;
        }
        let Type::Path(contract_type) = contract_impl.self_ty.as_ref() else {
            bail!("contractimpl target must have a named struct type");
        };
        let contract = contract_type.path.segments.last()
            .ok_or_else(|| anyhow!("missing contract name"))?.ident.to_string();

        for method in &contract_impl.items {
            let ImplItem::Fn(method) = method else { continue };
            if !matches!(method.vis, Visibility::Public(_)) { continue; }
            let method_name = method.sig.ident.to_string();
            let proof_name = format!(
                "verify_{}_{}", to_snake(&contract), to_snake(&method_name)
            );
            if !names.insert(proof_name.clone()) {
                bail!("duplicate generated proof name: {}", proof_name);
            }

            let mut setup = Vec::new();
            let mut args = Vec::new();
            let mut requires_env = false;

            for arg in &method.sig.inputs {
                let FnArg::Typed(arg) = arg else {
                    bail!("{}.{} has a receiver; Soroban contract entrypoints must be static",
                          contract, method_name);
                };
                let Pat::Ident(pat) = arg.pat.as_ref() else {
                    bail!("{}.{} has a destructured argument", contract, method_name);
                };
                let name = pat.ident.to_string();
                let kind = classify_type(&arg.ty).with_context(|| format!(
                    "unsupported argument {} in {}.{}", name, contract, method_name
                ))?;

                if !matches!(kind, ArgumentKind::Primitive) { requires_env = true; }
                let ty = arg.ty.to_token_stream().to_string();
                let expr = match kind {
                    ArgumentKind::Primitive => format!("kani::any::<{}>()", ty),
                    ArgumentKind::Env => "__kani_env.clone()".to_owned(),
                    ArgumentKind::Address => {
                        need_address = true;
                        "kani_address(&__kani_env)".to_owned()
                    }
                    ArgumentKind::Bytes => "soroban_sdk::Bytes::new(&__kani_env)".to_owned(),
                    ArgumentKind::Symbol => {
                        "soroban_sdk::Symbol::new(&__kani_env, \"kani\")".to_owned()
                    }
                    ArgumentKind::String => {
                        "soroban_sdk::String::from_str(&__kani_env, \"\")".to_owned()
                    }
                    ArgumentKind::BytesN(n) => format!(
                        "soroban_sdk::BytesN::<{n}>::from_array(&__kani_env, \
                         &kani::any::<[u8; {n}]>())"
                    ),
                    ArgumentKind::Vec(ty) => {
                        format!("soroban_sdk::Vec::<{ty}>::new(&__kani_env)")
                    }
                };
                setup.push(format!("    let {}: {} = {};", name, ty, expr));
                args.push(name);
            }

            let mut proof = format!(
                "#[kani::proof]\nfn {proof_name}() {{\n\
                 \x20   // TODO: constrain the symbolic pre-state with kani::assume.\n"
            );
            if requires_env {
                proof.push_str("    let __kani_env = soroban_sdk::Env::default();\n");
            }
            for line in setup { proof.push_str(&line); proof.push('\n'); }
            proof.push_str(&format!(
                "    let _result = {crate_ident}::{contract}::{method_name}({});\n",
                args.join(", ")
            ));
            proof.push_str(
                "    // TODO: assert a security or functional property of _result and post-state.\n\
                 \x20   // WARNING: Soroban Host operations need an explicit model before a sound proof.\n\
                 }\n"
            );
            proofs.push(proof);
        }
    }

    if proofs.is_empty() {
        bail!("no public #[contractimpl] entrypoints found");
    }
    let mut output = String::from(
        "// Generated by sanctifier-core: kani-harness-gen. Edit before use.\n\
         // This skeleton alone is NOT a formal verification result.\n\
         #![cfg(kani)]\n\
         #![allow(unused_variables)]\n\n"
    );
    output.push_str("use soroban_sdk::{Address, Bytes, BytesN, Env, String, Symbol, Vec};\n\n");
    if need_address {
        output.push_str(
            "fn kani_address(env: &soroban_sdk::Env) -> soroban_sdk::Address {\n\
             \x20   use soroban_sdk::testutils::Address as _;\n\
             \x20   soroban_sdk::Address::generate(env)\n\
             }\n\n"
        );
    }
    output.push_str(&proofs.join("\n"));
    syn::parse_file(&output).context("generated harnesses are not valid Rust syntax")?;
    Ok(output)
}

#[derive(Debug)]
enum ArgumentKind {
    Primitive,
    Env,
    Address,
    Bytes,
    BytesN(String),
    Symbol,
    String,
    Vec(String),
}

fn classify_type(ty: &Type) -> Result<ArgumentKind> {
    let Type::Path(ty) = ty else {
        bail!("non-path argument type is not supported");
    };
    if ty.qself.is_some() { bail!("qualified associated type is not supported"); }
    let seg = ty.path.segments.last().ok_or_else(|| anyhow!("empty type path"))?;
    let name = seg.ident.to_string();
    let no_args = matches!(seg.arguments, PathArguments::None);
    if no_args && matches!(
        name.as_str(),
        "bool" | "i8" | "i16" | "i32" | "i64" | "i128" |
        "u8" | "u16" | "u32" | "u64" | "u128" | "isize" | "usize"
    ) {
        return Ok(ArgumentKind::Primitive);
    }
    if no_args {
        return match name.as_str() {
            "Env" => Ok(ArgumentKind::Env),
            "Address" => Ok(ArgumentKind::Address),
            "Bytes" => Ok(ArgumentKind::Bytes),
            "Symbol" => Ok(ArgumentKind::Symbol),
            "String" => Ok(ArgumentKind::String),
            _ => bail!("unsupported type {}", name),
        };
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        bail!("unsupported generic type {}", name);
    };
    if args.args.len() != 1 { bail!("expected a single generic type/length"); }
    let first = args.args.first().ok_or_else(|| anyhow!("missing generic"))?;
    match (name.as_str(), first) {
        ("BytesN", GenericArgument::Const(n)) => {
            Ok(ArgumentKind::BytesN(n.to_token_stream().to_string()))
        }
        ("Vec", GenericArgument::Type(ty)) => {
            Ok(ArgumentKind::Vec(ty.to_token_stream().to_string()))
        }
        _ => bail!("unsupported generic type {}", name),
    }
}

fn to_snake(name: &str) -> String {
    let mut out = String::new();
    for (idx, ch) in name.chars().enumerate() {
        if ch.is_uppercase() && idx > 0 { out.push('_'); }
        out.extend(ch.to_lowercase());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_entrypoints_and_host_builders_without_faking_proofs() {
        let source = r#"
            #[contractimpl]
            impl TokenContract {
                pub fn transfer(from: Address, to: Address, amount: i128, memo: BytesN<32>) {}
                pub fn mint(env: Env, bytes: Bytes, symbol: Symbol, text: String) {}
            }
        "#;
        let actual = generate_kani_harnesses(source, "my-contract").unwrap();
        assert!(actual.contains("fn verify_token_contract_transfer()"));
        assert!(actual.contains("fn verify_token_contract_mint()"));
        assert!(actual.contains("kani::any::<i128>()"));
        assert!(actual.contains("kani_address(&__kani_env)"));
        assert!(actual.contains("BytesN::<32>::from_array"));
        assert!(actual.contains("my_contract::TokenContract::transfer"));
        assert!(actual.contains("TODO: assert a security"));
        syn::parse_file(&actual).unwrap();
    }

    #[test]
    fn refuses_to_generate_a_noncompilable_unsupported_argument() {
        let source = "#[contractimpl] impl Vault { pub fn deposit(x: Option<Address>) {} }";
        assert!(generate_kani_harnesses(source, "vault").is_err());
    }
}
