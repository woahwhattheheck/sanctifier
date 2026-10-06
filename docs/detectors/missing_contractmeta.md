# `missing_contractmeta` — Missing Soroban contract metadata

| **Code** | [`SANCT_MISSING_CONTRACTMETA`](../error-codes.md) |
| --- | --- |
| **Category** | metadata |
| **Severity** | Info |
| **Source rule** | [`rules/missing_contractmeta.rs`](../../tooling/sanctifier-core/src/rules/missing_contractmeta.rs) |

## What it catches

Flags a Soroban contract root declared with `#[contract]` when the same source file does not contain a `contractmeta!` invocation. Contract metadata is useful to explorers and other tooling that need a small amount of human-readable context about a deployed contract.

This is an advisory finding. Missing metadata does not by itself make contract execution unsafe.

## Vulnerable example

```rust
use soroban_sdk::contract;

#[contract]
pub struct Token;
```

## The fix

Add concise public metadata at the contract root:

```rust
use soroban_sdk::{contract, contractmeta};

contractmeta!(key = "Description", val = "Example token contract");

#[contract]
pub struct Token;
```

## How Sanctifier detects it

The detector parses the source and looks for a real `#[contract]` declaration. If one is present, it scans macros in the same source file for `contractmeta!`. A missing invocation produces one informational finding at the contract declaration.

The rule intentionally does not flag helper modules or files that only contain `#[contractimpl]`; metadata normally belongs at the contract root, and flagging every implementation module would create noisy false positives.

## Limits

This is source-level discoverability guidance, not a guarantee that deployed WASM contains specific metadata. Compiled-module checks remain the responsibility of Sanctifier's WASM analysis path.
