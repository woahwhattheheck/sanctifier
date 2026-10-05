#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn equal(env: Env, key: Symbol) {
        env.storage()
            .persistent()
            .extend_ttl(&key, 1_000, 1_000);
    }

    pub fn folded(env: Env) {
        env.storage()
            .instance()
            .extend_ttl(17_280 * 30, 17_280 * 29);
    }

    pub fn valid(env: Env) {
        env.storage().instance().extend_ttl(17_280 * 29, 17_280 * 30);
    }

    pub fn dynamic(env: Env, threshold: u32, extend_to: u32) {
        env.storage().instance().extend_ttl(threshold, extend_to);
    }
}
