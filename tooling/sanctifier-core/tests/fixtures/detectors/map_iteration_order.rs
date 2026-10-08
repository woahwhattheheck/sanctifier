#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Map, Vec};

#[contract]
pub struct MapIterationOrderContract;

#[contractimpl]
impl MapIterationOrderContract {
    pub fn first_positive(scores: Map<Address, i128>) -> Option<Address> {
        for (addr, score) in scores.iter() {
            if score > 0 {
                return Some(addr);
            }
        }
        None
    }

    pub fn keys_in_iteration_order(env: Env, scores: Map<Address, i128>) -> Vec<Address> {
        let mut out = Vec::new(&env);
        for (addr, _) in scores.iter() {
            out.push_back(addr);
        }
        out
    }

    pub fn first_key(scores: Map<Address, i128>) -> Option<Address> {
        scores.iter().next().map(|(addr, _)| addr)
    }

    pub fn total(scores: Map<Address, i128>) -> i128 {
        let mut sum = 0i128;
        for (_, score) in scores.iter() {
            sum += score;
        }
        sum
    }
}
