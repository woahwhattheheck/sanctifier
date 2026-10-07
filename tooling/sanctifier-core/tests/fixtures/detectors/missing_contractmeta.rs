use soroban_sdk::contract;

#[contract]
pub struct MissingMetadata;

impl MissingMetadata {
    pub fn ping() -> &'static str {
        "pong"
    }
}
