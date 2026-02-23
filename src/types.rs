use serde::{Deserialize, Serialize};

/// Error type exposed through UniFFI
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("Invalid seed: must be 32 bytes hex-encoded")]
    InvalidSeed,
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Mint returned an error: {0}")]
    MintError(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Encoding error: {0}")]
    EncodingError(String),
}

// We need a simple Error derive for UniFFI - the UDL enum handles mapping
// But we also use thiserror for nice Display impls. The UDL enum variant names
// must match. UniFFI scaffolding maps them automatically.

/// A proof representing ownership of ecash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    pub amount: u64,
    pub secret: String,
    #[serde(rename = "C")]
    pub c: String,
    pub id: String,
}

/// Blinded message sent to the mint for restore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedMessage {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "B_")]
    pub b_: String,
}

/// Blinded signature returned by the mint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlindedSignature {
    pub amount: u64,
    pub id: String,
    #[serde(rename = "C_")]
    pub c_: String,
}

/// Response from POST /v1/restore
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResponse {
    pub outputs: Vec<BlindedMessage>,
    pub signatures: Vec<BlindedSignature>,
}

/// Keyset info from GET /v1/keysets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetInfo {
    pub id: String,
    pub unit: String,
    pub active: bool,
}

/// Response from GET /v1/keysets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetsResponse {
    pub keysets: Vec<KeysetInfo>,
}

/// Individual key entry from the keys response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysResponse {
    pub keysets: Vec<KeysetEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysetEntry {
    pub id: String,
    pub unit: String,
    pub keys: std::collections::HashMap<String, String>,
}

/// Proof state from POST /v1/checkstate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStateItem {
    #[serde(rename = "Y")]
    pub y: String,
    pub state: String,
}

/// Response from POST /v1/checkstate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckStateResponse {
    pub states: Vec<ProofStateItem>,
}
