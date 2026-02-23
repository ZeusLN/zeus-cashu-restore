use std::collections::HashMap;

use crate::types::*;

/// Timeout for HTTP requests in milliseconds
const TIMEOUT_MS: u64 = 30_000;

/// Fetch keysets from the mint: GET /v1/keysets
pub fn fetch_keysets(mint_url: &str) -> Result<Vec<KeysetInfo>, RestoreError> {
    let url = format!("{}/v1/keysets", mint_url);
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_millis(TIMEOUT_MS))
        .call()
        .map_err(|e| RestoreError::NetworkError(format!("GET /v1/keysets: {}", e)))?;

    let body: KeysetsResponse = resp
        .into_json()
        .map_err(|e| RestoreError::MintError(format!("Failed to parse keysets: {}", e)))?;

    Ok(body.keysets)
}

/// Fetch keys for a specific keyset: GET /v1/keys/<keyset_id>
/// Returns a map of amount -> hex-encoded public key
pub fn fetch_keys(
    mint_url: &str,
    keyset_id: &str,
) -> Result<HashMap<u64, String>, RestoreError> {
    let url = format!("{}/v1/keys/{}", mint_url, keyset_id);
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_millis(TIMEOUT_MS))
        .call()
        .map_err(|e| RestoreError::NetworkError(format!("GET /v1/keys/{}: {}", keyset_id, e)))?;

    let body: KeysResponse = resp
        .into_json()
        .map_err(|e| RestoreError::MintError(format!("Failed to parse keys: {}", e)))?;

    // Find the matching keyset entry
    for entry in &body.keysets {
        if entry.id == keyset_id {
            let mut keys = HashMap::new();
            for (amount_str, pubkey) in &entry.keys {
                if let Ok(amount) = amount_str.parse::<u64>() {
                    keys.insert(amount, pubkey.clone());
                }
            }
            return Ok(keys);
        }
    }

    Err(RestoreError::MintError(format!(
        "Keyset {} not found in keys response",
        keyset_id
    )))
}

/// POST /v1/restore with blinded messages
pub fn post_restore(
    mint_url: &str,
    outputs: &[BlindedMessage],
) -> Result<RestoreResponse, RestoreError> {
    let url = format!("{}/v1/restore", mint_url);

    let body = serde_json::json!({
        "outputs": outputs,
    });

    let resp = ureq::post(&url)
        .timeout(std::time::Duration::from_millis(TIMEOUT_MS))
        .send_json(&body)
        .map_err(|e| RestoreError::NetworkError(format!("POST /v1/restore: {}", e)))?;

    let response: RestoreResponse = resp
        .into_json()
        .map_err(|e| RestoreError::MintError(format!("Failed to parse restore response: {}", e)))?;

    Ok(response)
}

/// POST /v1/checkstate with Y values
pub fn post_check_state(
    mint_url: &str,
    ys: &[String],
) -> Result<Vec<ProofStateItem>, RestoreError> {
    let url = format!("{}/v1/checkstate", mint_url);

    let body = serde_json::json!({
        "Ys": ys,
    });

    let resp = ureq::post(&url)
        .timeout(std::time::Duration::from_millis(TIMEOUT_MS))
        .send_json(&body)
        .map_err(|e| RestoreError::NetworkError(format!("POST /v1/checkstate: {}", e)))?;

    let response: CheckStateResponse = resp
        .into_json()
        .map_err(|e| RestoreError::MintError(format!("Failed to parse checkstate response: {}", e)))?;

    Ok(response.states)
}
