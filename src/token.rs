use base64::{engine::general_purpose, Engine as _};
use serde_json::json;

use crate::types::{Proof, RestoreError};

/// Encode proofs as a cashu token v3 string.
///
/// Format: "cashuA" + base64url(json)
/// JSON structure: { "token": [{ "mint": <url>, "proofs": [...] }], "memo": "" }
pub fn encode_token_v3(mint_url: &str, proofs: &[Proof]) -> Result<String, RestoreError> {
    let proofs_json: Vec<serde_json::Value> = proofs
        .iter()
        .map(|p| {
            json!({
                "amount": p.amount,
                "secret": p.secret,
                "C": p.c,
                "id": p.id,
            })
        })
        .collect();

    let token_json = json!({
        "token": [{
            "mint": mint_url,
            "proofs": proofs_json,
        }],
        "memo": "",
    });

    let json_str = serde_json::to_string(&token_json)
        .map_err(|e| RestoreError::EncodingError(format!("JSON serialization failed: {}", e)))?;

    // cashu token v3 uses base64url encoding (no padding)
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(json_str.as_bytes());

    Ok(format!("cashuA{}", encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_token_v3() {
        let proofs = vec![Proof {
            amount: 1,
            secret: "test_secret".to_string(),
            c: "02abcdef".to_string(),
            id: "00abcdef".to_string(),
        }];

        let token = encode_token_v3("https://mint.example.com", &proofs).unwrap();
        assert!(token.starts_with("cashuA"));
    }
}
