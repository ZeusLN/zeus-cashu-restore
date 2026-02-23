uniffi::include_scaffolding!("restore");

mod crypto;
mod mint_api;
mod token;
mod types;

use types::RestoreError;

/// Restore proofs from a v1 legacy seed (32 bytes hex-encoded).
///
/// Connects to the mint, iterates keysets, derives NUT-13 blinded messages,
/// calls POST /v1/restore, unblinds signatures, checks proof states,
/// and returns a cashu token v3 string containing unspent proofs.
///
/// Returns empty string if no unspent proofs are found.
pub fn restore_from_seed(mint_url: String, seed_hex: String) -> Result<String, RestoreError> {
    // Validate and decode seed
    let seed = hex::decode(&seed_hex).map_err(|_| RestoreError::InvalidSeed)?;
    if seed.len() != 32 {
        return Err(RestoreError::InvalidSeed);
    }

    let mint_url = mint_url.trim_end_matches('/').to_string();

    // Step 1: Fetch all keysets from the mint
    let keysets = mint_api::fetch_keysets(&mint_url)?;

    let mut all_unspent_proofs: Vec<types::Proof> = Vec::new();
    let mut keysets_processed: u32 = 0;
    let mut keysets_skipped: u32 = 0;
    let mut total_restore_hits: u32 = 0;
    let mut errors: Vec<String> = Vec::new();

    // Step 2: For each keyset, attempt restore
    for keyset_info in &keysets {
        // Only process "sat" unit keysets (or keysets with no unit specified)
        if keyset_info.unit != "sat" && !keyset_info.unit.is_empty() {
            keysets_skipped += 1;
            continue;
        }

        // Only process v1 (base64) keyset IDs — v1 proofs were never created under v2 hex keysets
        if keyset_info.id.chars().all(|c| c.is_ascii_hexdigit()) {
            keysets_skipped += 1;
            continue;
        }

        // Fetch full keys for this keyset
        let keys = match mint_api::fetch_keys(&mint_url, &keyset_info.id) {
            Ok(k) => k,
            Err(e) => {
                errors.push(format!("keys/{}: {}", keyset_info.id, e));
                continue;
            }
        };

        // Parse keyset ID to integer for BIP32 derivation path
        let keyset_id_int = match keyset_id_to_int(&keyset_info.id) {
            Some(v) => v,
            None => {
                errors.push(format!("bad keyset id: {}", keyset_info.id));
                continue;
            }
        };

        keysets_processed += 1;
        let mut consecutive_empty_batches = 0;
        let mut counter: u32 = 0;
        const BATCH_SIZE: u32 = 100;

        // Iterate in batches until gap limit (2 consecutive empty batches)
        while consecutive_empty_batches < 2 {
            let mut outputs = Vec::new();
            let mut blinding_data = Vec::new(); // (secret, r, amount)

            for i in 0..BATCH_SIZE {
                let idx = counter + i;

                // Derive secret and blinding factor via NUT-13 BIP32 paths
                let (secret, r) = crypto::derive_secret_and_r(&seed, keyset_id_int, idx)?;

                // Amount doesn't matter for restore - mint returns correct amount
                let amount: u64 = 1;

                // Compute blinded message: B_ = hash_to_curve(secret) + r * G
                let b_blind = crypto::compute_blinded_message(&secret, &r)?;

                outputs.push(types::BlindedMessage {
                    amount,
                    id: keyset_info.id.clone(),
                    b_: b_blind,
                });

                blinding_data.push((secret, r, amount));
            }

            // POST /v1/restore
            let restore_response = match mint_api::post_restore(&mint_url, &outputs) {
                Ok(resp) => resp,
                Err(e) => {
                    errors.push(format!("restore/{} batch {}: {}", keyset_info.id, counter, e));
                    consecutive_empty_batches += 1;
                    counter += BATCH_SIZE;
                    continue;
                }
            };

            if restore_response.outputs.is_empty() || restore_response.signatures.is_empty() {
                consecutive_empty_batches += 1;
                counter += BATCH_SIZE;
                continue;
            }

            // Reset gap counter on success
            consecutive_empty_batches = 0;
            total_restore_hits += restore_response.signatures.len() as u32;

            // Unblind signatures and assemble proofs
            for (out, sig) in restore_response
                .outputs
                .iter()
                .zip(restore_response.signatures.iter())
            {
                // Find the matching blinding data by B_ value
                let matching = blinding_data.iter().find(|(secret, r, _)| {
                    if let Ok(b) = crypto::compute_blinded_message(secret, r) {
                        b == out.b_
                    } else {
                        false
                    }
                });

                if let Some((secret, r, _)) = matching {
                    // Get the mint's public key for this amount
                    let amount = sig.amount;
                    let mint_pubkey = match keys.get(&amount) {
                        Some(pk) => pk,
                        None => continue,
                    };

                    // Unblind: C = C_ - r * K
                    match crypto::unblind_signature(&sig.c_, r, mint_pubkey) {
                        Ok(c) => {
                            all_unspent_proofs.push(types::Proof {
                                amount,
                                secret: secret.clone(),
                                c,
                                id: keyset_info.id.clone(),
                            });
                        }
                        Err(_) => continue,
                    }
                }
            }

            counter += BATCH_SIZE;
        }
    }

    // If we couldn't process any keysets, report the errors
    if keysets_processed == 0 && !errors.is_empty() {
        return Err(RestoreError::NetworkError(
            format!("Failed all {} keyset(s): {}", keysets.len(), errors.join("; "))
        ));
    }

    if all_unspent_proofs.is_empty() {
        // Return diagnostic info as an error so the caller can log it
        return Err(RestoreError::MintError(
            format!("No proofs found. keysets={}, processed={}, skipped={}, restore_hits={}, errors=[{}]",
                keysets.len(), keysets_processed, keysets_skipped, total_restore_hits,
                errors.join("; "))
        ));
    }

    // Step 3: Check which proofs are still unspent
    let unspent_proofs = check_and_filter_unspent(&mint_url, &all_unspent_proofs)?;

    if unspent_proofs.is_empty() {
        return Err(RestoreError::MintError(
            format!("All {} proofs are spent", all_unspent_proofs.len())
        ));
    }

    // Step 4: Encode as cashu token v3 string
    let token_str = token::encode_token_v3(&mint_url, &unspent_proofs)?;

    Ok(token_str)
}

/// Convert a v1 base64 keyset ID to a u32 for use in BIP32 derivation path (NUT-13).
///
/// Base64-decodes the keyset ID, interprets the bytes as a big-endian integer,
/// then reduces modulo (2^31 - 1) to fit in a BIP32 hardened child index.
/// This matches cashu-ts's getKeysetIdInt() for legacy keyset IDs.
fn keyset_id_to_int(keyset_id: &str) -> Option<u32> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(keyset_id)
        .ok()?;
    let modulus = i32::MAX as u128;
    let id_int = bytes.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128);
    Some((id_int % modulus) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyset_id_to_int() {
        // v1 base64 keyset IDs
        assert!(keyset_id_to_int("ctv28hTYzQwr").is_some());
        assert!(keyset_id_to_int("9mlfd5vCzgGl").is_some());
    }

    #[test]
    fn test_nut13_derivation_vectors() {
        // NUT-13 test vector: mnemonic "half depart obvious quality work element tank gorilla view sugar picture humble"
        // Full 64-byte BIP39 seed (no passphrase):
        let seed = hex::decode(
            "dd44ee516b0647e80b488e8dcc56d736a148f15276bef588b37057476d4b2b25\
             780d3688a32b37353d6995997842c0fd8b412475c891c16310471fbc86dcbda8"
        ).unwrap();

        let keyset_id_int: u32 = 864559728;

        // Expected secrets and r values for counters 0-4
        let expected = [
            (
                "485875df74771877439ac06339e284c3acfcd9be7abf3bc20b516faeadfe77ae",
                "ad00d431add9c673e843d4c2bf9a778a5f402b985b8da2d5550bf39cda41d679",
            ),
            (
                "8f2b39e8e594a4056eb1e6dbb4b0c38ef13b1b2c751f64f810ec04ee35b77270",
                "967d5232515e10b81ff226ecf5a9e2e2aff92d66ebc3edf0987eb56357fd6248",
            ),
            (
                "bc628c79accd2364fd31511216a0fab62afd4a18ff77a20deded7b858c9860c8",
                "b20f47bb6ae083659f3aa986bfa0435c55c6d93f687d51a01f26862d9b9a4899",
            ),
            (
                "59284fd1650ea9fa17db2b3acf59ecd0f2d52ec3261dd4152785813ff27a33bf",
                "fb5fca398eb0b1deb955a2988b5ac77d32956155f1c002a373535211a2dfdc29",
            ),
            (
                "576c23393a8b31cc8da6688d9c9a96394ec74b40fdaf1f693a6bb84284334ea0",
                "5f09bfbfe27c439a597719321e061e2e40aad4a36768bb2bcc3de547c9644bf9",
            ),
        ];

        for (counter, (expected_secret, expected_r)) in expected.iter().enumerate() {
            let (secret, r) = crypto::derive_secret_and_r(&seed, keyset_id_int, counter as u32)
                .expect("derivation should succeed");

            assert_eq!(&secret, expected_secret, "secret mismatch at counter {}", counter);

            // Convert r scalar back to hex for comparison
            let r_bytes: [u8; 32] = r.to_bytes().into();
            let r_hex = hex::encode(r_bytes);
            assert_eq!(&r_hex, expected_r, "r mismatch at counter {}", counter);
        }
    }
}

/// Check proof states and filter to only unspent proofs.
fn check_and_filter_unspent(
    mint_url: &str,
    proofs: &[types::Proof],
) -> Result<Vec<types::Proof>, RestoreError> {
    // Compute Y = hash_to_curve(secret) for each proof
    let ys: Vec<String> = proofs
        .iter()
        .map(|p| crypto::hash_to_curve_hex(&p.secret))
        .collect::<Result<Vec<_>, _>>()?;

    // POST /v1/checkstate in batches (max ~100 at a time)
    let mut unspent = Vec::new();
    for chunk_start in (0..ys.len()).step_by(100) {
        let chunk_end = std::cmp::min(chunk_start + 100, ys.len());
        let ys_chunk = &ys[chunk_start..chunk_end];
        let proofs_chunk = &proofs[chunk_start..chunk_end];

        let states = mint_api::post_check_state(mint_url, ys_chunk)?;

        for (i, state) in states.iter().enumerate() {
            if state.state == "UNSPENT" {
                if let Some(proof) = proofs_chunk.get(i) {
                    unspent.push(proof.clone());
                }
            }
        }
    }

    Ok(unspent)
}
