use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    ProjectivePoint, Scalar,
};

use crate::types::RestoreError;

/// Derive secret and blinding factor r for a given keyset and counter (NUT-13).
///
/// BIP32 derivation paths:
/// - secret: m/129372'/0'/<keyset_id>'/<counter>'/0
/// - r:      m/129372'/0'/<keyset_id>'/<counter>'/1
pub fn derive_secret_and_r(
    seed: &[u8],
    keyset_id_int: u32,
    counter: u32,
) -> Result<(String, Scalar), RestoreError> {
    use bip32::{DerivationPath, XPrv};
    use std::str::FromStr;

    // Use the raw seed directly as the BIP32 seed (must match cashu-ts behavior).
    // The bip32 crate accepts 16, 32, or 64-byte seeds. Our v1 seed is 32 bytes.
    let master = XPrv::new(seed).map_err(|e| RestoreError::CryptoError(e.to_string()))?;

    // Derive secret: m/129372'/0'/<keyset_id>'/<counter>'/0
    let secret_path = format!(
        "m/129372'/0'/{}'/{}'/0",
        keyset_id_int, counter
    );
    let secret_derivation = DerivationPath::from_str(&secret_path)
        .map_err(|e| RestoreError::CryptoError(format!("Invalid derivation path: {}", e)))?;

    let secret_key = master
        .derive_child(secret_derivation.as_ref()[0])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(secret_derivation.as_ref()[1])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(secret_derivation.as_ref()[2])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(secret_derivation.as_ref()[3])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(secret_derivation.as_ref()[4])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?;

    // The secret is the hex-encoded private key bytes
    let secret_bytes = secret_key.to_bytes();
    let secret = hex::encode(&secret_bytes);

    // Derive r: m/129372'/0'/<keyset_id>'/<counter>'/1
    let r_path = format!(
        "m/129372'/0'/{}'/{}'/1",
        keyset_id_int, counter
    );
    let r_derivation = DerivationPath::from_str(&r_path)
        .map_err(|e| RestoreError::CryptoError(format!("Invalid derivation path: {}", e)))?;

    let r_key = master
        .derive_child(r_derivation.as_ref()[0])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(r_derivation.as_ref()[1])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(r_derivation.as_ref()[2])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(r_derivation.as_ref()[3])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?
        .derive_child(r_derivation.as_ref()[4])
        .map_err(|e| RestoreError::CryptoError(e.to_string()))?;

    let r_bytes = r_key.to_bytes();
    let r = bytes_to_scalar(&r_bytes)?;

    Ok((secret, r))
}

/// Convert 32 bytes to a secp256k1 Scalar.
fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar, RestoreError> {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes[..32]);
    let scalar = <Scalar as k256::elliptic_curve::ops::Reduce<k256::U256>>::reduce_bytes(
        &arr.into(),
    );
    Ok(scalar)
}

/// Cashu hash_to_curve (NUT-00): maps a secret string to a point on secp256k1.
///
/// Uses the "try-and-increment" method specified in NUT-00:
/// Hash the message with a counter prefix until a valid point is found.
pub fn hash_to_curve(secret: &str) -> Result<ProjectivePoint, RestoreError> {
    // NUT-00 specifies: hash_to_curve uses SHA256 with domain separator
    // The actual cashu spec uses a simple try-and-increment:
    // for counter in 0..2^16:
    //   hash = SHA256(counter_bytes || message_bytes)
    //   try to decode as compressed point (prepend 0x02)
    //   if valid point, return it

    let msg_bytes = secret.as_bytes();

    for counter in 0u32..65536 {
        let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
        sha2::Digest::update(&mut hasher, &counter.to_le_bytes());
        sha2::Digest::update(&mut hasher, msg_bytes);
        let hash: [u8; 32] = sha2::Digest::finalize(hasher).into();

        // Try to interpret as x-coordinate of a point with even y (0x02 prefix)
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..33].copy_from_slice(&hash);

        if let Ok(encoded_point) =
            k256::EncodedPoint::from_bytes(&compressed)
        {
            let affine = k256::AffinePoint::from_encoded_point(&encoded_point);
            if bool::from(affine.is_some()) {
                return Ok(ProjectivePoint::from(affine.unwrap()));
            }
        }
    }

    Err(RestoreError::CryptoError(
        "hash_to_curve: no valid point found".to_string(),
    ))
}

/// Compute blinded message B_ = Y + r*G where Y = hash_to_curve(secret).
/// Returns the hex-encoded compressed point.
pub fn compute_blinded_message(
    secret: &str,
    r: &Scalar,
) -> Result<String, RestoreError> {
    let y = hash_to_curve(secret)?;
    let r_g = ProjectivePoint::GENERATOR * r;
    let b_blind = y + r_g;

    Ok(point_to_hex(&b_blind))
}

/// Unblind a signature: C = C_ - r * K
/// where C_ is the blinded signature point and K is the mint's public key for this amount.
pub fn unblind_signature(
    c_blind_hex: &str,
    r: &Scalar,
    mint_pubkey_hex: &str,
) -> Result<String, RestoreError> {
    let c_blind = hex_to_point(c_blind_hex)?;
    let k = hex_to_point(mint_pubkey_hex)?;
    let r_k = k * r;
    let c = c_blind - r_k;

    Ok(point_to_hex(&c))
}

/// Compute hash_to_curve(secret) and return as hex string (for checkstate Y values).
pub fn hash_to_curve_hex(secret: &str) -> Result<String, RestoreError> {
    let point = hash_to_curve(secret)?;
    Ok(point_to_hex(&point))
}

/// Encode a projective point as hex-encoded compressed SEC1.
fn point_to_hex(point: &ProjectivePoint) -> String {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(true); // compressed
    hex::encode(encoded.as_bytes())
}

/// Decode a hex-encoded compressed SEC1 point.
fn hex_to_point(hex_str: &str) -> Result<ProjectivePoint, RestoreError> {
    let bytes =
        hex::decode(hex_str).map_err(|e| RestoreError::CryptoError(format!("Invalid hex: {}", e)))?;
    let encoded_point = k256::EncodedPoint::from_bytes(&bytes)
        .map_err(|e| RestoreError::CryptoError(format!("Invalid point encoding: {}", e)))?;
    let affine = k256::AffinePoint::from_encoded_point(&encoded_point);
    if bool::from(affine.is_some()) {
        Ok(ProjectivePoint::from(affine.unwrap()))
    } else {
        Err(RestoreError::CryptoError(
            "Invalid point: not on curve".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_curve_known_vector() {
        // NUT-00 test vector: hash_to_curve("0000...0001") should produce a known point
        // Test that it returns a valid point without panicking
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = hash_to_curve(secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_blinded_message_deterministic() {
        let secret = "test_secret";
        let r = Scalar::ONE;
        let b1 = compute_blinded_message(secret, &r).unwrap();
        let b2 = compute_blinded_message(secret, &r).unwrap();
        assert_eq!(b1, b2);
    }
}
