use blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng;
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, KeyPairSha384PSSDeterministic,
    PublicKeySha384PSSDeterministic, SecretKeySha384PSSDeterministic, Signature,
};

use crate::error::CoreError;
use crate::serial::Serial;

/// RSA modulus size, in bits, for every denomination key (spec v0.2 section 3).
pub const MODULUS_BITS: usize = 3072;

/// `scheme_id` of the online RSA coin: RSABSSA-SHA384-PSS-Deterministic per RFC 9474.
///
/// This is the single source of truth for the value; the proto and bank crates reference
/// it rather than restating `0` (spec v0.2 section 4).
pub const SCHEME_ID_RSA_DETERMINISTIC: u8 = 0;

/// A denomination keypair: RSABSSA-SHA384-PSS-Deterministic, 3072-bit.
pub type DenominationKeypair = KeyPairSha384PSSDeterministic;
/// The public half of a denomination key, used to blind and to verify.
pub type DenominationPublicKey = PublicKeySha384PSSDeterministic;
/// The private half, held only by the bank, used to blind-sign.
pub type DenominationSecretKey = SecretKeySha384PSSDeterministic;

/// Generate a fresh 3072-bit denomination keypair from `rng`.
///
/// `rng` must be a cryptographically secure generator; [`blind_rsa_signatures::DefaultRng`]
/// (re-exported as [`crate::DefaultRng`]) is the default.
pub fn generate_keypair<R: CryptoRng + ?Sized>(
    rng: &mut R,
) -> Result<DenominationKeypair, CoreError> {
    DenominationKeypair::generate(rng, MODULUS_BITS).map_err(CoreError::KeyGeneration)
}

/// Accept only the one scheme this crate implements; reject any other `scheme_id`.
pub fn ensure_supported_scheme(scheme_id: u8) -> Result<(), CoreError> {
    if scheme_id == SCHEME_ID_RSA_DETERMINISTIC {
        Ok(())
    } else {
        Err(CoreError::UnsupportedScheme(scheme_id))
    }
}

/// Blind `serial` under `pk` so the bank can sign it without seeing it.
pub fn blind<R: CryptoRng + ?Sized>(
    pk: &DenominationPublicKey,
    rng: &mut R,
    serial: &Serial,
) -> Result<BlindingResult, CoreError> {
    pk.blind(rng, serial.as_bytes()).map_err(CoreError::Blinding)
}

/// Blind-sign a blinded message with the denomination secret key.
pub fn sign_blinded(
    sk: &DenominationSecretKey,
    blinded: &BlindMessage,
) -> Result<BlindSignature, CoreError> {
    sk.blind_sign(blinded).map_err(CoreError::Signing)
}

/// Unblind a blind signature into a coin signature over `serial`.
///
/// The underlying `finalize` verifies the signature before returning it, so a successful
/// result is already a valid signature over `serial`.
pub fn unblind(
    pk: &DenominationPublicKey,
    blind_sig: &BlindSignature,
    blinding: &BlindingResult,
    serial: &Serial,
) -> Result<Signature, CoreError> {
    pk.finalize(blind_sig, blinding, serial.as_bytes())
        .map_err(CoreError::Unblinding)
}

/// Verify a coin signature over `serial` under `pk`.
pub fn verify(
    pk: &DenominationPublicKey,
    serial: &Serial,
    sig: &Signature,
) -> Result<(), CoreError> {
    // Deterministic variant: no message randomizer, so verification passes None.
    pk.verify(sig, None, serial.as_bytes())
        .map_err(CoreError::Verification)
}

#[cfg(test)]
mod tests {
    use super::{
        blind, ensure_supported_scheme, generate_keypair, sign_blinded, unblind, verify,
        MODULUS_BITS, SCHEME_ID_RSA_DETERMINISTIC,
    };
    use crate::{CoreError, DefaultRng, Serial};

    #[test]
    fn keypair_is_3072_bit_and_public_key_derives() {
        let kp = generate_keypair(&mut DefaultRng).expect("keygen should succeed");
        assert_eq!(
            kp.pk.components().n().len(),
            MODULUS_BITS / 8,
            "denomination modulus is not 3072-bit"
        );
        let derived = kp.sk.public_key().expect("public key derives from secret key");
        assert_eq!(
            kp.pk.to_der().expect("bundled public key to DER"),
            derived.to_der().expect("derived public key to DER"),
            "public key derived from the secret key disagrees with the bundled one"
        );
    }

    #[test]
    fn blind_sign_unblind_verify_round_trip() {
        let kp = generate_keypair(&mut DefaultRng).expect("keygen");
        let serial = Serial::generate().expect("serial");
        let blinding = blind(&kp.pk, &mut DefaultRng, &serial).expect("blind");
        let blind_sig = sign_blinded(&kp.sk, &blinding.blind_message).expect("sign");
        let sig = unblind(&kp.pk, &blind_sig, &blinding, &serial).expect("unblind");
        verify(&kp.pk, &serial, &sig).expect("the unblinded signature must verify");
    }

    #[test]
    fn only_scheme_zero_is_supported() {
        assert!(ensure_supported_scheme(SCHEME_ID_RSA_DETERMINISTIC).is_ok());
        for id in [1u8, 2, 42, 255] {
            match ensure_supported_scheme(id) {
                Err(CoreError::UnsupportedScheme(got)) => assert_eq!(got, id),
                other => panic!("scheme_id {id} should be rejected, got {other:?}"),
            }
        }
    }
}
