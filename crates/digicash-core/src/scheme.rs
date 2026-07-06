use blind_rsa_signatures::reexports::rsa::rand_core::CryptoRng;
use blind_rsa_signatures::{
    KeyPairSha384PSSDeterministic, PublicKeySha384PSSDeterministic,
    SecretKeySha384PSSDeterministic,
};

use crate::error::CoreError;

/// RSA modulus size, in bits, for every denomination key (spec v0.2 section 3).
pub const MODULUS_BITS: usize = 3072;

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

#[cfg(test)]
mod tests {
    use super::{generate_keypair, MODULUS_BITS};
    use crate::DefaultRng;

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
}
