//! Byte-exact known-answer test against the published RFC 9474
//! RSABSSA-SHA384-PSS-Deterministic test vector (vendored in `rfc9474_vectors.json`).
//!
//! This reproduces the published blinded message, blind signature, and final signature
//! bit-for-bit under the exact variant this crate ships, driving the blinding randomness
//! from the vector so the output is deterministic. It is a real known-answer test, not a
//! freshly generated round-trip. Keys are built from the vector's own components (a
//! 4096-bit key), independent of this crate's 3072-bit `generate_keypair`.

use std::convert::Infallible;

use blind_rsa_signatures::reexports::rsa::rand_core::{TryCryptoRng, TryRng};
use blind_rsa_signatures::reexports::rsa::{BoxedUint, RsaPrivateKey};
use blind_rsa_signatures::SecretKeySha384PSSDeterministic;
use serde::{Deserialize, Deserializer};

#[derive(Deserialize)]
struct Vector {
    name: String,
    #[serde(deserialize_with = "uint")]
    p: BoxedUint,
    #[serde(deserialize_with = "uint")]
    q: BoxedUint,
    #[serde(deserialize_with = "uint")]
    n: BoxedUint,
    #[serde(deserialize_with = "uint")]
    e: BoxedUint,
    #[serde(deserialize_with = "uint")]
    d: BoxedUint,
    #[serde(deserialize_with = "uint")]
    inv: BoxedUint,
    #[serde(deserialize_with = "bytes")]
    msg: Vec<u8>,
    #[serde(deserialize_with = "bytes")]
    salt: Vec<u8>,
    #[serde(deserialize_with = "bytes")]
    blinded_msg: Vec<u8>,
    #[serde(deserialize_with = "bytes")]
    blind_sig: Vec<u8>,
    #[serde(deserialize_with = "bytes")]
    sig: Vec<u8>,
}

fn uint<'de, D: Deserializer<'de>>(d: D) -> Result<BoxedUint, D::Error> {
    let s: String = Deserialize::deserialize(d)?;
    BoxedUint::from_str_radix_vartime(&s[2..], 16).map_err(serde::de::Error::custom)
}

fn bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let mut s: String = Deserialize::deserialize(d)?;
    if s.is_empty() {
        s.push('0');
    }
    BoxedUint::from_str_radix_vartime(&s, 16)
        .map(|b| b.to_be_bytes().to_vec())
        .map_err(serde::de::Error::custom)
}

/// Feeds predetermined byte chunks, one per `fill_bytes` call, so the blinding salt and
/// blinding factor come from the vector rather than the OS.
struct MockRng(Vec<Vec<u8>>);

impl TryRng for MockRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("blinding consumes randomness through fill_bytes only")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("blinding consumes randomness through fill_bytes only")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.copy_from_slice(&self.0.remove(0));
        Ok(())
    }
}

impl TryCryptoRng for MockRng {}

#[test]
fn rfc9474_pss_deterministic_byte_exact() {
    let vectors: Vec<Vector> =
        serde_json::from_str(include_str!("rfc9474_vectors.json")).expect("parse vendored vectors");
    let v = vectors
        .into_iter()
        .find(|v| v.name == "RSABSSA-SHA384-PSS-Deterministic")
        .expect("deterministic vector present in the vendored set");

    // Blinding factor r = inv^-1 mod n, fed after the salt (deterministic: no randomizer).
    let r = v
        .inv
        .invert_mod(&v.n.to_nz().unwrap())
        .unwrap()
        .to_le_bytes()
        .to_vec();
    let mut mock = MockRng(vec![v.salt.clone(), r]);

    let inner = RsaPrivateKey::from_components(
        v.n.clone(),
        v.e.clone(),
        v.d.clone(),
        vec![v.p.clone(), v.q.clone()],
    )
    .expect("build private key from vector components");
    let sk = SecretKeySha384PSSDeterministic::new(inner);
    let pk = sk.public_key().expect("derive public key");

    let blinding = pk.blind(&mut mock, &v.msg).expect("blind");
    assert_eq!(
        blinding.blind_message.0, v.blinded_msg,
        "blinded message does not match the RFC 9474 vector"
    );

    let blind_sig = sk.blind_sign(&blinding.blind_message).expect("blind-sign");
    assert_eq!(
        blind_sig.0, v.blind_sig,
        "blind signature does not match the RFC 9474 vector"
    );

    let sig = pk.finalize(&blind_sig, &blinding, &v.msg).expect("finalize");
    assert_eq!(
        sig.0, v.sig,
        "final signature does not match the RFC 9474 vector"
    );

    pk.verify(&sig, blinding.msg_randomizer, &v.msg)
        .expect("the published signature must verify under the vector key");
}
