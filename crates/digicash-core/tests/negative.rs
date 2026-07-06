//! Negative tests: a coin signature must fail verification under the wrong denomination
//! key, when the signature is tampered, and when the serial is swapped.

use digicash_core::{
    blind, generate_keypair, sign_blinded, unblind, verify, DefaultRng, DenominationKeypair,
    Serial, Signature,
};

fn issue(kp: &DenominationKeypair, serial: &Serial) -> Signature {
    let blinding = blind(&kp.pk, &mut DefaultRng, serial).expect("blind");
    let blind_sig = sign_blinded(&kp.sk, &blinding.blind_message).expect("sign");
    unblind(&kp.pk, &blind_sig, &blinding, serial).expect("unblind")
}

#[test]
fn signature_from_one_key_fails_under_another() {
    let a = generate_keypair(&mut DefaultRng).expect("keygen a");
    let b = generate_keypair(&mut DefaultRng).expect("keygen b");
    let serial = Serial::generate().expect("serial");
    let sig = issue(&a, &serial);

    verify(&a.pk, &serial, &sig).expect("sanity: signature verifies under its own key");
    assert!(
        verify(&b.pk, &serial, &sig).is_err(),
        "signature verified under a different denomination key"
    );
}

#[test]
fn tampered_signature_fails() {
    let kp = generate_keypair(&mut DefaultRng).expect("keygen");
    let serial = Serial::generate().expect("serial");
    let sig = issue(&kp, &serial);

    let mut bytes = sig.0.clone();
    bytes[0] ^= 0x01;
    assert!(
        verify(&kp.pk, &serial, &Signature(bytes)).is_err(),
        "a signature with a flipped byte verified"
    );
}

#[test]
fn signature_over_a_different_serial_fails() {
    let kp = generate_keypair(&mut DefaultRng).expect("keygen");
    let serial = Serial::generate().expect("serial");
    let sig = issue(&kp, &serial);

    let other = Serial::generate().expect("second serial");
    assert!(
        verify(&kp.pk, &other, &sig).is_err(),
        "signature verified over a serial it was not issued for"
    );
}
