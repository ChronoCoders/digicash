//! End-to-end tests for digicash: a real bank process serving independent wallet instances
//! over mutual TLS with Ed25519-signed requests, exercising registration, withdraw, spend,
//! deposit, double-spend rejection, restart durability, and the anti-replay / tampered
//! signature / stale timestamp rejections. Test and dev only; not published.
