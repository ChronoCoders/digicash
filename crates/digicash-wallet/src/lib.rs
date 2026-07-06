//! digicash wallet: a client library and CLI for withdrawing, spending, and depositing
//! e-cash against a digicash bank. Consumes `digicash-core` (blind/unblind/verify, serials,
//! keys, Ed25519 identity) and `digicash-proto` (coin and wire types). Source of truth:
//! `digicash-spec.md` v0.3.1 section 7 and production-spec v1.2 section 2.
//!
//! The wallet registers an Ed25519 identity with the bank (obtaining an mTLS client
//! certificate) and signs every request. `account create` performs the registration; it
//! reads the bank's CA certificate path from `DIGICASH_CA_CERT` to pin the bank.

use std::io::Write;

mod cli;
mod client;
mod error;
mod store;
mod wallet;

#[cfg(test)]
mod testutil;

pub use cli::{AccountAction, Cli, Command};
pub use client::BankClient;
pub use error::WalletError;
pub use store::Store;
pub use wallet::{DepositOutcome, Wallet};

const DEFAULT_BANK_URL: &str = "https://127.0.0.1:3000";
const DEFAULT_ENROLL_URL: &str = "https://127.0.0.1:3001";
const DEFAULT_STORE_PATH: &str = "digicash-wallet-store";

/// Dispatch a parsed CLI command, reading the bank URL and store path from the environment
/// (`DIGICASH_BANK_URL`, `DIGICASH_WALLET_STORE`).
pub fn run(cli: Cli) -> Result<(), WalletError> {
    let bank_url =
        std::env::var("DIGICASH_BANK_URL").unwrap_or_else(|_| DEFAULT_BANK_URL.to_string());
    let store_path =
        std::env::var("DIGICASH_WALLET_STORE").unwrap_or_else(|_| DEFAULT_STORE_PATH.to_string());
    let wallet = Wallet::open(bank_url, store_path)?;
    let mut out = std::io::stdout();

    match cli.command {
        Command::Account { action } => match action {
            AccountAction::Create {
                account_id,
                balance,
            } => {
                let ca_path = std::env::var("DIGICASH_CA_CERT").map_err(|_| {
                    WalletError::Config(
                        "set DIGICASH_CA_CERT to the bank's CA certificate (ca-cert.pem) path"
                            .to_string(),
                    )
                })?;
                let ca_cert_pem = std::fs::read_to_string(&ca_path).map_err(|e| {
                    WalletError::Config(format!("cannot read CA certificate at {ca_path}: {e}"))
                })?;
                let enroll_url = std::env::var("DIGICASH_ENROLL_URL")
                    .unwrap_or_else(|_| DEFAULT_ENROLL_URL.to_string());
                wallet.register(&account_id, &ca_cert_pem, &enroll_url)?;
                let response = wallet.create_account(balance)?;
                writeln!(
                    out,
                    "registered and created account {} with balance {} cents",
                    response.account_id, response.balance_cents
                )?;
            }
        },
        Command::Balance => {
            let response = wallet.balance()?;
            writeln!(out, "{} cents", response.balance_cents)?;
        }
        Command::Withdraw { amount_cents } => {
            let coins = wallet.withdraw(amount_cents)?;
            writeln!(
                out,
                "withdrew {} coins totalling {} cents",
                coins.len(),
                amount_cents
            )?;
        }
        Command::Spend {
            amount_cents,
            out: bundle_path,
        } => {
            let coins = wallet.spend(amount_cents, &bundle_path)?;
            writeln!(
                out,
                "wrote {} coins totalling {} cents to {}",
                coins.len(),
                amount_cents,
                bundle_path.display()
            )?;
        }
        Command::Deposit { input } => {
            let mut credited = 0u64;
            for outcome in wallet.deposit(&input)? {
                if outcome.accepted {
                    credited = credited.saturating_add(outcome.denomination_cents);
                    writeln!(out, "accepted {} cents", outcome.denomination_cents)?;
                } else {
                    writeln!(
                        out,
                        "rejected {} cents: {:?}",
                        outcome.denomination_cents, outcome.reason
                    )?;
                }
            }
            writeln!(out, "credited {credited} cents total")?;
        }
    }
    Ok(())
}
