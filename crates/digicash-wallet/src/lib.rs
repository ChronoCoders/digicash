//! digicash wallet: a client library and CLI for withdrawing, spending, and depositing
//! e-cash against a digicash bank. Consumes `digicash-core` (blind/unblind/verify, serials,
//! keys) and `digicash-proto` (coin and wire types). Source of truth: `digicash-spec.md`
//! v0.3.1 section 7.
//!
//! No account authentication in this phase: `account_id` is trusted as supplied.

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
pub use wallet::Wallet;

const DEFAULT_BANK_URL: &str = "http://127.0.0.1:3000";
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
                let response = wallet.create_account(&account_id, balance)?;
                writeln!(
                    out,
                    "created account {} with balance {} cents",
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
        Command::Spend { .. } => return Err(WalletError::NotImplemented("spend")),
        Command::Deposit { .. } => return Err(WalletError::NotImplemented("deposit")),
    }
    Ok(())
}
