//! digicash wallet: a client library and CLI for withdrawing, spending, and depositing
//! e-cash against a digicash bank. Consumes `digicash-core` (blind/unblind/verify, serials,
//! keys) and `digicash-proto` (coin and wire types). Source of truth: `digicash-spec.md`
//! v0.3.1 section 7.
//!
//! No account authentication in this phase: `account_id` is trusted as supplied.

mod cli;
mod error;

pub use cli::{AccountAction, Cli, Command};
pub use error::WalletError;

/// Dispatch a parsed CLI command.
pub fn run(cli: Cli) -> Result<(), WalletError> {
    match cli.command {
        Command::Account { action } => match action {
            AccountAction::Create { .. } => Err(WalletError::NotImplemented("account create")),
        },
        Command::Balance => Err(WalletError::NotImplemented("balance")),
        Command::Withdraw { .. } => Err(WalletError::NotImplemented("withdraw")),
        Command::Spend { .. } => Err(WalletError::NotImplemented("spend")),
        Command::Deposit { .. } => Err(WalletError::NotImplemented("deposit")),
    }
}
