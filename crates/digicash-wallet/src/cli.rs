use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// digicash wallet command-line interface.
#[derive(Parser)]
#[command(
    name = "digicash-wallet",
    version,
    about = "Withdraw, spend, and deposit digicash e-cash"
)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level wallet commands.
#[derive(Subcommand)]
pub enum Command {
    /// Account operations.
    Account {
        /// The account subcommand.
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Show this wallet's account balance.
    Balance,
    /// Withdraw coins totalling AMOUNT_CENTS from the account.
    Withdraw {
        /// Total to withdraw, in cents.
        amount_cents: u64,
    },
    /// Select coins totalling AMOUNT_CENTS into a bundle file (no bank contact).
    Spend {
        /// Total to spend, in cents.
        amount_cents: u64,
        /// File to write the coin bundle to.
        #[arg(long)]
        out: PathBuf,
    },
    /// Deposit the coins in a bundle file to the bank.
    Deposit {
        /// Bundle file to deposit.
        #[arg(long = "in")]
        input: PathBuf,
    },
}

/// `account` subcommands.
#[derive(Subcommand)]
pub enum AccountAction {
    /// Create this wallet's account with a starting balance (demo credit).
    Create {
        /// The account id to create.
        account_id: String,
        /// Starting balance to credit, in cents.
        #[arg(long, default_value_t = 0)]
        balance: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::{AccountAction, Cli, Command};
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn all_subcommands_parse() {
        let account = Cli::try_parse_from([
            "digicash-wallet",
            "account",
            "create",
            "alice",
            "--balance",
            "1000",
        ])
        .expect("account create");
        match account.command {
            Command::Account {
                action: AccountAction::Create { account_id, balance },
            } => {
                assert_eq!(account_id, "alice");
                assert_eq!(balance, 1000);
            }
            _ => panic!("expected account create"),
        }

        let balance = Cli::try_parse_from(["digicash-wallet", "balance"]).expect("balance");
        assert!(matches!(balance.command, Command::Balance));

        let withdraw =
            Cli::try_parse_from(["digicash-wallet", "withdraw", "576"]).expect("withdraw");
        assert!(matches!(
            withdraw.command,
            Command::Withdraw { amount_cents: 576 }
        ));

        let spend =
            Cli::try_parse_from(["digicash-wallet", "spend", "100", "--out", "bundle.json"])
                .expect("spend");
        match spend.command {
            Command::Spend { amount_cents, out } => {
                assert_eq!(amount_cents, 100);
                assert_eq!(out, PathBuf::from("bundle.json"));
            }
            _ => panic!("expected spend"),
        }

        let deposit = Cli::try_parse_from(["digicash-wallet", "deposit", "--in", "bundle.json"])
            .expect("deposit");
        match deposit.command {
            Command::Deposit { input } => assert_eq!(input, PathBuf::from("bundle.json")),
            _ => panic!("expected deposit"),
        }
    }

    #[test]
    fn spend_requires_out_and_amount() {
        assert!(Cli::try_parse_from(["digicash-wallet", "spend", "100"]).is_err());
        assert!(Cli::try_parse_from(["digicash-wallet", "spend", "--out", "b.json"]).is_err());
    }
}
