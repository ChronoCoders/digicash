use digicash_proto::{
    BalanceResponse, CreateAccountRequest, DenominationsResponse, DepositRequest, DepositResponse,
    WithdrawRequest, WithdrawResponse,
};

use crate::error::WalletError;

/// Blocking HTTP client for a digicash bank.
pub struct BankClient {
    base_url: String,
    agent: ureq::Agent,
}

impl BankClient {
    /// Create a client for the bank at `base_url` (for example `http://127.0.0.1:3000`).
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            agent: ureq::agent(),
        }
    }

    /// `POST /accounts`: create an account and return its balance.
    pub fn create_account(
        &self,
        req: &CreateAccountRequest,
    ) -> Result<BalanceResponse, WalletError> {
        let url = format!("{}/accounts", self.base_url);
        let response = self
            .agent
            .post(&url)
            .send_json(req)
            .map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }

    /// `GET /accounts/{id}/balance`: fetch an account's balance.
    pub fn balance(&self, account_id: &str) -> Result<BalanceResponse, WalletError> {
        let url = format!("{}/accounts/{}/balance", self.base_url, account_id);
        let response = self.agent.get(&url).call().map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }

    /// `GET /denominations`: fetch the bank's published denomination public keys.
    pub fn denominations(&self) -> Result<DenominationsResponse, WalletError> {
        let url = format!("{}/denominations", self.base_url);
        let response = self.agent.get(&url).call().map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }

    /// `POST /withdraw`: submit a blinded message and return the blind signature.
    pub fn withdraw(&self, req: &WithdrawRequest) -> Result<WithdrawResponse, WalletError> {
        let url = format!("{}/withdraw", self.base_url);
        let response = self
            .agent
            .post(&url)
            .send_json(req)
            .map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }

    /// `POST /deposit`: deposit a coin and return whether it was accepted.
    pub fn deposit(&self, req: &DepositRequest) -> Result<DepositResponse, WalletError> {
        let url = format!("{}/deposit", self.base_url);
        let response = self
            .agent
            .post(&url)
            .send_json(req)
            .map_err(|e| http_err(&url, e))?;
        Ok(response.into_json()?)
    }
}

fn http_err(url: &str, source: ureq::Error) -> WalletError {
    WalletError::Http {
        url: url.to_string(),
        source: Box::new(source),
    }
}
