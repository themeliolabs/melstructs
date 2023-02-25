use crate::{Address, CoinData, CoinID, CoinValue, Denom, Transaction, TxKind};

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use tap::Pipe;
use thiserror::Error;
use tmelcrypt::Hashable;

#[derive(Error, Debug, Clone)]
pub enum TransactionBuildError {
    #[error("not well-formed")]
    NotWellFormed,
    #[error("inputs and outputs unbalanced")]
    Unbalanced,
    #[error("missing a covenant with hash {0}")]
    MissingCovenant(Address),
}

/// A helper struct for creating transactions.
#[derive(Debug)]
pub struct TransactionBuilder {
    in_progress: Transaction,
    required_covenants: BTreeSet<Address>,
    given_covenants: BTreeSet<Address>,
    in_balance: BTreeMap<Denom, CoinValue>,
    out_balance: BTreeMap<Denom, CoinValue>,
}

impl TransactionBuilder {
    /// Creates a new TransactionBuilder.
    pub fn new() -> Self {
        let in_progress = Transaction::default();
        TransactionBuilder {
            in_progress,
            required_covenants: BTreeSet::new(),
            given_covenants: BTreeSet::new(),
            in_balance: BTreeMap::new(),
            out_balance: BTreeMap::new(),
        }
    }

    /// Sets the kind.
    pub fn kind(mut self, kind: TxKind) -> Self {
        self.in_progress.kind = kind;
        self
    }

    /// Adds an input. A CoinData must be provided.
    pub fn input(mut self, coin_id: CoinID, coin_data: CoinData) -> Self {
        self.in_progress.inputs.push(coin_id);
        *self.in_balance.entry(coin_data.denom).or_default() += coin_data.value;
        self.required_covenants.insert(coin_data.covhash);
        self
    }

    /// Adds an output.
    pub fn output(mut self, data: CoinData) -> Self {
        if data.denom != Denom::NewCustom {
            *self.out_balance.entry(data.denom).or_default() += data.value;
        }
        self.in_progress.outputs.push(data);
        self
    }

    /// Adds a covenant script.
    pub fn covenant(mut self, script: Bytes) -> Self {
        self.given_covenants.insert(Address(script.hash()));
        self.in_progress.covenants.push(script);
        self
    }

    /// Adds a fee.
    pub fn fee(mut self, fee: CoinValue) -> Self {
        *self.out_balance.entry(Denom::Mel).or_default() += fee;
        self.in_progress.fee += fee;
        self
    }

    /// "Automatically" adds the base fee. An upper-bound for the number of signatures and the size of each signature is required.
    pub fn auto_base_fee(
        self,
        fee_multiplier: u128,
        max_sig_count: usize,
        max_sig_size: usize,
        cov_to_weight: impl Fn(&[u8]) -> u128,
    ) -> Self {
        let fee = self.in_progress.clone().pipe(|mut tx| {
            let range = 0..max_sig_count;

            range
                .into_iter()
                .for_each(|_index| tx.sigs.push(vec![0; max_sig_size].into()));

            tx.base_fee(fee_multiplier, 0, cov_to_weight)
        });
        self.fee(fee)
    }

    /// Balance the transaction on the given denomination. Sends any excess to a change output.
    pub fn change(mut self, denom: Denom, change_addr: Address) -> Self {
        let input = self.in_balance.get(&denom).copied().unwrap_or_default();
        let output = self.out_balance.get(&denom).copied().unwrap_or_default();
        if input >= output {
            let delta = input - output;
            self = self.output(CoinData {
                covhash: change_addr,
                value: delta,
                denom,
                additional_data: vec![].into(),
            });
        }
        self
    }

    /// Attempts to generate the transaction.
    pub fn build(self) -> Result<Transaction, TransactionBuildError> {
        if self.in_balance != self.out_balance && self.in_progress.kind != TxKind::Faucet {
            Err(TransactionBuildError::Unbalanced)
        } else if !self.in_progress.is_well_formed() {
            Err(TransactionBuildError::NotWellFormed)
        } else {
            let was_covenant_creation_successful: Result<(), TransactionBuildError> =
                self.required_covenants.iter().try_for_each(|cov| {
                    let is_covenant_missing_from_given_covenants: bool =
                        !self.given_covenants.contains(cov);

                    match is_covenant_missing_from_given_covenants {
                        true => Err(TransactionBuildError::MissingCovenant(*cov)),
                        false => Ok(()),
                    }
                });

            match was_covenant_creation_successful {
                Ok(()) => Ok(self.in_progress),
                Err(error) => Err(error),
            }
        }
    }

    /// Sets the associated data.
    pub fn data(mut self, data: Bytes) -> Self {
        self.in_progress.data = data;
        self
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txbuilder_basic_balance() {
        let init_coindata = CoinData {
            denom: Denom::Mel,
            value: CoinValue::from_millions(1000u64),
            additional_data: vec![].into(),
            covhash: Address::coin_destroy(),
        };
        TransactionBuilder::new()
            .input(CoinID::zero_zero(), init_coindata)
            .fee(20000.into())
            .output(CoinData {
                covhash: Address::coin_destroy(),
                value: 1000.into(),
                denom: Denom::Mel,
                additional_data: vec![].into(),
            })
            .change(Denom::Mel, Address::coin_destroy())
            .build()
            .expect_err("build failed");
    }
}
