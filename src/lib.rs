mod txbuilder;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tmelcrypt::HashVal;
pub use txbuilder::*;
mod units;
pub use units::*;
mod constants;
pub use constants::*;
mod transaction;
pub use transaction::*;

mod stake;
pub use stake::*;
mod melswap;
pub use melswap::*;
mod header;
pub use header::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: BlockHeight,
    pub header_hash: HashVal,
}

#[derive(Error, Debug)]
pub enum ParseCheckpointError {
    #[error("expected a ':' character to split the height and header hash")]
    ParseSplitError,
    #[error("height is not an integer")]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("failed to parse header hash as a hash")]
    ParseHeaderHash(#[from] hex::FromHexError),
}

impl FromStr for Checkpoint {
    type Err = ParseCheckpointError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (height_str, hash_str) = s
            .split_once(':')
            .ok_or(ParseCheckpointError::ParseSplitError)?;

        let height = BlockHeight::from_str(height_str)?;
        let header_hash = HashVal::from_str(hash_str)?;

        Ok(Self {
            height,
            header_hash,
        })
    }
}
