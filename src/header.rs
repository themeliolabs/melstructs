use std::collections::HashSet;

use crate::{Address, BlockHeight, CoinValue, Transaction, TxHash};
use arbitrary::Arbitrary;
use derivative::Derivative;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tmelcrypt::HashVal;

/// Identifies a network.
#[derive(
    Clone,
    Copy,
    IntoPrimitive,
    TryFromPrimitive,
    Eq,
    PartialEq,
    Debug,
    Serialize_repr,
    Deserialize_repr,
    Hash,
    Arbitrary,
)]
#[repr(u8)]
pub enum NetID {
    Testnet = 0x01,
    Custom02 = 0x02,
    Custom03 = 0x03,
    Custom04 = 0x04,
    Custom05 = 0x05,
    Custom06 = 0x06,
    Custom07 = 0x07,
    Custom08 = 0x08,
    Mainnet = 0xff,
}
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash, Arbitrary)]
/// A block header, which commits to a particular SealedState.
pub struct Header {
    pub network: NetID,
    pub previous: HashVal,
    pub height: BlockHeight,
    pub history_hash: HashVal,
    pub coins_hash: HashVal,
    pub transactions_hash: HashVal,
    pub fee_pool: CoinValue,
    pub fee_multiplier: u128,
    pub dosc_speed: u128,
    pub pools_hash: HashVal,
    pub stakes_hash: HashVal,
}

impl Header {
    pub fn hash(&self) -> tmelcrypt::HashVal {
        tmelcrypt::hash_single(&stdcode::serialize(self).unwrap())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
/// A (serialized) block.
pub struct Block {
    pub header: Header,
    pub transactions: HashSet<Transaction>,
    pub proposer_action: Option<ProposerAction>,
}

/// ProposerAction describes the standard action that the proposer takes when proposing a block.
#[derive(Derivative, Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct ProposerAction {
    /// Change in fee. This is scaled to the proper size.
    pub fee_multiplier_delta: i8,
    /// Where to sweep fees.
    pub reward_dest: Address,
}

impl Block {
    /// Abbreviate a block
    pub fn abbreviate(&self) -> AbbrBlock {
        AbbrBlock {
            header: self.header,
            txhashes: self.transactions.iter().map(|v| v.hash_nosigs()).collect(),
            proposer_action: self.proposer_action,
        }
    }
}

/// An abbreviated block
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AbbrBlock {
    pub header: Header,
    pub txhashes: HashSet<TxHash>,
    pub proposer_action: Option<ProposerAction>,
}
