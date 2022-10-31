use std::collections::BTreeMap;

use crate::CoinValue;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tmelcrypt::Ed25519PK;

/// StakeDoc is a stake document. It encapsulates all the information needed to verify consensus proofs.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct StakeDoc {
    /// Public key.
    pub pubkey: Ed25519PK,
    /// Starting epoch.
    pub e_start: u64,
    /// Ending epoch. This is the epoch *after* the last epoch in which the syms are effective.
    pub e_post_end: u64,
    /// Number of syms staked.
    pub syms_staked: CoinValue,
}

/// A consensus proof is a mapping from signing key to signature.
pub type ConsensusProof = BTreeMap<Ed25519PK, Bytes>;
