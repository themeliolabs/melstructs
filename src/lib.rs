mod txbuilder;
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

#[derive(Debug, Clone)]
pub struct Checkpoint {
    pub height: BlockHeight,
    pub header_hash: HashVal,
}
