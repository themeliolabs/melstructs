use std::{borrow::Cow, fmt::Display};

use arbitrary::Arbitrary;
use derive_more::{
    Add, AddAssign, Display, Div, DivAssign, From, FromStr, Into, Mul, MulAssign, Sub, SubAssign,
    Sum,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;
use tmelcrypt::HashVal;

use crate::{MICRO_CONVERTER, STAKE_EPOCH};

/// Newtype representing a monetary value in microunits. The Display and FromStr implementations divide by 1,000,000 automatically.
#[derive(
    Arbitrary,
    Clone,
    Copy,
    Default,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    From,
    Into,
    Add,
    AddAssign,
    Sub,
    SubAssign,
    Div,
    DivAssign,
    Mul,
    MulAssign,
    Sum,
)]
#[serde(transparent)]
pub struct CoinValue(pub u128);

impl Display for CoinValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{:06}",
            self.0 / MICRO_CONVERTER,
            self.0 % MICRO_CONVERTER
        )
    }
}

#[derive(Error, Debug)]
pub enum CoinValueParseError {
    #[error("cannot parse coinvalue")]
    CannotParse,
}

impl FromStr for CoinValue {
    type Err = CoinValueParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (first_half, second_half) =
            s.split_once('.').ok_or(CoinValueParseError::CannotParse)?;
        let first_half: u128 = first_half
            .trim()
            .parse()
            .ok()
            .ok_or(CoinValueParseError::CannotParse)?;

        // for the second half, we first pad it out to 6 digits, then parse
        let second_half = second_half.trim();
        if second_half.len() > 6 {
            return Err(CoinValueParseError::CannotParse);
        }
        let second_half = if second_half.len() == 6 {
            Cow::Borrowed(second_half)
        } else {
            let mut buf = String::new();
            let count = 6 - second_half.len();
            buf.push_str(second_half);
            for _ in 0..count {
                buf.push('0');
            }
            Cow::Owned(buf)
        };
        let second_half: u128 = second_half
            .parse()
            .ok()
            .ok_or(CoinValueParseError::CannotParse)?;

        if second_half >= 1_000_000 {
            return Err(CoinValueParseError::CannotParse);
        }
        Ok(CoinValue(
            first_half
                .checked_mul(1_000_000)
                .ok_or(CoinValueParseError::CannotParse)?
                .checked_add(second_half)
                .ok_or(CoinValueParseError::CannotParse)?,
        ))
    }
}

impl CoinValue {
    /// Converts from an integer value of millions of microunits.
    pub fn from_millions(i: impl Into<u64>) -> Self {
        let i: u64 = i.into();
        Self(i as u128 * MICRO_CONVERTER)
    }

    /// Checked addition.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

/// Newtype representing a block height.
#[derive(
    Arbitrary,
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    From,
    Into,
    Add,
    AddAssign,
    Sub,
    SubAssign,
    Display,
    FromStr,
    Div,
    DivAssign,
    Mul,
    MulAssign,
)]
#[serde(transparent)]
pub struct BlockHeight(pub u64);

impl BlockHeight {
    /// Epoch of this height
    pub fn epoch(&self) -> u64 {
        self.0 / STAKE_EPOCH
    }
}

/// An address is the hash of a MelVM covenant. In Bitcoin terminology, all Themelio addresses are "pay-to-script-hash".
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    PartialOrd,
    Ord,
    From,
    Into,
    Serialize,
    Deserialize,
    Arbitrary,
)]
pub struct Address(#[serde(with = "stdcode::asstr")] pub HashVal);

impl Address {
    /// Returns the address that represents destruction of a coin.
    pub fn coin_destroy() -> Self {
        Address(Default::default())
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.to_addr().fmt(f)
    }
}

impl FromStr for Address {
    type Err = AddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HashVal::from_addr(s)
            .ok_or(AddrParseError::CannotParse)
            .map(|v| v.into())
    }
}

#[derive(Error, Debug)]
pub enum AddrParseError {
    #[error("cannot parse covhash address")]
    CannotParse,
}

#[cfg(test)]
mod tests {
    use crate::CoinValue;

    #[test]
    fn coinvalue_parse() {
        let s = "12345.99";
        let cv: CoinValue = s.parse().unwrap();
        dbg!(cv.to_string());
    }
}
