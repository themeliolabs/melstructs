use std::{fmt::Display, str::FromStr};

use bytes::Bytes;
use num::{rational::Ratio, BigInt, BigRational, BigUint};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Denom, ParseDenomError, MICRO_CONVERTER};

/// The internal status of a Melswap pool. Notably, this *does not* identify which pool this is, or even what tokens are the "lefts" and "rights".
#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct PoolState {
    /// How many "left-hand" tokens (the token with the lexicographically smaller Denom) are there in the pool, in microunits.
    pub lefts: u128,
    /// How many "right-hand" tokens are there in the pool.
    pub rights: u128,
    /// A Uniswap-like TWAP of the price. TODO document this more
    pub price_accum: u128,
    /// How many liquidity tokens have been issued
    pub liqs: u128,
}

impl PoolState {
    /// Creates a new empty pool.
    pub fn new_empty() -> Self {
        Self {
            lefts: 0,
            rights: 0,
            price_accum: 0,
            liqs: 0,
        }
    }

    /// Executes a swap.
    #[must_use]
    pub fn swap_many(&mut self, lefts: u128, rights: u128) -> (u128, u128) {
        // deposit the tokens. intentionally saturate so that "overflowing" tokens are drained.
        self.lefts = self.lefts.saturating_add(lefts);
        self.rights = self.rights.saturating_add(rights);
        // "indiscriminately" use this new price to calculate how much of the other token to withdraw.
        let exchange_rate = Ratio::new(BigInt::from(self.lefts), BigInt::from(self.rights));
        let rights_to_withdraw: u128 = (BigRational::from(BigInt::from(lefts))
            / exchange_rate.clone()
            * BigRational::from(BigInt::from(995))
            / BigRational::from(BigInt::from(1000)))
        .floor()
        .numer()
        .try_into()
        .unwrap_or(u128::MAX);
        let lefts_to_withdraw: u128 = (BigRational::from(BigInt::from(rights))
            * exchange_rate
            * BigRational::from(BigInt::from(995))
            / BigRational::from(BigInt::from(1000)))
        .floor()
        .numer()
        .try_into()
        .unwrap_or(u128::MAX);
        // do the withdrawal
        self.lefts -= lefts_to_withdraw;
        self.rights -= rights_to_withdraw;

        self.price_accum = self
            .price_accum
            .overflowing_add((self.lefts).saturating_mul(MICRO_CONVERTER) / (self.rights))
            .0;

        (lefts_to_withdraw, rights_to_withdraw)
    }

    /// Deposits a set amount into the state, returning how many liquidity tokens were created.
    #[must_use]
    pub fn deposit(&mut self, lefts: u128, rights: u128) -> u128 {
        if self.liqs == 0 {
            self.lefts = lefts;
            self.rights = rights;
            self.liqs = lefts;
            lefts
        } else {
            // we first truncate mels and tokens because they can't overflow the state
            let mels = lefts.saturating_add(self.lefts) - self.lefts;
            let tokens = rights.saturating_add(self.rights) - self.rights;

            let delta_l_squared = (BigRational::from(BigInt::from(self.liqs).pow(2))
                * Ratio::new(
                    BigInt::from(mels) * BigInt::from(tokens),
                    BigInt::from(self.lefts) * BigInt::from(self.rights),
                ))
            .floor()
            .numer()
            .clone();
            let delta_l = delta_l_squared.sqrt();
            let delta_l = delta_l
                .to_biguint()
                .expect("deltaL can't possibly be negative");
            // we first convert deltaL to a u128, saturating on overflow
            let delta_l: u128 = delta_l.try_into().unwrap_or(u128::MAX);
            self.liqs = self.liqs.saturating_add(delta_l);
            self.lefts += mels;
            self.rights += tokens;
            // now we return
            delta_l
        }
    }

    /// Redeems a set amount of liquidity tokens, returning lefts and rights.
    #[must_use]
    pub fn withdraw(&mut self, liqs: u128) -> (u128, u128) {
        assert!(self.liqs >= liqs);
        let withdrawn_fraction = Ratio::new(BigUint::from(liqs), BigUint::from(self.liqs));
        let lefts =
            Ratio::new(BigUint::from(self.lefts), BigUint::from(1u32)) * withdrawn_fraction.clone();
        let rights =
            Ratio::new(BigUint::from(self.rights), BigUint::from(1u32)) * withdrawn_fraction;
        self.liqs -= liqs;
        if self.liqs == 0 {
            let toret = (self.lefts, self.rights);
            self.lefts = 0;
            self.rights = 0;
            toret
        } else {
            let toret = (
                lefts.floor().numer().try_into().unwrap(),
                rights.floor().numer().try_into().unwrap(),
            );
            self.lefts -= toret.0;
            self.rights -= toret.1;
            toret
        }
    }

    /// Returns the implied price as lefts per right.
    #[must_use]
    pub fn implied_price(&self) -> BigRational {
        Ratio::new(BigInt::from(self.lefts), BigInt::from(self.rights))
    }
    /// Returns the liquidity constant of the system.
    #[must_use]
    pub fn liq_constant(&self) -> u128 {
        self.lefts.saturating_mul(self.rights)
    }
}

/// A key identifying a pool.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct PoolKey {
    left: Denom,
    right: Denom,
}

impl Display for PoolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format!("{}/{}", self.left, self.right).fmt(f)
    }
}

impl FromStr for PoolKey {
    type Err = ParseDenomError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let splitted = s.split('/').collect::<Vec<_>>();
        if splitted.len() != 2 {
            Err(ParseDenomError::Invalid)
        } else {
            let left: Denom = splitted[0].parse()?;
            let right: Denom = splitted[1].parse()?;
            if left == right {
                return Err(ParseDenomError::Invalid);
            }
            Ok(PoolKey::new(left, right))
        }
    }
}

impl PoolKey {
    /// Pool key with two tokens. Panics if the two denoms are the same!
    pub fn new(x: Denom, y: Denom) -> Self {
        Self { left: x, right: y }.to_canonical().unwrap()
    }

    /// Gets the left-hand token denom.
    pub fn left(&self) -> Denom {
        self.left
    }

    /// Gets the right-hand token denom.
    pub fn right(&self) -> Denom {
        self.right
    }

    /// Ensures that this pool key is canonical. If the two denoms are the same, returns None.
    #[allow(clippy::comparison_chain)]
    fn to_canonical(self) -> Option<Self> {
        if self.left.to_bytes() < self.right.to_bytes() {
            Some(Self {
                left: self.left,
                right: self.right,
            })
        } else if self.left.to_bytes() > self.right.to_bytes() {
            Some(Self {
                left: self.right,
                right: self.left,
            })
        } else {
            None
        }
    }

    /// Denomination of the pool-liquidity token corresponding to this PoolKey.
    pub fn liq_token_denom(&self) -> Denom {
        Denom::Custom(tmelcrypt::hash_keyed(b"liq", self.to_bytes()).into())
    }

    /// Converts to the byte representation.
    pub fn to_bytes(self) -> Bytes {
        if self.left == Denom::Mel {
            self.right.to_bytes()
        } else if self.right == Denom::Mel {
            self.left.to_bytes()
        } else {
            let mut v = vec![0u8; 32];
            v.extend_from_slice(&stdcode::serialize(&(self.left, self.right)).unwrap());
            v.into()
        }
    }

    pub fn from_bytes(vec: &[u8]) -> Option<Self> {
        if vec.len() > 32 {
            // first 32 bytes must all be zero
            if vec[..32] != [0u8; 32] {
                None
            } else {
                let lr: (Denom, Denom) = stdcode::deserialize(&vec[32..]).ok()?;
                Some(Self {
                    left: lr.0,
                    right: lr.1,
                })
            }
        } else {
            Some(
                Self {
                    left: Denom::Mel,
                    right: Denom::from_bytes(vec)?,
                }
                .to_canonical()?,
            )
        }
    }
}

impl Serialize for PoolKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PoolKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inner = <Vec<u8>>::deserialize(deserializer)?;
        PoolKey::from_bytes(&inner)
            .ok_or_else(|| serde::de::Error::custom("not the right format for a PoolKey"))
    }
}
