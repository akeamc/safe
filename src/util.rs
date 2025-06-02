use std::fmt;

use generic_array::GenericArray;
use serde::Deserialize;
use serde::Serializer;

pub mod hex_generic_array {
    use super::*;
    use serde::{Deserializer, de::Error};

    pub fn serialize<S, N>(value: &GenericArray<u8, N>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        N: generic_array::ArrayLength<u8>,
    {
        let hex_str = hex::encode(value);
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D, N>(deserializer: D) -> Result<GenericArray<u8, N>, D::Error>
    where
        D: Deserializer<'de>,
        N: generic_array::ArrayLength<u8>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(D::Error::custom)?;
        GenericArray::from_exact_iter(bytes)
            .ok_or_else(|| D::Error::custom("Invalid length for GenericArray"))
    }
}

pub struct ColonSeparatedHex<'a>(pub &'a [u8]);

impl fmt::Display for ColonSeparatedHex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ":")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
