use std::fmt;

use generic_array::GenericArray;
use prost_types::Timestamp;
use serde::Deserialize;
use serde::Serializer;
use time::OffsetDateTime;

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

pub fn write_colon_separated_hex(bytes: &[u8], f: &mut impl fmt::Write) -> fmt::Result {
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            f.write_char(':')?;
        }
        write!(f, "{:02x}", byte)?;
    }

    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ParseHexError {
    #[error("invalid length for hex string")]
    InvalidLength,
    #[error("invalid character in hex string")]
    InvalidCharacter,
}

pub fn parse_colon_separated_hex(s: &str, buf: &mut [u8]) -> Result<(), ParseHexError> {
    let iter = s.split(':').map(|part| u8::from_str_radix(part, 16));

    // ensure length matches
    if iter.clone().count() != buf.len() {
        return Err(ParseHexError::InvalidLength);
    }

    for (i, byte) in iter.enumerate() {
        match byte {
            Ok(b) => buf[i] = b,
            Err(_) => return Err(ParseHexError::InvalidCharacter),
        }
    }

    Ok(())
}

pub(crate) trait IntoTimeType {
    type Out;

    fn into_time_type(self) -> Self::Out;
}

impl IntoTimeType for Timestamp {
    type Out = OffsetDateTime;

    fn into_time_type(self) -> Self::Out {
        let nanos = i128::from(self.seconds) * 1_000_000_000 + i128::from(self.nanos);
        OffsetDateTime::from_unix_timestamp_nanos(nanos).unwrap()
    }
}

impl IntoTimeType for prost_types::Duration {
    type Out = time::Duration;

    fn into_time_type(self) -> Self::Out {
        time::Duration::seconds(self.seconds) + time::Duration::nanoseconds(i64::from(self.nanos))
    }
}
