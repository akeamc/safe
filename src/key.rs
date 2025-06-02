use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use generic_array::{GenericArray, typenum::U32};
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use ssss::SsssConfig;
use zeroize::Zeroize;

#[derive(Debug, Serialize, Deserialize)]
pub struct AeadSssContainer {
    key_shares: Vec<String>,
    #[serde(with = "crate::util::hex_generic_array")]
    nonce: Nonce,
    #[serde(with = "hex::serde")]
    ciphertext: Vec<u8>,
}

fn ssss_config(hand_out: u8) -> SsssConfig {
    *SsssConfig::default()
        .set_threshold(hand_out + 1)
        .set_num_shares(2 * hand_out)
}

#[derive(Debug, thiserror::Error)]
pub enum SplitError {
    #[error("number of shares must be in the range [1, 127]")]
    InvalidKeyCount,
}

/// Splits the given plaintext into shares using secret sharing and encrypts it with ChaCha20-Poly1305.
/// `hand_out` specifies how many shares to hand out to others, and must be in the interval `[1, 127]` or
/// an error will be returned.
pub fn split(
    plaintext: &[u8],
    hand_out: usize,
) -> Result<(AeadSssContainer, Vec<String>), SplitError> {
    let hand_out_u8 = match hand_out {
        1..=127 => hand_out.try_into().expect("should fit in u8"),
        _ => return Err(SplitError::InvalidKeyCount),
    };

    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();

    let key_shares = ssss::gen_shares(&ssss_config(hand_out_u8), &key).unwrap();
    let (handed_out, ours) = key_shares.split_at(hand_out);

    Ok((
        AeadSssContainer {
            key_shares: ours.to_vec(),
            nonce,
            ciphertext,
        },
        handed_out.to_vec(),
    ))
}

impl AeadSssContainer {
    fn unlock_aead_key(&self, final_key_share: String) -> Option<GenericArray<u8, U32>> {
        let mut shares = self.key_shares.clone();
        shares.push(final_key_share);
        let aead_key = ssss::unlock(&shares).ok()?;
        shares.zeroize();
        GenericArray::from_exact_iter(aead_key)
    }

    pub fn decrypt(&self, final_key_share: String) -> Result<SecretSlice<u8>, DecryptError> {
        let mut key = self.unlock_aead_key(final_key_share).ok_or(DecryptError)?;
        let cipher = ChaCha20Poly1305::new(&key);
        key.zeroize();
        cipher
            .decrypt(&self.nonce, self.ciphertext.as_slice())
            .map_err(|_| DecryptError)
            .map(Into::into)
    }

    pub fn roll_secrets(
        &mut self,
        final_secret: String,
        n_secrets: usize,
    ) -> Result<Vec<String>, RollError> {
        let plaintext = self.decrypt(final_secret)?;
        let (new_container, new_secrets) = split(plaintext.expose_secret(), n_secrets)?;
        *self = new_container;
        Ok(new_secrets)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("decryption failed")]
pub struct DecryptError;

#[derive(Debug, thiserror::Error)]
pub enum RollError {
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
    #[error(transparent)]
    Split(#[from] SplitError),
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    #[test]
    fn roundtrip() {
        let plaintext = b"super secret message";
        let (container, shares) = super::split(plaintext, 2).unwrap();

        assert_eq!(
            container
                .decrypt(shares[0].clone())
                .unwrap()
                .expose_secret(),
            plaintext
        );
        assert!(container.decrypt("invalid share".into()).is_err());
    }
}
