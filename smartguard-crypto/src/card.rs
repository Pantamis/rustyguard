use card_backend_pcsc::PcscBackend;
use openpgp_card::{
    ocard::{
        crypto::{Cryptogram, PublicKeyMaterial},
        KeyType::Decryption,
    },
    state::Open,
    Card,
};
use rustyguard_crypto::{Key, PublicKey};
use secrecy::SecretString;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::CARD;

/// Information about a connected OpenPGP card with an X25519 decryption key.
pub struct CardInfo {
    pub ident: String,
    pub public_key: [u8; 32],
}

/// Enumerate all connected OpenPGP cards that have an X25519 decryption key.
///
/// Returns card identifiers and their public keys without verifying any PIN.
pub fn list_cards() -> Result<Vec<CardInfo>, SmartcardError> {
    let mut cards = Vec::new();
    for backend in PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))? {
        let backend = match backend {
            Ok(b) => b,
            Err(_) => continue,
        };
        let mut card = match Card::new(backend) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut tx = match card.transaction() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let ident = match tx.application_identifier() {
            Ok(ai) => ai.ident(),
            Err(_) => continue,
        };
        let pk = match tx.public_key_material(Decryption) {
            Ok(PublicKeyMaterial::E(ecc)) if ecc.data().len() == 32 => {
                let mut buf = [0u8; 32];
                buf.copy_from_slice(ecc.data());
                buf
            }
            _ => continue,
        };
        cards.push(CardInfo {
            ident,
            public_key: pk,
        });
    }
    Ok(cards)
}

#[derive(Error, Debug)]
pub enum SmartcardError {
    #[error("card not found: {0}")]
    CardNotFound(String),
    #[error("card does not have an X25519 decryption key")]
    NoDecryptionKey,
    #[error("PIN verification failed: {0}")]
    PinFailed(String),
    #[error("DH operation failed: {0}")]
    DhFailed(String),
    #[error("card communication error: {0}")]
    CardError(String),
    #[error("shared secret is zero (invalid peer public key)")]
    ZeroSharedSecret,
}

pub struct CardHandle {
    card: Card<Open>,
    pub cached_public_key: PublicKey,
    pub ident: String,
    pin: String,
}

impl CardHandle {
    /// Perform X25519 ECDH on the smartcard via the DECIPHER command.
    ///
    /// Opens a transaction, re-verifies the PIN, sends the peer's public key
    /// to the card's decryption slot, and returns the 32-byte shared secret.
    /// If the card connection is stale (e.g. scdaemon reclaimed it),
    /// automatically reconnects and retries once.
    pub fn decipher(&mut self, peer_public_key: &[u8; 32]) -> Result<Key, SmartcardError> {
        match self.try_decipher(peer_public_key) {
            Ok(result) => Ok(result),
            Err(_) => {
                // Connection may be stale — try to reconnect
                eprintln!("[smartcard] reconnecting to card {}...", self.ident);
                self.reconnect()?;
                self.try_decipher(peer_public_key)
            }
        }
    }

    fn try_decipher(&mut self, peer_public_key: &[u8; 32]) -> Result<Key, SmartcardError> {
        let mut tx = self
            .card
            .transaction()
            .map_err(|e| SmartcardError::CardError(e.to_string()))?;

        // PIN must be verified each transaction
        tx.verify_user_pin(SecretString::new(self.pin.clone()))
            .map_err(|e| SmartcardError::PinFailed(e.to_string()))?;

        // DECIPHER: send peer public key, card returns shared secret
        let shared_secret = tx
            .card()
            .decipher(Cryptogram::ECDH(peer_public_key))
            .map_err(|e| SmartcardError::DhFailed(e.to_string()))?;

        // Validate shared secret is non-zero (constant-time)
        let is_zero: bool = shared_secret
            .iter()
            .fold(0u8, |acc, b| acc | b)
            .ct_eq(&0u8)
            .into();
        if is_zero {
            return Err(SmartcardError::ZeroSharedSecret);
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&shared_secret);
        Ok(result)
    }

    /// Re-open the card connection by scanning for the same card identity.
    fn reconnect(&mut self) -> Result<(), SmartcardError> {
        for backend in
            PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))?
        {
            let backend = match backend {
                Ok(b) => b,
                Err(_) => continue,
            };
            let mut card = match Card::new(backend) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let tx = match card.transaction() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let ident = match tx.application_identifier() {
                Ok(ai) => ai.ident(),
                Err(_) => continue,
            };
            if ident == self.ident {
                drop(tx);
                self.card = card;
                eprintln!("[smartcard] reconnected to {}", self.ident);
                return Ok(());
            }
        }
        Err(SmartcardError::CardNotFound(self.ident.clone()))
    }
}

/// Initialize the thread-local smartcard handle.
///
/// Enumerates PC/SC card readers, finds the card matching `ident` (or the
/// first card with an X25519 decryption key if `ident` is `"auto"`),
/// reads its public key, verifies the PIN, and stores the handle.
pub fn init_smartcard(ident: &str, pin: &str) -> Result<PublicKey, SmartcardError> {
    for backend in PcscBackend::cards(None).map_err(|e| SmartcardError::CardError(e.to_string()))? {
        let backend = backend.map_err(|e| SmartcardError::CardError(e.to_string()))?;
        let mut card = Card::new(backend).map_err(|e| SmartcardError::CardError(e.to_string()))?;

        let mut tx = card
            .transaction()
            .map_err(|e| SmartcardError::CardError(e.to_string()))?;

        let card_ident = tx
            .application_identifier()
            .map_err(|e| SmartcardError::CardError(e.to_string()))?
            .ident();

        if ident != "auto" && ident != card_ident {
            continue;
        }

        // Read public key from the decryption slot
        let pk_bytes = match tx
            .public_key_material(Decryption)
            .map_err(|e| SmartcardError::CardError(e.to_string()))?
        {
            PublicKeyMaterial::E(ecc) => {
                let data = ecc.data();
                if data.len() != 32 {
                    if ident == "auto" {
                        continue;
                    }
                    return Err(SmartcardError::NoDecryptionKey);
                }
                let mut buf = [0u8; 32];
                buf.copy_from_slice(data);
                buf
            }
            _ => {
                if ident == "auto" {
                    continue;
                }
                return Err(SmartcardError::NoDecryptionKey);
            }
        };

        // Verify PIN
        tx.verify_user_pin(SecretString::new(pin.to_string()))
            .map_err(|e| SmartcardError::PinFailed(e.to_string()))?;

        // Must drop transaction before moving card into CardHandle
        drop(tx);

        CARD.set(Some(CardHandle {
            card,
            cached_public_key: PublicKey(pk_bytes),
            ident: card_ident,
            pin: pin.to_string(),
        }));

        return Ok(PublicKey(pk_bytes));
    }

    Err(SmartcardError::CardNotFound(ident.to_string()))
}
