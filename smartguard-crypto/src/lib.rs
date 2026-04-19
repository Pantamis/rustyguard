mod card;

pub use card::{init_smartcard, list_cards, CardHandle, CardInfo, SmartcardError};
pub use rustyguard_crypto::{
    CryptoCore, CryptoError, CryptoPrimatives, Key, Mac, PublicKey, StaticPrivateKey,
};

use std::cell::RefCell;
use std::collections::HashMap;

/// Sentinel value placed into `StaticInitiatorConfig::private_key`.
/// When `SmartcardCrypto::x25519` sees this, it routes to the smartcard.
/// A random ephemeral key will never collide (probability 2^-256).
pub const SMARTCARD_SENTINEL: StaticPrivateKey = StaticPrivateKey([0u8; 32]);

thread_local! {
    pub(crate) static CARD: RefCell<Option<CardHandle>> = const { RefCell::new(None) };

    /// Cache of precomputed static-static DH results.
    /// Maps peer public key bytes → DH(our_static, peer_static).
    ///
    /// Only peer static keys should be registered here (via `cache_peer_ss`).
    /// Ephemeral keys are never cached, ensuring se/es DH always goes
    /// through the smartcard.
    static SS_CACHE: RefCell<HashMap<[u8; 32], Key>> = RefCell::new(HashMap::new());
}

/// Register a precomputed static-static DH result for a peer.
///
/// Once registered, `SmartcardCrypto::x25519` will return the cached value
/// when called with the sentinel key and this peer's public key, avoiding
/// a smartcard round-trip for the `ss` DH step.
pub fn cache_peer_ss(peer_pk: &PublicKey, ss: Key) {
    SS_CACHE.with_borrow_mut(|c| {
        c.insert(peer_pk.0, ss);
    });
}

/// Remove a cached static-static DH result for a peer.
pub fn clear_peer_ss(peer_pk: &PublicKey) {
    SS_CACHE.with_borrow_mut(|c| {
        c.remove(&peer_pk.0);
    });
}

/// `CryptoPrimatives` implementation that routes static-key DH to a smartcard
/// and delegates everything else to `CryptoCore` (graviola).
pub struct SmartcardCrypto;

impl CryptoPrimatives for SmartcardCrypto {
    fn x25519(secret: &StaticPrivateKey, public: &PublicKey) -> Result<Key, CryptoError> {
        if secret.0 == SMARTCARD_SENTINEL.0 {
            // Check SS cache first — cached static-static DH results
            // bypass the smartcard entirely.
            let cached = SS_CACHE.with_borrow(|c| c.get(&public.0).copied());
            if let Some(ss) = cached {
                return Ok(ss);
            }

            // Not cached (ephemeral peer key) — call smartcard DECIPHER
            CARD.with_borrow_mut(|c| {
                c.as_mut()
                    .expect("smartcard not initialized; call init_smartcard() first")
                    .decipher(&public.0)
                    .map_err(|e| {
                        eprintln!("[smartcard] DH failed: {e}");
                        CryptoError::KeyExchangeError
                    })
            })
        } else {
            // Ephemeral key DH — software (graviola via Core)
            CryptoCore::x25519(secret, public)
        }
    }

    fn x25519_pubkey(secret: &StaticPrivateKey) -> PublicKey {
        if secret.0 == SMARTCARD_SENTINEL.0 {
            // Return cached public key read from card at init
            CARD.with_borrow(|c| {
                PublicKey(
                    c.as_ref()
                        .expect("smartcard not initialized; call init_smartcard() first")
                        .cached_public_key
                        .0,
                )
            })
        } else {
            CryptoCore::x25519_pubkey(secret)
        }
    }

    // --- All non-DH methods delegate to CryptoCore ---

    fn blake2s_hash(left: &[u8], right: &[u8]) -> Key {
        CryptoCore::blake2s_hash(left, right)
    }

    fn blake2s_mac(key: &[u8], msg: &[u8]) -> Mac {
        CryptoCore::blake2s_mac(key, msg)
    }

    fn hmac_blake2s(key: &Key, msg: &[u8]) -> Key {
        CryptoCore::hmac_blake2s(key, msg)
    }

    fn hkdf_blake2s<const N: usize>(key: &mut Key, msg: &[u8], output: &mut [Key; N]) {
        CryptoCore::hkdf_blake2s(key, msg, output)
    }

    fn chacha20poly1305_enc(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        CryptoCore::chacha20poly1305_enc(key, nonce, aad, payload, tag)
    }

    fn chacha20poly1305_dec(
        key: &Key,
        nonce: &[u8; 12],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        CryptoCore::chacha20poly1305_dec(key, nonce, aad, payload, tag)
    }

    fn xchacha20poly1305_enc(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &mut [u8; 16],
    ) {
        CryptoCore::xchacha20poly1305_enc(key, nonce, aad, payload, tag)
    }

    fn xchacha20poly1305_dec(
        key: &Key,
        nonce: &[u8; 24],
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        CryptoCore::xchacha20poly1305_dec(key, nonce, aad, payload, tag)
    }
}
