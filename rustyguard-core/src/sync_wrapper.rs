use core::net::SocketAddr;

use rand_core::CryptoRng;
use rustyguard_crypto::{DhOracle, StaticPrivateKey};
use rustyguard_utils::async_convert;
use tai64::Tai64N;

use crate::{Config, Error, MaintenanceMsg, Message, PeerId, SendMessage, Sessions};

/// Synchronous wrapper around [`Sessions`].
///
/// Provide [`Sessions`] methods without async coloring
/// when DH oracle is sync.
#[non_exhaustive]
pub struct SyncSessions<O: DhOracle = StaticPrivateKey> {
    /// The underlying asynchronous [`Sessions`]. Borrow it to drive the `async`
    /// API on the very same state this wrapper manages synchronously.
    pub asynchronous: Sessions<O>,
}

impl<O: DhOracle> Sessions<O> {
    /// Access sync methods for sync DH oracle case
    pub fn into_sync(self) -> SyncSessions<O> {
        SyncSessions { asynchronous: self }
    }
}

impl Sessions {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(config: Config, rng: &mut impl CryptoRng) -> SyncSessions {
        Sessions::new_with(config, rng).into_sync()
    }
}

impl AsMut<Sessions> for SyncSessions {
    fn as_mut(&mut self) -> &mut Sessions {
        &mut self.asynchronous
    }
}

impl<O: DhOracle> SyncSessions<O> {
    /// Should be called at least once per second.
    /// Should be called until it returns None.
    #[inline]
    pub fn turn(&mut self, now: Tai64N, rng: &mut impl CryptoRng) -> Option<MaintenanceMsg> {
        async_convert::poll_spin(self.asynchronous.turn(now, rng))
    }

    #[inline]
    pub fn send_message(
        &mut self,
        peer_idx: PeerId,
        payload: &mut [u8],
    ) -> Result<SendMessage, Error> {
        async_convert::poll_spin(self.asynchronous.send_message(peer_idx, payload))
    }

    #[inline]
    pub fn recv_message<'m>(
        &mut self,
        socket: SocketAddr,
        msg: &'m mut [u8],
    ) -> Result<Message<'m>, Error> {
        async_convert::poll_spin(self.asynchronous.recv_message(socket, msg))
    }
}
