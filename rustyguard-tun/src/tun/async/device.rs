use std::io;
use std::io::{IoSlice, Read, Write};

use core::pin::Pin;
use core::task::{Context, Poll};
use futures_core::ready;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tun::platform::posix::Fd;
use crate::tun::platform::Device;

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: AsyncFd<Fd>,
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    #[allow(unused_mut)]
    pub fn new(mut device: Device) -> io::Result<AsyncDevice> {
        device.set_nonblock()?;
        Ok(AsyncDevice {
            #[cfg(target_os = "macos")]
            inner: AsyncFd::new(device.queue.tun)?,
            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            inner: AsyncFd::new(device.queues.remove(0).tun)?,
        })
    }
}

// On BSD (macOS, FreeBSD, OpenBSD, NetBSD), tun/utun devices prepend a
// 4-byte address family header to every packet. Linux uses IFF_NO_PI
// which strips it, so no header handling is needed there.

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn af_header_for(packet: &[u8]) -> [u8; 4] {
    let af = if !packet.is_empty() && (packet[0] >> 4) == 6 {
        libc::AF_INET6 as u32
    } else {
        libc::AF_INET as u32
    };
    af.to_be_bytes()
}

impl AsyncRead for AsyncDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready_mut(cx))?;

            #[cfg(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            {
                // Use readv to separate the 4-byte AF header from the IP packet.
                let mut hdr = [0u8; 4];
                let unfilled = buf.initialize_unfilled();
                let mut bufs = [io::IoSliceMut::new(&mut hdr), io::IoSliceMut::new(unfilled)];
                match guard.try_io(|inner| inner.get_mut().read_vectored(&mut bufs)) {
                    Ok(Ok(n)) if n > 4 => {
                        buf.advance(n - 4);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Ok(_)) => return Poll::Ready(Ok(())),
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_wb) => continue,
                }
            }

            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            {
                let rbuf = buf.initialize_unfilled();
                match guard.try_io(|inner| inner.get_mut().read(rbuf)) {
                    Ok(res) => return Poll::Ready(res.map(|n| buf.advance(n))),
                    Err(_wb) => continue,
                }
            }
        }
    }
}

impl AsyncWrite for AsyncDevice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready_mut(cx))?;

            #[cfg(not(target_os = "linux"))]
            {
                // Prepend the 4-byte AF header using writev.
                // Detect IPv4 vs IPv6 from the version nibble.
                let af = af_header_for(buf);
                let bufs = [IoSlice::new(&af), IoSlice::new(buf)];
                match guard.try_io(|inner| inner.get_mut().write_vectored(&bufs)) {
                    Ok(Ok(n)) if n > 4 => return Poll::Ready(Ok(n - 4)),
                    Ok(Ok(_)) => return Poll::Ready(Ok(0)),
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_wb) => continue,
                }
            }

            #[cfg(not(any(
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            )))]
            {
                match guard.try_io(|inner| inner.get_mut().write(buf)) {
                    Ok(res) => return Poll::Ready(res),
                    Err(_wb) => continue,
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready_mut(cx))?;
            match guard.try_io(|inner| inner.get_mut().flush()) {
                Ok(res) => return Poll::Ready(res),
                Err(_wb) => continue,
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready_mut(cx))?;
            match guard.try_io(|inner| inner.get_mut().write_vectored(bufs)) {
                Ok(res) => return Poll::Ready(res),
                Err(_wb) => continue,
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}
