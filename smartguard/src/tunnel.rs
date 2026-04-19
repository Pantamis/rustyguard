//! High-level tunnel event loop with signal handling and route management.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use iptrie::{Ipv4LCTrieMap, Ipv4Prefix};
use rand::{rngs::OsRng, TryRngCore};
use rustyguard_core::{PeerId, Sessions};
use rustyguard_crypto::CryptoPrimatives;
use rustyguard_tun::{handle_extern, handle_intern, tun, AlignedPacket, Write, H};
use tai64::Tai64N;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::UdpSocket,
};

use crate::route::{cleanup_routes, setup_routes};

/// Run the WireGuard tunnel event loop.
///
/// Creates a TUN device, sets up routes for AllowedIPs, listens on a UDP socket,
/// and shuttles packets between the TUN interface and the WireGuard protocol.
/// Handles SIGINT/SIGTERM for graceful shutdown with route cleanup.
pub async fn run_tunnel<C: CryptoPrimatives>(
    mut sessions: Sessions,
    peer_net: Ipv4LCTrieMap<PeerId>,
    peer_ids: &[PeerId],
    listen_port: u16,
    tun_addr: ipnet::Ipv4Net,
    mtu: i32,
    allowed_ips: &[Ipv4Prefix],
    peer_endpoints: &[Option<SocketAddr>],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf: Box<AlignedPacket> = Box::new(AlignedPacket([0; 2048]));
    let mut reply_buf = vec![0u8; 2048];

    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), listen_port);
    let endpoint = UdpSocket::bind(bind_addr).await?;
    eprintln!("Listening on UDP {bind_addr}");

    let mut tun_config = tun::Configuration::default();
    tun_config
        .address(tun_addr.addr())
        .netmask(tun_addr.netmask())
        .mtu(mtu)
        .up();

    let tun_dev = tun::platform::create(&tun_config)?;
    #[cfg(target_os = "macos")]
    let tun_name = tun_dev.name().to_string();
    #[cfg(not(target_os = "macos"))]
    let tun_name = String::from("wg0");
    let mut dev = tun::AsyncDevice::new(tun_dev)?;
    eprintln!("TUN interface {tun_name} up with address {tun_addr}");

    // Set up routes for AllowedIPs.
    let added_routes = setup_routes(&tun_name, allowed_ips, peer_endpoints);

    // Initiate handshake to all peers with known endpoints at startup.
    for &peer_id in peer_ids {
        let mut dummy = [0u8; 16];
        match sessions.send_message::<C>(peer_id, &mut dummy) {
            Ok(rustyguard_core::SendMessage::Maintenance(msg)) => {
                eprintln!("Initiating handshake to {}", msg.to());
                endpoint.send_to(msg.data(), msg.to()).await?;
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }

    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let result: Result<(), Box<dyn std::error::Error>> = loop {
        let mut ep_buf = ReadBuf::new(&mut buf.0);
        let mut tun_buf = ReadBuf::new(&mut reply_buf[H..]);
        let action = tokio::select! {
            _ = sigint.recv() => break Ok(()),
            _ = sigterm.recv() => break Ok(()),
            _ = tick.tick() => {
                while let Some(msg) = sessions.turn::<C>(Tai64N::now(), &mut OsRng.unwrap_err()) {
                    endpoint.send_to(msg.data(), msg.to()).await?;
                }

                Write::None
            }
            res = endpoint.recv_buf_from(&mut ep_buf) => {
                let addr = res?.1;

                handle_extern::<C>(&mut sessions, &peer_net, addr, ep_buf.filled_mut())
            }
            res = dev.read_buf(&mut tun_buf) => {
                let n = res?;
                handle_intern::<C>(&mut sessions, &peer_net, &mut reply_buf, H + n)
            }
        };

        match action {
            Write::None => {}
            Write::Inbound(data) => dev.write_all(data).await?,
            Write::Outbound(data, addr) => {
                endpoint.send_to(data, addr).await?;
            }
        }
    };

    // Clean up routes, then drop the TUN fd (destroys the utun interface)
    eprintln!("\nShutting down...");
    cleanup_routes(&added_routes);
    result
}
