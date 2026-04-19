mod config;
mod route;
mod tunnel;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use iptrie::Ipv4Prefix;

use config::{Config, PrivateKeyConfig};
use smartguard_crypto::{init_smartcard, list_cards, CryptoPrimatives, SmartcardCrypto};

use rustyguard_core::{PublicKey, StaticPrivateKey};
use rustyguard_crypto::CryptoCore;

#[derive(Parser)]
#[command(
    name = "smartguard",
    version,
    about = "WireGuard with smartcard key protection"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bring up the WireGuard tunnel.
    Up {
        /// Path to the configuration file.
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Bring down the WireGuard tunnel.
    Down,
    /// Show tunnel status.
    Status,
    /// List connected OpenPGP smartcards with X25519 decryption keys.
    ShowCard,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Up { config } => cmd_up(&config),
        Command::Down => cmd_down(),
        Command::Status => cmd_status(),
        Command::ShowCard => cmd_show_card(),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

fn cmd_up(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_file(config_path)?;

    let listen_port = config.interface.listen_port.unwrap_or(51820);
    let mtu = config.interface.mtu.unwrap_or(1420);
    let tun_addr: ipnet::Ipv4Net = config
        .interface
        .address
        .as_deref()
        .ok_or("interface.address is required for tunnel mode")?
        .parse()?;

    // Parse peers into the format needed by build_sessions
    let peers: Vec<(
        PublicKey,
        Option<[u8; 32]>,
        Option<SocketAddr>,
        Vec<Ipv4Prefix>,
    )> = config
        .peers
        .iter()
        .map(|p| {
            let allowed_ips: Vec<Ipv4Prefix> = p
                .allowed_ips
                .iter()
                .map(|s| s.parse().expect("invalid AllowedIP prefix"))
                .collect();
            (
                PublicKey(p.public_key),
                p.preshared_key,
                p.endpoint,
                allowed_ips,
            )
        })
        .collect();

    let all_allowed_ips: Vec<Ipv4Prefix> = peers.iter().flat_map(|p| p.3.clone()).collect();
    let peer_endpoints: Vec<Option<SocketAddr>> = peers.iter().map(|p| p.2).collect();

    match &config.interface.private_key {
        PrivateKeyConfig::Software(key) => {
            eprintln!("Using software private key");
            let sk = StaticPrivateKey(*key);
            let pk = CryptoCore::x25519_pubkey(&sk);
            eprintln!("Public key: {}", BASE64.encode(pk.0));
            eprintln!("{} peer(s) configured", peers.len());

            let (sessions, peer_net, peer_ids) =
                rustyguard_tun::build_sessions::<CryptoCore>(sk, &peers);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(tunnel::run_tunnel::<CryptoCore>(
                sessions,
                peer_net,
                &peer_ids,
                listen_port,
                tun_addr,
                mtu,
                &all_allowed_ips,
                &peer_endpoints,
            ))?;
        }
        PrivateKeyConfig::Smartcard(ident) => {
            eprintln!("Opening smartcard {ident}...");
            let pin = obtain_pin(&config.interface.smartcard.pin_entry)?;
            let pk = init_smartcard(ident, &pin)?;
            eprintln!("Public key: {}", BASE64.encode(pk.0));
            eprintln!("{} peer(s) configured", peers.len());

            // Use the sentinel key — SmartcardCrypto routes DH to the card
            let sk = smartguard_crypto::SMARTCARD_SENTINEL;

            let (sessions, peer_net, peer_ids) =
                rustyguard_tun::build_sessions::<SmartcardCrypto>(sk, &peers);

            // Precompute SS for each peer so the card is only called once per peer
            for (peer_pk, _, _, _) in &peers {
                if let Ok(ss) =
                    SmartcardCrypto::x25519(&smartguard_crypto::SMARTCARD_SENTINEL, peer_pk)
                {
                    smartguard_crypto::cache_peer_ss(peer_pk, ss);
                }
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(tunnel::run_tunnel::<SmartcardCrypto>(
                sessions,
                peer_net,
                &peer_ids,
                listen_port,
                tun_addr,
                mtu,
                &all_allowed_ips,
                &peer_endpoints,
            ))?;
        }
        PrivateKeyConfig::SmartcardAuto => {
            eprintln!("Auto-detecting smartcard...");
            let pin = obtain_pin(&config.interface.smartcard.pin_entry)?;
            let pk = init_smartcard("auto", &pin)?;
            eprintln!("Public key: {}", BASE64.encode(pk.0));
            eprintln!("{} peer(s) configured", peers.len());

            let sk = smartguard_crypto::SMARTCARD_SENTINEL;

            let (sessions, peer_net, peer_ids) =
                rustyguard_tun::build_sessions::<SmartcardCrypto>(sk, &peers);

            for (peer_pk, _, _, _) in &peers {
                if let Ok(ss) =
                    SmartcardCrypto::x25519(&smartguard_crypto::SMARTCARD_SENTINEL, peer_pk)
                {
                    smartguard_crypto::cache_peer_ss(peer_pk, ss);
                }
            }

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(tunnel::run_tunnel::<SmartcardCrypto>(
                sessions,
                peer_net,
                &peer_ids,
                listen_port,
                tun_addr,
                mtu,
                &all_allowed_ips,
                &peer_endpoints,
            ))?;
        }
    }

    Ok(())
}

fn cmd_down() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Down not yet implemented (no active tunnel to tear down).");
    Ok(())
}

fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Status not yet implemented (no active tunnel to query).");
    Ok(())
}

fn cmd_show_card() -> Result<(), Box<dyn std::error::Error>> {
    let cards = list_cards()?;
    if cards.is_empty() {
        println!("No OpenPGP smartcards with X25519 decryption keys found.");
        println!();
        println!("Make sure:");
        println!("  - A smartcard reader is connected");
        println!("  - The card has an X25519 key in the decryption slot");
        println!("  - pcscd is running (Linux: systemctl start pcscd)");
        return Ok(());
    }

    println!("Found {} card(s):\n", cards.len());
    for card in &cards {
        println!("  Card:       {}", card.ident);
        println!("  Public key: {}", BASE64.encode(card.public_key));
        println!();
    }

    Ok(())
}

/// Obtain the smartcard PIN based on the configured pin_entry method.
fn obtain_pin(pin_entry: &str) -> Result<String, Box<dyn std::error::Error>> {
    if pin_entry == "prompt" {
        let pin = rpassword::prompt_password("Smartcard PIN: ")?;
        Ok(pin)
    } else if let Some(var_name) = pin_entry.strip_prefix("env:") {
        std::env::var(var_name)
            .map_err(|_| format!("environment variable {var_name} not set").into())
    } else {
        Err(format!("unsupported pin_entry method: {pin_entry}").into())
    }
}
