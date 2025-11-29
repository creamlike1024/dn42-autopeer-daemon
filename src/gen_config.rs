use crate::CONFIG;
use crate::model::*;
use anyhow::{Result, anyhow};
use askama::Template;

pub fn gen_wireguard_config(peer: &Peer) -> Result<String> {
    let listen_port = match peer.gen_listen_port() {
        Ok(port) => port,
        Err(e) => return Err(e),
    };
    let wg_config = WireguardConfig {
        wireguard_private_key: CONFIG.peer.wireguard_private_key.clone(),
        wireguard_listen_port: listen_port,
        wireguard_link_local_ipv6: CONFIG.peer.link_local.clone(),
        wireguard_peer_public_key: peer.wireguard_public_key.clone(),
        wireguard_peer_endpoint: peer.wireguard_endpoint.clone(),
    };

    wg_config
        .render()
        .map_err(|e| anyhow!("Failed to render WireGuard config: {}", e))
}

pub fn gen_bird_config(peer: &Peer) -> Result<String> {
    let bird_config = BirdConfig {
        interface_name: peer.gen_interface_name(),
        wireguard_link_local_ipv6: CONFIG.peer.link_local.clone(),
        peer_link_local_ipv6: peer.wireguard_link_local.clone(),
        peer_asn: peer.asn,
    };
    bird_config
        .render()
        .map_err(|e| anyhow!("Failed to render BIRD config: {}", e))
}
