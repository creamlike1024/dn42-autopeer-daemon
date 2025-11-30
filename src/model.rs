use crate::CONFIG;
use anyhow::Result;
use askama::Template;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use url::Url;

pub struct PeerDbInfo {
    pub asn: u64,
    pub wireguard_endpoint: String,
    pub wireguard_link_local: String,
    pub wireguard_public_key: String,
    pub interface_name: String,
    pub wireguard_config_path: String,
    pub bird_config_path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Peer {
    pub asn: u64,
    #[serde(default)]
    pub wireguard_endpoint: String,
    #[serde(default)]
    pub wireguard_link_local: String,
    #[serde(default)]
    pub wireguard_public_key: String,
}

impl Peer {
    pub fn gen_interface_name(&self) -> String {
        format!("dn42_{}", self.asn % 10000)
    }

    pub fn gen_wireguard_config_path(&self) -> String {
        format!("/etc/wireguard/{}.conf", self.gen_interface_name())
    }

    pub fn gen_bird_config_path(&self) -> String {
        format!("/etc/bird/peers/{}.conf", self.gen_interface_name())
    }

    pub fn gen_listen_port(&self) -> Result<u16> {
        let asn_suffix = self.asn % 10000;
        let port_prefix = CONFIG.peer.port_prefix_number as u64;
        let combined = port_prefix * 10000 + asn_suffix;
        if combined > 65535 || combined < 1024 {
            Err(anyhow::anyhow!("Invalid port number"))
        } else {
            Ok(combined as u16)
        }
    }

    pub fn is_valid_wireguard_endpoint(&self) -> bool {
        let wg_url = format!("wg://{}", self.wireguard_endpoint);
        let Ok(u) = Url::parse(&wg_url) else {
            return false;
        };
        match (u.host(), u.port()) {
            (Some(_), Some(p)) if p > 0 => true,
            _ => false,
        }
    }

    pub fn is_valid_asn(&self) -> bool {
        self.asn >= 4_242_420_000 && self.asn <= 4_242_429_999
    }

    pub fn is_valid_link_local(&self) -> bool {
        match self.wireguard_link_local.parse::<std::net::Ipv6Addr>() {
            Ok(addr) => {
                let seg0 = addr.segments()[0];
                (seg0 & 0xFFC0) == 0xFE80
            }
            Err(_) => false,
        }
    }

    pub fn is_valid_wireguard_public_key(&self) -> bool {
        if self.wireguard_public_key.len() != 44 {
            return false;
        }
        match BASE64_STANDARD.decode(&self.wireguard_public_key) {
            Ok(bytes) => bytes.len() == 32,
            Err(_) => false,
        }
    }
}

#[derive(Template)]
#[template(path = "wireguard.conf", escape = "none")]
pub struct WireguardConfig {
    pub wireguard_private_key: String,
    pub wireguard_listen_port: u16,
    pub wireguard_link_local_ipv6: String,
    pub wireguard_peer_public_key: String,
    pub wireguard_peer_endpoint: String,
}

#[derive(Template)]
#[template(path = "peer_mpbgp.conf", escape = "none")]
pub struct BirdConfig {
    pub interface_name: String,
    pub wireguard_link_local_ipv6: String,
    pub peer_link_local_ipv6: String,
    pub peer_asn: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn p() -> Peer {
        Peer {
            asn: 0,
            wireguard_endpoint: "1.2.3.4:51820".to_string(),
            wireguard_link_local: "fe80::1".to_string(),
            wireguard_public_key: "test".to_string(),
        }
    }

    #[test]
    fn test_endpoint_valid() {
        let mut peer = p();
        peer.wireguard_endpoint = "1.2.3.4:51820".to_string();
        assert!(peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "example.com:12345".to_string();
        assert!(peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "[::1]:51820".to_string();
        assert!(peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "[2001:db8::1]:1".to_string();
        assert!(peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "a-b.test:65535".to_string();
        assert!(peer.is_valid_wireguard_endpoint());
    }

    #[test]
    fn test_endpoint_invalid() {
        let mut peer = p();
        peer.wireguard_endpoint = "1.2.3.4".to_string();
        assert!(!peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "::1:51820".to_string();
        assert!(!peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "[::1]".to_string();
        assert!(!peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "example.com:0".to_string();
        assert!(!peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "example.com:65536".to_string();
        assert!(!peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = ":80".to_string();
        assert!(!peer.is_valid_wireguard_endpoint());
        peer.wireguard_endpoint = "".to_string();
        assert!(!peer.is_valid_wireguard_endpoint());
    }

    #[test]
    fn test_asn_valid() {
        let mut peer = p();
        peer.asn = 4_242_420_000;
        assert!(peer.is_valid_asn());
        peer.asn = 4_242_429_999;
        assert!(peer.is_valid_asn());
        peer.asn = 4_242_420_253; // 4242420253
        assert!(peer.is_valid_asn());
    }

    #[test]
    fn test_asn_invalid() {
        let mut peer = p();
        peer.asn = 4_242_420_00; // 9 digits
        assert!(!peer.is_valid_asn());
        peer.asn = 4_242_431_000; // prefix not 424242
        assert!(!peer.is_valid_asn());
        peer.asn = 0;
        assert!(!peer.is_valid_asn());
        peer.asn = 42_424_210_000; // 11 digits
        assert!(!peer.is_valid_asn());
    }

    #[test]
    fn test_link_local_valid() {
        let mut peer = p();
        peer.wireguard_link_local = "fe80::1".to_string();
        assert!(peer.is_valid_link_local());
        peer.wireguard_link_local = "fe80::abcd".to_string();
        assert!(peer.is_valid_link_local());
        peer.wireguard_link_local = "febf::1".to_string();
        assert!(peer.is_valid_link_local());
    }

    #[test]
    fn test_link_local_invalid() {
        let mut peer = p();
        peer.wireguard_link_local = "::1".to_string();
        assert!(!peer.is_valid_link_local());
        peer.wireguard_link_local = "fec0::1".to_string();
        assert!(!peer.is_valid_link_local());
        peer.wireguard_link_local = "fe7f::1".to_string();
        assert!(!peer.is_valid_link_local());
        peer.wireguard_link_local = "not-an-ip".to_string();
        assert!(!peer.is_valid_link_local());
    }

    #[test]
    fn test_public_key_valid() {
        let mut peer = p();
        peer.wireguard_public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string();
        assert!(peer.is_valid_wireguard_public_key());
    }

    #[test]
    fn test_public_key_invalid() {
        let mut peer = p();
        peer.wireguard_public_key = "not-a-key".to_string();
        assert!(!peer.is_valid_wireguard_public_key());
        peer.wireguard_public_key = format!("{}==", "A".repeat(42));
        assert!(!peer.is_valid_wireguard_public_key());
        peer.wireguard_public_key = format!("{}!=", "A".repeat(42));
        assert!(!peer.is_valid_wireguard_public_key());
    }

    #[test]
    fn test_deserialize_only_asn() {
        let v = json!({"asn": 4242420000u64});
        let peer: Peer = serde_json::from_value(v).unwrap();
        assert_eq!(peer.asn, 4242420000u64);
        assert_eq!(peer.wireguard_endpoint, "");
        assert_eq!(peer.wireguard_link_local, "");
        assert_eq!(peer.wireguard_public_key, "");
    }

    #[test]
    fn test_deserialize_missing_asn_error() {
        let v = json!({});
        assert!(serde_json::from_value::<Peer>(v).is_err());
    }
}
