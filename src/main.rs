use crate::db::*;
use crate::handler::*;
use async_io::Async;
use futures_lite::io::{AsyncRead, AsyncWrite};
use lazy_static::lazy_static;
use serde::Deserialize;
use std::fs;
use std::io::{self, Read};
use std::net::TcpListener;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
mod db;
mod gen_config;
mod handler;
mod model;
mod system;

#[derive(Deserialize, Debug)]
struct ApiConfig {
    api_port: u16,
    listen_address_v4: String,
    listen_address_v6: String,
    secret: String,
}

#[derive(Deserialize, Debug)]
struct PeerConfig {
    link_local: String,
    wireguard_private_key: String,
    port_prefix_number: u16,
}

#[derive(Deserialize, Debug)]
struct EnvironmentConfig {
    init_system: String,
    rc_service_path: String,
    rc_update_path: String,
    systemctl_path: String,
    birdc_path: String,
}

#[derive(Deserialize, Debug)]
struct AppConfig {
    #[serde(rename = "API")]
    api: ApiConfig,
    #[serde(rename = "Peer")]
    peer: PeerConfig,
    #[serde(rename = "Environment")]
    env: EnvironmentConfig,
}

lazy_static! {
    static ref CONFIG: AppConfig = {
        let config_path = "config.toml";

        let mut file = fs::File::open(config_path)
            .expect(&format!("Failed to open config file: {}", config_path));
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .expect("Failed to read config file content");

        toml::from_str(&contents).expect("Failed to parse TOML configuration")
    };
}

#[derive(Clone)]
struct CloneableStream {
    inner: Arc<Mutex<Async<std::net::TcpStream>>>,
}

impl AsyncRead for CloneableStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock().unwrap();
        Pin::new(&mut *inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CloneableStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut inner = self.inner.lock().unwrap();
        Pin::new(&mut *inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().unwrap();
        Pin::new(&mut *inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut inner = self.inner.lock().unwrap();
        Pin::new(&mut *inner).poll_close(cx)
    }
}

pub type Db = Arc<Mutex<rusqlite::Connection>>;

fn check_config() -> Result<(), String> {
    if CONFIG.peer.link_local.is_empty() {
        Err("No link-local address found".to_string())
    } else if CONFIG.peer.wireguard_private_key.is_empty() {
        Err("No wireguard private key found".to_string())
    } else if CONFIG.api.api_port == 0 {
        Err("Invalid API port".to_string())
    } else if CONFIG.api.listen_address_v4.is_empty() && CONFIG.api.listen_address_v6.is_empty() {
        Err("No listen address found".to_string())
    } else if CONFIG.peer.port_prefix_number == 0 || CONFIG.peer.port_prefix_number >= 6 {
        Err("Port prefix number must be between 1 and 5".to_string())
    } else if CONFIG.env.init_system != "systemd" && CONFIG.env.init_system != "openrc" {
        Err("Unsupported init system".to_string())
    } else if CONFIG.env.init_system == "systemd" && CONFIG.env.systemctl_path.is_empty() {
        Err("Environment: systemctl binary path is empty".to_string())
    } else if CONFIG.env.init_system == "openrc" && CONFIG.env.rc_service_path.is_empty() {
        Err("Environment: rc-service binary path is empty".to_string())
    } else if CONFIG.env.init_system == "openrc" && CONFIG.env.rc_update_path.is_empty() {
        Err("Environment: rc-update binary path is empty".to_string())
    } else if CONFIG.env.birdc_path.is_empty() {
        Err("Environment: birdc binary path is empty".to_string())
    } else {
        if CONFIG.api.secret.trim().is_empty() {
            println!("Warning: API secret is empty");
        }
        Ok(())
    }
}

fn main() -> std::io::Result<()> {
    if let Err(err_string) = check_config() {
        eprintln!("Error: {}", err_string);
        return Err(io::Error::new(io::ErrorKind::Other, err_string));
    }

    let conn = rusqlite::Connection::open("peers.db").expect("Failed to open peers.db");
    init_db(&conn).expect("Failed to initialize database");
    let db: Db = Arc::new(Mutex::new(conn));

    let (ctrlc_sender, ctrlc_receiver) = async_channel::bounded(100);
    let ctrlc_handle = move || {
        ctrlc_sender.try_send(()).ok();
    };
    ctrlc::set_handler(ctrlc_handle).unwrap();

    let mut listeners = Vec::new();

    if !CONFIG.api.listen_address_v4.is_empty() {
        let bind_address_v4 = format!("{}:{}", CONFIG.api.listen_address_v4, CONFIG.api.api_port);
        let sock_addr_v4 = bind_address_v4
            .to_socket_addrs()?
            .next()
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Could not resolve address",
            ))?;
        let listener_v4 = Async::<TcpListener>::bind(sock_addr_v4)?;
        listeners.push(listener_v4);
        println!(
            "Server running on http://{}:{}",
            sock_addr_v4.ip(),
            sock_addr_v4.port()
        );
    }

    if !CONFIG.api.listen_address_v6.is_empty() {
        let bind_address_v6 = format!("{}:{}", CONFIG.api.listen_address_v6, CONFIG.api.api_port);
        let sock_addr_v6 = bind_address_v6
            .to_socket_addrs()?
            .next()
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Could not resolve address",
            ))?;
        let listener_v6 = Async::<TcpListener>::bind(sock_addr_v6)?;
        listeners.push(listener_v6);
        println!(
            "Server running on http://[{}]:{}",
            sock_addr_v6.ip(),
            sock_addr_v6.port()
        );
    }

    smol::block_on(async {
        for listener in listeners {
            let db_clone = db.clone();
            smol::spawn(async move {
                loop {
                    let (stream, _) = match listener.accept().await {
                        Ok(conn) => conn,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                            // 忽略 ctrl-c 信号错误
                            continue;
                        }
                        Err(e) => {
                            eprintln!("Error accepting connection: {}", e);
                            continue;
                        }
                    };

                    let cloneable_stream = CloneableStream {
                        inner: Arc::new(Mutex::new(stream)),
                    };

                    let db_for_handler = db_clone.clone();
                    smol::spawn(async move {
                        if let Err(e) = async_h1::server::accept(cloneable_stream, move |req| {
                            serve_router(req, db_for_handler.clone())
                        })
                        .await
                        {
                            eprintln!("Connection error: {}", e);
                        }
                    })
                    .detach();
                }
            })
            .detach();
        }

        // Wait for Ctrl-C
        ctrlc_receiver.recv().await.ok();
        println!("\nCtrl-C received, shutting down...");
        Ok(())
    })
}
