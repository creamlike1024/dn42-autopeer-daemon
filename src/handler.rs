use crate::CONFIG;
use crate::Db;
use crate::db::*;
use crate::gen_config::*;
use crate::model::*;
use crate::system::*;
use http_types::{Method, Request, Response, StatusCode};

fn is_valid_secret(req: &Request) -> bool {
    let secret = req.header("Authorization").and_then(|values| values.get(0));
    match secret {
        Some(content) => match content.as_str().trim().strip_prefix("Bearer ") {
            Some(key) if key.trim() == CONFIG.api.secret.trim() => true,
            _ => false,
        },
        None => false,
    }
}

pub async fn serve_router(req: Request, db: Db) -> http_types::Result<Response> {
    if !CONFIG.api.secret.trim().is_empty() {
        if !is_valid_secret(&req) {
            let mut res = Response::new(StatusCode::Unauthorized);
            res.insert_header("Content-Type", "text/plain; charset=utf-8");
            res.set_body("Unauthorized\n".to_string());
            return Ok(res);
        }
    }
    match (req.method(), req.url().path()) {
        (Method::Post, "/add") => handle_add(req, db).await,
        (Method::Post, "/get") => handle_get(req, db).await,
        (Method::Post, "/del") => handle_del(req, db).await,

        _ => {
            let mut res = Response::new(StatusCode::NotFound);
            res.insert_header("Content-Type", "text/plain; charset=utf-8");
            res.set_body("Not Found\n".to_string());
            Ok(res)
        }
    }
}

pub async fn handle_add(mut req: Request, db: Db) -> http_types::Result<Response> {
    let req_peer: Peer = match req.body_json().await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            let mut res = Response::new(StatusCode::BadRequest);
            res.set_body(format!("Invalid JSON: {}", e));
            return Ok(res);
        }
    };

    if !req_peer.is_valid_wireguard_endpoint() {
        let mut res = Response::new(StatusCode::BadRequest);
        res.set_body("Invalid Wireguard endpoint".to_string());
        return Ok(res);
    }
    if !req_peer.is_valid_asn() {
        let mut res = Response::new(StatusCode::BadRequest);
        res.set_body("Invalid ASN".to_string());
        return Ok(res);
    }
    if !req_peer.is_valid_link_local() {
        let mut res = Response::new(StatusCode::BadRequest);
        res.set_body("Invalid Link-Local address".to_string());
        return Ok(res);
    }
    if !req_peer.is_valid_wireguard_public_key() {
        let mut res = Response::new(StatusCode::BadRequest);
        res.set_body("Invalid Wireguard public key".to_string());
        return Ok(res);
    }

    let req_peer_clone = req_peer.clone();

    let db_result: Result<(), PeerDbError> = smol::unblock(move || match db.lock() {
        Ok(conn) => match add_peer(&conn, &req_peer_clone) {
            Ok(_) => Ok(()),
            Err(e) => Err(e),
        },
        Err(e) => Err(PeerDbError::LockError(e.to_string())),
    })
    .await;

    match db_result {
        Ok(_) => match gen_wireguard_config(&req_peer) {
            Ok(wg_config) => match gen_bird_config(&req_peer) {
                Ok(bird_config) => {
                    match save_config(
                        &req_peer.gen_wireguard_config_path(),
                        &wg_config,
                        &req_peer.gen_bird_config_path(),
                        &bird_config,
                    ) {
                        Ok(_) => match apply_config(&req_peer.gen_interface_name()) {
                            Ok(_) => {
                                println!("Peer added: {}", req_peer.asn);
                                let mut res = Response::new(StatusCode::Ok);
                                res.set_body(format!("Peer added: {}", req_peer.asn));
                                Ok(res)
                            }
                            Err(e) => {
                                let mut res = Response::new(StatusCode::InternalServerError);
                                res.set_body(format!("Failed to apply config: {}", e));
                                return Ok(res);
                            }
                        },
                        Err(e) => {
                            let mut res = Response::new(StatusCode::InternalServerError);
                            res.set_body(format!("Failed to save config: {}", e));
                            return Ok(res);
                        }
                    }
                }
                Err(e) => {
                    let mut res = Response::new(StatusCode::InternalServerError);
                    res.set_body(format!("Failed to generate BIRD config: {}", e));
                    return Ok(res);
                }
            },
            Err(e) => {
                let mut res = Response::new(StatusCode::InternalServerError);
                res.set_body(format!("Failed to generate WireGuard config: {}", e));
                return Ok(res);
            }
        },
        Err(e) => match e {
            PeerDbError::AlreadyExist => {
                let mut res = Response::new(StatusCode::Conflict);
                res.set_body(format!("Peer already exists: {}", req_peer.asn));
                Ok(res)
            }

            PeerDbError::RusqliteError(err_string) => {
                let mut res = Response::new(StatusCode::InternalServerError);
                res.set_body(format!("Database error: {}", err_string));
                Ok(res)
            }

            _ => {
                let mut res = Response::new(StatusCode::InternalServerError);
                res.set_body(format!("Unknown error: {}", e));
                Ok(res)
            }
        },
    }
}

pub async fn handle_del(mut req: Request, db: Db) -> http_types::Result<Response> {
    let req_peer: Peer = match req.body_json().await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            let mut res = Response::new(StatusCode::BadRequest);
            res.set_body(format!("Invalid JSON: {}", e));
            return Ok(res);
        }
    };

    // del 操作传入的 req_peer 只有 asn，需要从数据库中获取完整的 Peer 对象
    let db_clone = db.clone();
    let peer_result: Result<PeerDbInfo, PeerDbError> =
        smol::unblock(move || match db_clone.lock() {
            Ok(conn) => match get_peer_by_asn(&conn, req_peer.asn) {
                Ok(peer) => Ok(peer),
                Err(e) => Err(e),
            },
            Err(e) => Err(PeerDbError::LockError(e.to_string())),
        })
        .await;

    match peer_result {
        Ok(peer) => {
            // 获取完整 peer 信息成功，开始移除 peer
            match remove_config(
                &peer.interface_name,
                &peer.wireguard_config_path,
                &peer.bird_config_path,
            ) {
                Ok(_) => {
                    // peer removed, clean database
                    let db_result: Result<(), PeerDbError> =
                        smol::unblock(move || match db.lock() {
                            Ok(conn) => match delete_peer_by_asn(&conn, req_peer.asn) {
                                Ok(_) => Ok(()),
                                Err(e) => Err(e),
                            },
                            Err(e) => Err(PeerDbError::LockError(e.to_string())),
                        })
                        .await;

                    match db_result {
                        Ok(_) => {
                            println!("Peer deleted: {}", req_peer.asn);
                            let mut res = Response::new(StatusCode::Ok);
                            res.set_body(format!("Peer deleted: {}", req_peer.asn));
                            Ok(res)
                        }
                        Err(e) => match e {
                            PeerDbError::NotFound => {
                                let mut res = Response::new(StatusCode::BadRequest);
                                res.set_body(format!("Peer not found: {}", req_peer.asn));
                                Ok(res)
                            }

                            PeerDbError::RusqliteError(err_string) => {
                                let mut res = Response::new(StatusCode::InternalServerError);
                                res.set_body(format!("Database error: {}", err_string));
                                Ok(res)
                            }

                            _ => {
                                let mut res = Response::new(StatusCode::InternalServerError);
                                res.set_body(format!("Unknown error: {}", e));
                                Ok(res)
                            }
                        },
                    }
                }
                Err(e) => {
                    let mut res = Response::new(StatusCode::InternalServerError);
                    res.set_body(format!("error: {}", e));
                    Ok(res)
                }
            }
        }
        // failed to get peer from db
        Err(e) => match e {
            PeerDbError::NotFound => {
                let mut res = Response::new(StatusCode::BadRequest);
                res.set_body(format!("Peer not found: {}", req_peer.asn));
                Ok(res)
            }

            PeerDbError::RusqliteError(err_string) => {
                let mut res = Response::new(StatusCode::InternalServerError);
                res.set_body(format!("Database error: {}", err_string));
                Ok(res)
            }

            _ => {
                let mut res = Response::new(StatusCode::InternalServerError);
                res.set_body(format!("Unknown error: {}", e));
                Ok(res)
            }
        },
    }
}

pub async fn handle_get(mut req: Request, db: Db) -> http_types::Result<Response> {
    let req_peer: Peer = match req.body_json().await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            let mut res = Response::new(StatusCode::BadRequest);
            res.set_body(format!("Invalid JSON: {}", e));
            return Ok(res);
        }
    };

    let db_result: Result<Peer, PeerDbError> = smol::unblock(move || match db.lock() {
        Ok(conn) => match get_peer_by_asn(&conn, req_peer.asn) {
            Ok(peer) => Ok(Peer {
                asn: peer.asn,
                wireguard_endpoint: peer.wireguard_endpoint.clone(),
                wireguard_link_local: peer.wireguard_link_local.clone(),
                wireguard_public_key: peer.wireguard_public_key.clone(),
            }),
            Err(e) => Err(e),
        },
        Err(e) => Err(PeerDbError::LockError(e.to_string())),
    })
    .await;

    match db_result {
        Ok(peer) => {
            let mut res = Response::new(StatusCode::Ok);
            match serde_json::to_string(&peer) {
                Ok(json_response) => {
                    res.insert_header("Content-Type", "application/json; charset=utf-8");
                    res.set_body(json_response);
                }
                Err(e) => {
                    eprintln!("Failed to serialize peer: {}", e);
                    let mut res = Response::new(StatusCode::InternalServerError);
                    res.set_body(format!("Failed to serialize peer: {}", e));
                }
            }
            Ok(res)
        }
        Err(e) => match e {
            PeerDbError::NotFound => {
                let mut res = Response::new(StatusCode::BadRequest);
                res.set_body(format!("Peer not found: {}", req_peer.asn));
                Ok(res)
            }

            PeerDbError::RusqliteError(err_string) => {
                let mut res = Response::new(StatusCode::InternalServerError);
                res.set_body(format!("Database error: {}", err_string));
                Ok(res)
            }

            _ => {
                let mut res = Response::new(StatusCode::InternalServerError);
                res.set_body(format!("Unknown error: {}", e));
                Ok(res)
            }
        },
    }
}
