# dn42-autopeer-daemon

A small daemon that automates adding and removing dn42 peers, and provides a simple API.

## Requirements
- Linux with `systemd`
- `wg-quick` is available
- BIRD2 installed
- Run as root (or grant sufficient permissions to complete all operations)

## How It Works
The program assumes that you have a `/etc/bird/peers` folder based on the BIRD2 configuration from the DN42 wiki.

It does the following:
- Writes peer info to `peers.db`
- Generates WireGuard and BIRD configurations and places them in `/etc/wireguard` and `/etc/bird/peers`
- Runs `systemctl start wg-quick@<interface_name>` to start the tunnel and `systemctl enable wg-quick@<interface_name>` to enable autostart
- Runs `birdc configure` to reload the BIRD configuration


## Limitations
The templates are limited to using WireGuard tunnels and BIRD with MP-BGP. This is currently the popular peering method in the DN42 community.

I have only tested on Debian.

## Configuration
Fill in `config.toml`


## API
- Base URL: `http://<listen_address>:<api_port>`
- Auth: add `Authorization: Bearer <secret>` when `API.secret` is set. If the header is missing or invalid, the response is `401 Unauthorized` with body `Unauthorized`.

### POST `/add`

```bash
curl -sS -X POST http://127.0.0.1:4242/add \
  -H "Authorization: Bearer $SECRET" \
  -H "Content-Type: application/json" \
  -d '{
        "asn": 4242421234,
        "wireguard_endpoint": "peer.example.net:51820",
        "wireguard_link_local": "fe80::beef",
        "wireguard_public_key": "<peer_public_key>"
      }'
```

Responses:
  - `200 OK` body: `Peer added: <asn>`
  - `400 Bad Request` body: `Invalid JSON: <error>`
  - `401 Unauthorized` body: `Unauthorized`
  - `409 Conflict` body: `Peer already exists: <asn>`
  - `500 Internal Server Error`

### POST `/del`

Curl:
```bash
curl -sS -X POST http://127.0.0.1:4242/del \
  -H "Authorization: Bearer $SECRET" \
  -H "Content-Type: application/json" \
  -d '{ "asn": 4242421234 }'
```

Responses:
  - `200 OK` body: `Peer deleted: <asn>`
  - `400 Bad Request` body: `Invalid JSON: <error>`
  - `401 Unauthorized` body: `Unauthorized`
  - `404 Not Found` body: `Peer not found: <asn>`
  - `500 Internal Server Error`


### POST `/get`


Curl:
```bash
curl -sS -X POST http://127.0.0.1:4242/get \
  -H "Authorization: Bearer $SECRET" \
  -H "Content-Type: application/json" \
  -d '{ "asn": 4242421234 }'
```
Responses:
  - `200 OK` header: `Content-Type: application/json; charset=utf-8`; body is the peer object:
    ```json
    {
      "asn": 4242420253,
      "wireguard_endpoint": "host.example.com:51820",
      "wireguard_link_local": "fe80::abcd",
      "wireguard_public_key": "<peer_public_key>"
    }
    ```
  - `400 Bad Request`
  - `401 Unauthorized` 
  - `404 Not Found`
  - `500 Internal Server Error`
