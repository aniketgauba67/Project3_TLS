# Project 3 TLS/SSL

This repository contains a completed Python implementation for a university
TLS/SSL project using the Python standard library `ssl` module.

The project is split into three parts:

- Part 1: secure TLS client/server communication with server authentication
- Part 2: written analysis of TLS misconfiguration and MITM risk
- Part 3: hardened TLS with TLS 1.3 enforcement, mutual TLS, and structured logging

## Repository Contents

Original files preserved:

- `server.py`
- `client.py`

New implementation files:

- `server_pt1.py`
- `client_pt1.py`
- `server_pt3.py`
- `client_pt3.py`

Report files:

- `proj3_pt2_report.md`
- `proj3_pt3_report.md`

Certificate generation:

- `gen_cert.sh`

Submission archive:

- `proj3.zip`

## Requirements

- Python 3.11+ recommended
- OpenSSL installed
- Linux or macOS shell environment

## Certificate Generation

Generate all required certificate materials with:

```bash
./gen_cert.sh
```

This creates a `certs/` directory containing:

- `ca.crt` and `ca.key`
- `server.crt` and `server.key`
- `client.crt` and `client.key`

The generated server certificate includes SAN entries for:

- `localhost`
- `127.0.0.1`

This allows hostname verification to work correctly during local testing.

## Part 1: Secure TLS Application

Start the Part 1 server:

```bash
python3 server_pt1.py --host 127.0.0.1 --port 8443
```

In another terminal, run the Part 1 client:

```bash
python3 client_pt1.py --host localhost --connect-host 127.0.0.1 --port 8443
```

What Part 1 does:

- uses TCP sockets
- wraps the connection in TLS
- presents an X.509 server certificate
- verifies the server certificate on the client
- logs negotiated TLS version and cipher suite

Expected client output:

```text
YYYY-MM-DD HH:MM:SS,sss INFO Connected with TLSv1.3 / TLS_AES_256_GCM_SHA384
Server Response: {"time": "..."}
```

Expected server output:

```text
YYYY-MM-DD HH:MM:SS,sss INFO Part 1 TLS server listening on 127.0.0.1:8443
YYYY-MM-DD HH:MM:SS,sss INFO Accepted TLS connection from 127.0.0.1:<port> using TLSv1.3 / TLS_AES_256_GCM_SHA384
YYYY-MM-DD HH:MM:SS,sss INFO Received request payload: {'command': 'GET_TIME'}
```

## Part 3: Hardened TLS System

Start the Part 3 server:

```bash
python3 server_pt3.py --host 127.0.0.1 --port 9443
```

In another terminal, run the Part 3 client:

```bash
python3 client_pt3.py --host localhost --connect-host 127.0.0.1 --port 9443
```

What Part 3 adds:

- minimum TLS version of 1.3
- mutual TLS requiring a valid client certificate
- structured JSON-style logging

Expected Part 3 client output:

```text
{"event": "tls_session_established", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", ...}
{"event": "response_received", "response": {"authenticated_client": "Project3 TLS Client", "time": "..."}}
Server Response: {"time": "...", "authenticated_client": "Project3 TLS Client"}
```

Expected Part 3 server output:

```text
{"event": "server_started", "host": "127.0.0.1", "minimum_tls": "TLSv1.3", "port": 9443, ...}
{"event": "tls_session_established", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384", "peer_common_name": "Project3 TLS Client", ...}
{"event": "request_received", "payload": {"command": "GET_TIME"}, ...}
{"event": "response_sent", "response": {"authenticated_client": "Project3 TLS Client", "time": "..."}, ...}
```

## Part 3 Negative Testing

To verify that Part 3 rejects a client without a certificate, keep the Part 3
server running and execute:

```bash
python3 client_pt1.py --host localhost --connect-host 127.0.0.1 --port 9443
```

Expected result:

- the client fails
- the server logs a TLS error such as `PEER_DID_NOT_RETURN_A_CERTIFICATE`

To verify TLS 1.3 enforcement:

```bash
openssl s_client -connect 127.0.0.1:9443 -servername localhost -tls1_2 -CAfile certs/ca.crt
```

Expected result:

- handshake failure
- protocol version alert
- server log showing an unsupported protocol error


