#!/usr/bin/env python3

"""
/******************************* server_pt3.py *******************************
 *
 *  Module: Part 3 Hardened TLS Server
 *
 *  This module implements the hardened server for Part 3 of the university
 *  TLS/SSL project.
 *
 *  The server provides:
 *
 *  - TCP-based communication over IPv4 sockets
 *  - Minimum TLS version enforcement of TLS 1.3
 *  - Mutual TLS (mTLS) by requiring a client certificate
 *  - JSON-style structured logging of negotiated TLS session details
 *  - Simple JSON request/response handling for the `GET_TIME` command
 *
 *  Security Properties:
 *
 *  - Only clients presenting a certificate signed by the trusted CA can
 *    complete the TLS handshake.
 *  - TLS 1.2 and older protocol versions are rejected.
 *  - Structured logs make negotiated cryptographic parameters visible.
 *
 *****************************************************************************/
"""

import argparse
import datetime
import json
import logging
import socket
import ssl
from typing import Any


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9443
DEFAULT_CA_CERT = "certs/ca.crt"
DEFAULT_SERVER_CERT = "certs/server.crt"
DEFAULT_SERVER_KEY = "certs/server.key"


def parse_args() -> argparse.Namespace:
    """Parse command-line options for the hardened TLS server."""
    parser = argparse.ArgumentParser(description="Part 3 hardened TLS server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument("--ca-cert", default=DEFAULT_CA_CERT, help="Trusted CA certificate")
    parser.add_argument("--certfile", default=DEFAULT_SERVER_CERT, help="Server certificate")
    parser.add_argument("--keyfile", default=DEFAULT_SERVER_KEY, help="Server private key")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Handle a single successful TLS client and then exit",
    )
    return parser.parse_args()


def configure_logging() -> None:
    """Initialize compact logging so JSON records remain easy to parse."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")


def create_ssl_context(certfile: str, keyfile: str, ca_cert: str) -> ssl.SSLContext:
    """Create a hardened TLS context with TLS 1.3 and client auth required."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Enforce the minimum protocol version required by Part 3.
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile=ca_cert)
    # Require the client to present a certificate signed by the trusted CA.
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def emit_event(event: str, **fields: Any) -> None:
    """Emit a JSON-style log record with a timestamp and event-specific fields."""
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event,
        **fields,
    }
    logging.info(json.dumps(record, sort_keys=True))


def peer_identity(peer_cert: dict[str, Any] | None) -> str | None:
    """Extract the common name from the peer certificate, if present."""
    if not peer_cert:
        return None
    for rdn in peer_cert.get("subject", []):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def session_details(ssl_sock: ssl.SSLSocket, client_addr: tuple[str, int]) -> dict[str, Any]:
    """Collect structured TLS session metadata for logging and auditing."""
    cipher_name, protocol_name, secret_bits = ssl_sock.cipher()
    peer_cert = ssl_sock.getpeercert()
    return {
        "client_ip": client_addr[0],
        "client_port": client_addr[1],
        "tls_version": ssl_sock.version(),
        "cipher_suite": cipher_name,
        "cipher_protocol": protocol_name,
        "secret_bits": secret_bits,
        "peer_common_name": peer_identity(peer_cert),
        "peer_subject": peer_cert.get("subject"),
        "peer_issuer": peer_cert.get("issuer"),
    }


def receive_json(ssl_sock: ssl.SSLSocket) -> dict[str, Any]:
    """Receive and decode a single JSON request from the authenticated client."""
    data = ssl_sock.recv(4096)
    if not data:
        raise ValueError("client closed the connection before sending data")
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("received invalid JSON request") from exc


def build_response(request: dict[str, Any], peer_cn: str | None) -> dict[str, Any]:
    """Build a response that also identifies the authenticated client."""
    if request.get("command") == "GET_TIME":
        return {
            "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "authenticated_client": peer_cn,
        }
    return {"error": "Unknown command"}


def serve(args: argparse.Namespace) -> int:
    """Start the hardened listener, enforce mTLS, and serve authenticated clients."""
    context = create_ssl_context(args.certfile, args.keyfile, args.ca_cert)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        # Reuse the address to make local testing less frustrating.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        sock.listen(5)
        emit_event("server_started", host=args.host, port=args.port, minimum_tls="TLSv1.3")

        while True:
            conn, addr = sock.accept()
            try:
                # If the client certificate is missing or untrusted, the
                # handshake fails here before application data is processed.
                with context.wrap_socket(conn, server_side=True) as ssl_sock:
                    details = session_details(ssl_sock, addr)
                    emit_event("tls_session_established", **details)
                    request = receive_json(ssl_sock)
                    emit_event("request_received", client_ip=addr[0], payload=request)
                    response = build_response(request, details["peer_common_name"])
                    ssl_sock.sendall(json.dumps(response).encode("utf-8"))
                    emit_event("response_sent", client_ip=addr[0], response=response)
                    if args.once:
                        break
            except ssl.SSLError as exc:
                emit_event("tls_error", client_ip=addr[0], client_port=addr[1], error=str(exc))
            except (OSError, ValueError) as exc:
                emit_event("connection_error", client_ip=addr[0], client_port=addr[1], error=str(exc))
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    return 0


if __name__ == "__main__":
    configure_logging()
    try:
        raise SystemExit(serve(parse_args()))
    except FileNotFoundError as exc:
        emit_event("startup_error", error=f"missing file: {exc.filename}")
        raise SystemExit(1) from exc
    except KeyboardInterrupt:
        emit_event("server_stopped", reason="keyboard_interrupt")
        raise SystemExit(0)
