#!/usr/bin/env python3

"""
/******************************* client_pt3.py *******************************
 *
 *  Module: Part 3 Hardened TLS Client
 *
 *  This module implements the hardened client for Part 3 of the university
 *  TLS/SSL project.
 *
 *  The client provides:
 *
 *  - TLS 1.3 minimum-version enforcement
 *  - Server certificate validation and hostname verification
 *  - Client certificate presentation for mutual TLS authentication
 *  - JSON-style structured logging of negotiated TLS session details
 *  - JSON request/response exchange for the `GET_TIME` command
 *
 *  Security Properties:
 *
 *  - The server must present a valid certificate signed by the trusted CA.
 *  - The client also presents its own certificate to satisfy server-side
 *    mutual TLS requirements.
 *  - TLS 1.2 and older versions are not accepted.
 *
 *****************************************************************************/
"""

import argparse
import json
import logging
import socket
import ssl
from typing import Any


DEFAULT_HOST = "localhost"
DEFAULT_PORT = 9443
DEFAULT_CA_CERT = "certs/ca.crt"
DEFAULT_CLIENT_CERT = "certs/client.crt"
DEFAULT_CLIENT_KEY = "certs/client.key"


def parse_args() -> argparse.Namespace:
    """Parse command-line options for the hardened TLS client."""
    parser = argparse.ArgumentParser(description="Part 3 hardened TLS client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server hostname")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument(
        "--connect-host",
        default=None,
        help="Optional TCP connect address when it differs from the TLS hostname",
    )
    parser.add_argument("--ca-cert", default=DEFAULT_CA_CERT, help="Trusted CA certificate")
    parser.add_argument("--certfile", default=DEFAULT_CLIENT_CERT, help="Client certificate")
    parser.add_argument("--keyfile", default=DEFAULT_CLIENT_KEY, help="Client private key")
    return parser.parse_args()


def configure_logging() -> None:
    """Initialize compact logging so JSON records remain readable."""
    logging.basicConfig(level=logging.INFO, format="%(message)s")


def emit_event(event: str, **fields: Any) -> None:
    """Emit a JSON-style log record describing a client-side event."""
    logging.info(json.dumps({"event": event, **fields}, sort_keys=True))


def create_ssl_context(ca_cert: str, certfile: str, keyfile: str) -> ssl.SSLContext:
    """Create a hardened TLS client context with mTLS credentials loaded."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
    # Reject any protocol version older than TLS 1.3.
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    # Present the client certificate so the server can authenticate us.
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def session_details(ssl_sock: ssl.SSLSocket) -> dict[str, Any]:
    """Collect negotiated TLS metadata from the authenticated session."""
    cipher_name, protocol_name, secret_bits = ssl_sock.cipher()
    peer_cert = ssl_sock.getpeercert()
    return {
        "tls_version": ssl_sock.version(),
        "cipher_suite": cipher_name,
        "cipher_protocol": protocol_name,
        "secret_bits": secret_bits,
        "peer_subject": peer_cert.get("subject"),
        "peer_issuer": peer_cert.get("issuer"),
    }


def run_client(args: argparse.Namespace) -> int:
    """Connect with mTLS, send a request, and print the server response."""
    context = create_ssl_context(args.ca_cert, args.certfile, args.keyfile)
    connect_host = args.connect_host or args.host
    request = {"command": "GET_TIME"}

    with socket.create_connection((connect_host, args.port)) as sock:
        # `server_hostname` keeps hostname verification active even when the
        # TCP destination is supplied separately for localhost testing.
        with context.wrap_socket(sock, server_hostname=args.host) as ssl_sock:
            emit_event("tls_session_established", **session_details(ssl_sock))
            ssl_sock.sendall(json.dumps(request).encode("utf-8"))
            response = json.loads(ssl_sock.recv(4096).decode("utf-8"))
            emit_event("response_received", response=response)

    print("Server Response:", json.dumps(response))
    return 0


if __name__ == "__main__":
    configure_logging()
    try:
        raise SystemExit(run_client(parse_args()))
    except FileNotFoundError as exc:
        emit_event("startup_error", error=f"missing file: {exc.filename}")
        raise SystemExit(1) from exc
    except ssl.SSLError as exc:
        emit_event("tls_error", error=str(exc))
        raise SystemExit(1) from exc
    except OSError as exc:
        emit_event("connection_error", error=str(exc))
        raise SystemExit(1) from exc
