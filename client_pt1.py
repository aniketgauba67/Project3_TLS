#!/usr/bin/env python3

"""
/******************************* client_pt1.py *******************************
 *
 *  Module: Part 1 TLS Client
 *
 *  This module implements the Part 1 secure TLS client for the university
 *  TLS/SSL project.
 *
 *  The client provides:
 *
 *  - TCP connection establishment to the server
 *  - TLS server authentication using a trusted CA certificate
 *  - Hostname verification during the TLS handshake
 *  - Logging of the negotiated TLS version and cipher suite
 *  - JSON request/response exchange for the `GET_TIME` command
 *
 *  Security Properties:
 *
 *  - Certificate verification remains enabled.
 *  - Hostname checking remains enabled.
 *  - The client trusts only the configured CA file.
 *  - This file is a new Part 1 implementation and does not alter the
 *    originally provided `client.py`.
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
DEFAULT_PORT = 8443
DEFAULT_CA_CERT = "certs/ca.crt"


def parse_args() -> argparse.Namespace:
    """Parse command-line options for the Part 1 TLS client."""
    parser = argparse.ArgumentParser(description="Part 1 TLS client")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server hostname")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument(
        "--connect-host",
        default=None,
        help="Optional TCP connect address when it differs from the TLS hostname",
    )
    parser.add_argument("--ca-cert", default=DEFAULT_CA_CERT, help="Trusted CA certificate")
    return parser.parse_args()


def configure_logging() -> None:
    """Initialize human-readable logging for client events."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def create_ssl_context(ca_cert: str) -> ssl.SSLContext:
    """Create a secure client TLS context for server authentication."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def tls_details(ssl_sock: ssl.SSLSocket) -> dict[str, Any]:
    """Collect negotiated TLS session details from the server connection."""
    cipher_name, protocol_name, secret_bits = ssl_sock.cipher()
    return {
        "tls_version": ssl_sock.version(),
        "cipher_suite": cipher_name,
        "cipher_protocol": protocol_name,
        "secret_bits": secret_bits,
        "peer_subject": ssl_sock.getpeercert().get("subject"),
    }


def run_client(args: argparse.Namespace) -> int:
    """Connect to the server over TLS, send a request, and print the response."""
    context = create_ssl_context(args.ca_cert)
    connect_host = args.connect_host or args.host
    request = {"command": "GET_TIME"}

    with socket.create_connection((connect_host, args.port)) as sock:
        # `server_hostname` is critical because it enables certificate hostname
        # validation against the certificate SAN/CN.
        with context.wrap_socket(sock, server_hostname=args.host) as ssl_sock:
            details = tls_details(ssl_sock)
            logging.info(
                "Connected with %s / %s",
                details["tls_version"],
                details["cipher_suite"],
            )
            # Send a simple JSON command after the TLS handshake succeeds.
            ssl_sock.sendall(json.dumps(request).encode("utf-8"))
            response = ssl_sock.recv(4096)

    print("Server Response:", response.decode("utf-8"))
    return 0


if __name__ == "__main__":
    configure_logging()
    try:
        raise SystemExit(run_client(parse_args()))
    except FileNotFoundError as exc:
        logging.error("Required certificate file was not found: %s", exc.filename)
        raise SystemExit(1) from exc
    except ssl.SSLError as exc:
        logging.error("TLS error: %s", exc)
        raise SystemExit(1) from exc
    except OSError as exc:
        logging.error("Connection error: %s", exc)
        raise SystemExit(1) from exc
