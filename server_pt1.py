#!/usr/bin/env python3

"""
/******************************* server_pt1.py *******************************
 *
 *  Module: Part 1 TLS Server
 *
 *  This module implements the Part 1 secure TLS server for the university
 *  TLS/SSL project.
 *
 *  The server provides:
 *
 *  - TCP-based communication over IPv4 sockets
 *  - TLS-wrapped server connections using Python's `ssl` module
 *  - X.509 server certificate presentation during the TLS handshake
 *  - Logging of the negotiated TLS version and cipher suite
 *  - Simple JSON request/response handling for the `GET_TIME` command
 *
 *  Security Properties:
 *
 *  - The server presents a certificate and private key loaded from disk.
 *  - The certificate is intended to be signed by the local project CA.
 *  - The TLS socket exposes negotiated session metadata for logging.
 *  - The server does not modify the original `server.py`; it is a new
 *    implementation for Part 1 only.
 *
 *****************************************************************************/
"""

import argparse
import datetime
import json
import logging
import socket
import ssl
import sys
from typing import Any


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8443
DEFAULT_CA_CERT = "certs/ca.crt"
DEFAULT_SERVER_CERT = "certs/server.crt"
DEFAULT_SERVER_KEY = "certs/server.key"


def parse_args() -> argparse.Namespace:
    """Parse command-line options for the Part 1 TLS server."""
    parser = argparse.ArgumentParser(description="Part 1 TLS server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Server bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Server port")
    parser.add_argument("--ca-cert", default=DEFAULT_CA_CERT, help="Trusted CA certificate")
    parser.add_argument("--certfile", default=DEFAULT_SERVER_CERT, help="Server certificate")
    parser.add_argument("--keyfile", default=DEFAULT_SERVER_KEY, help="Server private key")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Handle a single TLS connection and then exit",
    )
    return parser.parse_args()


def configure_logging() -> None:
    """Initialize human-readable logging for server events."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )


def create_ssl_context(certfile: str, keyfile: str, ca_cert: str) -> ssl.SSLContext:
    """Create the server TLS context and load certificate materials.

    Even though Part 1 does not require mutual TLS, the CA file is loaded so
    the trust anchor is available in the context and certificate handling stays
    aligned with the overall project certificate layout.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.load_verify_locations(cafile=ca_cert)
    return context


def tls_details(ssl_sock: ssl.SSLSocket) -> dict[str, Any]:
    """Collect negotiated TLS session details from an established connection."""
    cipher_name, protocol_name, secret_bits = ssl_sock.cipher()
    return {
        "tls_version": ssl_sock.version(),
        "cipher_suite": cipher_name,
        "cipher_protocol": protocol_name,
        "secret_bits": secret_bits,
        "server_side": ssl_sock.server_side,
    }


def receive_json(ssl_sock: ssl.SSLSocket) -> dict[str, Any]:
    """Receive and decode a single JSON request from the client."""
    data = ssl_sock.recv(4096)
    if not data:
        raise ValueError("client closed the connection before sending data")
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("received invalid JSON request") from exc


def build_response(request: dict[str, Any]) -> dict[str, Any]:
    """Build the JSON response for a recognized client request."""
    if request.get("command") == "GET_TIME":
        return {"time": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    return {"error": "Unknown command"}


def handle_client(ssl_sock: ssl.SSLSocket, client_addr: tuple[str, int]) -> None:
    """Process one TLS client connection from handshake through response."""
    details = tls_details(ssl_sock)
    # Log the negotiated TLS properties required by the assignment.
    logging.info(
        "Accepted TLS connection from %s:%s using %s / %s",
        client_addr[0],
        client_addr[1],
        details["tls_version"],
        details["cipher_suite"],
    )

    try:
        # Read the JSON command sent by the client and compute a reply.
        request = receive_json(ssl_sock)
        logging.info("Received request payload: %s", request)
        response = build_response(request)
    except ValueError as exc:
        logging.error("Request handling error: %s", exc)
        response = {"error": str(exc)}

    ssl_sock.sendall(json.dumps(response).encode("utf-8"))


def serve(args: argparse.Namespace) -> int:
    """Start the TCP listener, wrap accepted sockets with TLS, and serve clients."""
    context = create_ssl_context(args.certfile, args.keyfile, args.ca_cert)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        # Allow rapid local restarts while testing.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.host, args.port))
        sock.listen(5)
        logging.info("Part 1 TLS server listening on %s:%s", args.host, args.port)

        while True:
            # Accept a plain TCP connection first, then upgrade it to TLS.
            conn, addr = sock.accept()
            try:
                with context.wrap_socket(conn, server_side=True) as ssl_sock:
                    handle_client(ssl_sock, addr)
            except ssl.SSLError as exc:
                logging.error("TLS handshake/connection error from %s:%s: %s", addr[0], addr[1], exc)
            except OSError as exc:
                logging.error("Socket error with %s:%s: %s", addr[0], addr[1], exc)
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

            if args.once:
                break

    return 0


if __name__ == "__main__":
    configure_logging()
    try:
        raise SystemExit(serve(parse_args()))
    except FileNotFoundError as exc:
        logging.error("Required certificate file was not found: %s", exc.filename)
        raise SystemExit(1) from exc
    except KeyboardInterrupt:
        logging.info("Server interrupted, shutting down")
        raise SystemExit(0)
    except Exception as exc:  # pragma: no cover
        logging.exception("Unhandled server error: %s", exc)
        raise SystemExit(1) from exc
