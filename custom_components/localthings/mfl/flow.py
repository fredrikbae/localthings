"""The config flow's side of the MFL engine, kept here so config_flow.py
only gains a few lines."""

from __future__ import annotations

from .provider import MflCertificateAuth
from .transport import MflDtlsTransport, forget

# The plain handshake that ends in HandshakeTimeout takes an affected board
# off Wi-Fi for about 5-8 s (#504); dialling again before it rejoins just
# times out a second time.
RETRY_DELAY_S = 15.0

# The setup and reconfigure forms' checkbox, so an unlisted board can be put
# on the engine by hand.
FORM_FIELD = "use_max_fragment_length"

# Boards that go straight to the engine, by the plaintext /oic/p `vid`. A
# plain handshake with these sometimes completes (measured on .31,
# 2026-11-06), so a timeout cannot be relied on to pick the engine: the
# entry was then created without it and its sessions failed in service.
KNOWN_VENDOR_IDS = frozenset({"DA-AC-THERAC-01011"})


def known_board(scan) -> bool:
    plaintext = getattr(scan, "plaintext", None)
    return plaintext is not None and plaintext.vendor_id in KNOWN_VENDOR_IDS


def transport(host: str, port: int, cert_pem: str, key_pem: str, local_port: int | None):
    forget(host, port)
    return MflDtlsTransport(
        host, port, auth=MflCertificateAuth(cert_pem, key_pem), local_port=local_port
    )


def diagnostic_auth(cert_pem: str, key_pem: str) -> MflCertificateAuth:
    """The diagnostic handshake reports what the appliance did, so it must
    not reject the server chain itself."""
    return MflCertificateAuth(cert_pem, key_pem, verify_server=False)
