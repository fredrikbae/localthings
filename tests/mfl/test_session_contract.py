"""MflCertificateAuth driven through smartthings-local's own session and
diagnostic, against an in-process OpenSSL server.

The provider reaches the library through a private hook
(`_create_dtls_connection`), so these tests are what notices when an
upstream release changes it.
"""

from __future__ import annotations

import contextlib
import socket

import pytest
from OpenSSL import SSL
from smartthings_local.protocol import dtls_probe, dtls_session
from smartthings_local.protocol.auth import AuthenticationProvider
from smartthings_local.protocol.dtls_session import DtlsCoapSession
from smartthings_local.protocol.endpoint import ResolvedUdpEndpoint

from custom_components.localthings.mfl.engine import DtlsCertMflClient
from custom_components.localthings.mfl.provider import MflCertificateAuth, ocf_trust_anchors

from .pki import client_credentials, openssl_server, server_chain, split_records


class _ServerSocket:
    """A socket whose peer is an in-process OpenSSL DTLS server (the
    pattern of smartthings-local's test_psk_session_integration)."""

    def __init__(self, server):
        self.server = server
        self.inbound: list[bytes] = []
        self.sent: list[bytes] = []
        self.closed = False
        self.completed = False

    def send(self, record):
        self.sent.append(record)
        self.server.bio_write(record)
        try:
            self.server.do_handshake()
            self.completed = True
        except SSL.WantReadError:
            pass
        with contextlib.suppress(SSL.WantReadError):
            self.inbound.extend(split_records(self.server.bio_read(65535)))
        return len(record)

    def recv(self, _size=65535):
        if not self.inbound:
            raise TimeoutError()
        return self.inbound.pop(0)

    def settimeout(self, _timeout):
        return None

    def close(self):
        self.closed = True


def _install(monkeypatch, module, data_socket):
    endpoint = ResolvedUdpEndpoint(socket.AF_INET, ("192.0.2.10", 49154))
    monkeypatch.setattr(
        module, "open_host_filtered_udp_socket", lambda *_a, **_k: (data_socket, endpoint)
    )


@pytest.fixture(scope="module")
def pki():
    return server_chain(), client_credentials("rsa")


def _provider(pki, **kwargs):
    server_pki, client_pki = pki
    return MflCertificateAuth(
        client_pki.chain_pem,
        client_pki.key_pem,
        trust_anchors_pem=server_pki.root_pem,
        **kwargs,
    )


def test_provider_satisfies_the_library_protocol(pki):
    provider = _provider(pki)
    assert isinstance(provider, AuthenticationProvider)
    with pytest.raises(TypeError):
        provider.configure_context(SSL.Context(SSL.DTLS_METHOD))
    assert isinstance(provider._create_dtls_connection(mtu=1200), DtlsCertMflClient)


def test_default_trust_is_the_ocf_root_smartthings_local_ships():
    assert ocf_trust_anchors()


@pytest.mark.parametrize("cookies", [False, True])
def test_session_handshake_and_close_through_the_hook(monkeypatch, pki, cookies):
    server = openssl_server(pki[0], cookies=cookies)
    data_socket = _ServerSocket(server)
    _install(monkeypatch, dtls_session, data_socket)
    session = DtlsCoapSession("appliance.invalid", 49154, auth=_provider(pki))

    session.connect(timeout=5.0)

    assert data_socket.completed
    assert isinstance(session.conn, DtlsCertMflClient)
    assert session.server_certificate_identity is None
    for record in data_socket.sent:
        assert len(split_records(record)) == 1
        assert len(record) <= 1200

    session.conn.send(b"coap request")
    server.bio_write(session.conn.bio_read(65535))
    assert server.recv(65535) == b"coap request"

    before = len(data_socket.sent)
    session.close()
    closing = [r for d in data_socket.sent[before:] for r in split_records(d)]
    alerts = [r for r in closing if r[0] == 21]
    assert len(alerts) == 1
    assert int.from_bytes(alerts[0][3:5], "big") == 1
    with pytest.raises(SSL.ZeroReturnError):
        server.recv(65535)


def test_diagnostic_handshake_runs_the_engine_without_verifying(monkeypatch, pki):
    untrusted = server_chain()
    data_socket = _ServerSocket(openssl_server(untrusted, cookies=True))
    _install(monkeypatch, dtls_probe, data_socket)
    _, client_pki = pki
    provider = MflCertificateAuth(client_pki.chain_pem, client_pki.key_pem, verify_server=False)

    result = dtls_probe.diagnose_dtls_handshake(
        "appliance.invalid", 49154, auth=provider, timeout=5.0
    )

    assert result.outcome == dtls_probe.COMPLETED
