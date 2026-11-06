"""An authentication provider that brings its own DTLS engine.

smartthings-local routes a provider with a `_create_dtls_connection` factory
to that engine instead of pyOpenSSL (dtls_session.py `_new_dtls_connection`,
dtls_probe.py `_diagnostic_connection`), so no change to the library is
needed. The hook is private upstream; tests/mfl pin the contract.
"""

from __future__ import annotations

from importlib import resources

from OpenSSL import SSL

from .engine import DtlsCertMflClient, load_client_credential, load_trust_anchors

DEFAULT_MAX_FRAGMENT_LENGTH = 1024


def ocf_trust_anchors():
    """The OCF root smartthings-local's own certificate carrier verifies
    against, read from the installed package so the two never drift."""
    pem = resources.files("smartthings_local.protocol").joinpath("ocf_root_ca.pem").read_bytes()
    return load_trust_anchors(pem)


class MflCertificateAuth:
    """Certificate credentials offered with max_fragment_length.

    `verify_server=False` is for the diagnostic handshake only: it must
    report what the appliance did, so it may not reject the chain itself.
    """

    __slots__ = ("_credential", "_max_fragment_length", "_trust")

    def __init__(
        self,
        certificate_pem: str,
        private_key_pem: str,
        *,
        verify_server: bool = True,
        max_fragment_length: int = DEFAULT_MAX_FRAGMENT_LENGTH,
        trust_anchors_pem: bytes | None = None,
    ) -> None:
        """`trust_anchors_pem` replaces the OCF root; tests use it for a
        synthetic chain."""
        self._credential = load_client_credential(certificate_pem, private_key_pem)
        if not verify_server:
            self._trust = None
        elif trust_anchors_pem is not None:
            self._trust = load_trust_anchors(trust_anchors_pem)
        else:
            self._trust = ocf_trust_anchors()
        self._max_fragment_length = max_fragment_length

    def __repr__(self) -> str:
        return f"MflCertificateAuth(max_fragment_length={self._max_fragment_length})"

    def configure_context(self, context: SSL.Context) -> None:
        """Present for smartthings-local's AuthenticationProvider check; an
        OpenSSL context cannot carry max_fragment_length."""
        raise TypeError("MflCertificateAuth only runs through its own DTLS engine")

    def _create_dtls_connection(self, *, mtu: int) -> DtlsCertMflClient:
        return DtlsCertMflClient(
            self._credential,
            self._trust,
            mtu=mtu,
            max_fragment_length=self._max_fragment_length,
        )
