"""Throwaway certificates and an in-process OpenSSL DTLS server for the
MFL engine tests. Nothing here belongs to a real device."""

from __future__ import annotations

import datetime
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from OpenSSL import SSL

CIPHERS = b"ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0"


def _name(common_name: str, unit: str | None = None) -> x509.Name:
    attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Samsung Electronics"),
    ]
    if unit is not None:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit))
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


def _certificate(
    subject, issuer, public_key, issuer_key, *, ca: bool, padding_names: int = 0
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if padding_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(f"padding-{i:04d}.invalid") for i in range(padding_names)]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def server_chain(*, padding_names: int = 0) -> SimpleNamespace:
    """Root, intermediate and an OCF-style EC leaf. `padding_names` adds SAN
    entries to the intermediate so the server flight outgrows one record."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = _name("Synthetic OCF Root CA", "OCF Root CA")
    root = _certificate(root_name, root_name, root_key.public_key(), root_key, ca=True)

    intermediate_key = ec.generate_private_key(ec.SECP256R1())
    intermediate_name = _name("Synthetic SubCA", "OCF HA Device SubCA")
    intermediate = _certificate(
        intermediate_name,
        root_name,
        intermediate_key.public_key(),
        root_key,
        ca=True,
        padding_names=padding_names,
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _certificate(
        _name("OCF Device: Synthetic (00000000-0000-4000-8000-000000000001)", "OCF HA Device"),
        intermediate_name,
        leaf_key.public_key(),
        intermediate_key,
        ca=False,
    )
    return SimpleNamespace(
        root_pem=_pem(root).encode(),
        chain_pem=_pem(leaf) + _pem(intermediate),
        key_pem=_key_pem(leaf_key),
    )


def client_credentials(kind: str, *, extra_certificates: int = 0) -> SimpleNamespace:
    """A LocalThings-shaped self-signed client leaf (RSA-2048 like
    config_flow._mint_self_signed, or EC P-256), optionally followed by
    unrelated CA certificates to make the client flight large."""
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if kind == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    uuid = "00000000-0000-4000-8000-0000000000aa"
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "KR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Samsung Electronics"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"uuid:{uuid}"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"urn:uuid:{uuid}"),
        ]
    )
    leaf = _certificate(name, name, key.public_key(), key, ca=False)
    chain = _pem(leaf)
    for index in range(extra_certificates):
        extra_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        extra_name = _name(f"Synthetic padding CA {index}")
        chain += _pem(
            _certificate(extra_name, extra_name, extra_key.public_key(), extra_key, ca=True)
        )
    return SimpleNamespace(chain_pem=chain, key_pem=_key_pem(key), subject_uuid=uuid)


def openssl_server(chain: SimpleNamespace, *, cookies: bool, accept_client=True):
    """An OpenSSL DTLS server over memory BIOs that requests a client
    certificate; `accept_client=False` refuses whatever arrives."""
    context = SSL.Context(SSL.DTLS_METHOD)
    context.set_cipher_list(CIPHERS)
    certificates = x509.load_pem_x509_certificates(chain.chain_pem.encode())
    context.use_certificate(certificates[0])
    for certificate in certificates[1:]:
        context.add_extra_chain_cert(certificate)
    key = serialization.load_pem_private_key(chain.key_pem.encode(), password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    context.use_privatekey(key)
    context.set_verify(
        SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        lambda *_args: accept_client,
    )
    if cookies:
        context.set_cookie_generate_callback(lambda _connection: b"offline-cookie")
        context.set_cookie_verify_callback(lambda _connection, cookie: cookie == b"offline-cookie")
        assert SSL.OP_COOKIE_EXCHANGE is not None
        context.set_options(SSL.OP_COOKIE_EXCHANGE)
    server = SSL.Connection(context, None)
    server.set_accept_state()
    server.set_ciphertext_mtu(1200)
    return server


def split_records(data: bytes) -> list[bytes]:
    records = []
    offset = 0
    while offset + 13 <= len(data):
        length = int.from_bytes(data[offset + 11 : offset + 13], "big")
        records.append(data[offset : offset + 13 + length])
        offset += 13 + length
    return records
