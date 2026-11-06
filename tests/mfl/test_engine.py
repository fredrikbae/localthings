"""The MFL engine against a real OpenSSL DTLS server over memory BIOs."""

from __future__ import annotations

import struct

import pytest
from OpenSSL import SSL

from custom_components.localthings.mfl.engine import (
    EXT_MAX_FRAGMENT_LENGTH,
    SIGNATURE_ALGORITHMS,
    SUITE,
    DtlsCertMflClient,
    load_client_credential,
    load_trust_anchors,
)

from .pki import client_credentials, openssl_server, server_chain, split_records


def _client(server_pki, client_pki, *, trust=True, mtu=1200, mfl=1024):
    credential = load_client_credential(client_pki.chain_pem, client_pki.key_pem)
    anchors = load_trust_anchors(server_pki.root_pem) if trust else None
    return DtlsCertMflClient(credential, anchors, mtu=mtu, max_fragment_length=mfl)


def _pump(client, server, *, turns=60):
    """Run both ends until each has completed or the client failed.
    Returns (client_records, server_records) as sent on the wire."""
    sent = ([], [])
    done = [False, False]
    for _ in range(turns):
        for index, sender, receiver in ((0, client, server), (1, server, client)):
            if not done[index]:
                try:
                    sender.do_handshake()
                    done[index] = True
                except SSL.WantReadError:
                    pass
                except SSL.Error:
                    if sender is client:
                        raise
                    # The server gave up; its alert still has to reach the
                    # client, which is what these tests observe.
                    done[index] = True
            while True:
                try:
                    data = sender.bio_read(65535)
                except SSL.WantReadError:
                    break
                for record in split_records(data):
                    sent[index].append(record)
                    # One datagram per record, as the session driver sends them.
                    receiver.bio_write(record)
        if all(done):
            return sent
    raise AssertionError(f"handshake did not complete: {done}")


def _client_hello_extensions(record: bytes) -> tuple[list[int], dict[int, bytes]]:
    body = record[13 + 12 :]
    offset = 2 + 32
    offset += 1 + body[offset]  # session id
    offset += 1 + body[offset]  # cookie
    suites_len = int.from_bytes(body[offset : offset + 2], "big")
    suites = [
        int.from_bytes(body[i : i + 2], "big")
        for i in range(offset + 2, offset + 2 + suites_len, 2)
    ]
    offset += 2 + suites_len
    offset += 1 + body[offset]  # compression
    end = offset + 2 + int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    extensions = {}
    while offset < end:
        kind, length = struct.unpack("!HH", body[offset : offset + 4])
        extensions[kind] = body[offset + 4 : offset + 4 + length]
        offset += 4 + length
    return suites, extensions


@pytest.fixture(scope="module")
def server_pki():
    return server_chain()


@pytest.fixture(scope="module", params=["rsa", "ec"])
def client_pki(request):
    return client_credentials(request.param)


@pytest.mark.parametrize("cookies", [False, True])
def test_handshake_and_application_data(server_pki, client_pki, cookies):
    client = _client(server_pki, client_pki)
    server = openssl_server(server_pki, cookies=cookies)

    _pump(client, server)

    assert client.negotiated_max_fragment_length == 1024
    # The server authenticated the client's own certificate.
    peer = server.get_peer_certificate()
    assert client_pki.subject_uuid in peer.get_subject().CN
    client.send(b"coap request")
    server.bio_write(client.bio_read(65535))
    assert server.recv(65535) == b"coap request"
    server.send(b"coap response")
    client.bio_write(server.bio_read(65535))
    assert client.recv(65535) == b"coap response"
    client.shutdown()
    server.bio_write(client.bio_read(65535))
    with pytest.raises(SSL.ZeroReturnError):
        server.recv(65535)


def test_client_hello_offers_only_the_samsung_suite_and_mfl(server_pki, client_pki):
    client = _client(server_pki, client_pki)
    with pytest.raises(SSL.WantReadError):
        client.do_handshake()
    (record,) = split_records(client.bio_read(65535))

    suites, extensions = _client_hello_extensions(record)

    assert suites == [SUITE]
    assert extensions[EXT_MAX_FRAGMENT_LENGTH] == b"\x02"
    algorithms = extensions[0x000D]
    assert [int.from_bytes(algorithms[i : i + 2], "big") for i in range(2, len(algorithms), 2)] == [
        *SIGNATURE_ALGORITHMS
    ]


@pytest.mark.parametrize("mfl", [512, 1024])
def test_openssl_server_keeps_its_flight_under_the_limit(mfl):
    """The property the Wi-Fi fix rests on: with the extension granted no
    server record carries more than `mfl` bytes of plaintext."""
    server_pki = server_chain(padding_names=60)
    client_pki = client_credentials("rsa")
    client = _client(server_pki, client_pki, mfl=mfl)
    server = openssl_server(server_pki, cookies=True)

    _, server_records = _pump(client, server)

    handshake = [r for r in server_records if r[3:5] == b"\0\0"]
    assert max(len(r) - 13 for r in handshake) <= mfl
    certificate_fragments = [r for r in handshake if r[0] == 22 and r[13] == 11]
    assert len(certificate_fragments) > 1, "the padded chain should need fragmenting"


def test_large_client_flight_is_fragmented_within_limits(server_pki):
    client_pki = client_credentials("rsa", extra_certificates=3)
    client = _client(server_pki, client_pki, mtu=1200)
    server = openssl_server(server_pki, cookies=False)

    client_records, _ = _pump(client, server)

    assert all(len(r) <= 1200 for r in client_records)
    assert all(len(r) - 13 <= 1024 + 8 + 16 for r in client_records)
    certificate = [r for r in client_records if r[0] == 22 and r[3:5] == b"\0\0" and r[13] == 11]
    assert len(certificate) > 2


def test_untrusted_server_chain_is_refused(server_pki, client_pki):
    other_root = server_chain()
    credential = load_client_credential(client_pki.chain_pem, client_pki.key_pem)
    client = DtlsCertMflClient(credential, load_trust_anchors(other_root.root_pem))
    server = openssl_server(server_pki, cookies=False)

    with pytest.raises(SSL.Error, match="did not verify"):
        _pump(client, server)


def test_diagnostic_mode_completes_without_a_trusted_chain(server_pki, client_pki):
    client = _client(server_pki, client_pki, trust=False)
    server = openssl_server(server_pki, cookies=False)

    _pump(client, server)

    assert client.negotiated_max_fragment_length == 1024


def test_rejected_client_certificate_surfaces_the_alert(server_pki, client_pki):
    client = _client(server_pki, client_pki)
    server = openssl_server(server_pki, cookies=False, accept_client=False)

    with pytest.raises(SSL.Error) as raised:
        _pump(client, server)

    assert "tlsv1 alert" in str(raised.value)


def test_server_that_ignores_mfl_is_refused(server_pki, client_pki):
    client = _client(server_pki, client_pki)
    with pytest.raises(SSL.WantReadError):
        client.do_handshake()
    client.bio_read(65535)
    body = b"\xfe\xfd" + bytes(32) + b"\x00" + struct.pack("!H", SUITE) + b"\x00"
    length = len(body).to_bytes(3, "big")
    handshake = b"\x02" + length + b"\x00\x00" + b"\x00\x00\x00" + length + body
    record = b"\x16\xfe\xfd" + b"\x00" * 8 + struct.pack("!H", len(handshake)) + handshake

    client.bio_write(record)

    with pytest.raises(SSL.Error, match="did not accept max_fragment_length 1024"):
        client.do_handshake()


def test_send_refuses_a_record_over_the_negotiated_limit(server_pki, client_pki):
    client = _client(server_pki, client_pki)
    _pump(client, openssl_server(server_pki, cookies=False))

    client.send(b"x" * 1024)
    with pytest.raises(SSL.Error, match="exceeds the negotiated max_fragment_length"):
        client.send(b"x" * 1025)


def test_retransmission_uses_fresh_record_sequence_numbers(server_pki, client_pki):
    client = _client(server_pki, client_pki)
    with pytest.raises(SSL.WantReadError):
        client.do_handshake()
    (first,) = split_records(client.bio_read(65535))

    client.DTLSv1_handle_timeout()
    (again,) = split_records(client.bio_read(65535))

    assert first[13:] == again[13:]
    assert int.from_bytes(again[5:11], "big") > int.from_bytes(first[5:11], "big")
