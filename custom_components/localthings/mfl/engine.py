"""Pure-Python DTLS 1.2 client: ECDHE-ECDSA-AES128-GCM-SHA256 with the
max_fragment_length extension (RFC 6066 section 4).

pyOpenSSL cannot offer max_fragment_length. Without it the TP1X
DA-AC-THERAC-01011 board (Thermia Aura S3) sends its server flight as one
over-MTU datagram and drops off Wi-Fi; with a 1024-byte limit the handshake
completes and the unit stays online (measured 2026-11-06, docs/fork-mfl.md).

Adapted from smartthings_local/protocol/_dtls_psk.py (MIT, Copyright (c) 2026
Jack Nagy): the record layer, replay window, reassembly and
HelloVerifyRequest handling follow that engine. The interface is the same
memory-BIO subset of OpenSSL.SSL.Connection that smartthings-local's
handshake driver and DtlsCoapSession drive, with pyOpenSSL's exceptions.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
import time
import warnings
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from OpenSSL import SSL, crypto

WantRead = SSL.WantReadError
ZeroReturn = SSL.ZeroReturnError
DtlsError = SSL.Error

_LOGGER = logging.getLogger(__name__)

_CT_CHANGE_CIPHER_SPEC = 20
_CT_ALERT = 21
_CT_HANDSHAKE = 22
_CT_APPLICATION_DATA = 23

_HT_CLIENT_HELLO = 1
_HT_SERVER_HELLO = 2
_HT_HELLO_VERIFY_REQUEST = 3
_HT_CERTIFICATE = 11
_HT_SERVER_KEY_EXCHANGE = 12
_HT_CERTIFICATE_REQUEST = 13
_HT_SERVER_HELLO_DONE = 14
_HT_CERTIFICATE_VERIFY = 15
_HT_CLIENT_KEY_EXCHANGE = 16
_HT_FINISHED = 20

_VERSION = b"\xfe\xfd"
SUITE = 0xC02B  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
_NAMED_CURVE_SECP256R1 = 0x0017
_ECCURVETYPE_NAMED = 3

EXT_MAX_FRAGMENT_LENGTH = 0x0001
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B
_EXT_SIGNATURE_ALGORITHMS = 0x000D

# RFC 6066 codes. 1024 keeps the server flight under a 1500-byte MTU while
# every resource the TP1X AC reads per href still fits (largest 826 B).
MFL_CODES = {512: 1, 1024: 2, 2048: 3, 4096: 4}

# The client's offer, as smartthings-local's Samsung profile pins it.
SIGNATURE_ALGORITHMS = (0x0401, 0x0403, 0x0201, 0x0203)
SIG_RSA_PKCS1_SHA256 = 0x0401
SIG_ECDSA_SHA256 = 0x0403
_ECDSA_HASHES = {4: hashes.SHA256, 2: hashes.SHA1, 5: hashes.SHA384}

_RECORD_HEADER = 13
_HANDSHAKE_HEADER = 12
_GCM_EXPLICIT_NONCE = 8
_GCM_TAG = 16
_KEY_LEN = 16
_IV_LEN = 4
_VERIFY_DATA_LEN = 12
_MAX_SEQ = (1 << 48) - 1
_REPLAY_WINDOW = 64
_PLAIN_RECORD_LIMIT = 16384

_MAX_HANDSHAKE_MESSAGE = 16384
_MAX_OUTBOX = 262144
_MAX_PENDING_MESSAGES = 16
_MAX_INBOX = 64
_MAX_APPDATA = 256
_MAX_HELLO_VERIFY = 5

_ALERT_CLOSE_NOTIFY = 0
_ALERT_FATAL = 2
_ALERT_WARNING = 1
_ALERT_NAMES = {
    10: "unexpected message",
    20: "bad record mac",
    40: "handshake failure",
    42: "bad certificate",
    43: "unsupported certificate",
    45: "certificate expired",
    46: "certificate unknown",
    47: "illegal parameter",
    48: "unknown ca",
    49: "access denied",
    50: "decode error",
    51: "decrypt error",
    70: "protocol version",
    71: "insufficient security",
    80: "internal error",
    110: "unsupported extension",
    116: "certificate required",
}


def _prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.2 PRF with SHA-256 (RFC 5246 section 5)."""
    out = bytearray()
    a = hmac.new(secret, label + seed, hashlib.sha256).digest()
    while len(out) < length:
        out += hmac.new(secret, a + label + seed, hashlib.sha256).digest()
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return bytes(out[:length])


class _ReplayWindow:
    """RFC 6347 section 4.1.2.6 sliding window, committed only on records
    that authenticated."""

    __slots__ = ("_bitmap", "_highest")

    def __init__(self) -> None:
        self._bitmap = 0
        self._highest = -1

    def is_replay(self, seq: int) -> bool:
        if seq > self._highest:
            return False
        offset = self._highest - seq
        return offset >= _REPLAY_WINDOW or bool(self._bitmap & (1 << offset))

    def accept(self, seq: int) -> None:
        if seq > self._highest:
            shift = min(seq - self._highest, _REPLAY_WINDOW)
            self._bitmap = ((self._bitmap << shift) | 1) & ((1 << _REPLAY_WINDOW) - 1)
            self._highest = seq
            return
        offset = self._highest - seq
        if offset < _REPLAY_WINDOW:
            self._bitmap |= 1 << offset


class _GcmTransform:
    """AES-128-GCM records (RFC 5288): 4-byte implicit salt from the key
    block, 8-byte explicit nonce set to epoch and sequence number."""

    __slots__ = ("_decrypt", "_decrypt_salt", "_encrypt", "_encrypt_salt")

    def __init__(self, key_block: bytes) -> None:
        # RFC 5246 6.3 with no MAC keys: client key, server key, client IV, server IV.
        self._encrypt = AESGCM(key_block[0:_KEY_LEN])
        self._decrypt = AESGCM(key_block[_KEY_LEN : 2 * _KEY_LEN])
        self._encrypt_salt = key_block[2 * _KEY_LEN : 2 * _KEY_LEN + _IV_LEN]
        self._decrypt_salt = key_block[2 * _KEY_LEN + _IV_LEN : 2 * _KEY_LEN + 2 * _IV_LEN]

    @staticmethod
    def _aad(epoch: int, seq: int, content_type: int, length: int) -> bytes:
        return (
            struct.pack("!H", epoch)
            + seq.to_bytes(6, "big")
            + struct.pack("!BHH", content_type, 0xFEFD, length)
        )

    def protect(self, epoch: int, seq: int, content_type: int, payload: bytes) -> bytes:
        explicit = struct.pack("!H", epoch) + seq.to_bytes(6, "big")
        nonce = self._encrypt_salt + explicit
        aad = self._aad(epoch, seq, content_type, len(payload))
        return explicit + self._encrypt.encrypt(nonce, payload, aad)

    def unprotect(self, epoch: int, seq: int, content_type: int, fragment: bytes) -> bytes | None:
        if len(fragment) < _GCM_EXPLICIT_NONCE + _GCM_TAG:
            return None
        explicit, sealed = fragment[:_GCM_EXPLICIT_NONCE], fragment[_GCM_EXPLICIT_NONCE:]
        aad = self._aad(epoch, seq, content_type, len(sealed) - _GCM_TAG)
        try:
            return self._decrypt.decrypt(self._decrypt_salt + explicit, sealed, aad)
        except InvalidTag:
            return None


@dataclass(frozen=True, repr=False)
class ClientCredential:
    """Our certificate chain (DER, leaf first) and its private key."""

    chain: tuple[bytes, ...]
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey

    def __repr__(self) -> str:
        return f"ClientCredential(certificates={len(self.chain)})"

    @property
    def signature_algorithm(self) -> int:
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return SIG_RSA_PKCS1_SHA256
        return SIG_ECDSA_SHA256

    def sign(self, data: bytes) -> bytes:
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return self.private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))


def load_client_credential(certificate_pem: str, private_key_pem: str) -> ClientCredential:
    """Parse a PEM chain and key through OpenSSL, which reads Samsung's
    non-DER certificates that `cryptography` rejects."""
    blocks = [
        block + "-----END CERTIFICATE-----"
        for block in certificate_pem.split("-----END CERTIFICATE-----")
        if "-----BEGIN CERTIFICATE-----" in block
    ]
    if not blocks:
        raise ValueError("no certificate in certificate_pem")
    chain = tuple(
        crypto.dump_certificate(
            crypto.FILETYPE_ASN1,
            crypto.load_certificate(
                crypto.FILETYPE_PEM, block[block.index("-----BEGIN") :].encode()
            ),
        )
        for block in blocks
    )
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        raise ValueError(f"unsupported client key type {type(key).__name__}")
    return ClientCredential(chain=chain, private_key=key)


def load_trust_anchors(pem: bytes) -> tuple[crypto.X509, ...]:
    blocks = [
        block + b"-----END CERTIFICATE-----"
        for block in pem.split(b"-----END CERTIFICATE-----")
        if b"-----BEGIN CERTIFICATE-----" in block
    ]
    if not blocks:
        raise ValueError("no trust anchor certificate")
    return tuple(
        crypto.load_certificate(crypto.FILETYPE_PEM, block[block.index(b"-----BEGIN") :])
        for block in blocks
    )


def _public_key_of(certificate: crypto.X509):
    with warnings.catch_warnings():
        # pyOpenSSL deprecates get_pubkey for to_cryptography(), but that
        # reparses the whole certificate, which fails on Samsung's leaves.
        warnings.simplefilter("ignore", DeprecationWarning)
        return certificate.get_pubkey().to_cryptography_key()


class DtlsCertMflClient:
    """One DTLS 1.2 certificate session with max_fragment_length, driven
    through a memory BIO.

    `trust` is the set of anchors the server chain must verify against;
    None skips every server check (chain and ServerKeyExchange signature),
    which only a diagnostic handshake may ask for.
    """

    def __init__(
        self,
        credential: ClientCredential,
        trust: Sequence[crypto.X509] | None,
        *,
        mtu: int = 1200,
        max_fragment_length: int = 1024,
    ) -> None:
        if type(mtu) is not int or not 256 <= mtu <= 65535:
            raise ValueError("mtu must be between 256 and 65535")
        if max_fragment_length not in MFL_CODES:
            raise ValueError(f"max_fragment_length must be one of {sorted(MFL_CODES)}")
        self._credential = credential
        self._trust = tuple(trust) if trust is not None else None
        self._mtu = mtu
        self._mfl = max_fragment_length
        # Until the server confirms the extension nothing larger is promised.
        self._record_limit = _PLAIN_RECORD_LIMIT

        self._inbox: deque[bytes] = deque()
        self._outbox: deque[bytes] = deque()
        self._outbox_bytes = 0
        self._appdata: deque[bytes] = deque()

        self._state = "start"
        self._transcript = bytearray()
        self._send_epoch = 0
        self._send_seq = {0: 0, 1: 0}
        self._next_msg_seq = 0
        self._recv_windows: dict[int, _ReplayWindow] = {}
        self._transform: _GcmTransform | None = None
        self._read_active = False

        self._client_random = b""
        self._server_random = b""
        self._cookie = b""
        self._master_secret = b""
        self._private_key: ec.EllipticCurvePrivateKey | None = None
        self._peer_point = b""
        self._peer_chain: tuple[bytes, ...] = ()
        self._peer_leaf: crypto.X509 | None = None
        self._certificate_requested = False
        self._server_signature_algorithms: tuple[int, ...] = ()

        self._pending: dict[int, tuple[int, bytearray, bytearray]] = {}
        self._ready: dict[int, tuple[int, bytes]] = {}
        self._next_recv_msg_seq = 0

        # The last flight as messages, re-emitted with fresh record
        # sequence numbers on a retransmission (RFC 6347 4.2.4).
        self._flight: list[tuple[str, int, int, bytes, int]] = []
        self._rto = 1.0
        self._flight_deadline: float | None = None
        self._peer_closed = False
        self._hello_verify_count = 0
        self._failed: str | None = None

    # -- memory BIO ------------------------------------------------------

    def bio_write(self, datagram: bytes) -> int:
        if len(self._inbox) >= _MAX_INBOX:
            _LOGGER.debug("DTLS: inbound queue full, dropping datagram")
            return 0
        self._inbox.append(bytes(datagram))
        return len(datagram)

    def bio_read(self, capacity: int = 65535) -> bytes:
        """Whole pending records, as many as fit in `capacity` (at least one)."""
        if not self._outbox:
            raise WantRead()
        out = bytearray(self._outbox.popleft())
        while self._outbox and len(out) + len(self._outbox[0]) <= capacity:
            out += self._outbox.popleft()
        self._outbox_bytes -= len(out)
        return bytes(out)

    # -- handshake -------------------------------------------------------

    def do_handshake(self) -> None:
        if self._failed:
            raise DtlsError(self._failed)
        if self._state == "established":
            return
        if self._state == "start":
            self._send_client_hello(cookie=b"")
            self._state = "sent_hello"
        self._drain_inbox()
        if self._failed:
            raise DtlsError(self._failed)
        if self._state != "established":
            raise WantRead()

    def get_peer_certificate(self) -> crypto.X509 | None:
        return self._peer_leaf

    @property
    def negotiated_max_fragment_length(self) -> int | None:
        return self._record_limit if self._record_limit != _PLAIN_RECORD_LIMIT else None

    def _send_client_hello(self, cookie: bytes) -> None:
        if not cookie:
            self._client_random = os.urandom(32)
        body = bytearray(_VERSION)
        body += self._client_random
        body.append(0)  # session_id
        body.append(len(cookie))
        body += cookie
        body += struct.pack("!HH", 2, SUITE)
        body += bytes([1, 0])  # null compression
        signature_algorithms = b"".join(struct.pack("!H", alg) for alg in SIGNATURE_ALGORITHMS)
        extensions = (
            struct.pack("!HHHH", _EXT_SUPPORTED_GROUPS, 4, 2, _NAMED_CURVE_SECP256R1)
            + struct.pack("!HH", _EXT_EC_POINT_FORMATS, 2)
            + bytes([1, 0])
            + struct.pack(
                "!HHH",
                _EXT_SIGNATURE_ALGORITHMS,
                2 + len(signature_algorithms),
                len(signature_algorithms),
            )
            + signature_algorithms
            + struct.pack("!HH", EXT_MAX_FRAGMENT_LENGTH, 1)
            + bytes([MFL_CODES[self._mfl]])
        )
        body += struct.pack("!H", len(extensions)) + extensions
        self._start_flight()
        self._emit_handshake(_HT_CLIENT_HELLO, bytes(body), transcript=True)

    def _send_client_flight(self) -> None:
        """[Certificate] + ClientKeyExchange + [CertificateVerify] +
        ChangeCipherSpec + Finished."""
        self._start_flight()
        if self._certificate_requested:
            entries = b"".join(len(der).to_bytes(3, "big") + der for der in self._credential.chain)
            self._emit_handshake(
                _HT_CERTIFICATE, len(entries).to_bytes(3, "big") + entries, transcript=True
            )

        assert self._private_key is not None
        public = self._private_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self._emit_handshake(
            _HT_CLIENT_KEY_EXCHANGE, bytes([len(public)]) + public, transcript=True
        )

        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), self._peer_point)
        premaster = self._private_key.exchange(ec.ECDH(), peer)
        self._master_secret = _prf(
            premaster, b"master secret", self._client_random + self._server_random, 48
        )
        key_block = _prf(
            self._master_secret,
            b"key expansion",
            self._server_random + self._client_random,
            2 * _KEY_LEN + 2 * _IV_LEN,
        )

        if self._certificate_requested:
            algorithm = self._credential.signature_algorithm
            if self._server_signature_algorithms and (
                algorithm not in self._server_signature_algorithms
            ):
                self._fail(
                    f"server accepts none of our client signature algorithm 0x{algorithm:04x}"
                )
                return
            signature = self._credential.sign(bytes(self._transcript))
            self._emit_handshake(
                _HT_CERTIFICATE_VERIFY,
                struct.pack("!HH", algorithm, len(signature)) + signature,
                transcript=True,
            )

        self._emit_change_cipher_spec()
        self._transform = _GcmTransform(key_block)
        self._send_epoch = 1

        verify = _prf(
            self._master_secret,
            b"client finished",
            hashlib.sha256(self._transcript).digest(),
            _VERIFY_DATA_LEN,
        )
        self._emit_handshake(_HT_FINISHED, verify, transcript=True)

    # -- record emission -------------------------------------------------

    def _start_flight(self) -> None:
        self._flight = []
        self._rto = 1.0

    def _max_fragment(self, epoch: int) -> int:
        overhead = _RECORD_HEADER + _HANDSHAKE_HEADER
        if epoch > 0:
            overhead += _GCM_EXPLICIT_NONCE + _GCM_TAG
        return max(1, min(self._mtu - overhead, self._record_limit - _HANDSHAKE_HEADER))

    def _emit_handshake(self, msg_type: int, body: bytes, *, transcript: bool) -> None:
        msg_seq = self._next_msg_seq
        self._next_msg_seq += 1
        if transcript:
            self._transcript += (
                bytes([msg_type])
                + len(body).to_bytes(3, "big")
                + struct.pack("!H", msg_seq)
                + (0).to_bytes(3, "big")
                + len(body).to_bytes(3, "big")
                + body
            )
        self._flight.append(("handshake", msg_type, msg_seq, body, self._send_epoch))
        self._send_handshake_fragments(msg_type, msg_seq, body, self._send_epoch)

    def _send_handshake_fragments(
        self, msg_type: int, msg_seq: int, body: bytes, epoch: int
    ) -> None:
        limit = self._max_fragment(epoch)
        offset = 0
        while True:
            fragment = body[offset : offset + limit]
            header = struct.pack(
                "!B3sH3s3s",
                msg_type,
                len(body).to_bytes(3, "big"),
                msg_seq,
                offset.to_bytes(3, "big"),
                len(fragment).to_bytes(3, "big"),
            )
            self._emit_record(_CT_HANDSHAKE, header + fragment, epoch)
            offset += len(fragment)
            if offset >= len(body):
                break
        self._flight_deadline = _now() + self._rto

    def _emit_change_cipher_spec(self) -> None:
        self._flight.append(("ccs", 0, 0, b"\x01", 0))
        self._emit_record(_CT_CHANGE_CIPHER_SPEC, b"\x01", 0)

    def _emit_record(self, content_type: int, payload: bytes, epoch: int) -> None:
        seq = self._send_seq[epoch]
        if seq > _MAX_SEQ:
            self._fail("DTLS sequence number space exhausted")
            raise DtlsError(self._failed)
        self._send_seq[epoch] = seq + 1
        if epoch > 0:
            assert self._transform is not None
            fragment = self._transform.protect(epoch, seq, content_type, payload)
        else:
            fragment = payload
        record = (
            bytes([content_type])
            + _VERSION
            + struct.pack("!H", epoch)
            + seq.to_bytes(6, "big")
            + struct.pack("!H", len(fragment))
            + fragment
        )
        if self._outbox_bytes + len(record) > _MAX_OUTBOX:
            self._fail("DTLS outbound buffer overflow")
            raise DtlsError(self._failed)
        self._outbox.append(record)
        self._outbox_bytes += len(record)

    # -- inbound ---------------------------------------------------------

    def _drain_inbox(self) -> None:
        while self._inbox:
            datagram = self._inbox.popleft()
            offset = 0
            while offset + _RECORD_HEADER <= len(datagram):
                length = int.from_bytes(datagram[offset + 11 : offset + _RECORD_HEADER], "big")
                end = offset + _RECORD_HEADER + length
                if end > len(datagram):
                    break
                self._handle_record(datagram[offset:end])
                offset = end
                if self._failed:
                    return

    def _handle_record(self, record: bytes) -> None:
        content_type = record[0]
        epoch = int.from_bytes(record[3:5], "big")
        fragment = record[_RECORD_HEADER:]
        hello_verify_only = False
        if record[1:3] != _VERSION:
            # A DTLS 1.0-framed HelloVerifyRequest is legal (RFC 6347
            # 4.2.1); admitted for that one message only, as _dtls_psk does.
            if not (
                record[1:3] == b"\xfe\xff"
                and epoch == 0
                and content_type == _CT_HANDSHAKE
                and self._state in ("sent_hello", "sent_cookie_hello")
                and fragment[:1] == bytes([_HT_HELLO_VERIFY_REQUEST])
            ):
                return
            hello_verify_only = True
        seq = int.from_bytes(record[5:11], "big")

        expected_epoch = 1 if self._read_active else 0
        if epoch != expected_epoch:
            return
        if epoch > 0:
            if self._transform is None:
                return
            window = self._recv_windows.setdefault(epoch, _ReplayWindow())
            if window.is_replay(seq):
                return
            payload = self._transform.unprotect(epoch, seq, content_type, fragment)
            if payload is None:
                _LOGGER.debug("DTLS: discarding record that failed authentication")
                return
            window.accept(seq)
        else:
            payload = fragment

        if content_type == _CT_HANDSHAKE:
            self._handle_handshake_fragment(
                payload, authenticated=epoch > 0, hello_verify_only=hello_verify_only
            )
        elif content_type == _CT_CHANGE_CIPHER_SPEC:
            if payload == b"\x01" and self._state == "sent_client_flight":
                self._read_active = True
                self._recv_windows.pop(1, None)
        elif content_type == _CT_ALERT:
            self._handle_alert(payload, authenticated=epoch > 0)
        elif content_type == _CT_APPLICATION_DATA:
            if epoch == 0:
                _LOGGER.debug("DTLS: dropping unauthenticated epoch-0 app data")
                return
            if payload:
                if len(self._appdata) >= _MAX_APPDATA:
                    self._appdata.popleft()
                    _LOGGER.debug("DTLS: application queue full, dropped oldest")
                self._appdata.append(payload)

    def _handle_alert(self, payload: bytes, *, authenticated: bool) -> None:
        if len(payload) < 2:
            return
        level, description = payload[0], payload[1]
        if description == _ALERT_CLOSE_NOTIFY:
            if authenticated:
                self._peer_closed = True
            return
        if level == _ALERT_FATAL:
            name = _ALERT_NAMES.get(description, str(description))
            # The OpenSSL wording, so localthings' _alert_name reads it back.
            self._fail(f"tlsv1 alert {name}")

    def _handle_handshake_fragment(
        self,
        payload: bytes,
        *,
        authenticated: bool = False,
        hello_verify_only: bool = False,
    ) -> None:
        if self._state == "established" and authenticated:
            _LOGGER.debug("DTLS: ignoring handshake record on a live session")
            return
        offset = 0
        while offset + _HANDSHAKE_HEADER <= len(payload):
            msg_type = payload[offset]
            if hello_verify_only and msg_type != _HT_HELLO_VERIFY_REQUEST:
                return
            length = int.from_bytes(payload[offset + 1 : offset + 4], "big")
            msg_seq = int.from_bytes(payload[offset + 4 : offset + 6], "big")
            frag_off = int.from_bytes(payload[offset + 6 : offset + 9], "big")
            frag_len = int.from_bytes(payload[offset + 9 : offset + 12], "big")
            body_start = offset + _HANDSHAKE_HEADER
            if body_start + frag_len > len(payload) or frag_off + frag_len > length:
                return
            if length > _MAX_HANDSHAKE_MESSAGE:
                self._fail("handshake message too large")
                return
            body = payload[body_start : body_start + frag_len]
            offset = body_start + frag_len

            if msg_type == _HT_HELLO_VERIFY_REQUEST and frag_off == 0:
                self._handle_hello_verify_request(body, msg_seq)
                continue
            if msg_seq < self._next_recv_msg_seq:
                continue  # already consumed; a server retransmit
            complete = self._reassemble(msg_seq, length, frag_off, body)
            if complete is not None:
                if len(self._ready) >= _MAX_PENDING_MESSAGES:
                    self._fail("too many out-of-order handshake messages")
                    return
                self._ready[msg_seq] = (msg_type, complete)
                self._deliver_ready()
            if self._failed:
                return

    def _deliver_ready(self) -> None:
        while self._next_recv_msg_seq in self._ready:
            msg_seq = self._next_recv_msg_seq
            msg_type, body = self._ready.pop(msg_seq)
            self._deliver_handshake(msg_type, msg_seq, body)
            if self._failed:
                return

    def _reassemble(self, msg_seq: int, length: int, frag_off: int, body: bytes) -> bytes | None:
        if frag_off == 0 and len(body) == length:
            return body
        entry = self._pending.get(msg_seq)
        if entry is None or entry[0] != length:
            if entry is None and len(self._pending) >= _MAX_PENDING_MESSAGES:
                self._fail("too many incomplete handshake messages")
                return None
            entry = (length, bytearray(length), bytearray(length))
            self._pending[msg_seq] = entry
        _, buffer, seen = entry
        buffer[frag_off : frag_off + len(body)] = body
        seen[frag_off : frag_off + len(body)] = b"\x01" * len(body)
        if all(seen):
            del self._pending[msg_seq]
            return bytes(buffer)
        return None

    def _deliver_handshake(self, msg_type: int, msg_seq: int, body: bytes) -> None:
        self._next_recv_msg_seq = msg_seq + 1
        # Reconstructed unfragmented for the transcript (RFC 6347 4.2.6).
        message = (
            bytes([msg_type])
            + len(body).to_bytes(3, "big")
            + struct.pack("!H", msg_seq)
            + (0).to_bytes(3, "big")
            + len(body).to_bytes(3, "big")
            + body
        )
        if msg_type == _HT_FINISHED:
            self._handle_server_finished(body)
            return
        handler = {
            _HT_SERVER_HELLO: self._handle_server_hello,
            _HT_CERTIFICATE: self._handle_certificate,
            _HT_SERVER_KEY_EXCHANGE: self._handle_server_key_exchange,
            _HT_CERTIFICATE_REQUEST: self._handle_certificate_request,
            _HT_SERVER_HELLO_DONE: self._handle_server_hello_done,
        }.get(msg_type)
        if handler is None:
            self._fail(f"unexpected handshake message {msg_type}")
            return
        self._transcript += message
        handler(body)

    def _handle_hello_verify_request(self, body: bytes, msg_seq: int) -> None:
        if self._state not in ("sent_hello", "sent_cookie_hello"):
            return
        if len(body) < 3:
            return
        cookie_len = body[2]
        if 3 + cookie_len > len(body):
            return
        cookie = body[3 : 3 + cookie_len]
        if self._state == "sent_cookie_hello":
            self._hello_verify_count += 1
            if self._hello_verify_count > _MAX_HELLO_VERIFY:
                self._fail("server kept re-issuing HelloVerifyRequest")
                return
            if cookie == self._cookie:
                # Mbed TLS derives the cookie from a 1-second timestamp, so
                # a repeat inside that second is byte-identical; the flight
                # timer owns the retransmission (see _dtls_psk).
                return
        self._cookie = cookie
        self._transcript = bytearray()
        self._next_recv_msg_seq = msg_seq + 1
        self._ready.clear()
        self._send_client_hello(cookie=self._cookie)
        self._state = "sent_cookie_hello"

    def _handle_server_hello(self, body: bytes) -> None:
        if self._state not in ("sent_hello", "sent_cookie_hello"):
            self._fail("unexpected ServerHello")
            return
        if len(body) < 38:
            self._fail("short ServerHello")
            return
        if body[0:2] != _VERSION:
            self._fail("server selected a version other than DTLS 1.2")
            return
        self._server_random = body[2:34]
        offset = 35 + body[34]
        if offset + 3 > len(body):
            self._fail("malformed ServerHello")
            return
        suite = int.from_bytes(body[offset : offset + 2], "big")
        if suite != SUITE:
            self._fail(f"server selected unexpected ciphersuite 0x{suite:04x}")
            return
        if body[offset + 2] != 0:
            self._fail("server selected a compression method")
            return
        extensions = _parse_extensions(body[offset + 3 :])
        if extensions is None:
            self._fail("malformed ServerHello extensions")
            return
        granted = extensions.get(EXT_MAX_FRAGMENT_LENGTH)
        if granted != bytes([MFL_CODES[self._mfl]]):
            # Without the limit these boards send an over-MTU flight and
            # drop off Wi-Fi, so going on would be worse than stopping.
            self._fail(f"server did not accept max_fragment_length {self._mfl}")
            return
        self._record_limit = self._mfl
        self._state = "got_server_hello"

    def _handle_certificate(self, body: bytes) -> None:
        if self._state != "got_server_hello":
            self._fail("unexpected Certificate")
            return
        if len(body) < 3 or int.from_bytes(body[0:3], "big") != len(body) - 3:
            self._fail("malformed Certificate")
            return
        chain = []
        offset = 3
        while offset < len(body):
            if offset + 3 > len(body):
                self._fail("malformed Certificate")
                return
            length = int.from_bytes(body[offset : offset + 3], "big")
            der = body[offset + 3 : offset + 3 + length]
            if len(der) != length:
                self._fail("malformed Certificate")
                return
            chain.append(der)
            offset += 3 + length
        if not chain:
            self._fail("server sent no certificate")
            return
        self._peer_chain = tuple(chain)
        try:
            certificates = [crypto.load_certificate(crypto.FILETYPE_ASN1, der) for der in chain]
        except crypto.Error:
            if self._trust is None:
                self._state = "got_certificate"
                return
            self._fail("server certificate could not be parsed")
            return
        self._peer_leaf = certificates[0]
        if self._trust is not None:
            store = crypto.X509Store()
            for anchor in self._trust:
                store.add_cert(anchor)
            try:
                crypto.X509StoreContext(
                    store, certificates[0], chain=certificates[1:]
                ).verify_certificate()
            except crypto.X509StoreContextError as err:
                self._fail(f"server certificate chain did not verify: {err}")
                return
        self._state = "got_certificate"

    def _handle_server_key_exchange(self, body: bytes) -> None:
        if self._state != "got_certificate":
            self._fail("unexpected ServerKeyExchange")
            return
        if len(body) < 4 or body[0] != _ECCURVETYPE_NAMED:
            self._fail("server offered a non-named curve")
            return
        curve = int.from_bytes(body[1:3], "big")
        if curve != _NAMED_CURVE_SECP256R1:
            self._fail(f"server offered unexpected curve 0x{curve:04x}")
            return
        point_len = body[3]
        point = body[4 : 4 + point_len]
        if len(point) != point_len or point_len == 0:
            self._fail("malformed server ECDH point")
            return
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)
        except ValueError:
            self._fail("server ECDH point is not on secp256r1")
            return
        params = body[: 4 + point_len]
        rest = body[4 + point_len :]
        if len(rest) < 4:
            self._fail("ServerKeyExchange carries no signature")
            return
        hash_code, signature_code = rest[0], rest[1]
        signature_len = int.from_bytes(rest[2:4], "big")
        signature = rest[4 : 4 + signature_len]
        if len(signature) != signature_len:
            self._fail("malformed ServerKeyExchange signature")
            return
        if self._trust is not None:
            hash_type = _ECDSA_HASHES.get(hash_code)
            if signature_code != 3 or hash_type is None or self._peer_leaf is None:
                self._fail(f"unsupported ServerKeyExchange signature {hash_code}/{signature_code}")
                return
            public_key = _public_key_of(self._peer_leaf)
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                self._fail("server certificate key is not ECDSA")
                return
            try:
                public_key.verify(
                    signature,
                    self._client_random + self._server_random + params,
                    ec.ECDSA(hash_type()),
                )
            except InvalidSignature:
                self._fail("ServerKeyExchange signature did not verify")
                return
        self._peer_point = point
        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self._state = "got_server_params"

    def _handle_certificate_request(self, body: bytes) -> None:
        if self._state != "got_server_params":
            self._fail("unexpected CertificateRequest")
            return
        if len(body) < 1:
            self._fail("malformed CertificateRequest")
            return
        offset = 1 + body[0]
        if offset + 2 > len(body):
            self._fail("malformed CertificateRequest")
            return
        algorithms_len = int.from_bytes(body[offset : offset + 2], "big")
        algorithms = body[offset + 2 : offset + 2 + algorithms_len]
        if len(algorithms) != algorithms_len or algorithms_len % 2:
            self._fail("malformed CertificateRequest")
            return
        self._server_signature_algorithms = tuple(
            int.from_bytes(algorithms[index : index + 2], "big")
            for index in range(0, algorithms_len, 2)
        )
        self._certificate_requested = True

    def _handle_server_hello_done(self, _body: bytes) -> None:
        if self._state != "got_server_params":
            self._fail("unexpected ServerHelloDone")
            return
        self._state = "sent_client_flight"
        self._send_client_flight()

    def _handle_server_finished(self, body: bytes) -> None:
        if not self._read_active or self._state != "sent_client_flight":
            return
        expected = _prf(
            self._master_secret,
            b"server finished",
            hashlib.sha256(self._transcript).digest(),
            _VERIFY_DATA_LEN,
        )
        if len(body) != _VERIFY_DATA_LEN or not hmac.compare_digest(body, expected):
            self._fail("server Finished did not verify")
            return
        self._state = "established"
        self._flight = []
        self._flight_deadline = None

    def _fail(self, reason: str) -> None:
        if self._failed is None:
            self._failed = reason
            _LOGGER.debug("DTLS session failed: %s", reason)

    # -- application data ------------------------------------------------

    def send(self, data: bytes) -> int:
        if self._state != "established":
            raise DtlsError("session is not established")
        if self._failed:
            raise DtlsError(self._failed)
        if len(data) > self._record_limit:
            raise DtlsError(
                f"{len(data)}-byte record exceeds the negotiated max_fragment_length "
                f"{self._record_limit}"
            )
        self._emit_record(_CT_APPLICATION_DATA, bytes(data), self._send_epoch)
        return len(data)

    def recv(self, capacity: int = 65535) -> bytes:
        if not self._appdata:
            self._drain_inbox()
        if self._appdata:
            record = self._appdata.popleft()
            if len(record) > capacity:
                self._appdata.appendleft(record[capacity:])
                return record[:capacity]
            return record
        if self._failed:
            raise DtlsError(self._failed)
        if self._peer_closed:
            raise ZeroReturn()
        raise WantRead()

    def shutdown(self) -> None:
        if self._state == "established" and not self._failed:
            self._emit_record(
                _CT_ALERT, bytes([_ALERT_WARNING, _ALERT_CLOSE_NOTIFY]), self._send_epoch
            )

    # -- retransmission --------------------------------------------------

    def DTLSv1_get_timeout(self):  # noqa: N802 - mirrors the pyOpenSSL name
        if self._flight_deadline is None or not self._flight:
            return None
        return max(0.0, self._flight_deadline - _now())

    def DTLSv1_handle_timeout(self):  # noqa: N802 - mirrors the pyOpenSSL name
        """Re-emit the last flight with fresh record sequence numbers and
        back off, per RFC 6347 section 4.2.4."""
        if not self._flight or self._flight_deadline is None:
            return
        for kind, msg_type, msg_seq, body, epoch in self._flight:
            if kind == "ccs":
                self._emit_record(_CT_CHANGE_CIPHER_SPEC, body, epoch)
            else:
                self._send_handshake_fragments(msg_type, msg_seq, body, epoch)
        self._rto = min(self._rto * 2, 60.0)
        self._flight_deadline = _now() + self._rto


def _parse_extensions(data: bytes) -> dict[int, bytes] | None:
    """Extension map from a hello's trailing bytes; {} when absent, None
    when malformed."""
    if not data:
        return {}
    if len(data) < 2:
        return None
    total = int.from_bytes(data[0:2], "big")
    if total != len(data) - 2:
        return None
    extensions: dict[int, bytes] = {}
    offset = 2
    while offset < len(data):
        if offset + 4 > len(data):
            return None
        extension_type = int.from_bytes(data[offset : offset + 2], "big")
        length = int.from_bytes(data[offset + 2 : offset + 4], "big")
        value = data[offset + 4 : offset + 4 + length]
        if len(value) != length:
            return None
        extensions[extension_type] = value
        offset += 4 + length
    return extensions


def _now() -> float:
    return time.monotonic()
