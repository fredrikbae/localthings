"""The size guard on an MFL session's transport, and the entry wiring."""

from __future__ import annotations

from typing import Any, cast

import cbor2
import pytest

from custom_components.localthings.const import (
    AUTH_CERTIFICATE,
    CONF_AUTH_CARRIER,
    CONF_DTLS_ENGINE,
    CONF_HOST,
    CONF_LEAF_CERT_PEM,
    CONF_LEAF_KEY_PEM,
    CONF_PORT,
    DTLS_ENGINE_MFL1024,
)
from custom_components.localthings.mfl import transport as mfl_transport
from custom_components.localthings.mfl.provider import MflCertificateAuth
from custom_components.localthings.mfl.transport import MflDtlsTransport
from custom_components.localthings.session import authentication_provider_from_entry
from custom_components.localthings.transport import DtlsTransport, create_transport

from .pki import client_credentials

HOST, PORT = "192.0.2.31", 49154


class _FakeSession:
    """Answers GETs from `answers` (href -> (code, rep) or an exception)."""

    def __init__(self, answers):
        self.answers = answers
        self.gets: list[tuple[str, tuple]] = []

    def get(self, path, query=(), timeout=None):
        href = "/" + "/".join(path)
        self.gets.append((href, tuple(query)))
        answer = self.answers.get(href, (0x84, None))
        if isinstance(answer, Exception):
            raise answer
        code, rep = answer
        return code, cbor2.dumps(rep) if rep is not None else b""

    def pace(self):
        return None

    def close(self):
        self.closes += 1

    connects = 0
    closes = 0


class _FakeTransport(MflDtlsTransport):
    """Reconnects to the same fake session, counted in its `connects`, so
    `gets` spans every session; `refuse_reconnect` makes the board refuse."""

    fake: _FakeSession
    refuse_reconnect = False

    def connect(self) -> None:
        if self.refuse_reconnect:
            raise ConnectionError("handshake refused")
        self.fake.connects += 1
        self._session = cast(Any, self.fake)


def _transport(answers) -> tuple[_FakeTransport, _FakeSession]:
    transport = _FakeTransport(HOST, PORT, auth=cast(Any, object()))
    session = _FakeSession(answers)
    transport.fake = session
    transport._session = cast(Any, session)
    return transport, session


@pytest.fixture(autouse=True)
def _clean():
    mfl_transport.forget(HOST, PORT)
    yield
    mfl_transport.forget(HOST, PORT)


AC_DEVICE = (0x45, {"rt": ["oic.wk.d", "oic.d.airconditioner"], "di": "x"})


@pytest.mark.parametrize("path", [["device", "0"], ["device", "1"]])
def test_device_collections_are_answered_locally(path):
    transport, session = _transport({})
    assert transport.read(path, timeout=1.0) == (0x84, None)
    assert session.gets == []


@pytest.mark.parametrize("href", sorted(mfl_transport.WITHHELD_HREFS))
def test_withheld_hrefs_are_answered_locally(href):
    transport, session = _transport({})
    assert transport.read(href.strip("/").split("/"), timeout=1.0) == (0x84, None)
    assert session.gets == []


def test_oic_res_is_built_from_the_registry_and_cached():
    transport, session = _transport(
        {
            "/oic/d": AC_DEVICE,
            "/power/vs/0": (0x45, {"x.com.samsung.da.power": "On"}),
            "/temperatures/vs/0": (0x45, {"x.com.samsung.da.items": []}),
        }
    )

    code, links = transport.read(["oic", "res"], timeout=10.0)

    assert code == 0x45
    assert [link["href"] for link in links] == ["/power/vs/0", "/temperatures/vs/0"]
    requested = {href for href, _ in session.gets}
    assert "/information/vs/0" not in requested
    assert not any(href.startswith("/device/") for href in requested)

    session.gets.clear()
    assert transport.read(["oic", "res"], timeout=10.0) == (0x45, links)
    assert session.gets == []


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(mfl_transport, "_now", lambda: now[0])
    return now


WASHER_DEVICE = (0x45, {"rt": ["oic.wk.d", "oic.d.washer"], "di": "x"})


def test_a_silent_href_while_listing_does_not_end_the_listing(clock):
    """The washer's /course/vs/0 is over the limit: it times out and kills
    the session. The listing reconnects and confirms what comes after it."""
    answers: dict = {
        "/oic/d": WASHER_DEVICE,
        "/alarms/vs/0": (0x45, {"alarms": []}),
        "/course/vs/0": TimeoutError(),
        "/cycleinterface/vs/0": (0x45, {}),
    }
    transport, session = _transport(answers)

    code, links = transport.read(["oic", "res"], timeout=10.0)

    assert code == 0x45
    assert [link["href"] for link in links] == ["/alarms/vs/0", "/cycleinterface/vs/0"]
    assert (session.closes, session.connects) == (1, 1)
    requested = [href for href, _ in session.gets]
    assert requested.index("/course/vs/0") < requested.index("/cycleinterface/vs/0")


def test_a_silent_href_while_listing_is_retried_once_its_backoff_ends(clock):
    answers: dict = {"/oic/d": AC_DEVICE, "/alarms/vs/0": TimeoutError()}
    transport, session = _transport(answers)
    _, links = transport.read(["oic", "res"], timeout=10.0)
    assert "/alarms/vs/0" not in [link["href"] for link in links]

    # Inside the wait, a later /oic/res read leaves it alone...
    session.gets.clear()
    transport.read(["oic", "res"], timeout=10.0)
    assert session.gets == []

    # ...and once the wait is over it confirms it.
    answers["/alarms/vs/0"] = (0x45, {"alarms": []})
    clock[0] += mfl_transport.BACKOFF_INITIAL_S
    _, links = transport.read(["oic", "res"], timeout=10.0)
    assert session.gets == [("/alarms/vs/0", ())]
    assert "/alarms/vs/0" in [link["href"] for link in links]


def test_a_timeout_backs_off_progressively_and_is_always_retried(clock):
    transport, session = _transport({"/mode/vs/0": TimeoutError()})
    expected = [60.0, 120.0, 240.0, 480.0, 960.0, 1920.0, 3600.0, 3600.0]
    for delay in expected:
        with pytest.raises(TimeoutError):
            transport.read(["mode", "vs", "0"], timeout=1.0)
        session.gets.clear()
        # Inside the wait it is answered locally, without a GET...
        clock[0] += delay - 1
        assert transport.read(["mode", "vs", "0"], timeout=1.0) == (0x84, None)
        assert session.gets == []
        # ...and once the wait is over it goes to the board again.
        clock[0] += 1
    assert expected[-1] == mfl_transport.BACKOFF_MAX_S


def test_an_answer_resets_the_backoff(clock):
    answers: dict = {"/mode/vs/0": TimeoutError()}
    transport, _ = _transport(answers)
    with pytest.raises(TimeoutError):
        transport.read(["mode", "vs", "0"], timeout=1.0)
    clock[0] += mfl_transport.BACKOFF_INITIAL_S
    answers["/mode/vs/0"] = (0x45, {"modes": []})
    assert transport.read(["mode", "vs", "0"], timeout=1.0)[0] == 0x45

    answers["/mode/vs/0"] = TimeoutError()
    with pytest.raises(TimeoutError):
        transport.read(["mode", "vs", "0"], timeout=1.0)
    # Back to the first step, not the second.
    clock[0] += mfl_transport.BACKOFF_INITIAL_S
    answers["/mode/vs/0"] = (0x45, {"modes": []})
    assert transport.read(["mode", "vs", "0"], timeout=1.0)[0] == 0x45


def test_a_failed_retry_while_listing_keeps_the_known_links(clock):
    answers: dict = {"/oic/d": AC_DEVICE, "/power/vs/0": (0x45, {}), "/alarms/vs/0": TimeoutError()}
    transport, session = _transport(answers)
    _, first = transport.read(["oic", "res"], timeout=10.0)
    assert [link["href"] for link in first] == ["/power/vs/0"]

    # Times out again, and this time the board does not take the reconnect.
    clock[0] += mfl_transport.BACKOFF_INITIAL_S
    transport.refuse_reconnect = True
    assert transport.read(["oic", "res"], timeout=10.0) == (0x45, first)
    assert session.closes == 2


def test_a_failed_reconnect_on_the_first_listing_propagates(clock):
    transport, _ = _transport({"/oic/d": AC_DEVICE, "/alarms/vs/0": TimeoutError()})
    transport.refuse_reconnect = True
    with pytest.raises(ConnectionError):
        transport.read(["oic", "res"], timeout=10.0)
    # Nothing half-listed is kept: the next start lists from scratch.
    assert (HOST, PORT) not in mfl_transport._links


def test_queried_reads_pass_through():
    transport, session = _transport({"/oic/res": (0x45, [{"href": "/oic/p"}])})
    assert transport.read(["oic", "res"], timeout=1.0, query=["rt=oic.wk.p"]) == (
        0x45,
        [{"href": "/oic/p"}],
    )
    assert session.gets == [("/oic/res", ("rt=oic.wk.p",))]


def test_unknown_device_type_lists_nothing():
    transport, _ = _transport({"/oic/d": (0x45, {"rt": ["oic.wk.d"]})})
    assert transport.read(["oic", "res"], timeout=1.0) == (0x45, [])


def _entry(engine):
    client = client_credentials("rsa")
    data = {
        CONF_HOST: HOST,
        CONF_PORT: PORT,
        CONF_AUTH_CARRIER: AUTH_CERTIFICATE,
        CONF_LEAF_CERT_PEM: client.chain_pem,
        CONF_LEAF_KEY_PEM: client.key_pem,
    }
    if engine:
        data[CONF_DTLS_ENGINE] = engine
    return data


def test_entry_flag_selects_the_mfl_provider_and_transport():
    data = _entry(DTLS_ENGINE_MFL1024)
    assert isinstance(authentication_provider_from_entry(data), MflCertificateAuth)
    assert type(create_transport(data)) is MflDtlsTransport


def test_entry_without_the_flag_keeps_the_upstream_path():
    data = _entry(None)
    assert not isinstance(authentication_provider_from_entry(data), MflCertificateAuth)
    assert type(create_transport(data)) is DtlsTransport
