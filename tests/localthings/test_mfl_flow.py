"""The config flow's fallback to the max_fragment_length engine (fork)."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.localthings import config_flow
from custom_components.localthings.const import (
    CONF_DTLS_ENGINE,
    CONF_HOST,
    DOMAIN,
    DTLS_ENGINE_MFL1024,
)
from custom_components.localthings.mfl import flow as mfl_flow
from custom_components.localthings.probing import HostProbe, PlaintextIdentity

from .conftest import ENTRY_DATA, MOCK_HOST, _probe_result

PORT = 49154


@pytest.fixture
def probe_stage(monkeypatch):
    """_probe_and_validate with the network stubbed: `calls` records each
    _handshake_and_read's mfl flag, `outcomes` scripts what it does."""
    calls: list[bool] = []
    outcomes: list[dict | Exception] = []

    def handshake(host, scan, cert_pem, key_pem, local_port=None, *, psk=None, mfl=False):
        calls.append(mfl)
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return dict(outcome)

    monkeypatch.setattr(config_flow.probing, "look", lambda host: HostProbe(host, [PORT], [PORT]))
    monkeypatch.setattr(config_flow, "_mint_preferred", lambda *_a: ("CERT", "KEY"))
    monkeypatch.setattr(config_flow, "_handshake_and_read", handshake)
    monkeypatch.setattr(mfl_flow, "RETRY_DELAY_S", 0)
    return calls, outcomes


def test_handshake_timeout_is_retried_with_mfl(probe_stage):
    calls, outcomes = probe_stage
    outcomes += [config_flow.HandshakeTimeout("never completed"), {"port": PORT}]

    info = config_flow._probe_and_validate(MOCK_HOST)

    assert calls == [False, True]
    assert info["dtls_engine"] == DTLS_ENGINE_MFL1024


def test_a_plain_success_keeps_the_upstream_engine(probe_stage):
    calls, outcomes = probe_stage
    outcomes.append({"port": PORT})

    info = config_flow._probe_and_validate(MOCK_HOST)

    assert calls == [False]
    assert info["dtls_engine"] is None


def test_other_failures_are_not_retried_with_mfl(probe_stage):
    calls, outcomes = probe_stage
    outcomes.append(config_flow.NoResponse("nothing"))

    with pytest.raises(config_flow.NoResponse):
        config_flow._probe_and_validate(MOCK_HOST)
    assert calls == [False]


def test_an_mfl_entry_goes_straight_to_the_engine(probe_stage):
    calls, outcomes = probe_stage
    outcomes.append({"port": PORT})

    info = config_flow._probe_and_validate(MOCK_HOST, prefer_mfl=True)

    assert calls == [True]
    assert info["dtls_engine"] == DTLS_ENGINE_MFL1024


def _plaintext(vendor_id: str) -> PlaintextIdentity:
    return PlaintextIdentity(
        device_id=None,
        model="TP1X_DA-AC-THERAC-01011_0000",
        vendor_id=vendor_id,
        firmware="",
        name="",
        device_types=("oic.wk.d", "oic.d.airconditioner"),
    )


def test_a_known_board_goes_straight_to_the_engine(probe_stage, monkeypatch):
    """A plain handshake with this board sometimes completes, so the engine
    is picked from its plaintext vid rather than from a timeout."""
    calls, outcomes = probe_stage
    scan = HostProbe(MOCK_HOST, [PORT], [PORT], plaintext=_plaintext("DA-AC-THERAC-01011"))
    monkeypatch.setattr(config_flow.probing, "look", lambda host: scan)
    outcomes.append({"port": PORT})

    info = config_flow._probe_and_validate(MOCK_HOST)

    assert calls == [True]
    assert info["dtls_engine"] == DTLS_ENGINE_MFL1024


def test_an_unlisted_board_keeps_the_plain_path(probe_stage, monkeypatch):
    calls, outcomes = probe_stage
    scan = HostProbe(MOCK_HOST, [PORT], [PORT], plaintext=_plaintext("DA-REF-NORMAL-000001"))
    monkeypatch.setattr(config_flow.probing, "look", lambda host: scan)
    outcomes.append({"port": PORT})

    assert config_flow._probe_and_validate(MOCK_HOST)["dtls_engine"] is None
    assert calls == [False]


@pytest.mark.parametrize("ticked", [True, False])
async def test_the_setup_checkbox_is_passed_to_the_probe(hass: HomeAssistant, ticked) -> None:
    with patch.object(
        config_flow, "_probe_and_validate", return_value=_probe_result(recognized=True)
    ) as probe:
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HOST: MOCK_HOST, mfl_flow.FORM_FIELD: ticked}
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert probe.call_args.args[5] is ticked


async def test_the_reconfigure_checkbox_overrides_the_entry(hass: HomeAssistant) -> None:
    entry = MockConfigEntry(domain=DOMAIN, data=ENTRY_DATA, unique_id=ENTRY_DATA.get("device_key"))
    entry.add_to_hass(hass)
    probe = {**_probe_result(recognized=True), "dtls_engine": DTLS_ENGINE_MFL1024}
    with (
        patch.object(config_flow, "_probe_and_validate", return_value=probe) as probed_with,
        patch("custom_components.localthings.async_setup_entry", return_value=True),
    ):
        result = await entry.start_reconfigure_flow(hass)
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HOST: MOCK_HOST, mfl_flow.FORM_FIELD: True}
        )
    assert result["reason"] == "reconfigure_successful"
    assert probed_with.call_args.args[5] is True
    assert entry.data[CONF_DTLS_ENGINE] == DTLS_ENGINE_MFL1024


def test_mfl_retry_failing_reports_its_own_error(probe_stage):
    calls, outcomes = probe_stage
    outcomes += [config_flow.HandshakeTimeout("plain"), config_flow.HandshakeTimeout("mfl")]

    with pytest.raises(config_flow.HandshakeTimeout, match="mfl"):
        config_flow._probe_and_validate(MOCK_HOST)
    assert calls == [False, True]


async def test_setup_stores_the_engine_on_the_entry(hass: HomeAssistant) -> None:
    probe = {**_probe_result(recognized=True), "dtls_engine": DTLS_ENGINE_MFL1024}
    with patch.object(config_flow, "_probe_and_validate", return_value=probe):
        result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HOST: MOCK_HOST}
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_DTLS_ENGINE] == DTLS_ENGINE_MFL1024


async def test_setup_without_mfl_stores_no_engine(hass: HomeAssistant, mock_probe) -> None:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": "user"})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_HOST: MOCK_HOST}
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert CONF_DTLS_ENGINE not in result["data"]


@pytest.mark.parametrize(
    ("before", "probed", "after", "preferred"),
    [
        (DTLS_ENGINE_MFL1024, DTLS_ENGINE_MFL1024, DTLS_ENGINE_MFL1024, True),
        (None, DTLS_ENGINE_MFL1024, DTLS_ENGINE_MFL1024, False),
        (DTLS_ENGINE_MFL1024, None, None, True),
    ],
)
async def test_reconfigure_keeps_or_updates_the_engine(
    hass: HomeAssistant, before, probed, after, preferred
) -> None:
    data = {**ENTRY_DATA, **({CONF_DTLS_ENGINE: before} if before else {})}
    entry = MockConfigEntry(domain=DOMAIN, data=data, unique_id=data.get("device_key"))
    entry.add_to_hass(hass)
    probe = {**_probe_result(recognized=True), "dtls_engine": probed}
    with (
        patch.object(config_flow, "_probe_and_validate", return_value=probe) as probed_with,
        # The reload would start a real coordinator, as test_psk_flow avoids too.
        patch("custom_components.localthings.async_setup_entry", return_value=True),
    ):
        result = await entry.start_reconfigure_flow(hass)
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_HOST: MOCK_HOST}
        )
    assert result["reason"] == "reconfigure_successful"
    assert probed_with.call_args.args[5] is preferred
    assert entry.data.get(CONF_DTLS_ENGINE) == after
