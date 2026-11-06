"""DtlsTransport for a session that negotiated max_fragment_length.

Such a board cannot send a response larger than the limit: Mbed TLS refuses
an oversized DTLS write outright, so the reply never comes and the session
dies with it (measured on the TP1X AC, 2026-11-06: full /oic/res,
/device/0's batch and /information/vs/0). This transport answers those
requests locally instead, so the code above it lands in per-href (flat)
mode without each call site knowing about the limit.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Sequence
from typing import Any

from ..registry.by_type import for_device_by_oic_type
from ..transport import DtlsTransport, _is_device_collection

_LOGGER = logging.getLogger(__name__)

NOT_FOUND = 0x84
CONTENT = 0x45

# Measured over 1024 bytes on every board this was tried on; reading one
# kills the session, so they are never sent.
WITHHELD_HREFS = frozenset({"/information/vs/0", "/file/transfer/vs/0"})

# Each candidate href costs one GET while /oic/res is enumerated.
ENUMERATION_GET_TIMEOUT_S = 2.5
# An href whose read timed out is skipped for a while and then tried again,
# the wait doubling per consecutive timeout up to the cap. A timeout can be
# a reply the board could not fit, or just a busy board, so nothing is
# given up on for good.
BACKOFF_INITIAL_S = 60.0
BACKOFF_MAX_S = 3600.0

_lock = threading.Lock()
# Process-wide, keyed by endpoint: they survive the coordinator's reconnects.
_links: dict[tuple[str, int], list[dict[str, Any]]] = {}
# hrefs the last enumeration could not confirm because they were backing off.
_unlisted: dict[tuple[str, int], set[str]] = {}
# (host, port, href) -> (consecutive timeouts, monotonic time of next try)
_backoff: dict[tuple[str, int, str], tuple[int, float]] = {}


def _now() -> float:
    return time.monotonic()


def forget(host: str, port: int) -> None:
    """Drop what was learned about one endpoint (tests, a new setup)."""
    with _lock:
        _links.pop((host, port), None)
        _unlisted.pop((host, port), None)
        for key in [key for key in _backoff if key[:2] == (host, port)]:
            del _backoff[key]


class MflDtlsTransport(DtlsTransport):
    """`read` with the size guard; everything else as DtlsTransport."""

    def _backing_off(self, href: str) -> bool:
        with _lock:
            entry = _backoff.get((self.host, self.port, href))
        return entry is not None and _now() < entry[1]

    def _note_timeout(self, href: str) -> None:
        key = (self.host, self.port, href)
        with _lock:
            failures = _backoff.get(key, (0, 0.0))[0] + 1
            delay = min(BACKOFF_INITIAL_S * 2 ** (failures - 1), BACKOFF_MAX_S)
            _backoff[key] = (failures, _now() + delay)
        _LOGGER.info(
            "%s: %s timed out (%d in a row); trying it again in %.0fs",
            self.host,
            href,
            failures,
            delay,
        )

    def _note_answer(self, href: str) -> None:
        with _lock:
            _backoff.pop((self.host, self.port, href), None)

    def _get(self, href: str, timeout: float, query: Sequence[str] = ()) -> tuple[int, Any]:
        try:
            result = super().read(href.strip("/").split("/"), timeout, query)
        except TimeoutError:
            self._note_timeout(href)
            raise
        self._note_answer(href)
        return result

    def read(
        self, path_segs: Sequence[str], timeout: float, query: Sequence[str] = ()
    ) -> tuple[int, Any]:
        path = list(path_segs)
        href = "/" + "/".join(path)
        if _is_device_collection(path):
            return NOT_FOUND, None
        if not query:
            if href == "/oic/res":
                return CONTENT, self._oic_res(timeout)
            if href in WITHHELD_HREFS or self._backing_off(href):
                return NOT_FOUND, None
        return self._get(href, timeout, query)

    def _oic_res(self, timeout: float) -> list[dict[str, Any]]:
        """A link list built from the registry's hrefs for this device type,
        each confirmed by its own small GET, in /oic/res's bare shape.
        Listed once per start; hrefs that were backing off are tried again
        on a later call once their wait is over."""
        endpoint = (self.host, self.port)
        with _lock:
            cached = _links.get(endpoint)
            pending = sorted(_unlisted.get(endpoint, ()))
        if cached is not None:
            try:
                confirmed, still_pending = self._confirm(pending)
            except TimeoutError:
                # Already backing off again and logged by _get; the list as
                # known is still right, and the dead session is reconnected
                # on the caller's next request.
                return [dict(link) for link in cached]
            with _lock:
                cached = _links[endpoint] = cached + confirmed
                _unlisted[endpoint] = still_pending
            return [dict(link) for link in cached]

        code, device = super().read(["oic", "d"], timeout)
        device_types = device.get("rt", []) if code == CONTENT and isinstance(device, dict) else []
        registry = for_device_by_oic_type(device_types)
        if registry is None:
            _LOGGER.warning(
                "%s: no registry for device types %s; cannot list resources",
                self.host,
                device_types,
            )
            return []

        started = time.monotonic()
        candidates = [
            href
            for href in sorted(registry.capabilities)
            if href not in WITHHELD_HREFS and not href.startswith(("/oic/", "/device/"))
        ]
        links, unlisted = self._confirm(candidates)
        _LOGGER.info(
            "%s: listed %d resources from %d %s hrefs in %.0fs (%d to retry)",
            self.host,
            len(links),
            len(registry.capabilities),
            registry.name,
            time.monotonic() - started,
            len(unlisted),
        )
        with _lock:
            _links[endpoint] = links
            _unlisted[endpoint] = unlisted
        return [dict(link) for link in links]

    def _confirm(self, hrefs: Sequence[str]) -> tuple[list[dict[str, Any]], set[str]]:
        """GET each href; returns the links that answered 2.05 and the hrefs
        skipped because they are backing off. A timeout ends the session on
        these boards, so it propagates and the caller's reconnect resumes."""
        links: list[dict[str, Any]] = []
        skipped: set[str] = set()
        for href in hrefs:
            if self._backing_off(href):
                skipped.add(href)
                continue
            self.pace()
            code, _ = self._get(href, ENUMERATION_GET_TIMEOUT_S)
            if code == CONTENT:
                links.append({"href": href, "rt": [], "if": []})
        return links, skipped
