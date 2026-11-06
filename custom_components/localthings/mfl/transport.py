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

# Known to exceed 1024 bytes on the boards this was measured on.
WITHHELD_HREFS = frozenset({"/information/vs/0", "/file/transfer/vs/0"})

# Each candidate href costs one GET while /oic/res is enumerated.
ENUMERATION_GET_TIMEOUT_S = 2.5
# A read that times out this often is taken for one the board can't send.
OVERSIZED_AFTER_TIMEOUTS = 2

_lock = threading.Lock()
# Process-wide, keyed by (host, port): survive the coordinator's reconnects
# so /oic/res is enumerated once per start and a learned href stays withheld.
_links: dict[tuple[str, int], list[dict[str, Any]]] = {}
_timeouts: dict[tuple[str, int, str], int] = {}
_oversized: dict[tuple[str, int], set[str]] = {}


def forget(host: str, port: int) -> None:
    """Drop what was learned about one endpoint (tests, reconfigure)."""
    with _lock:
        _links.pop((host, port), None)
        _oversized.pop((host, port), None)
        for key in [key for key in _timeouts if key[:2] == (host, port)]:
            del _timeouts[key]


class MflDtlsTransport(DtlsTransport):
    """`read` with the size guard; everything else as DtlsTransport."""

    def _withheld(self, href: str) -> bool:
        with _lock:
            learned = _oversized.get((self.host, self.port), set())
        return href in WITHHELD_HREFS or href in learned

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
            if self._withheld(href):
                return NOT_FOUND, None
        try:
            return super().read(path_segs, timeout, query)
        except TimeoutError:
            self._note_timeout(href)
            raise

    def _note_timeout(self, href: str) -> None:
        key = (self.host, self.port, href)
        with _lock:
            _timeouts[key] = _timeouts.get(key, 0) + 1
            if _timeouts[key] < OVERSIZED_AFTER_TIMEOUTS:
                return
            _oversized.setdefault((self.host, self.port), set()).add(href)
        _LOGGER.info(
            "%s: %s timed out %d times under max_fragment_length; no longer read",
            self.host,
            href,
            OVERSIZED_AFTER_TIMEOUTS,
        )

    def _oic_res(self, timeout: float) -> list[dict[str, Any]]:
        """A link list built from the registry's hrefs for this device type,
        each confirmed by its own small GET, in /oic/res's bare shape."""
        with _lock:
            cached = _links.get((self.host, self.port))
        if cached is not None:
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

        links: list[dict[str, Any]] = []
        started = time.monotonic()
        for href in sorted(registry.capabilities):
            if self._withheld(href) or href.startswith(("/oic/", "/device/")):
                continue
            self.pace()
            try:
                code, _ = super().read(
                    href.strip("/").split("/"), timeout=ENUMERATION_GET_TIMEOUT_S
                )
            except TimeoutError:
                # The session is gone with an oversized reply; mark it now so
                # the coordinator's reconnect enumerates past it.
                with _lock:
                    _oversized.setdefault((self.host, self.port), set()).add(href)
                _LOGGER.info("%s: %s gave no reply while listing resources", self.host, href)
                raise
            if code == CONTENT:
                links.append({"href": href, "rt": [], "if": []})
        _LOGGER.info(
            "%s: listed %d resources from %d %s hrefs in %.0fs",
            self.host,
            len(links),
            len(registry.capabilities),
            registry.name,
            time.monotonic() - started,
        )
        with _lock:
            _links[(self.host, self.port)] = links
        return [dict(link) for link in links]
