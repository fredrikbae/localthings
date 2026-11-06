# Fork: DTLS with max_fragment_length (`claude/mfl-engine`)

This branch of [fredrikbae/localthings](https://github.com/fredrikbae/localthings)
adds one thing to upstream [mbillow/localthings](https://github.com/mbillow/localthings):
a DTLS engine that offers the `max_fragment_length` extension (RFC 6066 §4),
for boards that drop off Wi-Fi when the handshake starts.

## Why

On the TP1X `DA-AC-THERAC-01011` board (Thermia Aura S3,
firmware `ARA-KR-TP1-25-ARXX00_11260720`) the server flight goes out as one
datagram larger than the MTU. The unit then leaves Wi-Fi for several seconds and
the setup fails with `handshake_timeout` (upstream #504). pyOpenSSL cannot send
the extension. Measured 2026-11-06 on two units:

| Offered | Largest server datagram | Handshake | Lost pings |
|---|---|---|---|
| nothing | over-MTU | never completes | unit leaves Wi-Fi |
| MFL 1024 | 1037 B | completes in ~1.2 s | 0 |

The limit also applies to responses. Mbed TLS 2.7.8's `ssl_write_real` returns
`MBEDTLS_ERR_SSL_BAD_INPUT_DATA` for a DTLS write over the negotiated length, so
a response over ~1024 B never arrives and the session dies. On these boards that
is full `/oic/res`, the `/device/0` batch and `/information/vs/0`. Read one href
at a time, 39 of the 40 AC resources answer, the largest at 826 B.

## What changed

All new code is in `custom_components/localthings/mfl/`:

- `engine.py`: a pure-Python DTLS 1.2 client for
  `ECDHE-ECDSA-AES128-GCM-SHA256` with a client certificate and MFL. It is based
  on smartthings-local's `_dtls_psk.py` (MIT). The server chain is verified with
  pyOpenSSL against smartthings-local's `ocf_root_ca.pem`, because `cryptography`
  cannot parse Samsung's certificates. A server that does not grant MFL is
  refused.
- `provider.py`: `MflCertificateAuth`. smartthings-local reaches it through the
  `_create_dtls_connection` hook, so the library itself is unchanged and is
  installed from PyPI as usual.
- `transport.py`: `MflDtlsTransport`. It answers the reads that would kill the
  session locally:
  - `/device/<n>` → 4.04
  - `/information/vs/0` and `/file/transfer/vs/0` → 4.04
  - full `/oic/res` → a link list built from the registry's hrefs for the
    device type, each confirmed by its own GET

  Upstream code then runs in per-href (flat) mode, as it does for boards without
  a Collection.

  An href whose read times out is answered locally with 4.04 for a while and
  then tried again. The wait starts at 60 s, doubles on each consecutive
  timeout up to 1 h, and resets on an answer, so nothing is given up for good.
  The same applies while `/oic/res` is listed: an href skipped there is
  confirmed on a later call once its wait is over.
- `flow.py`: config-flow helpers.

Upstream files get small entry points only:

| File | Change |
|---|---|
| `const.py` | `CONF_DTLS_ENGINE`, `DTLS_ENGINE_MFL1024` |
| `session.py` | provider choice |
| `transport.py` | transport choice |
| `config_flow.py` | see below |

In `config_flow.py`, a `HandshakeTimeout` is retried once with the engine after
`mfl.flow.RETRY_DELAY_S`, which gives the board time to rejoin Wi-Fi. A
successful retry stores `dtls_engine: mfl1024` on the entry, and reconfigure
keeps it. Entries without the key behave exactly as upstream.

Tests are in `tests/mfl/` and `tests/localthings/test_mfl_flow.py`:

- the engine against an in-process OpenSSL DTLS server
- the provider through smartthings-local's own `DtlsCoapSession` and
  `diagnose_dtls_handshake`, which pins the private hook
- the transport guard
- the flow fallback

## Keeping up with upstream

```sh
git fetch origin --tags
git rebase vX.Y.Z            # the new upstream release tag
# Python 3.14 venv with requirements-dev.txt
ruff format --check custom_components tests
ruff check custom_components tests
ty check --python <venv>/bin/python custom_components tests
pytest tests/ -q -n auto
git push --force-with-lease fork claude/mfl-engine
# manifest.json "version": "X.Y.Z.N+mfl", then a GitHub release (not a pre-release)
gh release create vX.Y.Z.N+mfl --target claude/mfl-engine
```

Versions are upstream's `X.Y.Z` plus a fork counter `N`, and the PEP 440 local
part `+mfl`: `0.36.0.1+mfl`, `0.36.0.2+mfl`, and after a rebase onto 0.37.0,
`0.37.0.1+mfl`. Other forms fail in Home Assistant itself. For example,
`0.36.0.1-mfl` matches none of the strategies HA's loader accepts, so the
integration is blocked. `0.36.0-mfl.1` sorts below the upstream 0.36.0 it is
built on. HACS lists only GitHub releases not marked as pre-releases.

When a rebase conflicts, it will be in one of the four entry points above.
`tests/mfl/test_session_contract.py` failing after a smartthings-local upgrade
means the private hook changed.

The branch also carries one upstream fix unrelated to MFL. On v0.36.0 about one
full-suite run in five ended with a lingering-thread teardown error, because
`ObserveManager.close()` did not wait for its refresh thread. Commit
`fix(observe): wait for the refresh thread on close` fixes it, with 0 errors in
45 runs. Drop the commit at a rebase once upstream has its own fix.

## Not verified yet

- writes and Observe notifications under MFL
- sessions longer than a few seconds
- which Mbed TLS version TizenRT 4.0 actually ships
