"""Regression tests for AES-GCM key redaction in adapter logs (XEP-0454).

``aesgcm://`` URLs carry their decryption key in the URL fragment. The
helpers under test (``_log_safe_url``, ``_redact_aesgcm_in_text``) must be
applied at every call site that logs raw bodies, display texts or download
URLs, otherwise the key leaks into production logs.

The adapter imports the Hermes host framework (``gateway.*``) and the
transcription helper, which are not installable in the test environment.
Lightweight stubs are installed first so the module-level helpers can be
imported; if the real framework is importable, the stubs are skipped.

The behavioral tests below drive the smallest units that emit each log
(``_download_url`` / ``_download_aesgcm``, ``_on_message``, ``send``) with
``object.__new__(XMPPAdapter)`` instances plus lightweight stubs, capture the
real records with pytest's ``caplog`` and assert the sentinel key never
appears. ``_on_message`` is additionally driven end-to-end to pin the agent
boundary: ``MessageEvent.text`` must only ever carry the redacted form,
``raw_message`` must stay ``None``, while the downloader still receives the
original keyed URL.
"""

import asyncio
import logging
import sys
import time
import types
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _install_gateway_stubs() -> None:
    """Stub the Hermes host framework modules missing from the test env."""
    try:
        import gateway  # noqa: F401

        return  # Real framework available; keep it.
    except ModuleNotFoundError:
        pass

    from enum import Enum

    class Platform(str, Enum):
        XMPP = "xmpp"

    class MessageType(str, Enum):
        TEXT = "text"
        PHOTO = "photo"
        AUDIO = "audio"
        VIDEO = "video"
        FILE = "file"
        VOICE = "voice"

    class BasePlatformAdapter:
        pass

    class MessageEvent:
        pass

    class SendResult:
        pass

    gateway = types.ModuleType("gateway")
    config = types.ModuleType("gateway.config")
    config.Platform = Platform
    platforms = types.ModuleType("gateway.platforms")
    shared = types.ModuleType("gateway.platforms._shared")
    shared.get_scoped_secret = lambda *args, **kwargs: None
    shared.yaml_env_setter = None
    base = types.ModuleType("gateway.platforms.base")
    base.BasePlatformAdapter = BasePlatformAdapter
    base.MessageEvent = MessageEvent
    base.MessageType = MessageType
    base.SendResult = SendResult
    base.cache_media_bytes = lambda *args, **kwargs: None
    base.validate_inbound_media_size = lambda *args, **kwargs: None
    tools = types.ModuleType("tools")
    transcription = types.ModuleType("tools.transcription_tools")
    transcription.transcribe_audio = lambda *args, **kwargs: None

    gateway.config = config
    gateway.platforms = platforms
    platforms._shared = shared
    platforms.base = base
    tools.transcription_tools = transcription

    for name, module in {
        "gateway": gateway,
        "gateway.config": config,
        "gateway.platforms": platforms,
        "gateway.platforms._shared": shared,
        "gateway.platforms.base": base,
        "tools": tools,
        "tools.transcription_tools": transcription,
    }.items():
        sys.modules[name] = module


_install_gateway_stubs()

import adapter  # noqa: E402

# Sentinel key: deliberately distinct from the "<redacted>" marker so its
# absence can be asserted verbatim in every test below.
_KEY = "SENTINEL_KEY_abc123"

# ``_log_safe_url`` is the call-site-facing alias of ``_redact_aesgcm_url``
# and must behave identically; every URL-level case below runs on both.
_BOTH_REDACT_FNS = pytest.mark.parametrize(
    "redact_fn",
    [adapter._log_safe_url, adapter._redact_aesgcm_url],
    ids=["log_safe_url", "redact_aesgcm_url"],
)


class TestRedactAesgcmInText:
    """Unit tests for adapter._redact_aesgcm_in_text."""

    def test_text_without_aesgcm_url_unchanged(self):
        text = "plain message with https://example.com/page and no secrets"
        assert adapter._redact_aesgcm_in_text(text) == text

    def test_single_aesgcm_url_fragment_redacted(self):
        text = f"see aesgcm://upload.example.com/file.aesgcm#{_KEY} end"
        result = adapter._redact_aesgcm_in_text(text)
        assert _KEY not in result
        assert "<redacted>" in result
        assert result == "see aesgcm://upload.example.com/file.aesgcm#<redacted> end"

    def test_multiple_aesgcm_urls_all_redacted(self):
        text = (
            f"aesgcm://host-one.tld/a.aesgcm#{_KEY} mid "
            f"aesgcm://host-two.tld/b.aesgcm#{_KEY} tail"
        )
        result = adapter._redact_aesgcm_in_text(text)
        assert _KEY not in result
        assert result.count("<redacted>") == 2
        assert "host-one.tld" in result
        assert "host-two.tld" in result

    def test_aesgcm_url_without_fragment_unchanged(self):
        text = "look at aesgcm://upload.example.com/file.aesgcm please"
        assert adapter._redact_aesgcm_in_text(text) == text

    def test_empty_text_returned_as_is(self):
        assert adapter._redact_aesgcm_in_text("") == ""

    def test_none_returned_as_is(self):
        assert adapter._redact_aesgcm_in_text(None) is None

    def test_plain_text_without_url_unchanged(self):
        assert adapter._redact_aesgcm_in_text("hello world") == "hello world"

    def test_single_url_key_redacted_in_text(self):
        text = f"see aesgcm://host/f#{_KEY} now"
        result = adapter._redact_aesgcm_in_text(text)
        assert _KEY not in result
        assert "<redacted>" in result

    def test_multiple_urls_distinct_keys_all_redacted(self):
        text = f"aesgcm://h1/f#{_KEY}1 and aesgcm://h2/f#{_KEY}2"
        result = adapter._redact_aesgcm_in_text(text)
        assert f"{_KEY}1" not in result
        assert f"{_KEY}2" not in result
        assert _KEY not in result
        assert result.count("<redacted>") == 2

    def test_trailing_punctuation_does_not_leak_key(self):
        # The "." may be swallowed by the masked fragment; the key must not leak.
        text = f"aesgcm://host/f#{_KEY}."
        result = adapter._redact_aesgcm_in_text(text)
        assert _KEY not in result
        assert result.startswith("aesgcm://host/f#")

    def test_closing_quote_preserved_and_key_redacted(self):
        text = f'aesgcm://host/f#{_KEY}"'
        result = adapter._redact_aesgcm_in_text(text)
        assert _KEY not in result
        assert result.endswith('"')
        assert "<redacted>" in result

    def test_redaction_is_idempotent(self):
        text = f"see aesgcm://host/f#{_KEY} and aesgcm://h2/f#{_KEY} end"
        once = adapter._redact_aesgcm_in_text(text)
        assert adapter._redact_aesgcm_in_text(once) == once
        assert _KEY not in once

    def test_apostrophe_in_path_is_redacted(self):
        # The apostrophe is a legal URL-path character: the match must not
        # stop at it, or the fragment (and its key) would survive.
        text = f"see aesgcm://host/alice's-photo.png#{_KEY} now"
        result = adapter._redact_aesgcm_in_text(text)
        assert _KEY not in result
        assert "alice's-photo.png#<redacted>" in result

    def test_url_in_single_quotes_is_redacted(self):
        # A URL wrapped in single quotes: the closing quote is swallowed
        # into the masked fragment fail-closed — the key must not survive.
        text = f"'aesgcm://host/f#{_KEY}'"
        result = adapter._redact_aesgcm_in_text(text)
        assert _KEY not in result

    def test_apostrophe_idempotent(self):
        text = f"aesgcm://host/alice's-photo.png#{_KEY}"
        once = adapter._redact_aesgcm_in_text(text)
        assert adapter._redact_aesgcm_in_text(once) == once
        assert _KEY not in once

    def test_large_text_with_many_urls_redacted_quickly(self):
        # 200 KB of text carrying 50 keyed URLs must redact in < 2 seconds.
        padding = "x" * (200 * 1024 // 50)
        text = "".join(
            f"{padding} aesgcm://host{i}/file{i}.aesgcm#{_KEY} " for i in range(50)
        )
        assert len(text) >= 200 * 1024
        start = time.perf_counter()
        result = adapter._redact_aesgcm_in_text(text)
        elapsed = time.perf_counter() - start
        assert _KEY not in result
        assert result.count("<redacted>") == 50
        assert elapsed < 2.0


class TestLogSafeUrl:
    """Sanity tests for adapter._log_safe_url used by the redaction helper."""

    def test_aesgcm_fragment_redacted(self):
        url = f"aesgcm://upload.example.com/file.aesgcm#{_KEY}"
        result = adapter._log_safe_url(url)
        assert _KEY not in result
        assert result == "aesgcm://upload.example.com/file.aesgcm#<redacted>"

    def test_plain_https_url_unchanged(self):
        url = "https://upload.example.com/file.aesgcm"
        assert adapter._log_safe_url(url) == url

    def test_empty_url_returned_as_is(self):
        assert adapter._log_safe_url("") == ""

    @_BOTH_REDACT_FNS
    def test_valid_url_fragment_redacted(self, redact_fn):
        result = redact_fn(f"aesgcm://host/file.aesgcm#{_KEY}")
        assert _KEY not in result
        assert result == "aesgcm://host/file.aesgcm#<redacted>"

    @_BOTH_REDACT_FNS
    def test_malformed_authority_redacted_without_exception(self, redact_fn):
        # The pre-rewrite urlparse-based helper blew up on this input.
        result = redact_fn(f"aesgcm://[invalid]/file#{_KEY}")
        assert _KEY not in result
        assert result == "aesgcm://[invalid]/file#<redacted>"

    @_BOTH_REDACT_FNS
    def test_uppercase_scheme_redacted(self, redact_fn):
        result = redact_fn(f"AESGCM://Host/File#{_KEY}")
        assert _KEY not in result
        assert result == "AESGCM://Host/File#<redacted>"

    @_BOTH_REDACT_FNS
    def test_mixed_case_scheme_redacted(self, redact_fn):
        result = redact_fn(f"AesGcm://Host/File#{_KEY}")
        assert _KEY not in result
        assert result == "AesGcm://Host/File#<redacted>"

    @_BOTH_REDACT_FNS
    def test_url_without_fragment_unchanged(self, redact_fn):
        assert redact_fn("aesgcm://host/file") == "aesgcm://host/file"

    @_BOTH_REDACT_FNS
    def test_https_url_with_fragment_unchanged(self, redact_fn):
        url = "https://host/file#frag"
        assert redact_fn(url) == url

    @_BOTH_REDACT_FNS
    def test_empty_string_unchanged(self, redact_fn):
        assert redact_fn("") == ""

    @_BOTH_REDACT_FNS
    def test_none_url_returned_as_is(self, redact_fn):
        assert redact_fn(None) is None

    @_BOTH_REDACT_FNS
    def test_multiple_hash_signs_only_first_preserved(self, redact_fn):
        result = redact_fn(f"aesgcm://host/file#a#{_KEY}")
        assert _KEY not in result
        assert result == "aesgcm://host/file#<redacted>"
        assert result.count("#") == 1

    @_BOTH_REDACT_FNS
    def test_bare_scheme_without_fragment_unchanged(self, redact_fn):
        assert redact_fn("aesgcm://") == "aesgcm://"

    @_BOTH_REDACT_FNS
    def test_empty_fragment_redacted(self, redact_fn):
        result = redact_fn("aesgcm://host/file#")
        assert result == "aesgcm://host/file#<redacted>"

    @_BOTH_REDACT_FNS
    def test_redaction_is_idempotent(self, redact_fn):
        url = f"aesgcm://host/file.aesgcm#{_KEY}"
        once = redact_fn(url)
        assert redact_fn(once) == once
        assert _KEY not in once


# ---------------------------------------------------------------------------
# Behavioral drivers (caplog + agent boundary)
# ---------------------------------------------------------------------------


class _CapturedEvent:
    """Stand-in for gateway ``MessageEvent``: captures constructor kwargs."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeSendResult:
    """Stand-in for gateway ``SendResult``: captures constructor kwargs."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class _FakeMessage:
    """Minimal slixmpp ``Message`` stand-in for ``_on_message``."""

    def __init__(self, body="", oob_url=None, mtype="chat",
                 frm="alice@example.com/phone"):
        self._type = mtype
        self._from = frm
        self._body = body
        self.xml = ET.Element("{jabber:client}message")
        if oob_url:
            oob = ET.SubElement(self.xml, "{jabber:x:oob}x")
            url_el = ET.SubElement(oob, "{jabber:x:oob}url")
            url_el.text = oob_url

    def __getitem__(self, key):
        if key == "type":
            return self._type
        if key == "from":
            return self._from
        raise KeyError(key)

    def get(self, key, default=None):
        if key == "type":
            return self._type
        if key == "body":
            return self._body
        return default


def _bare_adapter():
    """XMPPAdapter skeleton with only the attributes the drivers touch."""
    instance = object.__new__(adapter.XMPPAdapter)
    instance._http = None
    instance._last_resources = {}
    instance._omemo_chats = set()
    instance.omemo_enabled = False
    instance._voice_reply_chats = {}
    instance.client = None  # _omemo_plugin() -> None: OMEMO path skipped
    instance.user_jid = "bot@example.com/hermes"
    return instance


def _message_adapter(monkeypatch, download=object()):
    """Adapter wired for ``_on_message``; returns ``(adapter, events)``.

    ``download`` is what the stubbed ``_download_aesgcm`` returns; the spy
    records every URL it was called with on ``adapter._received_download_urls``.
    """
    monkeypatch.setattr(adapter, "MessageEvent", _CapturedEvent)
    instance = _bare_adapter()
    events = []

    async def _capture(event):
        events.append(event)

    instance.handle_message = _capture
    instance.build_source = lambda **kwargs: dict(kwargs)
    instance._cache_media = (
        lambda data, kind="image", ext=None: f"/cache/{kind}.bin"
    )

    received_urls = []

    async def _spy_download(url):
        received_urls.append(url)
        return download

    instance._download_aesgcm = _spy_download
    instance._received_download_urls = received_urls
    return instance, events


class TestLogCallSitesRedactKeys:
    """caplog-based behavioral tests for every leak-prone log call site.

    Each test drives the smallest unit that emits the log and asserts the
    sentinel key never reaches the captured records. For the call-site tests
    the defensive ``_AesgcmRedactingFilter`` is stripped: with the filter
    active it would mask any call-site regression, so isolating it makes a
    reverted call-site redaction detectable. The filter itself is exercised
    by the last two tests.
    """

    @pytest.fixture
    def no_redacting_filter(self, monkeypatch):
        monkeypatch.setattr(adapter.logger, "filters", [])

    @staticmethod
    def _debug(caplog):
        caplog.set_level(logging.DEBUG, logger=adapter.logger.name)

    def test_download_url_failure_redacts_keyed_exception(
        self, caplog, no_redacting_filter, monkeypatch
    ):
        self._debug(caplog)
        monkeypatch.setattr(adapter, "_is_blocked_ssrf_url", lambda url: False)

        class _ExplodingHttp:
            async def get(self, url):
                raise RuntimeError(f"dial aesgcm://host/f#{_KEY} failed")

        instance = _bare_adapter()
        instance._http = _ExplodingHttp()
        data = asyncio.run(
            instance._download_url("https://upload.example.com/file.aesgcm")
        )
        assert data is None
        assert "XMPP: failed to download" in caplog.text
        assert _KEY not in caplog.text

    def test_download_aesgcm_failure_redacts_url(
        self, caplog, no_redacting_filter
    ):
        self._debug(caplog)
        # 88-char fragment carrying the sentinel: fromhex fails on the
        # non-hex sentinel characters, so the warning path logs the URL.
        fragment = _KEY + "0" * (88 - len(_KEY))
        url = f"aesgcm://upload.example.com/file.aesgcm#{fragment}"
        data = asyncio.run(_bare_adapter()._download_aesgcm(url))
        assert data is None
        assert "XMPP: failed to decrypt aesgcm" in caplog.text
        assert _KEY not in caplog.text

    def test_on_message_body_debug_redacted(
        self, caplog, no_redacting_filter, monkeypatch
    ):
        self._debug(caplog)
        instance, _events = _message_adapter(monkeypatch, download=b"image-bytes")
        asyncio.run(
            instance._on_message(_FakeMessage(body=f"see aesgcm://host/f#{_KEY} end"))
        )
        assert "XMPP: _on_message body=" in caplog.text
        assert _KEY not in caplog.text

    def test_on_message_body_apostrophe_url_redacted(
        self, caplog, no_redacting_filter, monkeypatch
    ):
        # The apostrophe in the URL path must not stop the redaction
        # before the keyed fragment.
        self._debug(caplog)
        instance, _events = _message_adapter(monkeypatch, download=b"image-bytes")
        asyncio.run(
            instance._on_message(
                _FakeMessage(body=f"see aesgcm://host/alice's-photo.png#{_KEY} end")
            )
        )
        assert "XMPP: _on_message body=" in caplog.text
        assert _KEY not in caplog.text

    def test_on_message_display_text_debug_redacted(
        self, caplog, no_redacting_filter, monkeypatch
    ):
        self._debug(caplog)
        # Failure path: the URL is NOT replaced by a media path in
        # display_text, so the raw keyed URL would leak here if the
        # call-site redaction were reverted.
        instance, _events = _message_adapter(monkeypatch, download=None)
        asyncio.run(
            instance._on_message(_FakeMessage(body=f"aesgcm://host/f#{_KEY}"))
        )
        assert "about to handle_message" in caplog.text
        assert _KEY not in caplog.text

    def test_send_debug_redacted(self, caplog, no_redacting_filter, monkeypatch):
        self._debug(caplog)
        monkeypatch.setattr(adapter, "SendResult", _FakeSendResult)
        result = asyncio.run(
            _bare_adapter().send(
                "alice@example.com", f"aesgcm://host/f#{_KEY} please check"
            )
        )
        assert result.success is False
        assert "XMPP: send() called" in caplog.text
        assert _KEY not in caplog.text

    def test_redacting_filter_scrubs_exc_info_traceback(self, caplog):
        # The defensive filter stays installed: even an unredacted call site
        # must never leak the key through an attached traceback.
        self._debug(caplog)
        try:
            raise ValueError(f"decrypt failed for aesgcm://host/f#{_KEY}")
        except ValueError:
            logging.getLogger(adapter.logger.name).warning(
                "media fetch blew up", exc_info=True
            )
        assert "media fetch blew up" in caplog.text
        assert "Traceback (most recent call last)" in caplog.text
        assert "ValueError" in caplog.text  # exception type preserved
        assert _KEY not in caplog.text

    def test_logger_exception_redacts_keyed_traceback(self, caplog):
        self._debug(caplog)
        try:
            raise ValueError(f"aesgcm://host/f#{_KEY} exploded")
        except ValueError as exc:
            logging.getLogger(adapter.logger.name).exception(
                "test", exc_info=(ValueError, exc, exc.__traceback__)
            )
        assert "Traceback (most recent call last)" in caplog.text
        assert _KEY not in caplog.text


class TestAgentBoundary:
    """``MessageEvent.text`` is the agent boundary: redacted form only.

    Drives the full ``_on_message`` path with a ``object.__new__(XMPPAdapter)``
    instance, a fake slixmpp message and a ``handle_message`` spy. The
    downloader spy proves the *original* keyed URL still reaches the media
    pipeline while the agent-facing text and metadata only ever carry the
    redacted form.
    """

    def test_download_success_downloader_sees_original_url_text_redacted(
        self, monkeypatch
    ):
        instance, events = _message_adapter(monkeypatch, download=b"fake image bytes")
        original_url = f"aesgcm://host/f#{_KEY}"
        asyncio.run(
            instance._on_message(_FakeMessage(body=f"see {original_url} end"))
        )
        # The media pipeline received the ORIGINAL url (key fragment included).
        assert instance._received_download_urls == [original_url]
        assert len(events) == 1
        event = events[0]
        # ... but the agent only sees the redacted form.
        assert _KEY not in event.text
        assert event.text == "see /cache/image.bin end"
        assert event.media_urls == ["/cache/image.bin"]
        assert _KEY not in (event.metadata.get("media_url") or "")
        assert event.raw_message is None

    def test_download_failure_text_redacted(self, monkeypatch):
        instance, events = _message_adapter(monkeypatch, download=None)
        asyncio.run(instance._on_message(_FakeMessage(body=f"aesgcm://host/f#{_KEY}")))
        assert len(events) == 1
        event = events[0]
        assert _KEY not in event.text
        assert "<redacted>" in event.text
        assert event.message_type == adapter.MessageType.TEXT
        assert _KEY not in (event.metadata.get("media_url") or "")
        assert event.raw_message is None

    def test_agent_text_apostrophe_url_redacted(self, monkeypatch):
        # Agent boundary: an apostrophe inside the URL path must not let
        # the keyed fragment leak into MessageEvent.text.
        instance, events = _message_adapter(monkeypatch, download=None)
        asyncio.run(
            instance._on_message(
                _FakeMessage(body=f"aesgcm://host/alice's-photo.png#{_KEY}")
            )
        )
        assert len(events) == 1
        event = events[0]
        assert _KEY not in event.text
        assert "<redacted>" in event.text

    def test_oob_only_url_text_redacted(self, monkeypatch):
        instance, events = _message_adapter(monkeypatch, download=b"fake image bytes")
        asyncio.run(
            instance._on_message(
                _FakeMessage(body="", oob_url=f"aesgcm://host/f#{_KEY}")
            )
        )
        assert len(events) == 1
        event = events[0]
        assert _KEY not in event.text
        assert event.metadata.get("media_path") == "/cache/image.bin"
        assert _KEY not in (event.metadata.get("media_url") or "")
        assert event.raw_message is None

    def test_plain_text_byte_identical_no_media(self, monkeypatch):
        instance, events = _message_adapter(monkeypatch)
        asyncio.run(instance._on_message(_FakeMessage(body="hello world")))
        assert len(events) == 1
        event = events[0]
        assert event.text == "hello world"
        assert event.media_urls == []
        assert event.media_types == []
        assert event.metadata.get("media_url") is None
        assert event.metadata.get("media_path") is None
        assert event.metadata.get("encrypted") is False
        assert event.raw_message is None
        # No downloader was invoked for plain text.
        assert instance._received_download_urls == []


class TestFilterDeduplication:
    """The filter install guard must dedupe across module reloads.

    ``logging.getLogger()`` returns the same singleton while a reload
    rebinds ``_AesgcmRedactingFilter`` to a fresh class object, so the
    guard keys on the reload-stable class NAME — an ``isinstance()``
    check would miss the reloaded class and stack duplicate filters.
    """

    def test_filter_deduplication_survives_reload(self, monkeypatch):
        """Simulating a reload: re-running the install guard must not add
        a second redacting filter to the module logger."""
        # Work on a copy of the shared logger's filter list so a broken
        # guard cannot permanently pollute other tests.
        monkeypatch.setattr(
            adapter.logger, "filters", list(adapter.logger.filters)
        )
        initial_count = sum(
            1
            for f in adapter.logger.filters
            if type(f).__name__ == "_AesgcmRedactingFilter"
        )
        assert initial_count >= 1

        # The module-level install guard, exactly as executed at import
        # time (i.e. re-run after every reload).
        if not any(
            type(f).__name__ == "_AesgcmRedactingFilter"
            for f in adapter.logger.filters
        ):
            adapter.logger.addFilter(adapter._AesgcmRedactingFilter())

        final_count = sum(
            1
            for f in adapter.logger.filters
            if type(f).__name__ == "_AesgcmRedactingFilter"
        )
        assert initial_count == final_count

    def test_fresh_class_object_is_deduped_by_name(self):
        """A fresh (reload-style) class object with the same name must be
        recognized by the guard: isinstance() returns False here — the
        exact regression this name-based replacement fixes."""
        class _AesgcmRedactingFilter(logging.Filter):
            pass

        fresh_instance = _AesgcmRedactingFilter()
        assert not isinstance(fresh_instance, adapter._AesgcmRedactingFilter)
        # The name-based guard recognizes the reloaded-style instance, so
        # the install guard would NOT stack a duplicate filter.
        assert any(
            type(f).__name__ == "_AesgcmRedactingFilter"
            for f in [fresh_instance]
        )


class TestExtractUrlApostrophe:
    """``_extract_url`` must capture the FULL keyed ``aesgcm://`` URL.

    The apostrophe is a legal URL-path character: stopping there strands
    the keyed fragment in the body, and the URL->media-path replacement in
    ``_on_message`` would then re-expose it in ``MessageEvent.text``.
    """

    def test_apostrophe_in_path_extracts_full_keyed_url(self):
        instance = _bare_adapter()
        url = f"aesgcm://host/alice's-photo.png#{_KEY}"
        assert instance._extract_url(f"see {url} end") == url

    def test_https_extraction_unchanged_by_apostrophe(self):
        instance = _bare_adapter()
        # https URLs carry no key fragment: their existing terminator set
        # (including the apostrophe) is deliberately left untouched.
        assert (
            instance._extract_url("see https://host/alice's-photo.png end")
            == "https://host/alice"
        )

    def test_quoted_aesgcm_url_extracted_without_quotes(self):
        # A URL wrapped in single quotes must extract WITHOUT them: the
        # regex swallows the closing quote, and the extra character would
        # make _download_aesgcm reject the 89-char fragment (it must be
        # exactly 88). Previously this URL decrypted; it must again.
        instance = _bare_adapter()
        url = f"aesgcm://host/f#{_KEY}"
        assert instance._extract_url(f"see '{url}' end") == url

    def test_bare_quoted_aesgcm_url_extracted_without_quotes(self):
        # Same as above with the quoted URL as the whole body (no leading
        # word: the regex then starts matching at the scheme itself).
        instance = _bare_adapter()
        url = f"aesgcm://host/f#{_KEY}"
        assert instance._extract_url(f"'{url}'") == url

    def test_internal_apostrophe_not_stripped_as_enclosing_quote(self):
        # Only ENCLOSING quotes are removed: an apostrophe inside the URL
        # path (alice's-photo.png) must survive extraction untouched.
        instance = _bare_adapter()
        url = f"aesgcm://host/alice's-photo.png#{_KEY}"
        assert instance._extract_url(url) == url

    def test_quoted_aesgcm_url_fragment_is_exactly_88_chars(self):
        # End-to-end guard for the _download_aesgcm length check: the
        # extracted fragment of a quoted URL is 88 chars — the closing
        # quote is NOT part of it.
        instance = _bare_adapter()
        fragment = _KEY + "0" * (88 - len(_KEY))
        url = f"aesgcm://host/f#{fragment}"
        extracted = instance._extract_url(f"'{url}'")
        assert len(extracted.split("#", 1)[1]) == 88
        assert extracted.split("#", 1)[1] == fragment

    def test_quoted_https_url_extracted_without_quotes(self):
        # The enclosing-quote strip covers the https branch too.
        instance = _bare_adapter()
        assert (
            instance._extract_url("see 'https://host/photo.png' end")
            == "https://host/photo.png"
        )

    def test_quoted_aesgcm_url_with_trailing_period(self):
        # A quoted URL followed by sentence punctuation: the period hides
        # the closing quote from the endswith("'") check, so punctuation
        # must be stripped BEFORE the enclosing-quote check.
        instance = _bare_adapter()
        url = f"aesgcm://host/f#{_KEY}"
        assert instance._extract_url(f"'{url}'.") == url

    def test_quoted_aesgcm_url_with_trailing_comma(self):
        instance = _bare_adapter()
        url = f"aesgcm://host/f#{_KEY}"
        assert instance._extract_url(f"'{url}',") == url

    def test_quoted_aesgcm_url_with_trailing_exclamation(self):
        instance = _bare_adapter()
        url = f"aesgcm://host/f#{_KEY}"
        assert instance._extract_url(f"'{url}'!") == url

    def test_quoted_aesgcm_url_fragment_valid_after_punctuation(self):
        # End-to-end guard for the _download_aesgcm length check: after
        # punctuation + enclosing-quote stripping, the fragment is exactly
        # the 88 chars the decrypt requires — no quote, no punctuation.
        instance = _bare_adapter()
        fragment = _KEY + "0" * (88 - len(_KEY))
        url = f"aesgcm://host/f#{fragment}"
        extracted = instance._extract_url(f"'{url}'.")
        assert extracted.split("#", 1)[1] == fragment
        assert len(extracted.split("#", 1)[1]) == 88
