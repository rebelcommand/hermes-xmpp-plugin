"""Regression tests: inbound ``MessageEvent`` must always carry ``metadata={}``.

Hermes core (gateway/session_envelope.py::_native_metadata) only admits
WhatsApp-shaped metadata natively; any other non-empty metadata dict is
refused with ``invalid_params`` and the message is dropped before the agent
ever sees it. The XMPP adapter therefore logs its XMPP-specific metadata at
DEBUG level and passes an empty dict so every inbound message passes
admission.

These tests exercise the real ``XMPPAdapter._on_message`` pipeline. The
Hermes host modules (``gateway.*``, ``tools.transcription_tools``) only exist
inside a Hermes installation, so minimal stand-ins are injected into
``sys.modules`` before importing ``adapter``; slixmpp itself is real.
"""

import asyncio
import enum
import logging
import sys
import types
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

METADATA_LOG_MARKER = "XMPP: message metadata (logged, not passed to gateway)"

SENDER_JID = "alice@example.com/laptop"
SELF_JID = "agent@example.com/hermes"

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
OGG_BYTES = b"OggS" + b"\x00" * 16


def _install_host_stubs() -> None:
    """Inject minimal stand-ins for the Hermes host modules.

    Only the names ``adapter.py`` imports at module load are provided so the
    inbound pipeline can run with the real adapter code.
    """
    if "adapter" in sys.modules:
        return

    gateway = types.ModuleType("gateway")
    gateway_config = types.ModuleType("gateway.config")

    class Platform(str, enum.Enum):
        XMPP = "xmpp"

    gateway_config.Platform = Platform

    gateway_platforms = types.ModuleType("gateway.platforms")
    shared = types.ModuleType("gateway.platforms._shared")
    shared.get_scoped_secret = lambda *args, **kwargs: None
    shared.yaml_env_setter = lambda *args, **kwargs: None

    base = types.ModuleType("gateway.platforms.base")

    class MessageType(str, enum.Enum):
        TEXT = "text"
        PHOTO = "photo"
        VOICE = "voice"
        AUDIO = "audio"

    class MessageEvent:
        """Stand-in recording exactly the kwargs the adapter passes."""

        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class SendResult:
        pass

    class BasePlatformAdapter:
        def build_source(self, **kwargs):
            return SimpleNamespace(**kwargs)

        async def handle_message(self, event):
            self.handled_events.append(event)

    base.MessageType = MessageType
    base.MessageEvent = MessageEvent
    base.SendResult = SendResult
    base.BasePlatformAdapter = BasePlatformAdapter
    base.cache_media_bytes = lambda data, **kwargs: None
    base.validate_inbound_media_size = lambda *args, **kwargs: None

    tools = types.ModuleType("tools")
    transcription = types.ModuleType("tools.transcription_tools")
    transcription.transcribe_audio = lambda path: {
        "success": True,
        "transcript": "hello from the voice note",
    }

    gateway.config = gateway_config
    gateway.platforms = gateway_platforms
    gateway_platforms._shared = shared
    gateway_platforms.base = base
    tools.transcription_tools = transcription

    sys.modules.update(
        {
            "gateway": gateway,
            "gateway.config": gateway_config,
            "gateway.platforms": gateway_platforms,
            "gateway.platforms._shared": shared,
            "gateway.platforms.base": base,
            "tools": tools,
            "tools.transcription_tools": transcription,
        }
    )


_install_host_stubs()

import adapter  # noqa: E402


class _FakeMessage:
    """Minimal stand-in for slixmpp.stanza.Message as ``_on_message`` uses it."""

    def __init__(self, body="", oob_url=None, encrypted_tag=None):
        self._values = {"type": "chat", "from": SENDER_JID, "id": "msg-1", "body": body}
        xml = ET.Element("message", {"type": "chat", "from": SENDER_JID, "id": "msg-1"})
        if body:
            ET.SubElement(xml, "body").text = body
        if oob_url:
            oob = ET.SubElement(xml, "{jabber:x:oob}x")
            ET.SubElement(oob, "{jabber:x:oob}url").text = oob_url
        if encrypted_tag:
            ET.SubElement(xml, encrypted_tag)
        self.xml = xml

    def get(self, key, default=None):
        return self._values.get(key, default)

    def __getitem__(self, key):
        return self._values[key]


class _FakeOmemoPlugin:
    """Returns a canned plaintext body for ``decrypt_message``."""

    def __init__(self, body):
        self._body = body

    async def decrypt_message(self, msg):
        return {"body": self._body}, None


class _FakeClient:
    def __init__(self, omemo_plugin=None):
        self._omemo = omemo_plugin

    def new_id(self):
        return "fake-id"

    def __getitem__(self, name):
        if self._omemo is not None and name == "xep_0384":
            return self._omemo
        raise KeyError(name)


def _make_adapter(
    *,
    omemo_enabled=False,
    omemo_plugin=None,
    download=None,
    media_path="/cache/xmpp_media",
):
    """Build an XMPPAdapter via ``__new__`` with only the attributes used by
    ``_on_message``, plus per-instance fakes for network and media cache."""
    ad = object.__new__(adapter.XMPPAdapter)
    ad.user_jid = SELF_JID
    ad.omemo_enabled = omemo_enabled
    ad.omemo_plugin_name = "xep_0384"
    ad._last_resources = {}
    ad._omemo_chats = set()
    ad._voice_reply_chats = {}
    ad.handled_events = []
    ad.client = _FakeClient(omemo_plugin)
    if download is not None:
        async def _fake_download(url):
            return download
        ad._download_url = _fake_download
        ad._download_aesgcm = _fake_download
    ad._cache_media = lambda data, kind="image", ext=None: media_path
    return ad


def _run_on_message(ad, msg):
    asyncio.run(ad._on_message(msg))
    assert len(ad.handled_events) == 1, "exactly one MessageEvent must be handled"
    return ad.handled_events[0]


def _metadata_records(caplog):
    return [r for r in caplog.records if METADATA_LOG_MARKER in r.getMessage()]


def test_plaintext_message_carries_empty_metadata(caplog):
    """A simple plaintext message yields metadata={} and no metadata log."""
    caplog.set_level(logging.DEBUG, logger="adapter")
    ad = _make_adapter()
    event = _run_on_message(ad, _FakeMessage(body="hello world"))

    assert event.metadata == {}
    assert event.text == "hello world"
    assert event.message_type == adapter.MessageType.TEXT
    assert event.media_urls == []
    assert event.media_types == []
    assert _metadata_records(caplog) == [], "plaintext must not emit the metadata log"


def test_omemo_message_carries_empty_metadata(caplog):
    """An OMEMO-encrypted message still yields metadata={} with the DEBUG log."""
    caplog.set_level(logging.DEBUG, logger="adapter")
    omemo = _FakeOmemoPlugin("decrypted secret text")
    ad = _make_adapter(
        omemo_enabled=True,
        omemo_plugin=omemo,
    )
    event = _run_on_message(
        ad,
        _FakeMessage(
            body="ciphertext-fallback",
            encrypted_tag="{eu.siacs.conversations.axolotl}encrypted",
        ),
    )

    assert event.metadata == {}
    assert event.text == "decrypted secret text"
    assert event.message_type == adapter.MessageType.TEXT
    assert event.media_urls == []
    assert event.media_types == []
    records = _metadata_records(caplog)
    assert records, "encrypted=True must emit the metadata log"
    assert all(r.levelno == logging.DEBUG for r in records)
    assert SENDER_JID.split("/")[0] in ad._omemo_chats


def test_image_message_carries_empty_metadata(caplog):
    """An inbound image (media_path + url present) still yields metadata={}."""
    caplog.set_level(logging.DEBUG, logger="adapter")
    image_url = "https://files.example.com/photo.png"
    ad = _make_adapter(download=PNG_BYTES, media_path="/cache/xmpp_img.png")
    event = _run_on_message(ad, _FakeMessage(body=image_url, oob_url=image_url))

    assert event.metadata == {}
    assert event.text == "/cache/xmpp_img.png"
    assert event.message_type == adapter.MessageType.PHOTO
    assert event.media_urls == ["/cache/xmpp_img.png"]
    assert event.media_types == ["image/png"]
    records = _metadata_records(caplog)
    assert records, "media_path/url present must emit the metadata log"
    assert all(r.levelno == logging.DEBUG for r in records)


def test_voice_message_carries_empty_metadata(caplog):
    """An inbound voice note (media_path present) still yields metadata={}.

    Voice messages are transcribed and converted to TEXT so the gateway core
    does not auto-TTS the reply; the media path is replaced by the transcript
    and the chat is queued for a voice reply.
    """
    caplog.set_level(logging.DEBUG, logger="adapter")
    voice_url = "https://files.example.com/voice-message-123.ogg"
    ad = _make_adapter(download=OGG_BYTES, media_path="/cache/xmpp_voice.ogg")
    event = _run_on_message(ad, _FakeMessage(body="", oob_url=voice_url))

    assert event.metadata == {}
    assert event.text == "hello from the voice note"
    assert event.message_type == adapter.MessageType.TEXT
    assert event.media_urls == []
    assert event.media_types == []
    assert SENDER_JID.split("/")[0] in ad._voice_reply_chats
    records = _metadata_records(caplog)
    assert records, "media_path present must emit the metadata log"
    assert all(r.levelno == logging.DEBUG for r in records)
