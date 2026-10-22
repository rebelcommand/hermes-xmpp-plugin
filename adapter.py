import asyncio
import hashlib
import io
import ipaddress
import logging
import os
import re
import socket
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from gateway.config import Platform
from gateway.platforms._shared import (
    get_scoped_secret as _get_scoped_secret,
)
from gateway.platforms._shared import (
    yaml_env_setter,
)
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
    cache_media_bytes,
    validate_inbound_media_size,
)
from PIL import Image
from slixmpp import JID, ClientXMPP
from slixmpp.plugins.base import register_plugin
from slixmpp.stanza import Message
from tools.transcription_tools import transcribe_audio


class _AesgcmRedactingFilter(logging.Filter):
    """Defensive filter: redact aesgcm:// fragments from any log record.

    Covers both the formatted message AND exception tracebacks (exc_info),
    pre-formatted exception text (exc_text) and stack_info. Each field is
    only processed when it may contain 'aesgcm' (case-insensitive) to keep
    cost ~0 for ordinary messages. Installed on the module logger so an
    unpatched call site can never leak an AES-GCM key fragment into the logs.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # 1. Redact the formatted message. Args are consumed by the
            # already-formatted msg so a second pass (idempotence) yields
            # the same string.
            msg = record.getMessage()
            if "aesgcm" in msg.lower():
                record.msg = _redact_aesgcm_in_text(msg)
                record.args = ()

            # 2. Redact exception tracebacks. logger.exception(...)/exc_info=
            # attach the raw exception whose text may carry an
            # aesgcm://...#KEY URL. Format eagerly, redact, cache in
            # exc_text and clear exc_info: standard Formatters reuse
            # exc_text when present, so the visible stack is preserved.
            # Never store a string in exc_info — that field expects an
            # (type, value, traceback) tuple or None.
            if record.exc_info:
                exc_text = logging.Formatter().formatException(record.exc_info)
                if "aesgcm" in exc_text.lower():
                    exc_text = _redact_aesgcm_in_text(exc_text)
                record.exc_text = exc_text
                record.exc_info = None

            # 3. Redact pre-formatted exception text (e.g. pre-filled by an
            # upstream formatter or a previous pass — keeps idempotence).
            if record.exc_text and "aesgcm" in record.exc_text.lower():
                record.exc_text = _redact_aesgcm_in_text(record.exc_text)

            # 4. Redact stack_info dumps the same way.
            if record.stack_info and "aesgcm" in record.stack_info.lower():
                record.stack_info = _redact_aesgcm_in_text(record.stack_info)
        except Exception:
            # Fail-closed: drop the record rather than risk leaking the
            # original (potentially keyed) payload.
            return False
        return True


logger = logging.getLogger(__name__)
# Install at most once: logging.getLogger() returns the same singleton across
# module reloads, so a naive addFilter() would stack duplicate filters. The
# dedup check compares the class NAME instead of isinstance(): a reload
# rebinds _AesgcmRedactingFilter to a fresh class object that isinstance()
# no longer recognizes, whereas the name is reload-stable.
if not any(type(_existing_filter).__name__ == "_AesgcmRedactingFilter" for _existing_filter in logger.filters):
    logger.addFilter(_AesgcmRedactingFilter())

# XMPP servers and clients choke on very large stanzas, so send() splits every
# reply into wire-sized chunks (see _send_text below). MAX_MESSAGE_LENGTH is
# declared at the true ceiling (below) so the gateway's progress-text and
# cron-delivery paths do not assume the 4096 default, and splits_long_messages
# tells the delivery router that send() chunks natively and should receive the
# full payload rather than a pre-truncated one.
_WIRE_CHUNK_SIZE = 2000


def _omemo_available() -> bool:
    try:
        import slixmpp_omemo  # noqa: F401
        return True
    except Exception:
        return False


def _parse_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off", ""):
        return False
    return default


def _guess_content_type(data: bytes) -> str:
    """Inspect file magic bytes to determine the real content type."""
    if len(data) < 4:
        return "unknown"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "image/gif"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"BM"):
        return "image/bmp"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "audio/m4a"
    if data.startswith(b"OggS"):
        return "audio/ogg"
    if data.startswith(b"ID3"):
        return "audio/mp3"
    if len(data) >= 2 and data[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        return "audio/mp3"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WAVE":
        return "audio/wav"
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return "audio/webm"
    return "unknown"


def _guess_extension_from_data(data: bytes) -> str:
    """Return a file extension based on actual file content."""
    content_type = _guess_content_type(data)
    return {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/gif": ".gif",
        "image/webp": ".webp",
        "image/bmp": ".bmp",
        "audio/m4a": ".m4a",
        "audio/ogg": ".ogg",
        "audio/mp3": ".mp3",
        "audio/wav": ".wav",
        "audio/webm": ".webm",
    }.get(content_type, "")


def _mime_from_extension(ext: str) -> str:
    return {
        ".m4a": "audio/mp4",
        ".mp4": "audio/mp4",
        ".opus": "audio/opus",
        ".ogg": "audio/ogg",
        ".oga": "audio/ogg",
        ".mp3": "audio/mpeg",
        ".wav": "audio/wav",
        ".webm": "audio/webm",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
    }.get(ext.lower(), "application/octet-stream")


def _is_audio_url(url: str) -> bool:
    # Strip query string and fragment so URLs like
    # https://example.com/audio.mp3?token=abc are still recognized as audio.
    try:
        path = urlparse(url).path
    except Exception:
        path = url
    return any(path.lower().endswith(ext) for ext in (
        ".ogg", ".oga", ".mp3", ".m4a", ".webm", ".wav", ".opus"
    ))


def _guess_audio_is_voice(url: str, body: str, data: Optional[bytes] = None) -> bool:
    """Heuristic to decide if an incoming audio URL is a voice message.

    A URL must NOT be treated as voice just because it is short or OMEMO-
    encrypted. OMEMO uses aesgcm:// for images, files, and voice alike, and
    a bare HTTPS URL is a text link unless it actually points to audio.

    The caller only invokes this after confirming the downloaded content is
    audio, so the final branch treats a bare audio URL with no caption as a
    voice message regardless of container (m4a, mp3, wav, ogg, etc.). That is
    intentional: a standalone audio attachment with no accompanying text is the
    signature of a voice message, while shared music/podcast files almost
    always carry a filename or description and stay AUDIO.
    """
    lowered = url.lower()
    # Conversations and similar clients often use voice-message-* filenames.
    if "voice-message" in lowered:
        return True
    # Voice messages are usually short, unadorned clips in these containers.
    if any(lowered.endswith(ext) for ext in (".ogg", ".oga", ".opus", ".webm")):
        return True
    # A bare audio URL with no caption is the signature of a voice message, so
    # treat any audio content as voice here (the caller has already confirmed
    # the content is audio). Shared music/podcast files carry a filename or
    # description, so they do not reach this branch and stay AUDIO.
    stripped = body.strip()
    if (stripped == url or not stripped) and data is not None:
        return _guess_content_type(data).startswith("audio/")
    return False


def _guess_audio_extension(url: str, data: bytes) -> str:
    """Return a sensible file extension for an audio file.

    First inspects the file magic bytes via the shared content-type sniffer
    (single source of truth for magic-byte detection), then falls back to the
    URL extension, then defaults to .ogg.
    """
    extension_by_type = {
        "audio/m4a": ".m4a",
        "audio/ogg": ".ogg",
        "audio/mp3": ".mp3",
        "audio/wav": ".wav",
        "audio/webm": ".webm",
    }
    content_type = _guess_content_type(data)
    if content_type in extension_by_type:
        return extension_by_type[content_type]

    lowered = url.lower()
    for ext in (".m4a", ".mp4", ".ogg", ".oga", ".opus", ".mp3", ".webm", ".wav"):
        if lowered.endswith(ext):
            return ext
    return ".ogg"

def _is_media_url(url: str) -> bool:
    """Return True if the URL path has a known media file extension.

    Query strings and fragments are stripped before the extension check so
    URLs like https://example.com/photo.jpg?size=large or
    https://example.com/audio.mp3#frag are still recognized as media.
    """
    try:
        path = urlparse(url).path
    except Exception:
        path = url
    lowered = path.lower()
    return any(lowered.endswith(ext) for ext in (
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico",
        ".mp3", ".m4a", ".ogg", ".oga", ".opus", ".wav", ".webm",
        ".mp4", ".mov", ".mkv", ".avi",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z",
    ))


def _redact_aesgcm_url(url: str) -> str:
    """Redact the fragment of an ``aesgcm://`` URL, fail-closed.

    Never returns the original string if it contains a fragment after an
    ``aesgcm://`` scheme, except for an already-redacted ``<redacted>``
    fragment (idempotence). Works on malformed URLs (no urlparse).
    """
    if not url:
        return url
    try:
        # Find first aesgcm:// occurrence (case-insensitive, anywhere).
        match = re.search(r"aesgcm://", url, re.IGNORECASE)
        if not match:
            return url
        # Find first # after the scheme.
        hash_pos = url.find("#", match.end())
        if hash_pos == -1:
            return url
        # Short-circuit an already-redacted fragment so applying the
        # redaction twice yields the same string (idempotence).
        if url[hash_pos + 1:] == "<redacted>":
            return url
        # Redact from # to end of string.
        return url[:hash_pos] + "#<redacted>"
    except Exception:
        # Fail-closed: if anything goes wrong, mask aggressively.
        return "<redacted>"


def _log_safe_url(url: str) -> str:
    """Return a URL safe to write to logs.

    An ``aesgcm://`` URL carries its AES-256-GCM key in the URL fragment
    (XEP-0454). The fragment is always redacted, even for malformed URLs.
    All other URLs are returned unchanged.
    """
    return _redact_aesgcm_url(url)


# ``aesgcm://`` URLs can be embedded inline in message bodies or display
# texts; capture each URL up to the next whitespace or double quote. The
# apostrophe is deliberately NOT excluded: it is a legal character inside
# URL paths (e.g. ``alice's-photo.png``), and stopping there would leave
# the fragment — and its key — unredacted. A URL wrapped in single quotes
# therefore swallows its closing ``'`` into the masked fragment
# fail-closed, which is acceptable (the key is what must not survive).
# Angle brackets are also NOT excluded so an already-redacted fragment
# (``#<redacted>``) is consumed as a single match, keeping the redaction
# idempotent; any extra trailing characters are swallowed fail-closed.
# ``*`` (not ``+``) also catches a bare ``aesgcm://`` or ``aesgcm://#KEY``,
# and ``re.IGNORECASE`` covers odd-cased schemes like ``AESGCM://``.
_AESGCM_URL_RE = re.compile(r"aesgcm://[^\s\"]*", re.IGNORECASE)


def _redact_aesgcm_in_text(text: str) -> str:
    """Redact AES-GCM key fragments from every ``aesgcm://`` URL in text.

    Known edge case: a malformed URL with whitespace before its fragment
    (``aesgcm://host/file #KEY``) stops the textual match at the space, so
    such fragments are NOT covered by this redaction (the defensive log
    filter may still scrub simple cases).
    """
    if not text:
        return text
    return _AESGCM_URL_RE.sub(lambda m: _redact_aesgcm_url(m.group(0)), text)


def _truncate_safe(text: str, limit: int) -> str:
    """Redact aesgcm keys then truncate — redaction MUST happen before slicing."""
    return _redact_aesgcm_in_text(text)[:limit]


def _is_blocked_ssrf_url(url: str) -> bool:
    """Return True when a URL resolves to a loopback/private/link-local/reserved address.

    Inbound messages may carry arbitrary URLs; fetching them blindly turns the
    gateway into an SSRF proxy that can reach internal hosts (cloud metadata
    endpoints, the local network, etc.). Hostnames are resolved before the
    range check so a name that maps to an internal address is caught too. The
    DNS lookup is blocking, so callers run this via ``asyncio.to_thread``.
    """
    try:
        hostname = urlparse(url).hostname
    except Exception:
        hostname = None
    if not hostname:
        return True
    host = hostname.strip().strip("[]")

    addresses: list[str] = []
    try:
        for info in socket.getaddrinfo(host, None):
            addr = str(info[4][0])
            if addr not in addresses:
                addresses.append(addr)
    except OSError:
        addresses = []
    if not addresses:
        # Could not resolve by name; treat a literal IP as authoritative.
        try:
            addresses = [str(ipaddress.ip_address(host))]
        except ValueError:
            # Unresolvable hostname: let the actual fetch fail and log it.
            return False

    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True
    return False


def _media_download_blocked(url: str) -> bool:
    """True when SSRF protection should refuse this media download.

    Only plain http(s) URLs are subject to the internal-address block; an
    operator who self-hosts their XMPP upload service on a private network can
    opt out with ``XMPP_ALLOW_PRIVATE_DOWNLOADS=true``.
    """
    if _parse_bool(_get_scoped_secret("XMPP_ALLOW_PRIVATE_DOWNLOADS"), False):
        return False
    return _is_blocked_ssrf_url(url)


class XMPPAdapter(BasePlatformAdapter):
    """
    XMPP Platform Adapter for Hermes.

    Features:
      - Plain-text or OMEMO-encrypted messaging
      - XEP-0085 typing indicators
      - XEP-0333 read receipts (chat markers)
      - XEP-0066 / XEP-0363 inbound images, files, and voice messages
      - aesgcm:// OMEMO media sharing decryption
      - XEP-0084 avatar publishing
      - Outgoing voice/audio messages via the Hermes core TTS tool
    """

    # XMPP's only edit primitive is XEP-0308 Last Message Correction: a
    # one-shot replace of the immediately previous message. It cannot express
    # the gateway's incremental streamed-edit model, so the draft/stream
    # consumer's mid-stream edits would be silently dropped and leave a stuck
    # cursor ("white block") partial.
    # SUPPORTS_MESSAGE_EDITING=False makes the gateway skip the stream consumer
    # for XMPP: no orphaned cursor and no duplicate partial+final delivery.
    # Tool progress still renders mid-turn as separate messages (the
    # post-install sets display.platforms.xmpp.tool_progress_grouping: separate,
    # so each tool call is its own send with no edit); only draft streaming of
    # the final answer and interim commentary are gone. edit_message below stays
    # and is used by the gateway's long-running "still working" heartbeat, which
    # edits its bubble in place via XEP-0308.
    SUPPORTS_MESSAGE_EDITING = False
    # XMPP has no edit or streaming transport, so replies are delivered whole
    # and split into wire-sized stanzas by send(). Declaring the true ceiling
    # and the native-chunking capability lets the gateway treat XMPP as a
    # self-chunking platform instead of assuming the 4096 default ceiling and
    # pre-truncating cron output at 4000 chars.
    splits_long_messages = True
    MAX_MESSAGE_LENGTH = _WIRE_CHUNK_SIZE

    def __init__(self, config, **kwargs):
        platform = Platform("xmpp")
        super().__init__(config=config, platform=platform)

        extra = getattr(config, "extra", {}) or {}

        self.user_jid = _get_scoped_secret("XMPP_USER_JID") or extra.get("user_jid", "")
        self.password = _get_scoped_secret("XMPP_PASSWORD") or extra.get("password", "")
        self.server = _get_scoped_secret("XMPP_SERVER") or extra.get("server", "")
        self.port = 5222
        raw_port = _get_scoped_secret("XMPP_PORT") or extra.get("port")
        if raw_port:
            try:
                self.port = int(raw_port)
            except (ValueError, TypeError):
                self.port = 5222

        # OMEMO is on by default. No installer writes an omemo_enabled key into
        # config.yaml anymore, so the default lives here in the adapter; an
        # explicit false (env or config) still disables it.
        self.omemo_enabled = _parse_bool(
            _get_scoped_secret("XMPP_OMEMO_ENABLED") or extra.get("omemo_enabled"), True
        )
        self.omemo_allow_untrusted = _parse_bool(
            _get_scoped_secret("XMPP_OMEMO_ALLOW_UNTRUSTED")
            or _get_scoped_secret("XMPP_OTR_ALLOW_UNTRUSTED")
            or extra.get("omemo_allow_untrusted"),
            True,
        )
        self.omemo_plugin_name = "xep_0384"
        self.omemo_storage_path: Optional[Path] = None
        self._omemo_ready_event = asyncio.Event()

        # XEP-0085 typing indicators are always enabled; do not allow config
        # to disable them. This also prevents an accidental null/false value
        # in config.yaml from breaking the composing indicator.
        self.typing_indicator = True
        self.avatar_path = _get_scoped_secret("XMPP_AVATAR_PATH") or ""
        self.home_channel = _get_scoped_secret("XMPP_HOME_CHANNEL") or extra.get("home_channel", "")

        self._session_started_event = asyncio.Event()
        self.client: Optional[ClientXMPP] = None
        self._roster_request: Optional[asyncio.Future] = None
        self._http = httpx.AsyncClient(timeout=300.0, follow_redirects=True)
        self._keepalive_task: Optional[asyncio.Task] = None
        self._avatar_republish_task: Optional[asyncio.Task] = None
        self._internal_reconnect_task: Optional[asyncio.Task] = None
        self._xmpp_background_tasks: set[asyncio.Task] = set()
        self._last_activity: float = 0.0
        self._ping_interval = 30.0
        self._ping_timeout = 10.0

        # Track chats where the last inbound message was a voice message so we
        # can reply with TTS audio at the end of the agent turn, not on the first
        # intermediate message. The simple "next non-tool message wins" approach
        # caused short acknowledgments to steal the voice reply before the real
        # response was ready.
        self._voice_reply_chats: Dict[str, Dict[str, Any]] = {}
        # Per-chat debounce tasks. A single global task would let a second
        # chat's voice message cancel the first chat's pending reply (leaving
        # the first entry stuck in _voice_reply_chats forever), so each chat
        # owns its own debounce timer.
        self._voice_reply_debounce_tasks: Dict[str, asyncio.Task] = {}
        self._voice_reply_debounce_delay: float = 2.0
        self._last_resources: Dict[str, str] = {}
        # Track bare JIDs that have sent us OMEMO-encrypted messages so replies
        # to those chats are always encrypted rather than falling back to plaintext.
        self._omemo_chats: set[str] = set()
        # Per-chat last-sent stanza id. XEP-0308 Last Message Correction can only
        # replace the immediately previous message, so edit_message must refuse
        # to correct anything that is no longer the most recent message we sent
        # (a client silently ignores a correction whose target is not the last
        # message, leaving the stale bubble on screen).
        self._last_sent_id: Dict[str, str] = {}
        # Anti-race typing state: stop_typing sets a cooldown so that stray
        # refresh ticks from the base adapter's _keep_typing loop (which may
        # outlive the adapter's own stop_typing call after /new or media sends)
        # cannot resurrect the composing indicator.
        self._typing_state: Dict[str, str] = {}
        self._typing_stop_until: Dict[str, float] = {}
        # Per-chat background refresh tasks owned by the XMPP adapter.  The base
        # adapter's _keep_typing loop can get orphaned across /new because the
        # session guard is swapped and the old task's stop_event is no longer the
        # one in _active_sessions.  By tracking our own task we can kill it
        # deterministically from send()/stop_typing() without relying on the base
        # adapter to cancel it for us.
        self._typing_refresh_tasks: Dict[str, asyncio.Task] = {}

    @property
    def name(self) -> str:
        return "XMPP"

    # -- OMEMO helpers -------------------------------------------------------

    def _configure_omemo(self) -> bool:
        if not self.omemo_enabled or self.client is None:
            return False
        if not _omemo_available():
            logger.error(
                "XMPP_OMEMO_ENABLED=true but slixmpp-omemo is not installed; "
                "run: pip install slixmpp-omemo"
            )
            return False
        try:
            from .omemo_plugin import HermesOMEMO

            register_plugin(HermesOMEMO, name=self.omemo_plugin_name)
            self.client.register_plugin(
                self.omemo_plugin_name,
                pconfig={
                    "allow_untrusted": self.omemo_allow_untrusted,
                    "storage_path": str(self.omemo_storage_path) if self.omemo_storage_path else None,
                },
            )
            logger.info("XMPP: OMEMO plugin enabled")
            return True
        except Exception as exc:
            logger.exception("XMPP: failed to configure OMEMO: %s", exc)
            return False

    def _omemo_plugin(self) -> Any:
        if self.client is None:
            return None
        try:
            return self.client[self.omemo_plugin_name]
        except Exception:
            return None

    # -- Connection ----------------------------------------------------------

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if not self.user_jid or not self.password:
            logger.error("XMPP: user_jid and password are required")
            self._set_fatal_error(
                "missing_credentials", "XMPP user_jid/password missing", retryable=False
            )
            return False

        # If this is a reconnect, tear down the old client and tasks first so
        # we don't end up with two slixmpp event loops racing or the old one
        # silently swallowing events while the new one claims to be connected.
        if is_reconnect:
            logger.info("XMPP: tearing down old client before reconnect")
            await self._cleanup_client()

        self._session_started_event.clear()
        self._omemo_ready_event.clear()

        try:
            # Use a fixed Hermes resource if none was provided, and advertise
            # a service-discovery identity so XMPP clients label the account
            # as "Hermes" in tooltips/contact lists.
            jid_str = self.user_jid
            if "/" not in jid_str:
                jid_str = f"{jid_str}/Hermes"

            self.client = ClientXMPP(jid_str, self.password)
            self.client.use_message_ids = True
            self.client.register_plugin("xep_0030")  # Service discovery
            try:
                disco = self.client.plugin.get("xep_0030")
                if disco is not None:
                    disco.add_identity(
                        category="client",
                        itype="pc",
                        name="Hermes",
                    )
            except Exception as exc:
                logger.debug("XMPP: could not set disco identity: %s", exc)

            self.client.register_plugin("xep_0004")  # Data Forms
            self.client.register_plugin("xep_0060")  # PubSub
            self.client.register_plugin("xep_0066")  # Out of Band Data
            self.client.register_plugin("xep_0054")  # vcard-temp
            self.client.register_plugin("xep_0084")  # User Avatar
            self.client.register_plugin("xep_0153")  # vCard-based Avatars
            self.client.register_plugin("xep_0085")  # Chat State Notifications
            self.client.register_plugin("xep_0163")  # PEP
            self.client.register_plugin("xep_0280")  # Message Carbons
            self.client.register_plugin("xep_0333")  # Chat Markers
            self.client.register_plugin("xep_0334")  # Message Processing Hints
            self.client.register_plugin("xep_0363")  # HTTP File Upload
            self.client.register_plugin("xep_0199")  # XMPP Ping
            self.client.register_plugin("xep_0308")  # Last Message Correction

            if self.omemo_enabled:
                from hermes_constants import get_hermes_home

                self.omemo_storage_path = get_hermes_home() / "sessions" / "omemo.json"
                self.client.add_event_handler(
                    "omemo_initialized", self._omemo_initialized
                )
                if not self._configure_omemo():
                    logger.warning(
                        "XMPP: OMEMO requested but could not be enabled; falling back to plaintext"
                    )

            self.client.add_event_handler("session_start", self._session_start)
            self.client.add_event_handler("message", self._on_message)
            self.client.add_event_handler("presence_subscribe", self._on_presence_subscribe)
            self.client.add_event_handler("exception", self._slixmpp_exception_handler)
            self.client.add_event_handler("disconnected", self._on_disconnected)
            self.client.add_event_handler("stream_negotiated", self._on_stream_negotiated)
            self.client.add_event_handler("failed_auth", self._on_failed_auth)

            logger.info("XMPP: connecting as %s to %s:%s ...", self.user_jid, self.server or "(auto)", self.port)

            # slixmpp connect() returns a Future that completes when the
            # connection *ends*; do not await it. Wait for session_start instead.
            connect_future = self.client.connect(host=self.server or None, port=self.port)
            if connect_future is not None:
                self._xmpp_background_tasks.add(
                    asyncio.create_task(self._watch_client_future(connect_future))
                )

            try:
                await asyncio.wait_for(
                    self._session_started_event.wait(), timeout=30.0
                )
                logger.info("XMPP: session_start event received and awaited")
            except asyncio.TimeoutError:
                logger.error("XMPP: session_start did not arrive within 30s")
                self._set_fatal_error(
                    "connect_timeout", "session_start timed out", retryable=True
                )
                return False

            self._mark_connected()
            self._last_activity = asyncio.get_event_loop().time()
            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

            # Finish slow setup in the background so connect() returns quickly.
            asyncio.create_task(self._finish_setup())
            return True
        except Exception as e:
            logger.error("XMPP: failed to connect as %s - %s", self.user_jid, e)
            self._set_fatal_error("connect_failed", str(e), retryable=True)
            return False

    async def _watch_client_future(self, future) -> None:
        """Wait for slixmpp's connection future and trigger reconnect if it exits."""
        try:
            await future
        except asyncio.CancelledError:
            return
        except Exception as exc:
            logger.warning("XMPP: client future ended with error: %s", exc)
        if self.is_connected:
            logger.warning("XMPP: client future ended while still marked connected")
            self._schedule_internal_reconnect("client_future_done", "slixmpp connection future ended")

    async def _finish_setup(self):
        if self.omemo_enabled:
            try:
                await asyncio.wait_for(self._omemo_ready_event.wait(), timeout=30.0)
                logger.info("XMPP: OMEMO ready")
            except asyncio.TimeoutError:
                logger.warning("XMPP: OMEMO did not signal readiness within 30s")
            # Prune stale OMEMO sessions/devices so the store does not balloon
            # and desynced ratchets do not accumulate.
            try:
                omemo = self._omemo_plugin()
                if omemo is not None and hasattr(omemo, "prune_stale_sessions"):
                    removed = await omemo.prune_stale_sessions()
                    if removed:
                        logger.info("XMPP: pruned %d stale OMEMO session/device keys", removed)
            except Exception as exc:
                logger.warning("XMPP: OMEMO session pruning failed: %s", exc)
        if self.avatar_path:
            logger.info("XMPP: publishing avatar from %s", self.avatar_path)
            await self._publish_avatar()
            self._schedule_avatar_republish()

    def _schedule_avatar_republish(self) -> None:
        """Schedule a one-time avatar republish in case the first attempt did not propagate."""
        if self._avatar_republish_task and not self._avatar_republish_task.done():
            return

        async def _republish_after_delay() -> None:
            await asyncio.sleep(60.0)
            if self.is_connected and self.avatar_path:
                logger.info("XMPP: republishing avatar from %s", self.avatar_path)
                await self._publish_avatar()

        self._avatar_republish_task = asyncio.create_task(_republish_after_delay())

    async def _keepalive_loop(self) -> None:
        while self.is_connected:
            await asyncio.sleep(self._ping_interval)
            if not self.is_connected or self.client is None:
                break
            try:
                ping = self.client.plugin.get("xep_0199", None)
                if ping is not None:
                    logger.debug("XMPP: sending keepalive ping")
                    await asyncio.wait_for(
                        ping.send_ping(jid=self.client.boundjid.bare),
                        timeout=self._ping_timeout,
                    )
                    self._last_activity = asyncio.get_event_loop().time()
                else:
                    # Fallback: send a whitespace keepalive.
                    self.client.send_raw(" ")
                    self._last_activity = asyncio.get_event_loop().time()
            except Exception as exc:
                # A single ping timeout is NOT fatal: on a slow link a ping can
                # exceed the timeout while the stream is still healthy. Fall back
                # to a whitespace keepalive and keep the loop alive. Only a real
                # stream drop (the slixmpp "disconnected" event) should trigger
                # a reconnect.
                logger.warning("XMPP: keepalive ping failed (%s); using whitespace keepalive", exc)
                try:
                    if self.client is not None:
                        self.client.send_raw(" ")
                        self._last_activity = asyncio.get_event_loop().time()
                except Exception:
                    pass

    def _schedule_internal_reconnect(self, code: str, message: str) -> None:
        """Schedule an internal reconnect attempt before escalating to the gateway.

        This handles transient TCP/XMPP stream drops without requiring the
        gateway-level reconnect watcher to wake up.
        """
        if self._internal_reconnect_task and not self._internal_reconnect_task.done():
            return

        async def _reconnect_attempts() -> None:
            delay = 5.0
            for attempt in range(1, 4):
                if self.is_connected:
                    logger.info("XMPP: connection already restored, aborting internal reconnect")
                    return
                logger.info(
                    "XMPP: internal reconnect attempt %d/3 after %s in %.0fs",
                    attempt, code, delay,
                )
                await asyncio.sleep(delay)
                if self.is_connected:
                    logger.info("XMPP: connection restored while waiting, aborting internal reconnect")
                    return
                try:
                    success = await self.connect(is_reconnect=True)
                    if success:
                        logger.info("XMPP: internal reconnect succeeded on attempt %d", attempt)
                        return
                except Exception as exc:
                    logger.warning("XMPP: internal reconnect attempt %d failed: %s", attempt, exc)
                delay = min(delay * 2, 60.0)
            logger.error(
                "XMPP: internal reconnect exhausted after %s (%s); escalating to gateway retry",
                code, message,
            )
            self._set_fatal_error(code, message, retryable=True)

        self._internal_reconnect_task = asyncio.create_task(_reconnect_attempts())

    async def _on_disconnected(self, event):
        logger.warning("XMPP: disconnected event received; event=%s", event)
        self._mark_disconnected()
        # Do not schedule reconnect if we are already trying, or if the
        # disconnect was caused by a deliberate shutdown/cleanup.
        if self.client is None:
            return
        self._schedule_internal_reconnect("disconnected", "XMPP stream disconnected")

    async def _on_stream_negotiated(self, event):
        logger.info("XMPP: stream_negotiated event received")

    async def _on_failed_auth(self, event):
        logger.error("XMPP: failed_auth event received; event=%s", event)

    async def disconnect(self) -> None:
        await self._cleanup_client()
        self._mark_disconnected()
        await self._http.aclose()

    async def _cleanup_client(self) -> None:
        """Cancel background tasks and disconnect the current slixmpp client."""
        for task_name in ("_keepalive_task", "_avatar_republish_task", "_internal_reconnect_task"):
            task = getattr(self, task_name, None)
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        # Cancel per-chat typing refresh loops and pending voice-reply debounce
        # timers so they do not outlive the client on a reconnect/shutdown.
        for task in list(self._typing_refresh_tasks.values()):
            if task and not task.done():
                task.cancel()
        self._typing_refresh_tasks.clear()
        for task in list(self._voice_reply_debounce_tasks.values()):
            if task and not task.done():
                task.cancel()
        self._voice_reply_debounce_tasks.clear()
        self._voice_reply_chats.clear()
        # Cancel any slixmpp connection-future watchers.
        for task in list(self._xmpp_background_tasks):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                self._xmpp_background_tasks.discard(task)
        if self.client:
            old_client = self.client
            self.client = None
            try:
                await old_client.disconnect()
            except Exception:
                pass

    # -- Sending ---------------------------------------------------------------

    def _resolve_recipient(self, chat_id: str) -> tuple[JID, str]:
        """Resolve ``chat_id`` to the JID to send to, plus its bare form.

        OMEMO-active chats send to the bare JID so slixmpp-omemo encrypts for
        every published device; otherwise a cached resource is preferred so the
        reply lands on the device that last messaged us (matching how Dino /
        Conversations route replies). Raises ``ValueError`` for an unparseable
        JID.
        """
        recipient = JID(chat_id)
        recipient_bare = str(recipient.bare)
        if recipient_bare in self._omemo_chats:
            recipient = JID(recipient_bare)
            logger.debug("XMPP: using bare JID for OMEMO chat %s", recipient_bare)
        else:
            cached_resource = self._last_resources.get(recipient_bare)
            if cached_resource:
                try:
                    recipient = JID(cached_resource)
                    logger.debug("XMPP: using cached resource %s", cached_resource)
                except Exception as exc:
                    logger.warning("XMPP: could not use cached resource %s: %s", cached_resource, exc)
        return recipient, recipient_bare

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        # reply_to is accepted for base-class compatibility but unused: XMPP has
        # no reply-threading primitive wired into this adapter's delivery path.
        logger.debug("XMPP: send() called chat_id=%s content=%r", chat_id, _truncate_safe(content, 80))
        if self.client is None:
            logger.error("XMPP: cannot send, client not connected")
            return SendResult(success=False, error="not connected")

        try:
            recipient, recipient_bare = self._resolve_recipient(chat_id)
        except Exception as exc:
            logger.error("XMPP: invalid recipient JID %s: %s", chat_id, exc)
            return SendResult(success=False, error="invalid recipient jid")

        text = content
        is_tool_progress = self._is_tool_progress_message(content, metadata)

        # If this chat has a pending voice reply, update the buffered text
        # instead of sending immediately. Tool progress messages are ignored;
        # every other message restarts the debounce timer so the voice reply
        # fires only after the agent turn has settled.
        if recipient_bare in self._voice_reply_chats:
            if is_tool_progress:
                return await self._send_text(recipient, text)
            self._voice_reply_chats[recipient_bare]["text"] = text
            self._schedule_voice_reply(recipient_bare, recipient)
            return await self._send_text(recipient, text)

        return await self._send_text(recipient, text)

    @staticmethod
    def _is_tool_progress_message(
        content: str, metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Return True if this send must not consume the pending voice reply.

        Tool progress messages are ephemeral updates like "💻 Running...",
        "📖 Reading...", or "🐍 Running code..." that should not consume the
        pending voice reply. Two signals, in priority order:

        1. Gateway metadata. Core already marks every non-turn-final send
           (commentary, heartbeats, status, approvals) with
           ``metadata["_interim_send"] = True``; a future core may stamp the
           tool-progress drain with that same flag or a dedicated
           ``is_tool_progress`` key. Honoring the flag first means the gate
           stops depending on message text as soon as core emits it.
        2. Emoji-prefix fallback. Core's tool-progress renderer prefixes every
           line with the tool's emoji, so an emoji-first message is tool
           progress in practice. The tool-progress drain is sent WITHOUT the
           interim flag today, so this covers it until core emits the flag. It
           is more robust than a fixed verb list, which missed most verbs
           (Searching, Browsing, Writing, Editing, Generating, Delegating,
           Scheduling, Asking, Updating, Listing, Clicking, Typing, etc.). Its
           one known weakness (a real reply that starts with an emoji) is the
           reason signal 1 is preferred whenever present.
        """
        if metadata:
            if metadata.get("is_tool_progress") or metadata.get("tool_progress"):
                return True
            if metadata.get("_interim_send"):
                return True
        if not content:
            return False
        first = content[0]
        return not first.isalnum() and not first.isspace()

    def _schedule_voice_reply(self, recipient_bare: str, recipient: JID) -> None:
        """Restart the debounce timer for a pending voice reply (per chat)."""
        existing = self._voice_reply_debounce_tasks.get(recipient_bare)
        if existing is not None and not existing.done():
            existing.cancel()
            self._voice_reply_debounce_tasks.pop(recipient_bare, None)

        async def _debounced_send() -> None:
            try:
                await asyncio.sleep(self._voice_reply_debounce_delay)
            except asyncio.CancelledError:
                return
            self._voice_reply_debounce_tasks.pop(recipient_bare, None)
            pending = self._voice_reply_chats.pop(recipient_bare, None)
            if pending is None or not pending.get("text"):
                return
            try:
                await self._send_voice_reply_text(recipient, pending["text"])
            except Exception as exc:
                logger.warning("XMPP: TTS voice reply failed (%s); text already sent", exc)

        self._voice_reply_debounce_tasks[recipient_bare] = asyncio.create_task(_debounced_send())

    async def _send_voice_reply_text(self, recipient: JID, text: str) -> SendResult:
        """Generate TTS audio for the first chunk of text and send as a voice message.

        The full text response has already been delivered by send(); this only
        adds the audio reply. Falls back to doing nothing if TTS fails.
        """
        from tools.tts_tool import check_tts_requirements, text_to_speech_tool

        if not check_tts_requirements():
            logger.warning("XMPP: TTS requirements not met; skipping voice reply")
            return SendResult(success=False, error="TTS requirements not met")

        # Only TTS the first chunk; XMPP voice messages are short.
        tts_text = self.prepare_tts_text(text[:4000])
        if not tts_text:
            logger.warning("XMPP: no TTS text after cleanup; skipping voice reply")
            return SendResult(success=False, error="empty TTS text")

        import json as _json
        tts_result_str = await asyncio.to_thread(text_to_speech_tool, text=tts_text)
        tts_data = _json.loads(tts_result_str)
        audio_path = tts_data.get("file_path")

        if audio_path and Path(audio_path).exists():
            logger.info("XMPP: sending TTS voice reply to %s", recipient.bare)
            voice_result = await self.send_voice(str(recipient.bare), audio_path)
            try:
                os.remove(audio_path)
            except OSError:
                pass
            return voice_result

        logger.warning("XMPP: TTS audio generation failed or empty; skipping voice reply")
        return SendResult(success=False, error="TTS audio generation failed")

    async def _send_text(self, recipient: JID, text: str) -> SendResult:
        logger.debug("XMPP: _send_text() called for %s: %d chars omemo_chats=%s", recipient.bare, len(text), self._omemo_chats)
        chunks = [text[i : i + _WIRE_CHUNK_SIZE] for i in range(0, len(text), _WIRE_CHUNK_SIZE)]

        recipient_bare = str(recipient.bare)
        force_omemo = self.omemo_enabled and recipient_bare in self._omemo_chats

        last_msg_id: Optional[str] = None
        try:
            for i, chunk in enumerate(chunks):
                msg = self.client.make_message(mto=recipient, mtype="chat")
                msg["body"] = chunk
                msg["id"] = self.client.new_id()
                last_msg_id = msg["id"]
                # NOTE: no chat-state is set on the outgoing chunks here, and no
                # trailing <active/> stanza is sent. If a client shows a stuck
                # "composing" indicator, that is a known gap (see the follow-up
                # comment at the end of this method).

                omemo = self._omemo_plugin()
                if omemo is not None and self.omemo_enabled:
                    try:
                        # Match slixmpp-omemo echo client: set explicit to/from on the stanza
                        msg.set_to(recipient)
                        msg.set_from(self.client.boundjid)
                        encrypted, _errors = await omemo.encrypt_message(
                            msg,
                            recipient_jids={recipient},
                            identifier=str(recipient.bare),
                        )
                        logger.debug("XMPP: encrypt_message returned encrypted=%s errors=%s", encrypted is not None, _errors)
                        if encrypted is not None:
                            # `encrypted` is the original Message stanza with its payload
                            # replaced by the OMEMO <encrypted/> element. Try to tag it
                            # with XEP-0380 EME; if that fails, just send it.
                            try:
                                if hasattr(encrypted, "xml"):
                                    ns_eme = "urn:xmpp:eme:0"
                                    eme_el = ET.Element("{" + ns_eme + "}encryption")
                                    eme_el.set("namespace", "eu.siacs.conversations.axolotl")
                                    eme_el.set("name", "OMEMO")
                                    encrypted.xml.append(eme_el)
                                else:
                                    encrypted["eme"]["namespace"] = "eu.siacs.conversations.axolotl"
                                    encrypted["eme"]["name"] = "OMEMO"
                            except Exception as eme_exc:
                                logger.debug("XMPP: failed to set EME namespace: %s", eme_exc)
                            encrypted.send()
                            logger.debug("XMPP: OMEMO message chunk %d/%d sent to %s", i+1, len(chunks), recipient)
                            if i < len(chunks) - 1:
                                await asyncio.sleep(0.2)
                            continue
                        elif force_omemo:
                            logger.error("XMPP: OMEMO encryption required for %s but failed; not falling back to plaintext", recipient)
                            return SendResult(success=False, error="OMEMO encryption required but failed")
                    except Exception as exc:
                        if force_omemo:
                            logger.error("XMPP: OMEMO encryption required for %s but failed: %s", recipient, exc)
                            return SendResult(success=False, error=f"OMEMO encryption required but failed: {exc}")
                        logger.warning("XMPP: OMEMO send failed (%s); falling back to plaintext", exc)

                if force_omemo:
                    # Should have been handled inside the omemo block above.
                    logger.error("XMPP: OMEMO encryption required for %s but no encrypted stanza produced", recipient)
                    return SendResult(success=False, error="OMEMO encryption required but no encrypted stanza produced")

                logger.debug("XMPP: sending plaintext chunk %d/%d to %s", i+1, len(chunks), recipient)
                msg.send()
                logger.debug("XMPP: plaintext message chunk %d/%d sent to %s", i+1, len(chunks), recipient)
                if i < len(chunks) - 1:
                    await asyncio.sleep(0.2)

            # NOTE: no standalone <active/> chat-state stanza is sent after the
            # chunks here, and the chunks do not set msg["chat_state"]. Sending
            # <active/> after EVERY send would prematurely end the agent's turn
            # for a streaming client like EchoTalk. The end-of-turn <active/> is
            # instead sent once by stop_typing() at the true end of the turn
            # (to the bare JID so every resource sees it).
            if last_msg_id is not None:
                self._last_sent_id[recipient_bare] = last_msg_id
            return SendResult(success=True, message_id=last_msg_id)
        except Exception as exc:
            logger.exception("XMPP: failed to send message to %s: %s", recipient.bare, exc)
            return SendResult(success=False, error=str(exc))

    async def send_voice(
        self,
        chat_id: str,
        audio_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Send an audio file as a voice/audio message over XMPP.

        Used by the Hermes core auto-TTS path. The file at ``audio_path`` is
        uploaded and delivered with an XEP-0066 out-of-band reference when
        applicable.
        """
        try:
            recipient = JID(chat_id)
        except Exception as exc:
            logger.error("XMPP: invalid recipient JID %s: %s", chat_id, exc)
            return SendResult(success=False, error="invalid recipient jid")

        audio_path_obj = Path(audio_path)
        if not audio_path_obj.exists():
            return SendResult(success=False, error=f"audio file not found: {audio_path}")

        audio_bytes = audio_path_obj.read_bytes()
        ext = audio_path_obj.suffix.lower() or ".mp3"
        content_type = _mime_from_extension(ext)
        filename = f"voice_{uuid.uuid4().hex}{ext}"

        url = await self._upload_media_for_chat(recipient, audio_bytes, filename, content_type)
        if not url:
            return SendResult(success=False, error="HTTP file upload failed")

        msg = self.client.make_message(mto=recipient, mtype="chat")
        msg["body"] = caption if caption else url
        msg["id"] = self.client.new_id()

        self._attach_oob_url(msg, url)
        return await self._send_media_stanza(msg, recipient, "voice message")

    async def send_image_file(
        self,
        chat_id: str,
        image_path: str,
        caption: Optional[str] = None,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> SendResult:
        """Send an image file over XMPP using HTTP File Upload.

        Reuses the same encrypted upload and XEP-0066 out-of-band reference as
        send_voice, but sends an image file suitable for inline display.
        """
        try:
            recipient = JID(chat_id)
        except Exception as exc:
            logger.error("XMPP: invalid recipient JID %s: %s", chat_id, exc)
            return SendResult(success=False, error="invalid recipient jid")

        image_path_obj = Path(image_path)
        if not image_path_obj.exists():
            return SendResult(success=False, error=f"image file not found: {image_path}")

        image_bytes = image_path_obj.read_bytes()
        ext = image_path_obj.suffix.lower() or ".png"
        content_type = _mime_from_extension(ext)
        filename = f"image_{uuid.uuid4().hex}{ext}"

        url = await self._upload_media_for_chat(recipient, image_bytes, filename, content_type)
        if not url:
            return SendResult(success=False, error="HTTP file upload failed")

        msg = self.client.make_message(mto=recipient, mtype="chat")
        msg["body"] = caption if caption else url
        msg["id"] = self.client.new_id()

        self._attach_oob_url(msg, url)
        return await self._send_media_stanza(msg, recipient, "image")



    def _attach_oob_url(self, msg, url: str) -> None:
        """Attach an XEP-0066 Out-of-Band Data element to a media stanza.

        Marks the http(s) URL in the body as a media attachment (rather than a
        clickable link) so clients inline it. Replaces the former XEP-0447
        stateless-file-sharing block, which was Experimental and emitted
        spec-noncompliant XML. ``aesgcm://`` URLs are deliberately left alone:
        XEP-0454 specifies no such annotation for them. Best-effort; failures
        fall back to the plain URL body.
        """
        if not url.startswith(("http://", "https://")):
            return
        try:
            ns_oob = "jabber:x:oob"
            x = ET.Element("{" + ns_oob + "}x")
            ET.SubElement(x, "{" + ns_oob + "}url").text = url
            msg.xml.append(x)
        except Exception as exc:
            logger.debug("XMPP: could not attach OOB URL: %s", exc)

    async def _send_media_stanza(self, msg, recipient: JID, kind_label: str) -> SendResult:
        """Send a media stanza, encrypting for OMEMO-active chats and refusing a plaintext downgrade.

        For a chat that is OMEMO-active the ``aesgcm://`` key must not travel in a
        plaintext body, so an encryption failure is a hard error (matching
        ``_send_text``) rather than a silent plaintext fallback. Non-OMEMO chats
        fall back to plaintext, which is the normal XEP-0454 transport for peers
        that do not use OMEMO.
        """
        recipient_bare = str(recipient.bare)
        force_omemo = self.omemo_enabled and recipient_bare in self._omemo_chats

        omemo = self._omemo_plugin()
        if omemo is not None and self.omemo_enabled:
            try:
                encrypted, _errors = await omemo.encrypt_message(
                    msg,
                    recipient_jids={recipient},
                    identifier=recipient_bare,
                )
                if encrypted:
                    encrypted.send()
                    logger.info("XMPP: OMEMO %s sent to %s", kind_label, recipient.bare)
                    self._last_sent_id[recipient_bare] = msg["id"]
                    return SendResult(success=True, message_id=msg["id"])
            except Exception as exc:
                logger.warning("XMPP: OMEMO %s send failed (%s)", kind_label, exc)

        if force_omemo:
            logger.error(
                "XMPP: refusing to send %s to OMEMO chat %s in plaintext",
                kind_label,
                recipient_bare,
            )
            return SendResult(success=False, error="OMEMO encryption required but failed")

        msg.send()
        logger.info("XMPP: %s sent to %s", kind_label, recipient.bare)
        self._last_sent_id[recipient_bare] = msg["id"]
        return SendResult(success=True, message_id=msg["id"])

    async def _upload_media_for_chat(
        self, recipient: JID, data: bytes, filename: str, content_type: str
    ) -> Optional[str]:
        """Upload outbound media, encrypting only for OMEMO-active chats.

        An ``aesgcm://`` URL carries its AES-256-GCM key in the URL fragment, so
        it is only meaningful when the carrying stanza is itself OMEMO-encrypted
        (the encryption protects the key). Shipping that key in a plaintext body
        to a non-OMEMO chat yields no confidentiality (the whole chat is already
        plaintext) while still placing the key alongside its ciphertext, so
        non-OMEMO chats upload plain and send a normal ``http(s)://`` URL.
        """
        recipient_bare = str(recipient.bare)
        if self.omemo_enabled and recipient_bare in self._omemo_chats:
            url = await self._upload_encrypted_media(data, filename, content_type)
            if url:
                return url
            # aesgcm encryption/upload failed; fall back to a plain upload. The
            # plain http(s) URL still travels inside an OMEMO-encrypted stanza,
            # so the media location is protected even though the blob is not
            # independently encrypted at rest.
        return await self._upload_file(data, filename, content_type)

    async def _upload_encrypted_media(self, plaintext: bytes, filename: str, content_type: str) -> Optional[str]:
        """Encrypt plaintext with AES-256-GCM and upload via HTTP File Upload.

        Returns an aesgcm:// URL with the IV+key in the fragment, suitable for
        OMEMO media sharing / Conversations inline playback.
        """
        try:
            upload = self.client.plugin.get("xep_0363", None)
            if upload is None:
                return None

            key = AESGCM.generate_key(bit_length=256)
            iv = os.urandom(12)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(iv, plaintext, None)

            enc_filename = f"{Path(filename).stem}.aesgcm{Path(filename).suffix}"
            get_url = await upload.upload_file(
                filename=enc_filename,
                size=len(ciphertext),
                content_type="application/octet-stream",
                input_file=io.BytesIO(ciphertext),
                domain=JID(self.client.boundjid.bare).domain,
                timeout=60.0,
            )
            if not get_url:
                return None

            # Convert https://upload... to aesgcm://upload... and append IV+key.
            # Handles http:// too so a non-TLS upload host still yields a valid
            # aesgcm:// URL rather than being silently left as a plain http URL.
            fragment = (iv + key).hex()
            if get_url.startswith("https://"):
                aesgcm_url = get_url.replace("https://", "aesgcm://", 1) + "#" + fragment
            elif get_url.startswith("http://"):
                aesgcm_url = get_url.replace("http://", "aesgcm://", 1) + "#" + fragment
            else:
                aesgcm_url = "aesgcm://" + get_url + "#" + fragment
            return aesgcm_url
        except Exception as exc:
            logger.warning("XMPP: encrypted media upload failed: %s", exc)
            return None

    async def _upload_file(self, data: bytes, filename: str, content_type: str) -> Optional[str]:
        try:
            upload = self.client.plugin.get("xep_0363", None)
            if upload is None:
                logger.warning("XMPP: xep_0363 plugin not available")
                return None

            # Use the helper that handles service discovery and upload.
            get_url = await upload.upload_file(
                filename=filename,
                size=len(data),
                content_type=content_type,
                input_file=io.BytesIO(data),
                domain=JID(self.client.boundjid.bare).domain,
                timeout=60.0,
            )
            return get_url
        except Exception as exc:
            logger.warning("XMPP: file upload failed: %s", exc)
            return None

    async def _keep_typing(self, chat_id: str, interval: float = 2.0, metadata=None, stop_event: asyncio.Event | None = None) -> None:
        """
        XMPP-owned typing lifecycle.

        The base adapter's generic refresh loop passes an ``interrupt_event``
        that gets swapped out by ``/new`` and other session-reset commands, so
        the base loop can become orphaned and keep calling ``send_typing()``
        forever.  For XMPP we ignore that loop and drive typing state directly:
        this method resets the anti-resurrection cooldown for a fresh turn and
        sends one ``<composing/>`` stanza, which starts a self-owned 2-second
        refresh task that we cancel deterministically from ``stop_typing()``.
        """
        if not self.typing_indicator or self.client is None:
            return
        try:
            recipient_str = self._last_resources.get(chat_id, chat_id)
            chat_key = str(JID(recipient_str).bare)
        except Exception:
            chat_key = chat_id
        # A fresh turn is starting; clear any stale stop cooldown so the user
        # sees the composing indicator for this new genuine turn.
        self._typing_stop_until.pop(chat_key, None)
        self._typing_state.pop(chat_key, None)
        await self.send_typing(chat_id, metadata=metadata)

    async def send_typing(self, chat_id: str, metadata=None) -> None:
        if not self.typing_indicator or self.client is None:
            logger.debug("XMPP: send_typing skipped (disabled or no client)")
            return
        try:
            # Use the bare JID as the canonical chat key for state tracking.
            # Send chat-state notifications to the bare JID so every resource
            # (phone, desktop, web) sees the composing indicator.
            recipient_str = self._last_resources.get(chat_id, chat_id)
            recipient_full = JID(recipient_str)
            recipient_bare = JID(recipient_full.bare)
            chat_key = str(recipient_bare)
            now = asyncio.get_event_loop().time()
            # If we recently stopped typing for this chat, ignore stray refresh
            # ticks from any orphaned loop.
            if self._typing_stop_until.get(chat_key, 0.0) > now:
                logger.debug("XMPP: send_typing suppressed for %s (cooldown active)", chat_key)
                return
            # Don't resurrect composing if we already deliberately stopped.
            if self._typing_state.get(chat_key) == "active":
                logger.debug("XMPP: send_typing suppressed for %s (state is active)", chat_key)
                return
            msg = self.client.make_message(mto=recipient_bare, mtype="chat")
            msg["chat_state"] = "composing"
            msg.send()
            self._typing_state[chat_key] = "composing"
            logger.debug("XMPP: typing indicator sent to %s", recipient_bare)
            # Start a self-owned refresh loop for XEP-0085 chat states.  This is
            # the only refresh loop we rely on; the base adapter's generic loop
            # is overridden above to a single send + this refresh.
            self._ensure_typing_refresh_task(chat_key, recipient_bare)
        except Exception as exc:
            logger.warning("XMPP: typing indicator send failed: %s", exc)

    def _ensure_typing_refresh_task(self, chat_key: str, recipient: JID) -> None:
        """Start a 2s refresh loop for <composing/> that we can kill locally."""
        task = self._typing_refresh_tasks.get(chat_key)
        if task is not None and not task.done():
            return

        async def _refresh() -> None:
            try:
                while True:
                    await asyncio.sleep(2.0)
                    try:
                        await self.send_typing(str(recipient.bare))
                    except Exception:
                        break
            except asyncio.CancelledError:
                pass

        self._typing_refresh_tasks[chat_key] = asyncio.create_task(_refresh())

    def _cancel_typing_refresh_task(self, chat_key: str) -> None:
        """Cancel the self-owned composing refresh loop, if running."""
        task = self._typing_refresh_tasks.pop(chat_key, None)
        if task is not None and not task.done():
            task.cancel()
        # Once we cancel, reset state so a future genuine turn can type again.
        # We deliberately do NOT clear _typing_stop_until here; that cooldown is
        # managed by stop_typing() and protects against orphaned ticks.
        if self._typing_state.get(chat_key) == "composing":
            self._typing_state.pop(chat_key, None)

    async def _send_active_to_bare(self, recipient_bare: str) -> None:
        """Send a standalone <active/> chat-state stanza to a bare JID.

        Sent to the BARE JID (not a specific resource) so every connected
        resource - including EchoTalk's /EchoTalk and desktop clients like
        Gajim - observes the composing->active transition and clears its
        "thinking" indicator. A redundant <active/> is harmless (chat-state is
        idempotent), so this is safe even when the base adapter also sends one.
        """
        if self.client is None:
            return
        try:
            msg = self.client.make_message(mto=JID(recipient_bare), mtype="chat")
            msg["chat_state"] = "active"
            msg.send()
            logger.debug("XMPP: sent standalone <active/> to %s", recipient_bare)
        except Exception as exc:
            logger.warning("XMPP: failed to send <active/> to %s: %s", recipient_bare, exc)

    async def stop_typing(self, chat_id: str, metadata=None) -> None:
        if not self.typing_indicator or self.client is None:
            logger.debug("XMPP: stop_typing skipped (disabled or no client)")
            return
        try:
            recipient_str = self._last_resources.get(chat_id, chat_id)
            recipient = JID(recipient_str)
            chat_key = str(recipient.bare)
            # Kill our own refresh loop first so it cannot resurrect composing
            # while we are sending the active stanza or right after.
            self._cancel_typing_refresh_task(chat_key)
            # Send the end-of-turn <active/> to the BARE JID (not the last-seen
            # resource) so every connected resource - including EchoTalk's
            # /EchoTalk and desktop clients like Gajim - observes the
            # composing->active transition. The base adapter calls stop_typing()
            # once at the true end of the agent turn, which is the correct
            # timing for a streaming client: composing stays true through the
            # turn and flips to active exactly once at the end.
            await self._send_active_to_bare(str(recipient.bare))
            self._typing_state[chat_key] = "active"
            # Cooldown: suppress composing refreshes for 3s after a deliberate stop.
            # The base adapter's _keep_typing loop refreshes every 2s and may
            # outlive the stop signal on the /new path, so this prevents the
            # composing bubble from popping back up.
            self._typing_stop_until[chat_key] = asyncio.get_event_loop().time() + 3.0
            logger.debug("XMPP: stop typing sent to %s", recipient.bare)
        except Exception as exc:
            logger.warning("XMPP: stop typing send failed: %s", exc)

    async def edit_message(
        self,
        chat_id: str,
        message_id: str,
        content: str,
        *,
        finalize: bool = False,
    ) -> SendResult:
        """Edit a sent message via XEP-0308 Last Message Correction.

        XEP-0308 can only replace the *immediately previous* message, so this is
        correct for the gateway's long-running "still working" heartbeat bubble
        (which is the last thing sent until the next update), but not for
        arbitrary-message edits. ``message_id`` is the stanza id returned by
        ``send()``.
        """
        if self.client is None:
            return SendResult(success=False, error="not connected")

        try:
            recipient, recipient_bare = self._resolve_recipient(chat_id)
        except Exception as exc:
            return SendResult(success=False, error=f"invalid recipient jid: {exc}")

        # XEP-0308 only corrects the immediately previous message. If the target
        # is no longer our last-sent id (e.g. an OMEMO re-key stanza or a media
        # message landed in between), refuse so the gateway falls back to a fresh
        # send rather than emitting a correction every client will silently drop.
        if self._last_sent_id.get(recipient_bare) != message_id:
            logger.debug(
                "XMPP: refusing XEP-0308 correction for %s (target %s is not the "
                "last-sent id %s)",
                recipient_bare,
                message_id,
                self._last_sent_id.get(recipient_bare),
            )
            return SendResult(success=False, error="not the last message")

        force_omemo = self.omemo_enabled and recipient_bare in self._omemo_chats
        try:
            msg = self.client.make_message(mto=recipient, mtype="chat")
            msg["body"] = content
            msg["id"] = self.client.new_id()
            # Attach the correction element targeting the original stanza id.
            # XEP-0308 exposes it as the "replace" plugin on the Message stanza.
            msg["replace"]["id"] = message_id

            omemo = self._omemo_plugin()
            if force_omemo and omemo is not None:
                # encrypt_message() calls .clear() on the copy, wiping the
                # <replace/> element; re-attach it after encryption (the same
                # pattern as the EME tag in _send_text).
                encrypted, _errors = await omemo.encrypt_message(
                    msg,
                    recipient_jids={recipient},
                    identifier=str(recipient.bare),
                )
                if encrypted is None:
                    return SendResult(success=False, error="OMEMO encryption required but no encrypted stanza produced")
                if hasattr(encrypted, "xml"):
                    replace_el = ET.Element("{urn:xmpp:message-correct:0}replace")
                    replace_el.set("id", message_id)
                    encrypted.xml.append(replace_el)
                else:
                    encrypted["replace"]["id"] = message_id
                encrypted.send()
            else:
                msg.send()

            # The correction itself is now the last message on the wire.
            self._last_sent_id[recipient_bare] = msg["id"]
            return SendResult(success=True, message_id=message_id)
        except Exception as exc:
            logger.warning("XMPP: edit_message failed for %s: %s", recipient_bare, exc)
            return SendResult(success=False, error=str(exc))

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": chat_id, "type": "dm"}

    async def _download_url(self, url: str) -> Optional[bytes]:
        try:
            if url.startswith("aesgcm://"):
                return await self._download_aesgcm(url)
            if await asyncio.to_thread(_media_download_blocked, url):
                logger.warning(
                    "XMPP: refusing media download from internal address: %s",
                    _log_safe_url(url),
                )
                return None
            resp = await self._http.get(url)
            resp.raise_for_status()
            return resp.content
        except Exception as exc:
            logger.warning(
                "XMPP: failed to download %s: %s",
                _log_safe_url(url),
                _redact_aesgcm_in_text(str(exc)),
            )
            return None

    async def _download_aesgcm(self, url: str) -> Optional[bytes]:
        try:
            parsed = urlparse(url)
            fragment = parsed.fragment
            if not fragment or len(fragment) != 88:
                logger.warning("XMPP: invalid aesgcm fragment length")
                return None
            iv = bytes.fromhex(fragment[:24])
            key = bytes.fromhex(fragment[24:])
            https_url = f"https://{parsed.netloc}{parsed.path}"
            if await asyncio.to_thread(_media_download_blocked, https_url):
                logger.warning(
                    "XMPP: refusing aesgcm media download from internal address: %s",
                    _log_safe_url(url),
                )
                return None
            resp = await self._http.get(https_url)
            resp.raise_for_status()
            ciphertext = resp.content
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
            return plaintext
        except Exception as exc:
            # httpx and cryptography exceptions can embed the full aesgcm://
            # URL (key included) in their message; redact before logging.
            logger.warning(
                "XMPP: failed to decrypt aesgcm %s: %s",
                _log_safe_url(url),
                _redact_aesgcm_in_text(str(exc)),
            )
            return None

    def _extract_url(self, text: str) -> Optional[str]:
        # Match a URL, then strip trailing punctuation (.,;:!?) and closing
        # brackets/quotes that are not part of the URL. The period is kept in
        # the match because it is a legitimate URL character (domain names and
        # file extensions); only a trailing period is removed afterward.
        # The aesgcm alternative deliberately allows apostrophes: they are
        # legal URL-path characters (e.g. alice's-photo.png) and stopping
        # there would strand the keyed fragment in the body, which the
        # URL->media-path replacement in _on_message would then re-expose.
        # A URL wrapped in single quotes therefore swallows its closing
        # quote into the match; the enclosing-quote strip below removes it
        # so the key fragment keeps its required 88-character length.
        match = re.search(
            r"https?://[^\s<>\"')\]}]+|aesgcm://[^\s<>\")\]}]+",
            text,
        )
        if not match:
            return None
        url = match.group(0)
        # Strip the closing single quote of a URL enclosed in quotes (e.g.
        # 'aesgcm://host/f#KEY' -> aesgcm://host/f#KEY) while keeping
        # internal apostrophes (e.g. alice's-photo.png) untouched: the
        # extra character would corrupt the key fragment (89 chars instead
        # of 88) and make _download_aesgcm reject a decryptable URL. The
        # regex always starts at the scheme, so only the trailing quote can
        # end up inside the match; the URL is treated as enclosed when the
        # character right before the match is a quote too. Trailing
        # punctuation is stripped BEFORE the quote check because a quoted
        # URL followed by sentence punctuation (e.g. 'aesgcm://host/f#KEY'.)
        # hides the quote behind it; punctuation is re-stripped afterward in
        # case more of it followed the quote inside the match.
        url = url.rstrip(".,;:!?")
        if (
            len(url) >= 2
            and url.endswith("'")
            and match.start() > 0
            and text[match.start() - 1] == "'"
        ):
            url = url[:-1]
        return url.rstrip(".,;:!?")

    # -- Avatar --------------------------------------------------------------

    @staticmethod
    def _avatar_sha1(data: bytes) -> str:
        """sha1 of the avatar bytes, matching slixmpp's XEP-0084 ``generate_id``."""
        return hashlib.sha1(data).hexdigest()

    async def _server_has_avatar(self, data: bytes) -> bool:
        """True when the server already stores this exact avatar for the bot.

        Queries the server's current vCard (XEP-0054) and compares its PHOTO
        BINVAL sha1 to the local bytes. This is the same call slixmpp's
        ``set_avatar`` makes internally, so it is authoritative: when it matches,
        the avatar is already published and there is nothing to re-send (and no
        ``send_last_presence`` that would surface as a duplicate "online" blip).

        Best-effort: any failure returns False so the caller publishes rather
        than incorrectly skipping.
        """
        client = self.client
        if client is None:
            return False
        try:
            vcard = await asyncio.wait_for(
                client.plugin["xep_0054"].get_vcard(
                    client.boundjid.bare, cached=False
                ),
                timeout=15.0,
            )
            stored = vcard["vcard_temp"]["PHOTO"]["BINVAL"]
            if not stored:
                return False
            return hashlib.sha1(bytes(stored)).hexdigest() == self._avatar_sha1(data)
        except Exception as exc:
            logger.debug("XMPP: could not read server vCard to compare avatar: %s", exc)
            return False

    async def _publish_avatar(self) -> None:
        if not self.avatar_path or self.client is None:
            return
        try:
            path = Path(self.avatar_path)
            if not path.exists():
                logger.warning("XMPP: avatar path does not exist: %s", self.avatar_path)
                return

            # Image processing is blocking CPU work; run it off the event loop so
            # a large source image cannot stall the gateway loop during startup.
            data, width, height = await asyncio.to_thread(self._prepare_avatar_bytes, path)

            # Ask the server whether it already has this exact avatar. When it
            # does there is nothing to publish: republishing on every start is
            # what produced the duplicate "bot is online" toast (set_avatar's
            # send_last_presence re-broadcast presence ~1s after the initial one).
            if await self._server_has_avatar(data):
                logger.info("XMPP: avatar already on server; skipping publish")
                return

            # Always publish vCard avatar (XEP-0153); most clients use this.
            vcard_avatar = self.client.plugin.get("xep_0153", None)
            if vcard_avatar is not None:
                try:
                    await asyncio.wait_for(
                        vcard_avatar.set_avatar(avatar=data, mtype="image/png"),
                        timeout=15.0,
                    )
                    logger.info("XMPP: published vCard avatar (%d bytes, %dx%d)", len(data), width, height)
                except Exception as exc:
                    logger.warning("XMPP: vCard avatar publish failed: %s", exc)
            else:
                logger.warning("XMPP: xep_0153 plugin not available")

            # Try PEP/XEP-0084 second (best effort, can hang on some servers).
            pep_avatar = self.client.plugin.get("xep_0084", None)
            if pep_avatar is not None:
                try:
                    avatar_id = pep_avatar.generate_id(data)
                    await asyncio.wait_for(pep_avatar.publish_avatar(data), timeout=5.0)
                    await asyncio.wait_for(pep_avatar.publish_avatar_metadata({
                        "id": avatar_id,
                        "type": "image/png",
                        "bytes": len(data),
                        "width": width,
                        "height": height,
                    }), timeout=5.0)
                    logger.info("XMPP: published PEP avatar id=%s (%d bytes, %dx%d)", avatar_id[:16], len(data), width, height)
                except Exception as exc:
                    logger.warning("XMPP: PEP avatar publish failed: %s", exc)
            else:
                logger.debug("XMPP: xep_0084 plugin not available")
        except Exception as exc:
            logger.warning("XMPP: failed to publish avatar: %s", exc, exc_info=True)

    def _prepare_avatar_bytes(self, path: Path):
        """Open, crop, resize, and PNG-encode the avatar (blocking; run off-loop).

        Returns (png_bytes, width, height). Runs inside asyncio.to_thread so the
        synchronous PIL work never blocks the gateway event loop.
        """
        img = Image.open(path)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        # Avatars should be square. Crop to center square and resize.
        width, height = img.size
        side = min(width, height)
        left = (width - side) // 2
        top = (height - side) // 2
        img = img.crop((left, top, left + side, top + side))
        try:
            img = img.resize((480, 480), Image.Resampling.LANCZOS)
        except AttributeError:
            # Pillow < 9.1 uses the Image.LANCZOS constant.
            img = img.resize((480, 480), Image.LANCZOS)

        png_buffer = io.BytesIO()
        img.save(png_buffer, format="PNG", optimize=True)
        return png_buffer.getvalue(), img.width, img.height

    # -- Receiving -----------------------------------------------------------

    async def _session_start(self, event):
        logger.info("XMPP: session_start handler fired for %s", self.user_jid)
        try:
            if self.client:
                self.client.send_presence()
                self._roster_request = self.client.get_roster()
        except Exception:
            pass
        self._session_started_event.set()
        # Proactively request presence subscriptions from allowlisted users so
        # fresh installs show online (green) in the contact's client without a
        # manual re-add. Users who already have an established subscription are
        # skipped so every connect does not re-issue a redundant `subscribe`.
        asyncio.create_task(self._send_subscription_requests())

    def _allowed_users_set(self) -> set[str]:
        """Bare-JID allowlist set from env/config (empty when none configured)."""
        raw = _get_scoped_secret("XMPP_ALLOWED_USERS")
        if not raw:
            extra = getattr(getattr(self, "config", None), "extra", None) or {}
            value = extra.get("allowed_users", "")
            raw = value if isinstance(value, str) else ""
        entries = raw.split(",") if isinstance(raw, str) else list(raw or [])
        return {e.strip().lower() for e in entries if e and e.strip()}

    def _allow_all_users(self) -> bool:
        return (_get_scoped_secret("XMPP_ALLOW_ALL_USERS", "") or "").strip().lower() in {
            "true", "1", "yes",
        }

    def _has_established_subscription(self, bare: str) -> bool:
        """True when the roster already records a subscription to ``bare``.

        A subscription is "established" when the roster says we are subscribed
        to the contact (``to``) or mutually subscribed (``both``). In both cases
        re-sending a ``subscribe`` presence on every connect is redundant; only
        a contact with no subscription (or a one-way ``from``) warrants a
        request. Reads the in-memory roster slixmpp built from the server's
        roster push.
        """
        try:
            if self.client is None or self.client.client_roster is None:
                return False
            item = self.client.client_roster[bare]
            return item["subscription"] in ("to", "both")
        except Exception:
            return False

    async def _send_subscription_requests(self) -> None:
        """Proactively ask allowlisted JIDs for a subscription when one is missing.

        Skipped entirely when no allowlist is configured (allow-all or deny-all):
        there is no one to invite. Users who already have an established
        subscription are skipped so the bot does not re-issue a redundant
        ``subscribe`` presence on every connect. Errors are logged, never fatal.
        """
        try:
            allowed = self._allowed_users_set()
            if not allowed:
                return
            client = self.client
            if client is None:
                return
            await asyncio.wait_for(
                self._session_started_event.wait(), timeout=5.0
            )
            # Wait for the roster to load so we can tell which subscriptions are
            # already established; fall back to 3s so a slow server cannot make
            # this a hard stall.
            if self._roster_request is not None:
                try:
                    await asyncio.wait_for(self._roster_request, timeout=3.0)
                except Exception:
                    pass
            for bare in sorted(allowed):
                if bare == JID(self.user_jid).bare.lower():
                    continue  # never subscribe to ourselves
                if self._has_established_subscription(bare):
                    logger.debug(
                        "XMPP: subscription to %s already established; skipping", bare
                    )
                    continue
                try:
                    client.send_presence(pto=bare, ptype="subscribe")
                    logger.info(
                        "XMPP: sent presence subscription request to %s", bare
                    )
                except Exception as exc:
                    logger.warning(
                        "XMPP: subscription request to %s failed: %s", bare, exc
                    )
        except Exception:
            logger.exception("XMPP: subscription-request pass failed")

    def _sender_authorized(self, bare_jid: str) -> bool:
        """True when a bare JID may interact (allowlist or allow-all)."""
        if self._allow_all_users():
            return True
        return bare_jid in self._allowed_users_set()

    async def _on_presence_subscribe(self, presence):
        """Option 1: auto-approve subscription requests from allowed senders.

        Allowed senders get an immediate `subscribed` plus our own `subscribe`
        so the roster ends up mutual ("both") and the bot shows green.
        Requests from anyone else are silently ignored (same policy as denied
        messages). Runs on the event loop; handler bodies must not block.
        """
        try:
            from_jid = presence["from"]
            bare = str(from_jid.bare).lower()
            if not self._sender_authorized(bare):
                logger.info(
                    "XMPP: ignoring presence subscription request from non-allowlisted %s",
                    bare,
                )
                return
            client = self.client
            if client is None:
                return
            client.send_presence(pto=str(from_jid.bare), ptype="subscribed")
            client.send_presence(pto=str(from_jid.bare), ptype="subscribe")
            logger.info("XMPP: approved presence subscription for %s", bare)
        except Exception:
            logger.exception("XMPP: presence_subscribe handling failed")

    async def _omemo_initialized(self, event=None):
        logger.info("XMPP: OMEMO initialized and device list published")
        self._omemo_ready_event.set()

    async def _on_message(self, msg: Message):
        try:
            if msg["type"] not in ("chat", "normal"):
                return

            logger.debug("XMPP: _on_message fired type=%s from=%s", msg.get("type", ""), msg["from"])
            sender_jid = msg["from"]
            if not sender_jid:
                logger.debug("XMPP: _on_message returning - no sender_jid")
                return
            sender_full = JID(sender_jid)
            sender_bare = str(sender_full.bare)
            self._last_resources[sender_bare] = str(sender_full)
            if sender_bare == JID(self.user_jid).bare:
                logger.debug("XMPP: _on_message returning - self-message from %s", sender_bare)
                return

            body = msg.get("body", "").strip()
            logger.debug(
                "XMPP: _on_message body=%r has_encrypted check next",
                _redact_aesgcm_in_text(body),
            )
            encrypted = False

            # Only attempt OMEMO decryption if the stanza actually contains an
            # OMEMO <encrypted> payload. If OMEMO is enabled but the message is
            # plaintext, slixmpp-omemo raises "No supported encrypted content";
            # in that case we keep the plaintext body.
            omemo = self._omemo_plugin()
            has_encrypted = (
                msg.xml.find(".//{eu.siacs.conversations.axolotl}encrypted") is not None
                or msg.xml.find(".//{urn:xmpp:omemo:2}encrypted") is not None
            )
            logger.debug("XMPP: _on_message has_encrypted=%s omemo=%s omemo_enabled=%s", has_encrypted, omemo is not None, self.omemo_enabled)
            if omemo is not None and self.omemo_enabled and has_encrypted:
                try:
                    decrypted, _device_info = await omemo.decrypt_message(msg)
                    body_text = str(decrypted.get("body", "") or "").strip()
                    if body_text and body_text != body:
                        body = body_text
                        encrypted = True
                        logger.debug("XMPP: OMEMO decrypted message from %s: %s chars", sender_bare, len(body))
                except Exception as exc:
                    logger.warning("XMPP: OMEMO decrypt attempt failed: %s", exc, exc_info=True)
                    # Self-heal a desynced/stale session: drop the sending
                    # device's session keys so the next outbound message
                    # re-establishes the ratchet via a fresh key exchange.
                    # Without this, every subsequent message from that device
                    # keeps failing and we silently fall back to plaintext.
                    sender_device_id: Optional[int] = None
                    try:
                        sid_el = msg.xml.find(
                            ".//{eu.siacs.conversations.axolotl}header"
                        )
                        if sid_el is None:
                            sid_el = msg.xml.find(".//{urn:xmpp:omemo:2}header")
                        if sid_el is not None and sid_el.get("sid"):
                            sender_device_id = int(sid_el.get("sid"))
                            if hasattr(omemo, "recover_stale_session"):
                                await omemo.recover_stale_session(
                                    sender_bare, sender_device_id
                                )
                    except Exception as recover_exc:
                        logger.warning(
                            "XMPP: OMEMO session recovery failed: %s", recover_exc
                        )
                    # The undecryptable body is ciphertext, not text; it must
                    # never reach the agent (it once produced a confabulated
                    # "my client has no OMEMO support" reply). Suppress the
                    # stanza entirely, re-establish the session with a silent
                    # key exchange, and ask the sender to resend.
                    await omemo.build_recovery_message(sender_bare, "")
                    notice = (
                        "[Hermes] Your last message used an outdated encryption "
                        "session, so it could not be decrypted. The session has "
                        "been re-established, please resend that message."
                    )
                    notice_msg = self.client.make_message(
                        mto=JID(sender_bare), mtype="chat"
                    )
                    notice_msg["body"] = notice
                    notice_msg["id"] = self.client.new_id()
                    notice_msg.set_to(JID(sender_bare))
                    notice_msg.set_from(self.client.boundjid)
                    try:
                        encrypted_notice, _errs = await omemo.encrypt_message(
                            notice_msg,
                            recipient_jids={JID(sender_bare)},
                            identifier=sender_bare,
                        )
                        if encrypted_notice is not None:
                            encrypted_notice.send()
                            logger.warning(
                                "XMPP: sent OMEMO recovery notice to %s", sender_bare
                            )
                        else:
                            notice_msg.send()
                            logger.warning(
                                "XMPP: sent plaintext OMEMO recovery notice to %s",
                                sender_bare,
                            )
                    except Exception as notice_exc:
                        logger.warning(
                            "XMPP: failed to send OMEMO recovery notice: %s",
                            notice_exc,
                        )
                        try:
                            notice_msg.send()
                        except Exception:
                            pass
                    # Do not process the undecryptable stanza further.
                    return

            # Remember that this chat is OMEMO-active so all replies are encrypted.
            if encrypted and sender_bare not in self._omemo_chats:
                self._omemo_chats.add(sender_bare)
                logger.debug("XMPP: chat %s added to OMEMO-active set", sender_bare)
            elif not encrypted and sender_bare in self._omemo_chats:
                # If the contact downgrades to plaintext, stop forcing OMEMO.
                self._omemo_chats.discard(sender_bare)
                logger.debug("XMPP: chat %s removed from OMEMO-active set (plaintext received)", sender_bare)

            # NOTE: do NOT return early on an empty body here. Voice and image
            # messages are often sent as standalone media with an empty text
            # body; the URL lives in <oob>, which is extracted below. We only
            # drop the message later if there is no body AND no media URL.

            # Send read receipt for messages that request it.
            try:
                markable = msg.xml.find(".//{urn:xmpp:chat-markers:0}markable") is not None
                logger.debug("XMPP: _on_message markable=%s", markable)
                if markable:
                    await self._send_displayed_marker(sender_bare, msg.get("id", self.client.new_id()))
            except Exception as marker_exc:
                logger.warning("XMPP: failed to send displayed marker: %s", marker_exc)

            url: Optional[str] = None
            try:
                oob = msg.xml.find(".//{jabber:x:oob}x")
                if oob is not None:
                    url_el = oob.find("{jabber:x:oob}url")
                    if url_el is not None and url_el.text:
                        url = url_el.text.strip()
            except Exception:
                pass
            if not url:
                url = self._extract_url(body)

            # Drop only when there is no text AND no media URL. A standalone
            # media message (voice/image) has an empty body but a URL, so it
            # must not be dropped here.
            if not body and not url:
                logger.debug("XMPP: _on_message returning - empty body and no media URL")
                return

            media_path: Optional[str] = None
            msg_type = MessageType.TEXT
            original_msg_type = MessageType.TEXT
            if url:
                logger.debug("XMPP: detected URL in message: %s", _log_safe_url(url))
                if url.startswith("aesgcm://") or _is_media_url(url):
                    if url.startswith("aesgcm://"):
                        data = await self._download_aesgcm(url)
                    else:
                        data = await self._download_url(url)
                    logger.debug("XMPP: downloaded %d bytes from %s", len(data) if data else 0, _log_safe_url(url))
                    if data:
                        content_type = _guess_content_type(data)
                        if content_type.startswith("image/"):
                            msg_type = MessageType.PHOTO
                            ext = _guess_extension_from_data(data)
                            media_path = self._cache_media(data, "image", ext=ext)
                        elif content_type.startswith("audio/"):
                            if _guess_audio_is_voice(url, body, data):
                                msg_type = MessageType.VOICE
                            else:
                                msg_type = MessageType.AUDIO
                            ext = _guess_audio_extension(url, data)
                            media_path = self._cache_media(data, "audio", ext=ext)
                        elif _is_audio_url(url):
                            # URL claims to be audio but content could not be sniffed;
                            # trust the URL extension and treat as plain audio.
                            msg_type = MessageType.AUDIO
                            ext = _guess_audio_extension(url, data)
                            media_path = self._cache_media(data, "audio", ext=ext)
                        else:
                            # Fallback for any other downloaded binary blob.
                            msg_type = MessageType.PHOTO
                            media_path = self._cache_media(data, "image")
                    else:
                        logger.warning("XMPP: failed to download media from %s", _log_safe_url(url))
                        msg_type = MessageType.TEXT
                else:
                    # Plain hyperlink, not media; leave as text.
                    # Fail-closed: even a "plain" hyperlink is passed through the
                    # safe helper so no raw URL can ever reach the logs.
                    logger.debug("XMPP: treating URL as text link: %s", _log_safe_url(url))
                    msg_type = MessageType.TEXT

                # Remember that this was a voice message before we convert it to TEXT
                # after transcription, so the adapter can still queue a TTS reply.
                original_msg_type = msg_type
                logger.debug("XMPP: cached media path=%s", media_path)

            # If media was cached, replace the URL in the body with the local
            # path so downstream tools analyse the actual file, not the link.
            display_text = body
            media_urls: list[str] = []
            media_types: list[str] = []
            if media_path and url:
                if msg_type == MessageType.VOICE:
                    # Voice messages should reach the LLM as plain text, not as a
                    # file attachment. Transcribe locally via Hermes core STT and
                    # replace the message content with the transcript.
                    stripped = body.replace(url, "").strip()
                    try:
                        result = transcribe_audio(media_path)
                        if result.get("success"):
                            display_text = result.get("transcript", "(voice message)").strip() or "(voice message)"
                            logger.info(
                                "XMPP: transcribed voice message: %r",
                                display_text,
                            )
                            # Convert to TEXT after successful transcription so the
                            # gateway core doesn't also generate an auto-TTS reply.
                            # The adapter-level _voice_reply_chats queue handles the
                            # single outbound voice reply at turn end.
                            msg_type = MessageType.TEXT
                        else:
                            error = result.get("error", "unknown error")
                            logger.warning("XMPP: voice transcription failed: %s", error)
                            display_text = stripped or "(voice message could not be transcribed)"
                            msg_type = MessageType.TEXT
                    except Exception as exc:
                        logger.warning("XMPP: voice transcription error: %s", exc)
                        display_text = stripped or "(voice message could not be transcribed)"
                        msg_type = MessageType.TEXT
                else:
                    display_text = body.replace(url, media_path)
                    if display_text == body:
                        # URL not in body (e.g. only in oob); use a direct note.
                        display_text = f"{body}\n[Attached media: {media_path}]".strip()
                    media_urls = [media_path]
                    media_types = [content_type]

            source = self.build_source(
                chat_id=sender_bare,
                chat_name=sender_bare,
                chat_type="dm",
                user_id=sender_bare,
                user_name=sender_bare,
                thread_id=None,
            )

            # Invariant: the agent only ever sees the redacted form.
            # The local download used the original URL (kept in `url` variable).
            event = MessageEvent(
                text=_redact_aesgcm_in_text(display_text),
                message_type=msg_type,
                source=source,
                # Contrat vérifié : le core accepte None (gateway/platforms/event.py:55,
                # raw_message: Any = None). Le stanza brut peut contenir des clés
                # aesgcm:// ; ne pas le transmettre.
                raw_message=None,
                media_urls=media_urls,
                media_types=media_types,
                metadata={
                    "encrypted": encrypted,
                    # The raw media URL can carry the aesgcm:// decryption key in
                    # its fragment; keep the key out of the agent context and the
                    # session store by recording a redacted form here.
                    "media_url": _log_safe_url(url) if url else url,
                    "media_path": media_path,
                },
            )

            logger.debug(
                "XMPP: about to handle_message event text=%r type=%s",
                _redact_aesgcm_in_text(display_text),
                msg_type,
            )

            # If the inbound message was a voice message, opt this DM chat into
            # the adapter-level voice reply queue so we reply with TTS audio plus
            # the full text response. This is independent of the global
            # voice.auto_tts setting, which controls auto-TTS for *all* replies.
            if original_msg_type == MessageType.VOICE:
                self._voice_reply_chats[sender_bare] = {"text": ""}
                logger.info(
                    "XMPP: queued voice reply for chat %s (voice input)",
                    sender_bare,
                )

            await self.handle_message(event)
            logger.debug("XMPP: handle_message completed")
        except Exception:
            logger.exception("XMPP: unhandled error in message handler")

    async def _send_displayed_marker(self, to_jid: str, message_id: str) -> None:
        try:
            marker_plugin = self.client.plugin.get("xep_0333", None)
            if marker_plugin is None:
                logger.debug("XMPP: xep_0333 plugin not available")
                return

            # Determine actual recipient. Prefer the last known full resource for
            # this bare JID; otherwise use the bare JID.
            recipient_str = self._last_resources.get(to_jid, to_jid)
            recipient = JID(recipient_str)

            # XEP-0333 markers are standalone chat markers and should not be
            # encrypted as message bodies. Send them in plaintext so the recipient
            # client displays the proper read receipt (second checkmark) instead of
            # treating the marker as a regular message.
            marker_plugin.send_marker(mto=recipient, id=message_id, marker="displayed", mtype="chat")
            logger.debug("XMPP: sent displayed marker to %s for %s", recipient, message_id)
        except Exception as exc:
            logger.debug("XMPP: failed to send displayed marker: %s", exc)

    def _cache_media(self, data: bytes, kind: str = "image", ext: Optional[str] = None) -> Optional[str]:
        try:
            if ext is None:
                ext = ".ogg" if kind == "audio" else ".png"
            elif not ext:
                ext = ".ogg" if kind == "audio" else ".png"
            # Derive the MIME type from the actual extension so the cached file
            # is tagged correctly (e.g. .ogg -> audio/ogg, not audio/mpeg).
            mime = _mime_from_extension(ext)
            validate_inbound_media_size(len(data), media_type=kind)
            # Use a unique filename to prevent cache collisions
            filename = f"xmpp_{uuid.uuid4().hex}{ext}"
            cached = cache_media_bytes(data, filename=filename, mime_type=mime, default_kind=kind)
            return str(cached.path) if cached and getattr(cached, "path", None) else None
        except Exception as exc:
            logger.warning("XMPP: failed to cache media: %s", exc)
            return None

    # -- Helpers -------------------------------------------------------------

    async def _slixmpp_exception_handler(self, exc):
        logger.exception("XMPP: slixmpp internal exception: %s", exc)


def check_requirements() -> bool:
    """Return True when the adapter's top-level imports are all importable.

    adapter.py imports slixmpp, httpx, PIL, and cryptography unconditionally at
    module load, so probing only slixmpp reports "ready" even when one of the
    others is missing and the adapter would crash on import. slixmpp-omemo is
    deliberately not required here: it is optional and only imported when OMEMO
    is enabled.
    """
    for module in ("slixmpp", "httpx", "PIL", "cryptography"):
        try:
            __import__(module)
        except ImportError:
            return False
    return True


def validate_config(config) -> bool:
    extra = getattr(config, "extra", {}) or {}
    return bool(
        (_get_scoped_secret("XMPP_USER_JID") or extra.get("user_jid"))
        and (_get_scoped_secret("XMPP_PASSWORD") or extra.get("password"))
    )


def is_configured(config) -> bool:
    """Return True when the platform is configured (credentials present).

    The gateway's platform registry names this enablement hook ``is_connected``,
    but it is a configuration gate (has the user set credentials?), not a live
    connection-state probe. The running adapter's real connection state is the
    base class's ``self.is_connected``.
    """
    return validate_config(config)


def interactive_setup() -> None:
    """Collect the bot JID and password without echoing the password.

    Invoked by ``hermes setup`` as the platform's ``setup_fn``. Credentials are
    reported back to the user to persist (the installer writes them via
    ``post_install.py``, which uses ``getpass``); this prompt must never echo
    the password to the terminal.
    """
    import builtins
    import getpass

    jid = builtins.input("XMPP JID (e.g. hermes@example.com): ").strip()
    password = getpass.getpass("XMPP password: ").strip()
    if jid and password:
        print(f"Set XMPP_USER_JID={jid} and XMPP_PASSWORD=*** in ~/.hermes/.env")


def _env_enablement() -> Optional[dict]:
    user_jid = (_get_scoped_secret("XMPP_USER_JID", "") or "").strip()
    password = (_get_scoped_secret("XMPP_PASSWORD", "") or "").strip()
    server = (_get_scoped_secret("XMPP_SERVER", "") or "").strip()
    if not user_jid or not password:
        return None
    extra: dict = {"user_jid": user_jid, "password": password}
    if server:
        extra["server"] = server
    return extra


async def _standalone_send(
    pconfig,
    chat_id: str,
    message: str,
    *,
    thread_id=None,
    media_files=None,
    force_document=False,
) -> dict:
    extra = getattr(pconfig, "extra", {}) or {}
    user_jid = _get_scoped_secret("XMPP_USER_JID") or extra.get("user_jid", "")
    password = _get_scoped_secret("XMPP_PASSWORD") or extra.get("password", "")
    server = _get_scoped_secret("XMPP_SERVER") or extra.get("server", "")
    if not user_jid or not password:
        return {"error": "XMPP_USER_JID and XMPP_PASSWORD must be configured"}

    client = None
    try:
        raw_port = (_get_scoped_secret("XMPP_PORT", "") or "").strip()
        try:
            port = int(raw_port) if raw_port else 5222
        except ValueError:
            port = 5222
        client = ClientXMPP(user_jid, password)
        client.use_message_ids = True
        session_started = asyncio.Event()
        client.add_event_handler("session_start", lambda _: session_started.set())
        client.connect(host=server or None, port=port)
        await asyncio.wait_for(session_started.wait(), timeout=30.0)
        msg = client.make_message(mto=JID(chat_id), mtype="chat")
        msg["id"] = client.new_id()
        msg["body"] = message
        msg.send()
        await client.disconnect(wait=True)
        return {"success": True}
    except Exception as e:
        return {"error": f"XMPP standalone send failed: {e}"}
    finally:
        if client:
            try:
                await client.disconnect(wait=True)
            except Exception:
                pass


_XMPP_YAML_KEYS = (
    "user_jid",
    "password",
    "server",
    "port",
    "omemo_enabled",
    "omemo_allow_untrusted",
    "home_channel",
    "allowed_users",
    "allow_all_users",
)


def _apply_yaml_config(yaml_cfg: dict, platform_cfg: dict) -> Optional[dict]:
    seeded = {k: platform_cfg[k] for k in _XMPP_YAML_KEYS if k in platform_cfg}
    # Bridge the allowlist / allow-all config keys to the env vars the gateway
    # authorization layer reads (XMPP_ALLOWED_USERS / XMPP_ALLOW_ALL_USERS), so
    # config.yaml is the source of truth for access control. Env vars win when
    # already set (env > YAML precedence). The shared setter skips the env write
    # under a secondary multiplex profile's scope so one profile's allowlist
    # never pins another's process-wide (first-writer-wins poisoning, #80099);
    # the values are still seeded into ``extra`` above so each profile reads its
    # own through the scoped getter.
    set_env = yaml_env_setter()
    if "allow_all_users" in platform_cfg:
        set_env("XMPP_ALLOW_ALL_USERS", str(platform_cfg["allow_all_users"]).lower())
    if "allowed_users" in platform_cfg:
        set_env("XMPP_ALLOWED_USERS", str(platform_cfg["allowed_users"]))
    return seeded if seeded else None


def register(ctx):
    ctx.register_platform(
        name="xmpp",
        label="XMPP",
        adapter_factory=lambda cfg: XMPPAdapter(cfg),
        check_fn=check_requirements,
        validate_config=validate_config,
        is_connected=is_configured,
        required_env=["XMPP_USER_JID", "XMPP_PASSWORD"],
        install_hint="Talk to Hermes over XMPP",
        setup_fn=interactive_setup,
        env_enablement_fn=_env_enablement,
        apply_yaml_config_fn=_apply_yaml_config,
        cron_deliver_env_var="XMPP_HOME_CHANNEL",
        standalone_sender_fn=_standalone_send,
        allowed_users_env="XMPP_ALLOWED_USERS",
        allow_all_env="XMPP_ALLOW_ALL_USERS",
        max_message_length=4096,
        emoji="💬",
        pii_safe=False,
        allow_update_command=True,
        platform_hint=(
            "You are chatting via XMPP. Use plain text responses. "
            "XMPP does not render markdown reliably."
        ),
    )
