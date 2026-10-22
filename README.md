# Hermes XMPP Platform Plugin

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

XMPP gateway adapter for [Hermes Agent](https://github.com/NousResearch/hermes-agent). Connects the agent to an XMPP server, routes messages, supports inbound/outbound media, OMEMO end-to-end encryption by default, and voice/audio messages via the Hermes core TTS/STT configuration.

This repository IS a Hermes plugin: the plugin manifest (`plugin.yaml`), the adapter, and its dependencies live at the repository root, so Hermes installs and updates it with its own plugin commands. No checkout to maintain and nothing to run by hand.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Upgrading](#upgrading)
- [Configuration](#configuration)
- [OMEMO End-to-End Encryption](#omemo-end-to-end-encryption)
- [Voice and Audio](#voice-and-audio)
- [Avatar](#avatar)
- [Read Receipts (Chat Markers)](#read-receipts-chat-markers)
- [Inbound Images and Files](#inbound-images-and-files)
- [Typing Indicator](#typing-indicator)
- [Streaming Behavior](#streaming-behavior)
- [Uninstallation](#uninstallation)
- [Development](#development)
- [License](#license)

## Features

- OMEMO-encrypted messaging (default; plain-text fallback)
- XEP-0085 typing indicators
- XEP-0333 read receipts / chat markers
- XEP-0066 / XEP-0363 inbound images, files, and voice messages
- `aesgcm://` OMEMO media sharing decryption
- XEP-0084 avatar publishing
- Outgoing voice/audio messages via Hermes core TTS
- Inbound voice-message transcription via Hermes core STT

## Requirements

- Python 3.10+
- A running [Hermes Agent](https://github.com/NousResearch/hermes-agent) installation
- An XMPP account for the bot

## Installation

Installation is three steps: install the plugin, run post-install, then restart the gateway.

### 1. Install the plugin

```bash
hermes plugins install rebelcommand/hermes-xmpp-plugin --enable
hermes plugins enable xmpp-platform   # only if you installed without --enable
```

The installer clones the repository into a temporary directory, copies the plugin into your Hermes home (`~/.hermes/plugins/xmpp-platform/`), runs its security scan, and removes the temporary clone. You never keep a working copy of this repository.

### 2. Run post-install

```bash
python3 ~/.hermes/plugins/xmpp-platform/post_install.py
```

`post_install.py` completes what the core installer intentionally leaves alone:

1. Sets `display.platforms.xmpp.tool_progress_grouping: separate` in `config.yaml` (after backing the file up), so tool progress arrives as one message per tool call. This is the one display default XMPP needs and that the core installer does not set.
2. Prompts for an optional bot avatar path and writes `XMPP_AVATAR_PATH` to `~/.hermes/.env`.

Everything else is handled natively by `hermes plugins install` (credentials and Python dependencies) or by Hermes core (access control via the allowlist env var or DM pairing codes).

It is safe to re-run: existing `.env` values win and config defaults are only added when missing.

### 3. Restart the gateway

```bash
hermes gateway restart
```

### Installing into a specific profile

Hermes profiles are independent. Install into the profile you want the bot in, running post-install against that profile before restarting:

```bash
hermes -p my-bot plugins install rebelcommand/hermes-xmpp-plugin --enable
python3 ~/.hermes/plugins/xmpp-platform/post_install.py --profile my-bot
hermes -p my-bot gateway restart
```

Post-install reads the active profile's config and `.env`; pass `--profile my-bot` (or `--hermes-home`) if you want it explicit.

When there is no terminal, post-install sets the tool-progress key and skips the optional avatar prompt silently (keeping any existing avatar), so the same command works for headless installs with no extra flag.

## Upgrading

```bash
hermes plugins update xmpp-platform
hermes gateway restart
```

That is the whole upgrade. `hermes plugins update` pulls the latest revision from this repository into your Hermes plugin directory, refreshes the installed files, and re-runs the security scan; the gateway restart loads the new code. Check what you are running with:

```bash
hermes plugins list
```

Because this repository is a plugin root, upgrades work natively. If you ever see `was not installed from git (no .git directory)`, you installed a subdirectory path instead of the repository root; reinstall with the command above.

Nothing in your configuration is touched by an upgrade. Settings live in `config.yaml` and credentials in `.env`, both outside the plugin directory, so upgrades never ask you to re-enter anything.

## Configuration

The plugin needs no `platforms.xmpp` block in `config.yaml` by default. OMEMO is enabled in the adapter (no config key required), the platform self-enables from your credentials, and `allow_all_users` defaults to deny-all (off). The only config key `post_install.py` writes is:

```yaml
display:
  platforms:
    xmpp:
      tool_progress_grouping: separate
```

If you want an explicit `platforms.xmpp` block, its supported keys are `enabled`, `omemo_enabled`, `omemo_allow_untrusted`, and `allow_all_users`, though the OMEMO and access-control settings are normally set with the `.env` variables below instead.

All install-specific settings (credentials, allowlist, home channel, avatar path) are stored in your Hermes `.env` file:

```bash
# ~/.hermes/.env
XMPP_USER_JID="hermes@example.com"
XMPP_PASSWORD="hermes-password"
XMPP_ALLOWED_USERS="you@example.com,friend@example.net"
XMPP_HOME_CHANNEL="you@example.com"
XMPP_AVATAR_PATH="/path/to/avatar.png"
```

### Environment variables

| Variable | Purpose |
|---|---|
| `XMPP_USER_JID` | Bot XMPP address |
| `XMPP_PASSWORD` | Bot account password |
| `XMPP_ALLOWED_USERS` | Comma-separated JIDs allowed to message the bot (default: none, deny all) |
| `XMPP_ALLOW_ALL_USERS` | Allow any user to message the bot (default: false) |
| `XMPP_SERVER` | Server hostname override (default: the JID domain) |
| `XMPP_PORT` | Server port (default: 5222) |
| `XMPP_OMEMO_ENABLED` | Enable OMEMO (default: true) |
| `XMPP_OMEMO_ALLOW_UNTRUSTED` | Auto-trust new OMEMO devices (default: true) |
| `XMPP_AVATAR_PATH` | Path to an avatar image (optional) |
| `XMPP_HOME_CHANNEL` | Default JID for cron / notifications. Set with `/sethome` in a chat with the bot, or in `.env` yourself. |
| `XMPP_ALLOW_PRIVATE_DOWNLOADS` | Allow inbound media to be fetched from private/link-local/loopback addresses (default: false). Set `true` only if your XMPP upload service is self-hosted on a private network. |

> **Home channel note:** cron delivery and restart notifications need a home target. It is not seeded automatically. Use `/sethome` in a chat with the bot, or set `XMPP_HOME_CHANNEL` in `.env` yourself. `/sethome` records the home channel in `config.yaml` (core Hermes behavior for every platform); the `.env` value is what the env fallback reads.

> **Security note:** without `XMPP_ALLOWED_USERS` and without `allow_all_users`, the bot denies every sender until you approve them. Approve a new user by DMing the bot from an unapproved account and running `hermes pairing approve <code>` on the host, or set `XMPP_ALLOWED_USERS` in `.env`.

## OMEMO End-to-End Encryption

OMEMO (XEP-0384) is enabled by default, so messages between the bot and supporting XMPP clients are end-to-end encrypted.

### Trust model

By default the bot uses **Blind Trust Before Verification (BTBV)**: new OMEMO devices are automatically trusted so the bot can reply immediately. This is appropriate for a personal bot where you control both endpoints.

To require manual trust before replying to a new device, set `XMPP_OMEMO_ALLOW_UNTRUSTED=false` in `.env`. With manual trust, the bot logs a warning and replies to untrusted devices fail until you approve the device from your XMPP client.

### Key storage

OMEMO identity keys, sessions, device bundles, and trust decisions are stored in a single JSON file created automatically at `~/.hermes/sessions/omemo.json`.

### Disabling OMEMO

Set `XMPP_OMEMO_ENABLED=false` in `.env`. The adapter then uses plain-text XMPP messages and keeps working with clients that do not support OMEMO.

## Voice and Audio

Voice replies and transcription use the Hermes core TTS/STT configuration; the plugin adds no defaults of its own. The core defaults (STT autodetect, `voice.auto_tts: false`) apply.

With the default the adapter transcribes inbound voice messages using Hermes core STT (`faster-whisper`) and replies with both a TTS voice message and the full text response. Text messages receive text-only replies.

If you set `voice.auto_tts` to `true`, **every** reply (voice or text input) is sent as a TTS voice message in addition to the text response. The adapter-level voice reply to inbound voice messages is independent of this setting.

Change the STT model or TTS provider by editing the corresponding blocks in `~/.hermes/config.yaml`.

## Avatar

The adapter publishes a bot avatar using XEP-0084 (User Avatar) and XEP-0153 (vCard-based Avatars). Most XMPP clients show this as the bot's profile picture.

Provide a PNG or JPEG; the adapter crops to a centered square, resizes to 256x256, converts to PNG, and publishes through both PEP (XEP-0084) and vCard (XEP-0153) for maximum client compatibility. Avatars whose base64 encoding exceeds 200 KiB are skipped entirely: publishing them would exceed the server's stanza size limit and close the stream. `post_install.py` prompts for it and stores it as `XMPP_AVATAR_PATH` in `.env` (or set it there yourself):

```bash
# ~/.hermes/.env
XMPP_AVATAR_PATH="/path/to/avatar.png"
```

On connect the adapter checks the server's current avatar and only publishes when it is missing or different, so restarting the gateway does not re-publish an unchanged avatar (or re-announce presence). Change the file and restart the gateway to update it.

## Read Receipts (Chat Markers)

The adapter supports XEP-0333 Chat Markers. When a client such as Conversations sends a markable message, the bot replies with a `displayed` marker after processing it, which gives you the second checkmark in Conversations.

## Inbound Images and Files

The adapter receives images and other files sent from XMPP clients:

- Plain `https://` URLs in the message body are downloaded directly.
- `aesgcm://` URLs (OMEMO-encrypted media sharing used by Conversations) are downloaded over HTTPS and decrypted with the AES-256-GCM key in the URL fragment.
- Downloaded files are cached in the Hermes image cache and passed to the agent as `media_urls` so tools like `vision_analyze` can inspect them.

No extra configuration is required.

## Typing Indicator

The adapter supports XEP-0085 Chat State Notifications. While the agent generates a response your client shows a composing state; it clears when the response is sent. Enabled by default.

## Streaming Behavior

XMPP has no live-streaming transport, so replies arrive whole rather than streaming in as they are generated (long replies are split into ~2000-character messages). While the agent works you still see live progress: a typing indicator, one short line per tool call, and a "still working" heartbeat on long tasks.

## Uninstallation

Run the cleanup script first (it is standalone), then remove the plugin, then restart:

```bash
python3 ~/.hermes/plugins/xmpp-platform/post_uninstall.py
hermes plugins remove xmpp-platform
hermes gateway restart
```

`post_uninstall.py` removes the `display.platforms.xmpp.tool_progress_grouping` key, the stale `xmpp-platform` entries in `plugins.enabled`/`plugins.disabled`, and (with `--omemo`) the OMEMO key store at `sessions/omemo.json`. It deliberately leaves the `XMPP_*` variables in `.env` and any core pairing grants; it prints the commands to delete those by hand if you want them fully gone.

## Development

```bash
python3 -m pip install ruff pytest
ruff check .
python3 -m pytest
```

Layout: `plugin.yaml`, `__init__.py`, `adapter.py`, and `omemo_plugin.py` at the repository root are the plugin Hermes installs. `hermes_xmpp_plugin_common.py` holds shared config/`.env` helpers used by `post_install.py` and the tests.

## License

MIT License - see [LICENSE](LICENSE).

Copyright (c) 2026 rebelcommand.
