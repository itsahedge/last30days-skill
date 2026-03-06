"""Read OpenClaw OAuth tokens for ChatGPT subscription auth.

Reads the access token from OpenClaw's auth-profiles.json so last30days
can use the ChatGPT Responses API via subscription instead of API keys.

Token refresh is handled by OpenClaw automatically — we just read the
current token from disk.
"""

import glob
import json
import os
import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any


def _log(msg: str):
    sys.stderr.write(f"[OAUTH] {msg}\n")
    sys.stderr.flush()


def _get_state_dir() -> Path:
    """Get OpenClaw state directory."""
    override = os.environ.get("OPENCLAW_STATE_DIR")
    if override:
        return Path(override)
    return Path.home() / ".openclaw"


def _find_oauth_profile(state_dir: Path) -> Optional[Dict[str, Any]]:
    """Find the first valid openai-codex OAuth profile across all agents.

    Searches auth-profiles.json files for an openai-codex profile with
    an access token. Prefers non-expired tokens.
    """
    agents_dir = state_dir / "agents"
    if not agents_dir.exists():
        return None

    best = None
    best_expires = 0

    for auth_file in agents_dir.glob("*/agent/auth-profiles.json"):
        try:
            with open(auth_file) as f:
                data = json.load(f)

            profiles = data.get("profiles", {})
            for profile_id, profile in profiles.items():
                if profile.get("provider") != "openai-codex":
                    continue
                if profile.get("type") != "oauth":
                    continue

                access = profile.get("access")
                if not access:
                    continue

                expires = profile.get("expires", 0)

                # Prefer the freshest token
                if expires > best_expires:
                    best = {
                        "access_token": access,
                        "refresh_token": profile.get("refresh"),
                        "expires": expires,
                        "account_id": profile.get("accountId"),
                        "source": str(auth_file),
                    }
                    best_expires = expires

        except (json.JSONDecodeError, OSError) as e:
            _log(f"Failed to read {auth_file}: {e}")
            continue

    return best


def get_chatgpt_token() -> Optional[str]:
    """Get a valid ChatGPT OAuth access token.

    Returns the access token string, or None if unavailable/expired.
    OpenClaw handles refresh automatically — if the token is expired,
    it means OpenClaw hasn't refreshed it yet (gateway may be down).
    """
    state_dir = _get_state_dir()
    profile = _find_oauth_profile(state_dir)

    if not profile:
        _log("No openai-codex OAuth profile found in OpenClaw auth")
        return None

    token = profile["access_token"]
    expires = profile.get("expires", 0)
    now_ms = int(time.time() * 1000)

    if expires and expires < now_ms:
        _log(f"OAuth token expired ({expires} < {now_ms}). "
             f"OpenClaw should auto-refresh — try restarting gateway.")
        # Return it anyway — the server will reject it and we'll get a clear error
        # Better than silently falling back to nothing
        return token

    _log(f"Found valid OAuth token (expires in {(expires - now_ms) // 1000}s)")
    return token


def is_chatgpt_oauth_available() -> bool:
    """Check if ChatGPT OAuth is available (token exists, regardless of expiry)."""
    state_dir = _get_state_dir()
    profile = _find_oauth_profile(state_dir)
    return profile is not None
