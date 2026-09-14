"""Per-user chat history, persisted as one JSON file per user id.

Not a database table because chat history is personal, low-volume, and
never queried across users -- a flat file keyed by a validated user id is
simpler and easier to audit than adding a table + migrations for it.
"""

import json
import pathlib
import re
from datetime import datetime, timezone
from typing import TypedDict

from contracts import precondition

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHATS_DIR = ROOT / "data" / "chats"

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class ChatSummary(TypedDict):
    """One row of a user's chat list."""

    id: str
    title: str
    updated_at: str


class Chat(TypedDict):
    """A single stored chat: its title, message log, and last-touch time."""

    title: str
    messages: list[dict[str, object]]
    updated_at: str


class _Store(TypedDict):
    chats: dict[str, Chat]


def _path_for(user_id: str) -> pathlib.Path:
    """Resolve a user's chat file, rejecting anything that isn't a bare id.

    The safe-id check is what stands between this function and a path
    traversal (`user_id` ultimately comes from an OAuth-provided subject
    claim, which this app does not otherwise sanitize) -- it must run
    before the path is ever built.
    """
    if not _SAFE_ID_RE.match(user_id):
        raise ValueError("invalid user id")
    CHATS_DIR.mkdir(parents=True, exist_ok=True)
    return CHATS_DIR / f"{user_id}.json"


def _load(user_id: str) -> _Store:
    path = _path_for(user_id)
    if not path.exists():
        return {"chats": {}}
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def _save(user_id: str, data: _Store) -> None:
    _path_for(user_id).write_text(json.dumps(data, indent=2), encoding="utf-8")


def list_chats(user_id: str) -> list[ChatSummary]:
    """Return this user's chats as summaries, most recently updated first."""
    data = _load(user_id)
    chats: list[ChatSummary] = [
        {"id": chat_id, "title": chat["title"], "updated_at": chat["updated_at"]}
        for chat_id, chat in data["chats"].items()
    ]
    chats.sort(key=lambda c: c["updated_at"], reverse=True)
    return chats


def get_chat(user_id: str, chat_id: str) -> Chat | None:
    """Return one chat's full record, or None if it doesn't exist."""
    data = _load(user_id)
    return data["chats"].get(chat_id)


def upsert_chat(
    user_id: str, chat_id: str, title: str, messages: list[dict[str, object]]
) -> None:
    """Create or overwrite one chat, stamping it with the current time."""
    precondition(bool(chat_id), "chat_id must not be empty")
    data = _load(user_id)
    data["chats"][chat_id] = {
        "title": title,
        "messages": messages,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save(user_id, data)


def delete_chat(user_id: str, chat_id: str) -> bool:
    """Delete one chat. Returns whether it existed."""
    data = _load(user_id)
    if chat_id in data["chats"]:
        del data["chats"][chat_id]
        _save(user_id, data)
        return True
    return False
