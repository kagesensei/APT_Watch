import json
import pathlib
import re
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHATS_DIR = ROOT / "data" / "chats"

_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _path_for(user_id):
    if not _SAFE_ID_RE.match(user_id):
        raise ValueError("invalid user id")
    CHATS_DIR.mkdir(parents=True, exist_ok=True)
    return CHATS_DIR / f"{user_id}.json"


def _load(user_id):
    path = _path_for(user_id)
    if not path.exists():
        return {"chats": {}}
    return json.loads(path.read_text(encoding="utf-8"))


def _save(user_id, data):
    _path_for(user_id).write_text(json.dumps(data, indent=2), encoding="utf-8")


def list_chats(user_id):
    data = _load(user_id)
    chats = [
        {"id": chat_id, "title": chat["title"], "updated_at": chat["updated_at"]}
        for chat_id, chat in data["chats"].items()
    ]
    chats.sort(key=lambda c: c["updated_at"], reverse=True)
    return chats


def get_chat(user_id, chat_id):
    data = _load(user_id)
    return data["chats"].get(chat_id)


def upsert_chat(user_id, chat_id, title, messages):
    data = _load(user_id)
    data["chats"][chat_id] = {
        "title": title,
        "messages": messages,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _save(user_id, data)


def delete_chat(user_id, chat_id):
    data = _load(user_id)
    if chat_id in data["chats"]:
        del data["chats"][chat_id]
        _save(user_id, data)
        return True
    return False
