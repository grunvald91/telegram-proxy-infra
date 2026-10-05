"""Transactional SQLite storage for the Mishkin&Mishkin Telegram bot.

The storage layer keeps the public bot records as dictionaries so the Telegram
handlers do not depend on SQL column details.  Existing JSONL files are imported
once, inside one transaction, and are then treated as read-only legacy data.
"""

from __future__ import annotations

import hashlib
import contextlib
import json
import pathlib
import sqlite3
import time
import uuid
from typing import Iterable


BOOKING_STATUSES = {
    "received",
    "in_progress",
    "contacted",
    "no_answer",
    "confirmed",
    "cancelled",
}

LEGACY_DATASETS = (
    "bookings.jsonl",
    "consents.jsonl",
    "dating_profiles.jsonl",
    "dating_reactions.jsonl",
    "dating_matches.jsonl",
    "notification_recipients.jsonl",
    "notification_deliveries.jsonl",
)


def _json(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _loads(value: str | None) -> dict:
    if not value:
        return {}
    try:
        record = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return record if isinstance(record, dict) else {}


def _integer(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _raw_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.is_file():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def _dating_code_from_number(value: int) -> str:
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    result: list[str] = []
    for _ in range(5):
        result.append(alphabet[value % len(alphabet)])
        value //= len(alphabet)
    return "".join(result)


def _legacy_profile_code(record: dict) -> str:
    existing = str(record.get("profile_code", "")).strip().upper()
    if len(existing) == 5 and existing.isalnum():
        return existing
    seed = f"mishkin-dating:{record.get('chat_id', '')}:{record.get('created_at', '')}"
    return _dating_code_from_number(uuid.uuid5(uuid.NAMESPACE_URL, seed).int)


class SQLiteStorage:
    """Small, connection-per-operation SQLite repository."""

    def __init__(self, data_dir: pathlib.Path):
        self.data_dir = pathlib.Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "bot.sqlite3"
        self._ensure_schema()
        self._import_legacy_once()
        self._import_legacy_bookings_without_codes_once()

    @contextlib.contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS consents (
                    chat_id INTEGER PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS bookings (
                    request_code TEXT PRIMARY KEY COLLATE NOCASE,
                    created_at INTEGER NOT NULL,
                    chat_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    assigned_manager_id INTEGER,
                    assigned_manager_username TEXT,
                    assigned_at INTEGER,
                    status_version INTEGER NOT NULL DEFAULT 1,
                    closed_at INTEGER,
                    last_contact_at INTEGER,
                    no_answer_count INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    CHECK (status IN ('received', 'in_progress', 'contacted', 'no_answer', 'confirmed', 'cancelled'))
                );
                CREATE INDEX IF NOT EXISTS idx_bookings_chat_created
                    ON bookings(chat_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_bookings_status_created
                    ON bookings(status, created_at DESC);

                CREATE TABLE IF NOT EXISTS booking_status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    request_code TEXT NOT NULL COLLATE NOCASE,
                    previous_status TEXT,
                    new_status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    actor_id INTEGER,
                    actor_username TEXT,
                    actor_label TEXT,
                    assigned_manager_id INTEGER,
                    action TEXT NOT NULL,
                    note TEXT,
                    callback_query_id TEXT UNIQUE,
                    FOREIGN KEY(request_code) REFERENCES bookings(request_code) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_booking_history_code_created
                    ON booking_status_history(request_code, created_at, id);
                CREATE TRIGGER IF NOT EXISTS booking_history_no_update
                    BEFORE UPDATE ON booking_status_history
                    BEGIN SELECT RAISE(ABORT, 'booking status history is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS booking_history_no_delete
                    BEFORE DELETE ON booking_status_history
                    BEGIN SELECT RAISE(ABORT, 'booking status history is append-only'); END;

                CREATE TABLE IF NOT EXISTS notification_recipients (
                    username TEXT PRIMARY KEY COLLATE NOCASE,
                    chat_id INTEGER NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS notification_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    request_code TEXT COLLATE NOCASE,
                    recipient TEXT,
                    chat_id INTEGER,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL,
                    telegram_message_id INTEGER,
                    created_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_deliveries_booking
                    ON notification_deliveries(request_code, created_at DESC);

                CREATE TABLE IF NOT EXISTS dating_profiles (
                    chat_id INTEGER PRIMARY KEY,
                    profile_code TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS dating_reactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER NOT NULL,
                    target_profile_code TEXT NOT NULL COLLATE NOCASE,
                    created_at INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    UNIQUE(chat_id, target_profile_code)
                );
                CREATE INDEX IF NOT EXISTS idx_reactions_target
                    ON dating_reactions(target_profile_code);

                CREATE TABLE IF NOT EXISTS dating_matches (
                    match_key TEXT PRIMARY KEY,
                    first_profile_code TEXT NOT NULL COLLATE NOCASE,
                    second_profile_code TEXT NOT NULL COLLATE NOCASE,
                    created_at INTEGER NOT NULL,
                    payload TEXT NOT NULL
                );
                """
            )
            booking_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(bookings)")
            }
            for name, definition in (
                ("status_version", "INTEGER NOT NULL DEFAULT 1"),
                ("closed_at", "INTEGER"),
                ("last_contact_at", "INTEGER"),
                ("no_answer_count", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if name not in booking_columns:
                    connection.execute(f"ALTER TABLE bookings ADD COLUMN {name} {definition}")
            history_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(booking_status_history)")
            }
            for name, definition in (
                ("assigned_manager_id", "INTEGER"),
                ("callback_query_id", "TEXT"),
            ):
                if name not in history_columns:
                    connection.execute(f"ALTER TABLE booking_status_history ADD COLUMN {name} {definition}")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_booking_history_callback "
                "ON booking_status_history(callback_query_id) WHERE callback_query_id IS NOT NULL"
            )
            connection.execute("PRAGMA user_version = 1")

    def _meta(self, connection: sqlite3.Connection, key: str) -> str | None:
        row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def _set_meta(self, connection: sqlite3.Connection, key: str, value: str) -> None:
        connection.execute(
            "INSERT INTO metadata(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def _import_legacy_once(self) -> None:
        with self.connect() as connection:
            if self._meta(connection, "legacy_jsonl_import_v1") == "complete":
                return
            connection.execute("BEGIN IMMEDIATE")
            for name in LEGACY_DATASETS:
                for record in _raw_jsonl(self.data_dir / name):
                    self._import_record(connection, name, record)
            self._set_meta(connection, "legacy_jsonl_import_v1", "complete")
            self._set_meta(connection, "legacy_jsonl_imported_at", str(int(time.time())))

    def _import_legacy_bookings_without_codes_once(self) -> None:
        """Import pre-QR bookings that legitimately have no request_code."""
        with self.connect() as connection:
            if self._meta(connection, "legacy_missing_booking_codes_v1") == "complete":
                return
            connection.execute("BEGIN IMMEDIATE")
            for record in _raw_jsonl(self.data_dir / "bookings.jsonl"):
                if not str(record.get("request_code", "")).strip():
                    self._upsert_booking(connection, record, imported=True)
            self._set_meta(connection, "legacy_missing_booking_codes_v1", "complete")

    def import_legacy_record(self, dataset: str, record: dict) -> None:
        """Compatibility helper used by tests and manual recovery tools."""
        if dataset not in LEGACY_DATASETS:
            raise ValueError(f"Unknown legacy dataset: {dataset}")
        with self.connect() as connection:
            self._import_record(connection, dataset, dict(record))

    def _import_record(self, connection: sqlite3.Connection, dataset: str, record: dict) -> None:
        if dataset == "consents.jsonl":
            chat_id = _integer(record.get("chat_id"))
            if chat_id:
                self._save_consent(connection, chat_id, _integer(record.get("created_at"), int(time.time())), record)
        elif dataset == "bookings.jsonl":
            self._upsert_booking(connection, record, imported=True)
        elif dataset == "notification_recipients.jsonl":
            username = str(record.get("username", "")).strip().lstrip("@").lower()
            chat_id = _integer(record.get("chat_id"))
            if username and chat_id:
                try:
                    connection.execute(
                        "INSERT INTO notification_recipients(username, chat_id, created_at, payload) VALUES(?, ?, ?, ?) "
                        "ON CONFLICT(username) DO UPDATE SET "
                        "chat_id = excluded.chat_id, created_at = excluded.created_at, payload = excluded.payload",
                        (username, chat_id, _integer(record.get("created_at")), _json(record)),
                    )
                except sqlite3.IntegrityError:
                    pass
        elif dataset == "notification_deliveries.jsonl":
            self._insert_delivery(connection, record, imported=True)
        elif dataset == "dating_profiles.jsonl":
            self._save_profile(connection, record)
        elif dataset == "dating_reactions.jsonl":
            self._insert_reaction(connection, record)
        elif dataset == "dating_matches.jsonl":
            self._insert_match(connection, record)

    def _save_consent(self, connection: sqlite3.Connection, chat_id: int, created_at: int, record: dict) -> None:
        payload = {**record, "chat_id": int(chat_id), "created_at": int(created_at)}
        connection.execute(
            "INSERT INTO consents(chat_id, created_at, payload) VALUES(?, ?, ?) "
            "ON CONFLICT(chat_id) DO NOTHING",
            (int(chat_id), int(created_at), _json(payload)),
        )

    def save_consent(self, chat_id: int, created_at: int | None = None) -> bool:
        created_at = int(created_at or time.time())
        with self.connect() as connection:
            before = connection.total_changes
            self._save_consent(connection, int(chat_id), created_at, {"chat_id": int(chat_id), "created_at": created_at})
            return connection.total_changes > before

    def has_consent(self, chat_id: int) -> bool:
        with self.connect() as connection:
            return connection.execute("SELECT 1 FROM consents WHERE chat_id = ?", (int(chat_id),)).fetchone() is not None

    def consented_chat_ids(self) -> set[int]:
        with self.connect() as connection:
            return {int(row["chat_id"]) for row in connection.execute("SELECT chat_id FROM consents")}

    @staticmethod
    def _booking_from_row(row: sqlite3.Row | None) -> dict | None:
        if row is None:
            return None
        record = _loads(row["payload"])
        record.update(
            {
                "request_code": row["request_code"],
                "created_at": int(row["created_at"]),
                "chat_id": int(row["chat_id"]),
                "status": row["status"],
            }
        )
        if row["assigned_manager_id"] is not None:
            record["assigned_manager_id"] = int(row["assigned_manager_id"])
        if row["assigned_manager_username"]:
            record["assigned_manager_username"] = row["assigned_manager_username"]
            record["assigned_manager"] = f"@{row['assigned_manager_username']}"
        if row["assigned_at"] is not None:
            record["assigned_at"] = int(row["assigned_at"])
        record["status_version"] = int(row["status_version"])
        record["no_answer_count"] = int(row["no_answer_count"] or 0)
        if row["closed_at"] is not None:
            record["closed_at"] = int(row["closed_at"])
        if row["last_contact_at"] is not None:
            record["last_contact_at"] = int(row["last_contact_at"])
        return record

    def _history_event(
        self,
        connection: sqlite3.Connection,
        request_code: str,
        previous_status: str | None,
        new_status: str,
        created_at: int,
        *,
        actor_id: int | None = None,
        actor_username: str | None = None,
        actor_label: str | None = None,
        action: str = "status_changed",
        note: str | None = None,
        event_id: str | None = None,
        assigned_manager_id: int | None = None,
        callback_query_id: str | None = None,
    ) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO booking_status_history("
            "event_id, request_code, previous_status, new_status, created_at, actor_id, actor_username, actor_label, "
            "assigned_manager_id, action, note, callback_query_id"
            ") VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id or uuid.uuid4().hex,
                request_code,
                previous_status,
                new_status,
                int(created_at),
                actor_id,
                actor_username,
                actor_label,
                assigned_manager_id,
                action,
                note,
                callback_query_id,
            ),
        )

    def _upsert_booking(self, connection: sqlite3.Connection, record: dict, imported: bool = False) -> bool:
        code = str(record.get("request_code", "")).strip().upper()
        if not code:
            if not imported:
                return False
            code = "MKR-" + hashlib.sha256(_json(record).encode("utf-8")).hexdigest()[:10].upper()
            record = {**record, "request_code": code, "legacy_generated_code": True}
        created_at = _integer(record.get("created_at"), int(time.time()))
        chat_id = _integer(record.get("chat_id"))
        status = str(record.get("status", "received"))
        if status not in BOOKING_STATUSES:
            status = "received"
        assigned_id = record.get("assigned_manager_id")
        assigned_id = _integer(assigned_id) if assigned_id not in (None, "") else None
        assigned_username = str(record.get("assigned_manager_username", "")).strip().lstrip("@").lower() or None
        assigned_at = record.get("assigned_at")
        assigned_at = _integer(assigned_at) if assigned_at not in (None, "") else None
        updated_at = _integer(record.get("status_updated_at") or record.get("updated_at"), created_at)
        status_version = max(1, _integer(record.get("status_version"), 2 if status != "received" else 1))
        closed_at = record.get("closed_at")
        if closed_at in (None, "") and status in {"confirmed", "cancelled"}:
            closed_at = updated_at
        closed_at = _integer(closed_at) if closed_at not in (None, "") else None
        last_contact_at = record.get("last_contact_at")
        last_contact_at = _integer(last_contact_at) if last_contact_at not in (None, "") else None
        no_answer_count = max(0, _integer(record.get("no_answer_count")))
        payload = {
            **record,
            "request_code": code,
            "created_at": created_at,
            "chat_id": chat_id,
            "status": status,
            "status_version": status_version,
        }
        connection.execute(
            "INSERT INTO bookings(request_code, created_at, chat_id, status, assigned_manager_id, "
            "assigned_manager_username, assigned_at, status_version, closed_at, last_contact_at, no_answer_count, "
            "updated_at, payload) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(request_code) DO UPDATE SET "
            "created_at = excluded.created_at, chat_id = excluded.chat_id, status = excluded.status, "
            "assigned_manager_id = excluded.assigned_manager_id, "
            "assigned_manager_username = excluded.assigned_manager_username, assigned_at = excluded.assigned_at, "
            "status_version = excluded.status_version, closed_at = excluded.closed_at, "
            "last_contact_at = excluded.last_contact_at, no_answer_count = excluded.no_answer_count, "
            "updated_at = excluded.updated_at, payload = excluded.payload",
            (
                code, created_at, chat_id, status, assigned_id, assigned_username, assigned_at,
                status_version, closed_at, last_contact_at, no_answer_count, updated_at, _json(payload),
            ),
        )
        creation_key = hashlib.sha256(f"booking-created:{code}".encode()).hexdigest()
        self._history_event(
            connection,
            code,
            None,
            "received",
            created_at,
            action="imported" if imported else "created",
            event_id=creation_key,
        )
        if status != "received":
            transition_key = hashlib.sha256(
                f"booking-import:{code}:{status}:{updated_at}:{record.get('status_updated_by', '')}".encode()
            ).hexdigest()
            self._history_event(
                connection,
                code,
                "received",
                status,
                updated_at,
                actor_label=str(record.get("status_updated_by", "")) or None,
                action="imported_status",
                event_id=transition_key,
            )
        return True

    def create_booking(self, record: dict) -> dict:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            code = str(record.get("request_code", "")).strip().upper()
            if not code:
                raise ValueError("Booking request_code is required")
            exists = connection.execute("SELECT 1 FROM bookings WHERE request_code = ?", (code,)).fetchone()
            if exists:
                raise ValueError(f"Booking {code} already exists")
            self._upsert_booking(connection, record)
            row = connection.execute("SELECT * FROM bookings WHERE request_code = ?", (code,)).fetchone()
            result = self._booking_from_row(row)
            assert result is not None
            return result

    def booking_by_code(self, code: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM bookings WHERE request_code = ?", (str(code).upper(),)).fetchone()
            return self._booking_from_row(row)

    def bookings_for_chat(self, chat_id: int, limit: int = 5) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM bookings WHERE chat_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (int(chat_id), int(limit)),
            ).fetchall()
            return [record for row in rows if (record := self._booking_from_row(row)) is not None]

    def recent_bookings(self, since: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM bookings WHERE created_at >= ? ORDER BY created_at DESC, rowid DESC",
                (int(since),),
            ).fetchall()
            return [record for row in rows if (record := self._booking_from_row(row)) is not None]

    def transition_booking(
        self,
        code: str,
        new_status: str,
        *,
        actor_id: int,
        actor_username: str,
        actor_label: str,
        now: int | None = None,
        expected_version: int | None = None,
        callback_query_id: str | None = None,
    ) -> tuple[str, dict | None]:
        """Atomically claim/change a booking and append immutable history.

        Result codes: updated, unchanged, not_found, invalid_status,
        assigned_to_other, terminal.
        """
        if new_status not in BOOKING_STATUSES - {"received"}:
            return "invalid_status", None
        now = int(now or time.time())
        username = str(actor_username).strip().lstrip("@").lower()
        wanted = str(code).strip().upper()
        allowed = {
            "received": {"in_progress", "contacted", "no_answer", "confirmed", "cancelled"},
            "in_progress": {"contacted", "no_answer", "confirmed", "cancelled"},
            "contacted": {"no_answer", "confirmed", "cancelled"},
            "no_answer": {"in_progress", "contacted", "confirmed", "cancelled"},
            "confirmed": set(),
            "cancelled": set(),
        }
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM bookings WHERE request_code = ?", (wanted,)).fetchone()
            current = self._booking_from_row(row)
            if current is None:
                return "not_found", None
            current_version = int(row["status_version"])
            current["status_version"] = current_version
            if callback_query_id:
                prior = connection.execute(
                    "SELECT 1 FROM booking_status_history WHERE callback_query_id = ?", (callback_query_id,)
                ).fetchone()
                if prior:
                    return "unchanged", current
            current_status = str(current.get("status", "received"))
            assigned_id = current.get("assigned_manager_id")
            if current_status in {"confirmed", "cancelled"}:
                return "unchanged" if current_status == new_status else "terminal", current
            if assigned_id is not None and int(assigned_id) != int(actor_id):
                return "assigned_to_other", current
            if expected_version is not None and int(expected_version) != current_version:
                return "stale", current
            if current_status == new_status:
                return "unchanged", current
            if new_status not in allowed.get(current_status, set()):
                return "invalid_status", current

            assignment_changed = assigned_id is None
            if assignment_changed:
                current["assigned_manager_id"] = int(actor_id)
                current["assigned_manager_username"] = username
                current["assigned_manager"] = actor_label
                current["assigned_at"] = now
            current["status"] = new_status
            current["status_updated_at"] = now
            current["status_updated_by"] = actor_label
            current["status_version"] = current_version + 1
            current["updated_at"] = now
            if new_status in {"contacted", "no_answer"}:
                current["last_contact_at"] = now
            if new_status == "no_answer":
                current["no_answer_count"] = int(row["no_answer_count"] or 0) + 1
            else:
                current["no_answer_count"] = int(row["no_answer_count"] or 0)
            if new_status in {"confirmed", "cancelled"}:
                current["closed_at"] = now
            connection.execute(
                "UPDATE bookings SET status = ?, assigned_manager_id = ?, assigned_manager_username = ?, "
                "assigned_at = ?, status_version = ?, closed_at = ?, last_contact_at = ?, no_answer_count = ?, "
                "updated_at = ?, payload = ? WHERE request_code = ? AND status_version = ?",
                (
                    new_status,
                    int(current["assigned_manager_id"]),
                    current["assigned_manager_username"],
                    int(current["assigned_at"]),
                    current["status_version"],
                    current.get("closed_at"),
                    current.get("last_contact_at"),
                    current["no_answer_count"],
                    now,
                    _json(current),
                    wanted,
                    current_version,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                latest_row = connection.execute("SELECT * FROM bookings WHERE request_code = ?", (wanted,)).fetchone()
                return "stale", self._booking_from_row(latest_row)
            self._history_event(
                connection,
                wanted,
                current_status,
                new_status,
                now,
                actor_id=int(actor_id),
                actor_username=username,
                actor_label=actor_label,
                assigned_manager_id=int(current["assigned_manager_id"]),
                action="claimed" if new_status == "in_progress" and current_status == "received" else "status_changed",
                note="Назначен ответственный" if assignment_changed else None,
                callback_query_id=callback_query_id,
            )
            updated_row = connection.execute("SELECT * FROM bookings WHERE request_code = ?", (wanted,)).fetchone()
            return "updated", self._booking_from_row(updated_row)

    def bookings_by_status(
        self,
        statuses: Iterable[str],
        *,
        assigned_manager_id: int | None = None,
        since: int | None = None,
        limit: int = 10,
    ) -> list[dict]:
        wanted = [status for status in statuses if status in BOOKING_STATUSES]
        if not wanted:
            return []
        placeholders = ",".join("?" for _ in wanted)
        conditions = [f"status IN ({placeholders})"]
        parameters: list[object] = list(wanted)
        if assigned_manager_id is not None:
            conditions.append("assigned_manager_id = ?")
            parameters.append(int(assigned_manager_id))
        if since is not None:
            conditions.append("updated_at >= ?")
            parameters.append(int(since))
        parameters.append(int(limit))
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM bookings WHERE {' AND '.join(conditions)} "
                "ORDER BY CASE status WHEN 'received' THEN 0 WHEN 'no_answer' THEN 1 ELSE 2 END, "
                "created_at ASC, rowid ASC LIMIT ?",
                parameters,
            ).fetchall()
            return [record for row in rows if (record := self._booking_from_row(row)) is not None]

    def booking_status_counts(self, assigned_manager_id: int | None = None) -> dict[str, int]:
        conditions = ""
        parameters: tuple[object, ...] = ()
        if assigned_manager_id is not None:
            conditions = " WHERE assigned_manager_id = ?"
            parameters = (int(assigned_manager_id),)
        with self.connect() as connection:
            return {
                str(row["status"]): int(row["amount"])
                for row in connection.execute(
                    f"SELECT status, COUNT(*) AS amount FROM bookings{conditions} GROUP BY status",
                    parameters,
                )
            }

    def booking_history(self, code: str, limit: int = 10) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM booking_status_history WHERE request_code = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (str(code).upper(), int(limit)),
            ).fetchall()
            return [dict(row) for row in rows]

    def register_recipient(self, username: str, chat_id: int, created_at: int | None = None) -> str:
        username = str(username).strip().lstrip("@").lower()
        chat_id = int(chat_id)
        created_at = int(created_at or time.time())
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT chat_id FROM notification_recipients WHERE username = ?", (username,)
            ).fetchone()
            if row:
                return "unchanged" if int(row["chat_id"]) == chat_id else "conflict"
            collision = connection.execute(
                "SELECT username FROM notification_recipients WHERE chat_id = ?", (chat_id,)
            ).fetchone()
            if collision:
                return "conflict"
            record = {"created_at": created_at, "username": username, "chat_id": chat_id}
            connection.execute(
                "INSERT INTO notification_recipients(username, chat_id, created_at, payload) VALUES(?, ?, ?, ?)",
                (username, chat_id, created_at, _json(record)),
            )
            return "created"

    def recipients(self) -> dict[str, int]:
        with self.connect() as connection:
            return {
                str(row["username"]).lower(): int(row["chat_id"])
                for row in connection.execute("SELECT username, chat_id FROM notification_recipients")
            }

    def _insert_delivery(self, connection: sqlite3.Connection, record: dict, imported: bool = False) -> None:
        created_at = _integer(record.get("created_at"), int(time.time()))
        stable = _json(record)
        event_id = str(record.get("event_id", "")).strip()
        if not event_id:
            event_id = hashlib.sha256(("legacy:" if imported else "delivery:").encode() + stable.encode()).hexdigest()
            if not imported:
                event_id = f"{event_id}:{uuid.uuid4().hex}"
        connection.execute(
            "INSERT OR IGNORE INTO notification_deliveries(event_id, request_code, recipient, chat_id, status, "
            "attempts, telegram_message_id, created_at, payload) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                str(record.get("request_code", "")).upper() or None,
                str(record.get("recipient", "")) or None,
                _integer(record.get("chat_id")) or None,
                str(record.get("status", "unknown")),
                _integer(record.get("attempts")),
                _integer(record.get("telegram_message_id")) or None,
                created_at,
                stable,
            ),
        )

    def add_delivery(self, record: dict) -> None:
        with self.connect() as connection:
            self._insert_delivery(connection, dict(record))

    @staticmethod
    def _delivery_from_row(row: sqlite3.Row) -> dict:
        record = _loads(row["payload"])
        record.update(
            {
                "request_code": row["request_code"],
                "recipient": row["recipient"],
                "chat_id": row["chat_id"],
                "status": row["status"],
                "attempts": int(row["attempts"]),
                "created_at": int(row["created_at"]),
            }
        )
        if row["telegram_message_id"] is not None:
            record["telegram_message_id"] = int(row["telegram_message_id"])
        return record

    def deliveries(self, code: str | None = None) -> list[dict]:
        with self.connect() as connection:
            if code is None:
                rows = connection.execute("SELECT * FROM notification_deliveries ORDER BY id").fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM notification_deliveries WHERE request_code = ? ORDER BY id DESC",
                    (str(code).upper(),),
                ).fetchall()
            return [self._delivery_from_row(row) for row in rows]

    def _save_profile(self, connection: sqlite3.Connection, record: dict) -> bool:
        chat_id = _integer(record.get("chat_id"))
        code = _legacy_profile_code(record)
        if not chat_id or not code:
            return False
        record = {**record, "profile_code": code}
        created_at = _integer(record.get("created_at"), int(time.time()))
        updated_at = _integer(record.get("updated_at"), created_at)
        connection.execute(
            "INSERT INTO dating_profiles(chat_id, profile_code, created_at, updated_at, payload) VALUES(?, ?, ?, ?, ?) "
            "ON CONFLICT(chat_id) DO UPDATE SET profile_code = excluded.profile_code, "
            "created_at = excluded.created_at, updated_at = excluded.updated_at, payload = excluded.payload",
            (chat_id, code, created_at, updated_at, _json(record)),
        )
        return True

    def save_profile(self, record: dict) -> dict:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._save_profile(connection, record)
        return dict(record)

    def profile_for_chat(self, chat_id: int) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT payload FROM dating_profiles WHERE chat_id = ?", (int(chat_id),)).fetchone()
            return _loads(row["payload"]) if row else None

    def profiles(self) -> list[dict]:
        with self.connect() as connection:
            return [_loads(row["payload"]) for row in connection.execute("SELECT payload FROM dating_profiles")]

    def _insert_reaction(self, connection: sqlite3.Connection, record: dict) -> bool:
        chat_id = _integer(record.get("chat_id"))
        target = str(record.get("target_profile_code", "")).strip().upper()
        if not chat_id or not target:
            return False
        connection.execute(
            "INSERT INTO dating_reactions(chat_id, target_profile_code, created_at, action, payload) "
            "VALUES(?, ?, ?, ?, ?) ON CONFLICT(chat_id, target_profile_code) DO NOTHING",
            (chat_id, target, _integer(record.get("created_at"), int(time.time())), str(record.get("action", "")), _json(record)),
        )
        return connection.execute("SELECT changes()").fetchone()[0] > 0

    def add_reaction(self, record: dict) -> bool:
        with self.connect() as connection:
            return self._insert_reaction(connection, dict(record))

    def reactions_for(self, chat_id: int) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM dating_reactions WHERE chat_id = ? ORDER BY created_at, id", (int(chat_id),)
            ).fetchall()
            return [_loads(row["payload"]) for row in rows]

    def _insert_match(self, connection: sqlite3.Connection, record: dict) -> bool:
        key = str(record.get("match_key", "")).strip()
        codes = [str(value).upper() for value in record.get("profile_codes", []) if str(value).strip()]
        if not key or len(codes) < 2:
            return False
        connection.execute(
            "INSERT INTO dating_matches(match_key, first_profile_code, second_profile_code, created_at, payload) "
            "VALUES(?, ?, ?, ?, ?) ON CONFLICT(match_key) DO NOTHING",
            (key, codes[0], codes[1], _integer(record.get("created_at"), int(time.time())), _json(record)),
        )
        return connection.execute("SELECT changes()").fetchone()[0] > 0

    def add_match(self, record: dict) -> bool:
        with self.connect() as connection:
            return self._insert_match(connection, dict(record))

    def match_exists(self, key: str) -> bool:
        with self.connect() as connection:
            return connection.execute("SELECT 1 FROM dating_matches WHERE match_key = ?", (str(key),)).fetchone() is not None

    def matches(self) -> list[dict]:
        with self.connect() as connection:
            return [_loads(row["payload"]) for row in connection.execute("SELECT payload FROM dating_matches ORDER BY created_at")]

    def delete_profile(self, chat_id: int) -> tuple[bool, str]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT profile_code FROM dating_profiles WHERE chat_id = ?", (int(chat_id),)
            ).fetchone()
            if not row:
                return False, ""
            code = str(row["profile_code"]).upper()
            connection.execute("DELETE FROM dating_profiles WHERE chat_id = ?", (int(chat_id),))
            connection.execute(
                "DELETE FROM dating_reactions WHERE chat_id = ? OR target_profile_code = ?", (int(chat_id), code)
            )
            connection.execute(
                "DELETE FROM dating_matches WHERE first_profile_code = ? OR second_profile_code = ?", (code, code)
            )
            return True, code

    def records_for_legacy(self, dataset: str) -> list[dict]:
        if dataset == "consents.jsonl":
            with self.connect() as connection:
                return [_loads(row["payload"]) for row in connection.execute("SELECT payload FROM consents ORDER BY created_at")]
        if dataset == "bookings.jsonl":
            with self.connect() as connection:
                rows = connection.execute("SELECT * FROM bookings ORDER BY created_at, rowid").fetchall()
                return [record for row in rows if (record := self._booking_from_row(row)) is not None]
        if dataset == "notification_recipients.jsonl":
            with self.connect() as connection:
                return [_loads(row["payload"]) for row in connection.execute("SELECT payload FROM notification_recipients ORDER BY created_at")]
        if dataset == "notification_deliveries.jsonl":
            return self.deliveries()
        if dataset == "dating_profiles.jsonl":
            return self.profiles()
        if dataset == "dating_reactions.jsonl":
            with self.connect() as connection:
                return [_loads(row["payload"]) for row in connection.execute("SELECT payload FROM dating_reactions ORDER BY created_at, id")]
        if dataset == "dating_matches.jsonl":
            return self.matches()
        raise ValueError(f"Unknown legacy dataset: {dataset}")

    def backup_to(self, destination: pathlib.Path) -> None:
        destination = pathlib.Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as source, contextlib.closing(sqlite3.connect(destination)) as target:
            source.backup(target)

    def integrity_check(self) -> str:
        with self.connect() as connection:
            row = connection.execute("PRAGMA integrity_check").fetchone()
            return str(row[0]) if row else "unknown"

    def counts(self) -> dict[str, int]:
        tables: Iterable[str] = (
            "bookings",
            "booking_status_history",
            "consents",
            "dating_profiles",
            "dating_reactions",
            "dating_matches",
            "notification_recipients",
            "notification_deliveries",
        )
        with self.connect() as connection:
            return {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in tables
            }
