import contextlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from storage import LEGACY_DATASETS, SQLiteStorage


class SQLiteStorageTests(unittest.TestCase):
    @staticmethod
    def booking(code="MKR-STORAGE01", created_at=100):
        return {
            "request_code": code,
            "created_at": created_at,
            "chat_id": 100,
            "city": "Краснодар",
            "kind": "Рестобар",
            "name": "Анна",
            "phone": "+79990000000",
            "datetime": "10 сентября 2026, 20:00",
            "guests": "2",
            "comment": "нет",
            "status": "received",
        }

    def test_empty_bootstrap_has_schema_and_integrity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SQLiteStorage(Path(temp_dir))
            self.assertEqual(repository.integrity_check(), "ok")
            with contextlib.closing(sqlite3.connect(repository.path)) as connection:
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                foreign_key_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
            self.assertEqual(version, 1)
            self.assertEqual(foreign_key_errors, [])
            self.assertTrue(
                {"bookings", "booking_status_history", "notification_recipients", "dating_profiles"}
                <= tables
            )

    def test_imports_all_legacy_jsonl_once_without_modifying_sources(self):
        fixtures = {
            "bookings.jsonl": self.booking("MKR-LEGACY01"),
            "consents.jsonl": {"created_at": 1, "chat_id": 100},
            "dating_profiles.jsonl": {
                "created_at": 2,
                "chat_id": 100,
                "name": "Анна",
                "age": "30",
                "gender": "Жен",
                "about": "Музыка",
            },
            "dating_reactions.jsonl": {
                "created_at": 3,
                "chat_id": 100,
                "target_profile_code": "BBBBB",
                "action": "like",
            },
            "dating_matches.jsonl": {
                "created_at": 4,
                "match_key": "AAAAA:BBBBB",
                "profile_codes": ["AAAAA", "BBBBB"],
            },
            "notification_recipients.jsonl": {
                "created_at": 5,
                "username": "grunvald",
                "chat_id": 501,
            },
            "notification_deliveries.jsonl": {
                "created_at": 6,
                "request_code": "MKR-LEGACY01",
                "recipient": "grunvald",
                "chat_id": 501,
                "status": "delivered",
                "attempts": 1,
                "telegram_message_id": 77,
            },
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            before = {}
            for name in LEGACY_DATASETS:
                value = (json.dumps(fixtures[name], ensure_ascii=False) + "\n").encode("utf-8")
                (root / name).write_bytes(value)
                before[name] = value
            first = SQLiteStorage(root)
            first_counts = first.counts()
            second = SQLiteStorage(root)
            self.assertEqual(second.counts(), first_counts)
            self.assertEqual(second.booking_by_code("mkr-legacy01")["name"], "Анна")
            self.assertEqual(second.profile_for_chat(100)["profile_code"], first.profile_for_chat(100)["profile_code"])
            self.assertEqual(second.recipients(), {"grunvald": 501})
            for name, contents in before.items():
                self.assertEqual((root / name).read_bytes(), contents)

    def test_booking_creation_and_history_are_one_transaction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SQLiteStorage(Path(temp_dir))
            created = repository.create_booking(self.booking())
            history = repository.booking_history(created["request_code"])
            self.assertEqual(created["status_version"], 1)
            self.assertEqual(len(history), 1)
            self.assertEqual(history[0]["new_status"], "received")

    def test_pre_qr_booking_without_code_gets_stable_migration_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            legacy = {**self.booking(), "created_at": 50}
            legacy.pop("request_code")
            (root / "bookings.jsonl").write_text(
                json.dumps(legacy, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            first = SQLiteStorage(root)
            records = first.records_for_legacy("bookings.jsonl")
            self.assertEqual(len(records), 1)
            self.assertRegex(records[0]["request_code"], r"^MKR-[A-F0-9]{10}$")
            self.assertTrue(records[0]["legacy_generated_code"])
            stable_code = records[0]["request_code"]
            second = SQLiteStorage(root)
            self.assertEqual(second.counts()["bookings"], 1)
            self.assertEqual(second.records_for_legacy("bookings.jsonl")[0]["request_code"], stable_code)

    def test_history_is_database_enforced_append_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SQLiteStorage(Path(temp_dir))
            repository.create_booking(self.booking())
            with contextlib.closing(sqlite3.connect(repository.path)) as connection:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("UPDATE booking_status_history SET note='changed'")
                connection.rollback()
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("DELETE FROM booking_status_history")

    def test_claim_is_atomic_and_second_manager_cannot_take_booking(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            SQLiteStorage(root).create_booking(self.booking())

            def claim(actor_id):
                return SQLiteStorage(root).transition_booking(
                    "MKR-STORAGE01",
                    "in_progress",
                    actor_id=actor_id,
                    actor_username=f"manager{actor_id}",
                    actor_label=f"@manager{actor_id}",
                    expected_version=1,
                    callback_query_id=f"claim-{actor_id}",
                )[0]

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(claim, (501, 502)))
            self.assertEqual(results.count("updated"), 1)
            self.assertEqual(results.count("assigned_to_other"), 1)
            current = SQLiteStorage(root).booking_by_code("MKR-STORAGE01")
            self.assertIn(current["assigned_manager_id"], {501, 502})
            self.assertEqual(len(SQLiteStorage(root).booking_history("MKR-STORAGE01")), 2)

    def test_stale_and_terminal_actions_do_not_add_history(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = SQLiteStorage(Path(temp_dir))
            repository.create_booking(self.booking())
            result, current = repository.transition_booking(
                "MKR-STORAGE01",
                "in_progress",
                actor_id=501,
                actor_username="grunvald",
                actor_label="@grunvald",
                expected_version=1,
                callback_query_id="claim",
            )
            self.assertEqual(result, "updated")
            stale, _ = repository.transition_booking(
                "MKR-STORAGE01",
                "contacted",
                actor_id=501,
                actor_username="grunvald",
                actor_label="@grunvald",
                expected_version=1,
                callback_query_id="stale",
            )
            self.assertEqual(stale, "stale")
            confirmed, current = repository.transition_booking(
                "MKR-STORAGE01",
                "confirmed",
                actor_id=501,
                actor_username="grunvald",
                actor_label="@grunvald",
                expected_version=2,
                callback_query_id="confirm",
            )
            self.assertEqual(confirmed, "updated")
            terminal, _ = repository.transition_booking(
                "MKR-STORAGE01",
                "cancelled",
                actor_id=501,
                actor_username="grunvald",
                actor_label="@grunvald",
                expected_version=current["status_version"],
                callback_query_id="cancel-after-confirm",
            )
            self.assertEqual(terminal, "terminal")
            self.assertEqual(len(repository.booking_history("MKR-STORAGE01")), 3)

    def test_backup_api_produces_restorable_database(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repository = SQLiteStorage(root / "source")
            repository.create_booking(self.booking())
            backup_path = root / "backup" / "bot.sqlite3"
            repository.backup_to(backup_path)
            restored = SQLiteStorage(root / "backup")
            self.assertEqual(restored.integrity_check(), "ok")
            self.assertEqual(restored.booking_by_code("MKR-STORAGE01")["phone"], "+79990000000")


if __name__ == "__main__":
    unittest.main()
