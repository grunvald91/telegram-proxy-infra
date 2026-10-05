import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bot


class ManagerWorkflowTests(unittest.TestCase):
    def setUp(self):
        bot.FLOWS.clear()
        self.sent = []

    def fake_send(self, chat_id, text, reply_markup=None):
        self.sent.append((chat_id, text, reply_markup))
        return {"message_id": len(self.sent) + 100}

    @staticmethod
    def query(data, user_id, username, callback_id):
        return {
            "id": callback_id,
            "data": data,
            "from": {"id": user_id, "username": username, "is_bot": False},
            "message": {"chat": {"id": user_id, "type": "private"}, "message_id": 900},
        }

    @staticmethod
    def booking():
        return {
            "request_code": "MKR-MANAGER1",
            "created_at": 100,
            "chat_id": 100,
            "city": "Краснодар",
            "kind": "Рестобар",
            "name": "Гость",
            "phone": "+79990000000",
            "datetime": "10 сентября 2026, 20:00",
            "guests": "2",
            "comment": "нет",
            "status": "received",
        }

    @patch.object(bot, "edit_message")
    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_manager_claims_and_other_manager_cannot_overwrite(self, send, callback_ack, edit_message):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)), patch.object(
            bot, "ADMIN_CHAT_ID", ""
        ):
            bot.register_notification_recipient({"id": 501, "username": "studio_goroda"})
            bot.register_notification_recipient({"id": 502, "username": "grunvald"})
            record = bot.storage().create_booking(self.booking())
            bot.on_callback(
                self.query(
                    f"bm:claim:{record['request_code']}:{record['status_version']}",
                    501,
                    "studio_goroda",
                    "claim-501",
                )
            )
            claimed = bot.booking_by_code(record["request_code"])
            self.assertEqual(claimed["status"], "in_progress")
            self.assertEqual(claimed["assigned_manager_id"], 501)
            bot.on_callback(
                self.query(
                    f"bm:contacted:{record['request_code']}:{claimed['status_version']}",
                    502,
                    "grunvald",
                    "contact-502",
                )
            )
            unchanged = bot.booking_by_code(record["request_code"])
            history = bot.storage().booking_history(record["request_code"])
        self.assertEqual(unchanged["status"], "in_progress")
        self.assertEqual(len(history), 2)
        self.assertIn("у @studio_goroda", callback_ack.call_args.args[1])

    @patch.object(bot, "edit_message")
    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_cancel_requires_explicit_second_tap(self, send, callback_ack, edit_message):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)), patch.object(
            bot, "ADMIN_CHAT_ID", ""
        ):
            bot.register_notification_recipient({"id": 502, "username": "grunvald"})
            created = bot.storage().create_booking(self.booking())
            bot.on_callback(
                self.query(
                    f"bm:claim:{created['request_code']}:{created['status_version']}",
                    502,
                    "grunvald",
                    "claim",
                )
            )
            claimed = bot.booking_by_code(created["request_code"])
            bot.on_callback(
                self.query(
                    f"bmc:{created['request_code']}:{claimed['status_version']}",
                    502,
                    "grunvald",
                    "cancel-question",
                )
            )
            self.assertEqual(bot.booking_by_code(created["request_code"])["status"], "in_progress")
            confirm_callback = self.sent[-1][2]["inline_keyboard"][0][0]["callback_data"]
            bot.on_callback(self.query(confirm_callback, 502, "grunvald", "cancel-confirm"))
            cancelled = bot.booking_by_code(created["request_code"])
            history_len = len(bot.storage().booking_history(created["request_code"]))
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(history_len, 3)

    def test_manager_identity_survives_username_change(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)), patch.object(
            bot, "ADMIN_CHAT_ID", ""
        ):
            bot.register_notification_recipient({"id": 502, "username": "grunvald"})
            actor = bot.manager_actor({"id": 502, "username": "new_manager_name", "is_bot": False})
            impostor = bot.manager_actor({"id": 999, "username": "grunvald", "is_bot": False})
        self.assertEqual(actor["id"], 502)
        self.assertEqual(actor["label"], "@new_manager_name")
        self.assertIsNone(impostor)

    def test_card_buttons_follow_status(self):
        new_labels = [
            item["text"]
            for row in bot.manager_booking_keyboard({"request_code": "MKR-X", "status": "received", "status_version": 1})[
                "inline_keyboard"
            ]
            for item in row
        ]
        active_labels = [
            item["text"]
            for row in bot.manager_booking_keyboard(
                {"request_code": "MKR-X", "status": "in_progress", "status_version": 2}
            )["inline_keyboard"]
            for item in row
        ]
        self.assertIn("🙋 Взять в работу", new_labels)
        self.assertNotIn("✅ Подтвердить бронь", new_labels)
        self.assertIn("📞 Связались", active_labels)
        self.assertIn("✅ Подтвердить бронь", active_labels)
        self.assertIn("❌ Отменить заявку", active_labels)


if __name__ == "__main__":
    unittest.main()
