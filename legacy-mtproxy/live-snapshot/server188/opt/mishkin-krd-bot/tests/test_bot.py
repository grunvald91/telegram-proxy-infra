import datetime as dt
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bot
from qrmini import make_matrix, write_png


class KrasnodarBotTests(unittest.TestCase):
    def setUp(self):
        self.token_patch = patch.object(bot, "TOKEN", "")
        self.token_patch.start()
        self.addCleanup(self.token_patch.stop)
        bot.FLOWS.clear()
        bot.DATING_BROWSE.clear()
        bot.DATING_CARD_MESSAGE_IDS.clear()
        bot.DATING_OWN_MESSAGE_IDS.clear()
        bot.CONSENTED_CHAT_IDS.add(100)
        self.sent = []

    def fake_send(self, chat_id, text, reply_markup=None):
        self.sent.append((chat_id, text, reply_markup))
        return {"message_id": len(self.sent)}

    @staticmethod
    def query(data, username=None, user_id=100, message_id=777, chat_type="private", chat_id=None):
        actual_chat_id = user_id if chat_id is None else chat_id
        query = {
            "id": "callback-1",
            "data": data,
            "message": {"chat": {"id": actual_chat_id, "type": chat_type}, "message_id": message_id},
        }
        if username:
            query["from"] = {"id": user_id, "username": username, "is_bot": False}
        return query

    def test_main_keyboard_matches_reference_structure(self):
        labels = [item["text"] for row in bot.MAIN_KB["inline_keyboard"] for item in row]
        for expected in [
            "Рестобар",
            "Банкеты и ДР",
            "Танцевальные выходные",
            "Караоке-холл",
            "Картинг",
            "Арена VR и автосимуляторы",
            "Мишкин Парк",
            "Фуд Мишкин",
            "Дым Мишкин",
            "Подарочный сертификат",
            "О нас",
            "Мои QR",
            "Знакомства",
            "Поддержка",
            "Карта лояльности UDS",
        ]:
            self.assertIn(expected, labels)

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send_document")
    @patch.object(bot, "send")
    def test_all_callback_routes(self, send, send_document, callback_ack):
        send.side_effect = self.fake_send
        routes = [
            "main",
            "restaurant", "restaurant_menu", "restaurant_promo",
            "banquets", "banquet_menu", "banquet_promo",
            "dance", "dance_poster", "dance_promos",
            "karaoke", "karaoke_menu", "karaoke_promo",
            "menu:restaurant_kitchen", "menu:restaurant_kids", "menu:restaurant_bar",
            "menu:banquet_kitchen", "menu:banquet_kids", "menu:banquet_bar",
            "menu:karaoke_kitchen", "menu:karaoke_kids", "menu:karaoke_bar",
            "menu:food_menu",
            "karting", "karting_prices", "karting_academy", "karting_promo",
            "arena", "arena_prices", "arena_packages",
            "park", "park_prices", "park_packages", "park_programs",
            "food", "lounge",
            "events", "gift", "about", "contacts", "support", "loyalty",
            "dating", "dating_start", "my_qr", "notification_test_ack", "noop",
            "booking:Рестобар",
        ]
        for route in routes:
            with self.subTest(route=route):
                bot.on_callback(self.query(route))
        self.assertTrue(send.called)
        self.assertEqual(send_document.call_count, 10)
        self.assertEqual(callback_ack.call_count, len(routes))

    @patch.object(bot, "send")
    def test_start_requires_consent(self, send):
        send.side_effect = self.fake_send
        bot.CONSENTED_CHAT_IDS.discard(100)
        bot.on_message({"chat": {"id": 100}, "text": "/start"})
        self.assertEqual(self.sent[-1][1], bot.PRIVACY_TEXT)
        self.assertEqual(self.sent[-1][2]["inline_keyboard"][0][0]["callback_data"], "consent_accept")

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_consent_is_persisted(self, send, callback_ack):
        send.side_effect = self.fake_send
        bot.CONSENTED_CHAT_IDS.discard(100)
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.on_callback(self.query("consent_accept"))
            persisted = bot.storage().has_consent(100)
            self.assertTrue((Path(temp_dir) / "bot.sqlite3").is_file())
        self.assertTrue(persisted)
        self.assertIn(100, bot.CONSENTED_CHAT_IDS)
        self.assertIn("Согласие получено", self.sent[0][1])

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "edit_message")
    @patch.object(bot, "send")
    def test_booking_flow_reaches_confirmation(self, send, edit_message, callback_ack):
        send.side_effect = self.fake_send
        bot.start_booking(100, "Рестобар")
        for value in ["Тест", "+79990000000"]:
            bot.on_message({"chat": {"id": 100}, "text": value})
        selected_date = dt.date.today() + dt.timedelta(days=1)
        bot.on_callback(self.query(f"cald:{selected_date.isoformat()}"))
        selected_time = bot.available_booking_times("Рестобар", selected_date)[0]
        bot.on_callback(self.query(f"btime:{selected_time.replace(':', '')}"))
        bot.on_callback(self.query("bguest:4"))
        bot.on_callback(self.query("bcomment:none"))
        self.assertEqual(bot.FLOWS[100]["step"], "confirm")
        self.assertIn("Проверьте заявку", self.sent[-1][1])
        self.assertIn(selected_time, bot.FLOWS[100]["data"]["datetime"])

    def test_colored_buttons_use_current_telegram_styles(self):
        styles = {
            item.get("style")
            for row in bot.MAIN_KB["inline_keyboard"]
            for item in row
        }
        self.assertEqual(styles, {"primary"})
        self.assertEqual(bot.button("Забронировать", callback="booking:test")["style"], "success")
        self.assertEqual(bot.button("Назад", callback="main")["style"], "danger")

    def test_bot_api_10_3_reply_markup_features(self):
        disabled = bot.button("Недоступно", disabled=True)
        self.assertEqual(disabled["disabled"], {})
        self.assertNotIn("callback_data", disabled)
        prompt = bot.back("main", "Отменить", force_reply=True)
        self.assertTrue(prompt["force_reply"])
        self.assertEqual(bot.BOT_API_TARGET_VERSION, "10.3")

    def test_phone_keyboard_can_share_own_contact(self):
        markup = bot.phone_reply_keyboard()
        contact_button = markup["keyboard"][0][0]
        self.assertTrue(contact_button["request_contact"])
        self.assertEqual(contact_button["style"], "success")
        self.assertEqual(markup["keyboard"][1][0]["text"], bot.PHONE_CANCEL_TEXT)
        self.assertTrue(markup["one_time_keyboard"])

    def test_russian_mobile_phone_formats_are_normalized(self):
        for value in (
            "+7 (999) 000-00-00",
            "8 999 000 00 00",
            "999-000-00-00",
            "79990000000",
        ):
            with self.subTest(value=value):
                self.assertEqual(bot.normalize_russian_mobile_phone(value), "+79990000000")
        for value in (
            "999000000",
            "999000000000",
            "+7 499 000-00-00",
            "8 999 000-00-0a",
            "7+9990000000",
        ):
            with self.subTest(value=value):
                self.assertIsNone(bot.normalize_russian_mobile_phone(value))

    @patch.object(bot, "edit_message")
    @patch.object(bot, "send")
    def test_booking_accepts_shared_contact_and_rejects_wrong_manual_phone(self, send, edit_message):
        send.side_effect = self.fake_send
        bot.start_booking(100, "Рестобар")
        bot.on_message({"chat": {"id": 100}, "from": {"id": 100}, "message_id": 10, "text": "Тест"})
        bot.on_message({"chat": {"id": 100}, "from": {"id": 100}, "message_id": 11, "text": "12345"})
        self.assertEqual(bot.FLOWS[100]["step"], "phone")
        self.assertIn("Не удалось распознать", self.sent[-1][1])
        bot.on_message(
            {
                "chat": {"id": 100},
                "from": {"id": 100},
                "message_id": 12,
                "contact": {"user_id": 100, "phone_number": "8 (999) 000-00-00"},
            }
        )
        self.assertEqual(bot.FLOWS[100]["step"], "date")
        self.assertEqual(bot.FLOWS[100]["data"]["phone"], "+79990000000")
        self.assertEqual(self.sent[-2][2], {"remove_keyboard": True})

    @patch.object(bot, "api")
    def test_intermediate_messages_are_deleted_in_one_batch(self, api):
        with patch.object(bot, "TOKEN", "test-token"):
            bot.delete_messages_safely(100, [4, 2, 4, None, 3])
        method, payload = api.call_args.args
        self.assertEqual(method, "deleteMessages")
        self.assertEqual(payload["chat_id"], 100)
        self.assertEqual(payload["message_ids"], [2, 3, 4])

    def test_calendar_disables_past_dates_and_has_navigation(self):
        today = dt.date(2026, 8, 21)
        markup = bot.booking_calendar(2026, 8, today)
        buttons = [item for row in markup["inline_keyboard"] for item in row]
        callbacks = {item.get("callback_data") for item in buttons}
        self.assertIn("cald:2026-08-21", callbacks)
        self.assertNotIn("cald:2026-08-20", callbacks)
        self.assertIn("calm:2026-09", callbacks)
        selected = next(item for item in buttons if item.get("callback_data") == "cald:2026-08-21")
        self.assertEqual(selected["style"], "primary")
        past = next(item for item in buttons if item.get("text") == "20")
        self.assertEqual(past["disabled"], {})
        self.assertNotIn("callback_data", past)

    @patch.object(bot, "api")
    def test_rich_contacts_use_bot_api_10_3_markup(self, api):
        api.return_value = {"message_id": 1}
        with patch.object(bot, "TOKEN", "test-token"):
            bot.show_contacts(100)
        method, payload = api.call_args.args
        self.assertEqual(method, "sendRichMessage")
        rich_html = payload["rich_message"]["html"]
        self.assertIn("<table compact>", rich_html)
        self.assertIn("<tg-button-row", rich_html)
        self.assertIn('type="url"', rich_html)
        self.assertIn("reply_markup", payload)

    def test_time_picker_filters_slots_that_are_too_close(self):
        now = dt.datetime(2026, 8, 21, 18, 20)
        slots = bot.available_booking_times("Караоке-холл", now.date(), now)
        self.assertNotIn("19:00", slots)
        self.assertIn("19:30", slots)
        self.assertEqual(slots[-1], "23:30")

    @patch.object(bot, "send")
    def test_dating_flow_is_adults_only(self, send):
        send.side_effect = self.fake_send
        bot.start_dating(100)
        bot.on_message({"chat": {"id": 100}, "text": "Тест"})
        bot.on_message({"chat": {"id": 100}, "text": "17"})
        self.assertEqual(bot.FLOWS[100]["step"], "age")
        self.assertIn("совершеннолетним", self.sent[-1][1])
        bot.on_message({"chat": {"id": 100}, "text": "30"})
        self.assertEqual(bot.FLOWS[100]["step"], "gender")
        with patch.object(bot, "callback_ack"):
            bot.on_callback(
                self.query("dating_gender:male", message_id=bot.FLOWS[100]["form_message_id"])
            )
        self.assertEqual(bot.FLOWS[100]["step"], "about")
        bot.on_message({"chat": {"id": 100}, "text": "Люблю музыку"})
        self.assertEqual(bot.FLOWS[100]["step"], "photo")
        with patch.object(bot, "callback_ack"):
            bot.on_callback(
                self.query("dating_photo_skip", message_id=bot.FLOWS[100]["form_message_id"])
            )
        self.assertEqual(bot.FLOWS[100]["step"], "confirm")
        self.assertEqual(bot.FLOWS[100]["data"]["gender"], "Муж")

    def test_dating_keyboards_match_reference_layout(self):
        reply_markup = bot.dating_reply_keyboard()
        self.assertEqual(
            [[item["text"] for item in row] for row in reply_markup["keyboard"]],
            [["👍", "👎"], ["💤"]],
        )
        self.assertTrue(reply_markup["is_persistent"])
        profile = {
            "profile_code": "5EXRO",
            "published": True,
            "name": "Иван",
            "age": "32",
            "gender": "Муж",
            "about": "Хорош во всем)))",
        }
        inline_markup = bot.dating_profile_actions_keyboard(profile)
        self.assertEqual(
            [[item["text"] for item in row] for row in inline_markup["inline_keyboard"]],
            [
                ["👤 Имя", "⚧️ Пол"],
                ["🎂 Возраст", "📝 О себе"],
                ["🖼️ Фото"],
                ["🗑️ Удалить анкету"],
                ["Главное меню"],
            ],
        )
        self.assertIn("Анкета #5EXRO", bot.dating_profile_text(profile))
        self.assertIn("Пол: Муж", bot.dating_profile_text(profile))

    @patch.object(bot, "send_photo_by_id")
    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_dating_creation_accepts_largest_photo(self, send, callback_ack, send_photo_by_id):
        send.side_effect = self.fake_send
        send_photo_by_id.return_value = {"message_id": 900}
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.start_dating(100)
            bot.on_message({"chat": {"id": 100}, "message_id": 10, "text": "Анна"})
            bot.on_message({"chat": {"id": 100}, "message_id": 11, "text": "28"})
            bot.on_callback(
                self.query("dating_gender:female", message_id=bot.FLOWS[100]["form_message_id"])
            )
            bot.on_message({"chat": {"id": 100}, "message_id": 12, "text": "Люблю концерты"})
            bot.on_message(
                {
                    "chat": {"id": 100},
                    "from": {"id": 100, "username": "anna_test"},
                    "message_id": 13,
                    "photo": [{"file_id": "small"}, {"file_id": "largest"}],
                }
            )
        self.assertEqual(bot.FLOWS[100]["step"], "confirm")
        self.assertEqual(bot.FLOWS[100]["data"]["photo_file_id"], "largest")
        self.assertEqual(send_photo_by_id.call_args.args[1], "largest")

    @patch.object(bot, "send_photo_by_id")
    @patch.object(bot, "send")
    def test_dating_field_edit_preserves_other_data(self, send, send_photo_by_id):
        send.side_effect = self.fake_send
        send_photo_by_id.return_value = {"message_id": 901}
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            original = {
                "created_at": 1,
                "chat_id": 100,
                "profile_code": "ABCDE",
                "published": True,
                "name": "Старое имя",
                "age": "29",
                "gender": "Жен",
                "about": "Текст",
                "photo_file_id": "photo-1",
            }
            bot.append_jsonl(Path(temp_dir) / "dating_profiles.jsonl", original)
            self.assertTrue(bot.start_dating_edit(100, "name"))
            bot.on_message(
                {"chat": {"id": 100}, "from": {"id": 100}, "message_id": 20, "text": "Новое имя"}
            )
            updated = bot.latest_dating_profile(100)
        self.assertEqual(updated["name"], "Новое имя")
        self.assertEqual(updated["profile_code"], "ABCDE")
        self.assertEqual(updated["age"], "29")
        self.assertEqual(updated["gender"], "Жен")
        self.assertEqual(updated["photo_file_id"], "photo-1")

    @patch.object(bot, "send")
    def test_dating_reactions_advance_and_exclude_seen_profiles(self, send):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            for chat_id, code, created_at in ((100, "AAAAA", 1), (200, "BBBBB", 2), (300, "CCCCC", 3)):
                bot.append_jsonl(
                    Path(temp_dir) / "dating_profiles.jsonl",
                    {
                        "created_at": created_at,
                        "chat_id": chat_id,
                        "profile_code": code,
                        "published": True,
                        "name": code,
                        "age": "30",
                        "gender": "Муж",
                        "about": "Тест",
                    },
                )
            self.assertTrue(bot.show_next_dating_profile(100))
            self.assertEqual(bot.DATING_BROWSE[100], "BBBBB")
            bot.handle_dating_reaction(100, "👍", 30)
            self.assertEqual(bot.DATING_BROWSE[100], "CCCCC")
            bot.handle_dating_reaction(100, "👎", 31)
            self.assertNotIn(100, bot.DATING_BROWSE)
            reactions = bot.dating_reactions_for(100)
            self.assertEqual([item["action"] for item in reactions], ["like", "skip"])
            self.assertEqual(bot.available_dating_profiles(100), [])

    @patch.object(bot, "send")
    def test_mutual_like_notifies_both_without_early_contact_disclosure(self, send):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            first = {
                "created_at": 1,
                "chat_id": 100,
                "profile_code": "AAAAA",
                "published": True,
                "name": "Анна",
                "age": "30",
                "gender": "Жен",
                "about": "Тест",
            }
            second = {
                "created_at": 2,
                "chat_id": 200,
                "profile_code": "BBBBB",
                "published": True,
                "name": "Иван",
                "age": "31",
                "gender": "Муж",
                "about": "Тест",
            }
            bot.append_jsonl(Path(temp_dir) / "dating_profiles.jsonl", first)
            bot.append_jsonl(Path(temp_dir) / "dating_profiles.jsonl", second)
            bot.append_jsonl(
                Path(temp_dir) / "dating_reactions.jsonl",
                {
                    "created_at": 3,
                    "chat_id": 200,
                    "actor_profile_code": "BBBBB",
                    "target_profile_code": "AAAAA",
                    "action": "like",
                },
            )
            bot.DATING_BROWSE[100] = "BBBBB"
            self.assertTrue(bot.record_dating_reaction(100, "like"))
            matches = bot.read_jsonl(Path(temp_dir) / "dating_matches.jsonl")
        self.assertEqual(len(matches), 1)
        match_messages = [item for item in self.sent if "Взаимная симпатия" in item[1]]
        self.assertEqual({item[0] for item in match_messages}, {100, 200})
        self.assertTrue(all("tg://user?id=" in item[2]["inline_keyboard"][0][0]["url"] for item in match_messages))

    def test_legacy_dating_profile_is_not_published_automatically(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.append_jsonl(
                Path(temp_dir) / "dating_profiles.jsonl",
                {"created_at": 1, "chat_id": 200, "name": "Старая", "age": "25", "about": "—"},
            )
            profile = bot.latest_dating_profile(200)
            candidates = bot.available_dating_profiles(100)
        self.assertFalse(profile["published"])
        self.assertRegex(profile["profile_code"], r"^[A-Z0-9]{5}$")
        self.assertEqual(candidates, [])

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_dating_is_private_chat_only(self, send, callback_ack):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            for chat_type in ("group", "supergroup", "channel"):
                with self.subTest(chat_type=chat_type):
                    bot.FLOWS.clear()
                    bot.DATING_BROWSE.clear()
                    bot.on_callback(self.query("dating_start", chat_type=chat_type))
                    self.assertNotIn(100, bot.FLOWS)
                    self.assertFalse((Path(temp_dir) / "dating_profiles.jsonl").exists())
                    self.assertTrue(callback_ack.call_args.args[-1])

            bot.DATING_BROWSE[100] = "ABCDE"
            bot.DATING_CARD_MESSAGE_IDS[100] = 55
            bot.on_message(
                {"chat": {"id": 100, "type": "supergroup"}, "message_id": 56, "text": "👍"}
            )
            self.assertEqual(bot.DATING_BROWSE[100], "ABCDE")
            self.assertEqual(bot.DATING_CARD_MESSAGE_IDS[100], 55)
            self.assertFalse((Path(temp_dir) / "dating_reactions.jsonl").exists())
            bot.on_message({"chat": {"id": 100, "type": "group"}, "text": "/profile"})
        self.assertTrue(all("только в личном чате" in item[1] for item in self.sent))

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_dating_flow_callbacks_require_current_form_message(self, send, callback_ack):
        send.side_effect = self.fake_send
        bot.FLOWS[100] = {
            "type": "dating",
            "mode": "create",
            "step": "gender",
            "form_message_id": 501,
            "data": {"profile_code": "ABCDE", "name": "Анна", "age": "30"},
        }
        bot.on_callback(self.query("dating_gender:female", message_id=500))
        self.assertEqual(bot.FLOWS[100]["step"], "gender")
        self.assertNotIn("gender", bot.FLOWS[100]["data"])
        self.assertTrue(callback_ack.call_args.args[-1])

        bot.on_callback(self.query("dating_gender:female", message_id=501))
        self.assertEqual(bot.FLOWS[100]["step"], "about")
        self.assertEqual(bot.FLOWS[100]["data"]["gender"], "Жен")

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_stale_confirmation_cannot_replace_profile(self, send, callback_ack):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            path = Path(temp_dir) / "dating_profiles.jsonl"
            bot.append_jsonl(
                path,
                {
                    "created_at": 1,
                    "chat_id": 100,
                    "profile_code": "OLD25",
                    "published": True,
                    "name": "Старая",
                    "age": "25",
                    "gender": "Жен",
                    "about": "Текст",
                },
            )
            bot.FLOWS[100] = {
                "type": "dating",
                "mode": "create",
                "step": "confirm",
                "form_message_id": 700,
                "data": {
                    "profile_code": "NEW26",
                    "name": "Новая",
                    "age": "26",
                    "gender": "Жен",
                    "about": "Музыка",
                },
            }
            before = path.read_bytes()
            bot.on_callback(self.query("dating_confirm", message_id=699))
            self.assertEqual(path.read_bytes(), before)
            self.assertIn(100, bot.FLOWS)

            bot.on_callback(self.query("dating_confirm", message_id=700))
            self.assertEqual(bot.latest_dating_profile(100)["profile_code"], "NEW26")
            self.assertNotIn(100, bot.FLOWS)

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send")
    def test_old_profile_buttons_cannot_touch_recreated_profile(self, send, callback_ack):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            old_profile = {
                "created_at": 1,
                "chat_id": 100,
                "profile_code": "AAAAA",
                "published": True,
                "name": "Старая",
                "age": "30",
                "gender": "Жен",
                "about": "Текст",
            }
            bot.append_jsonl(Path(temp_dir) / "dating_profiles.jsonl", old_profile)
            bot.show_dating_profile(100)
            old_action_message_id = bot.DATING_OWN_MESSAGE_IDS[100][-1]
            old_delete_callback = next(
                item["callback_data"]
                for row in bot.dating_profile_actions_keyboard(old_profile)["inline_keyboard"]
                for item in row
                if "Удалить" in item["text"]
            )
            bot.delete_dating_profile(100)
            new_profile = {**old_profile, "created_at": 2, "profile_code": "NEW99", "name": "Новая"}
            bot.save_dating_profile(new_profile)

            bot.on_callback(self.query(old_delete_callback, message_id=old_action_message_id))
            current = bot.latest_dating_profile(100)
        self.assertEqual(current["profile_code"], "NEW99")
        self.assertEqual(current["name"], "Новая")
        self.assertTrue(callback_ack.call_args.args[-1])

    @patch.object(bot, "delete_messages_safely")
    def test_delete_profile_evicts_viewers_and_preserves_unrelated_state(self, delete_messages):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.append_jsonl(
                Path(temp_dir) / "dating_profiles.jsonl",
                {
                    "created_at": 1,
                    "chat_id": 100,
                    "profile_code": "AAAAA",
                    "published": True,
                    "name": "Анна",
                    "age": "30",
                    "gender": "Жен",
                    "about": "Текст",
                },
            )
            bot.DATING_BROWSE.update({200: "AAAAA", 300: "AAAAA", 400: "DDDDD"})
            bot.DATING_CARD_MESSAGE_IDS.update({200: 20, 300: 30, 400: 40})
            bot.DATING_OWN_MESSAGE_IDS[100] = [10, 11]
            self.assertTrue(bot.delete_dating_profile(100))
        self.assertNotIn(200, bot.DATING_BROWSE)
        self.assertNotIn(300, bot.DATING_BROWSE)
        self.assertEqual(bot.DATING_BROWSE[400], "DDDDD")
        self.assertNotIn(200, bot.DATING_CARD_MESSAGE_IDS)
        self.assertNotIn(300, bot.DATING_CARD_MESSAGE_IDS)
        self.assertEqual(bot.DATING_CARD_MESSAGE_IDS[400], 40)
        self.assertNotIn(100, bot.DATING_OWN_MESSAGE_IDS)
        calls = [item.args for item in delete_messages.call_args_list]
        self.assertIn((200, [20]), calls)
        self.assertIn((300, [30]), calls)
        self.assertIn((100, [10, 11]), calls)

    @patch.object(bot, "delete_messages_safely")
    @patch.object(bot, "send")
    def test_repeated_profile_render_cleans_previous_card_and_actions(self, send, delete_messages):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.append_jsonl(
                Path(temp_dir) / "dating_profiles.jsonl",
                {
                    "created_at": 1,
                    "chat_id": 100,
                    "profile_code": "AAAAA",
                    "published": True,
                    "name": "Анна",
                    "age": "30",
                    "gender": "Жен",
                    "about": "Текст",
                },
            )
            bot.show_dating_profile(100)
            first_ids = list(bot.DATING_OWN_MESSAGE_IDS[100])
            bot.show_dating_profile(100)
        self.assertEqual(first_ids, [1, 2])
        self.assertIn((100, first_ids), [item.args for item in delete_messages.call_args_list])
        self.assertEqual(bot.DATING_OWN_MESSAGE_IDS[100], [3, 4])

    @patch.object(bot, "send")
    def test_swipe_emojis_are_not_saved_during_profile_edit(self, send):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            profile = {
                "created_at": 1,
                "chat_id": 100,
                "profile_code": "AAAAA",
                "published": True,
                "name": "Анна",
                "age": "30",
                "gender": "Жен",
                "about": "Текст",
                "photo_file_id": "photo-old",
            }
            bot.append_jsonl(Path(temp_dir) / "dating_profiles.jsonl", profile)
            self.assertTrue(bot.start_dating_edit(100, "name"))
            bot.on_message(
                {"chat": {"id": 100, "type": "private"}, "message_id": 80, "text": "👍"}
            )
            self.assertEqual(bot.FLOWS[100]["step"], "name")
            self.assertEqual(bot.FLOWS[100]["data"]["name"], "Анна")
            self.assertEqual(bot.latest_dating_profile(100)["name"], "Анна")

            bot.FLOWS.pop(100)
            self.assertTrue(bot.start_dating_edit(100, "photo"))
            bot.on_message(
                {"chat": {"id": 100, "type": "private"}, "message_id": 81, "text": "💤"}
            )
            self.assertEqual(bot.FLOWS[100]["step"], "photo")
            self.assertEqual(bot.FLOWS[100]["data"]["photo_file_id"], "photo-old")
            self.assertFalse((Path(temp_dir) / "dating_reactions.jsonl").exists())

    def test_dating_card_text_stays_within_telegram_caption_limit(self):
        profile = {
            "profile_code": "ABCDE",
            "name": "<&😀" * 100,
            "age": "123456",
            "gender": "Очень длинное значение" * 10,
            "about": "😀<&" * 1000,
        }
        rendered = bot.dating_profile_text(profile, "Проверьте анкету:\n\n")
        plain = __import__("html").unescape(rendered)
        self.assertLessEqual(len(plain.encode("utf-16-le")) // 2, 1024)
        self.assertNotIn("<&", rendered)

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send_request_qr")
    @patch.object(bot, "send")
    def test_confirmed_booking_is_tagged_krasnodar(self, send, send_request_qr, callback_ack):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)), patch.object(
            bot, "ADMIN_CHAT_ID", ""
        ):
            bot.FLOWS[100] = {
                "type": "booking",
                "kind": "VR Arena",
                "step": "confirm",
                "data": {
                    "name": "Тест",
                    "phone": "+79990000000",
                    "datetime": "20 августа 19:00",
                    "guests": "4",
                    "comment": "нет",
                },
            }
            bot.on_callback(self.query("booking_confirm"))
            record = bot.booking_by_code(next(iter(bot.storage().bookings_for_chat(100)))["request_code"])
        self.assertEqual(record["city"], "Краснодар")
        self.assertEqual(record["kind"], "VR Arena")
        self.assertEqual(record["status"], "received")
        self.assertTrue(record["request_code"].startswith("MKR-"))
        send_request_qr.assert_called_once()

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "send_request_qr")
    @patch.object(bot, "send")
    def test_recent_duplicate_booking_is_not_saved_twice(self, send, send_request_qr, callback_ack):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            flow = {
                "type": "booking",
                "kind": "Рестобар",
                "step": "confirm",
                "data": {
                    "name": "Тест",
                    "phone": "+79990000000",
                    "datetime": "20 августа 19:00",
                    "guests": "4",
                    "comment": "нет",
                },
            }
            bot.FLOWS[100] = json.loads(json.dumps(flow))
            bot.on_callback(self.query("booking_confirm"))
            bot.FLOWS[100] = json.loads(json.dumps(flow))
            bot.on_callback(self.query("booking_confirm"))
            records = bot.read_jsonl(Path(temp_dir) / "bookings.jsonl")
        self.assertEqual(len(records), 1)
        self.assertIn("Повторно создавать", self.sent[-1][1])

    @patch.object(bot, "send_request_qr")
    @patch.object(bot, "send")
    def test_my_qr_returns_only_current_users_requests(self, send, send_request_qr):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            path = Path(temp_dir) / "bookings.jsonl"
            bot.append_jsonl(path, {"chat_id": 999, "request_code": "MKR-OTHER"})
            bot.append_jsonl(path, {"chat_id": 100, "request_code": "MKR-MINE", "kind": "Караоке"})
            found = bot.show_my_qr(100)
        self.assertTrue(found)
        self.assertEqual(send_request_qr.call_count, 1)
        self.assertEqual(send_request_qr.call_args.args[1]["request_code"], "MKR-MINE")

    @patch.object(bot, "callback_ack")
    @patch.object(bot, "edit_message")
    @patch.object(bot, "send")
    def test_dating_profile_can_be_replaced_and_deleted(self, send, edit_message, callback_ack):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            path = Path(temp_dir) / "dating_profiles.jsonl"
            bot.append_jsonl(path, {"chat_id": 100, "name": "Старая", "age": "25", "about": "—"})
            bot.FLOWS[100] = {
                "type": "dating",
                "mode": "create",
                "step": "confirm",
                "form_message_id": 700,
                "data": {
                    "profile_code": "NEW26",
                    "name": "Новая",
                    "age": "26",
                    "gender": "Жен",
                    "about": "Музыка",
                },
            }
            bot.on_callback(self.query("dating_confirm", message_id=700))
            self.assertEqual(len(bot.read_jsonl(path)), 1)
            self.assertEqual(bot.latest_dating_profile(100)["name"], "Новая")
            action_message_id = bot.DATING_OWN_MESSAGE_IDS[100][-1]
            bot.on_callback(
                self.query("dating_delete_confirm:NEW26", message_id=action_message_id)
            )
            bot.on_callback(self.query("dating_delete:NEW26", message_id=action_message_id))
            self.assertIsNone(bot.latest_dating_profile(100))

    def test_generated_qr_is_a_valid_png_shape(self):
        matrix = make_matrix("https://t.me/Mishkinkrd_bot?start=qr_MKR-1234567890")
        self.assertEqual(len(matrix), 37)
        self.assertTrue(all(len(row) == 37 for row in matrix))
        with tempfile.TemporaryDirectory() as temp_dir:
            path = write_png("https://t.me/Mishkinkrd_bot?start=qr_MKR-1234567890", Path(temp_dir) / "qr.png")
            data = path.read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", data[16:24]), (360, 360))

    def test_maintenance_creates_health_and_daily_backup(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.append_jsonl(Path(temp_dir) / "bookings.jsonl", {"chat_id": 100})
            bot.perform_maintenance(force=True)
            backups = list((Path(temp_dir) / "backups").glob("*/bookings.jsonl"))
            self.assertEqual(len(backups), 1)
            health = json.loads((Path(temp_dir) / "health.json").read_text(encoding="utf-8"))
        self.assertEqual(health["status"], "ok")

    def test_only_whitelisted_notification_accounts_are_registered(self):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            self.assertTrue(
                bot.register_notification_recipient({"id": 501, "username": "Studio_Goroda", "is_bot": False})
            )
            self.assertTrue(bot.register_notification_recipient({"id": 502, "username": "grunvald", "is_bot": False}))
            self.assertFalse(bot.register_notification_recipient({"id": 503, "username": "visitor", "is_bot": False}))
            self.assertFalse(bot.register_notification_recipient({"id": 501, "username": "studio_goroda"}))
            self.assertFalse(bot.register_notification_recipient({"id": 999, "username": "studio_goroda"}))
            recipients = bot.notification_recipients()
        self.assertEqual(recipients, {"grunvald": 502, "studio_goroda": 501})

    @patch.object(bot, "send")
    def test_booking_notification_is_sent_to_both_accounts(self, send):
        send.side_effect = self.fake_send
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)), patch.object(
            bot, "ADMIN_CHAT_ID", ""
        ):
            bot.register_notification_recipient({"id": 501, "username": "studio_goroda"})
            bot.register_notification_recipient({"id": 502, "username": "grunvald"})
            delivered = bot.notify_booking({"request_code": "MKR-TEST", "kind": "Рестобар"})
            deliveries = bot.read_jsonl(Path(temp_dir) / "notification_deliveries.jsonl")
        self.assertEqual(delivered, 2)
        self.assertEqual({item[0] for item in self.sent}, {501, 502})
        self.assertEqual(len(deliveries), 2)
        self.assertTrue(all(item["status"] == "delivered" for item in deliveries))
        self.assertTrue(all("created_at:" not in item[1] for item in self.sent))
        self.assertTrue(all("chat_id:" not in item[1] for item in self.sent))
        self.assertTrue(all("<b>Направление:</b>" in item[1] for item in self.sent))
        labels = [
            button["text"]
            for row in self.sent[0][2]["inline_keyboard"]
            for button in row
        ]
        self.assertIn("🙋 Взять в работу", labels)
        self.assertNotIn("✅ Подтвердить бронь", labels)

    @patch.object(bot, "notify_client_booking_status")
    @patch.object(bot, "refresh_manager_notifications")
    @patch.object(bot, "callback_ack")
    def test_manager_can_confirm_booking(self, callback_ack, refresh_manager_notifications, notify_client):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.register_notification_recipient({"id": 502, "username": "grunvald", "is_bot": False})
            bot.append_jsonl(
                Path(temp_dir) / "bookings.jsonl",
                {
                    "chat_id": 100,
                    "request_code": "MKR-TEST",
                    "status": "received",
                    "datetime": "28 августа 2026, 21:00",
                },
            )
            bot.on_callback(self.query("bst:confirmed:MKR-TEST", username="grunvald", user_id=502))
            updated = bot.booking_by_code("MKR-TEST")
        self.assertEqual(updated["status"], "confirmed")
        self.assertEqual(updated["status_updated_by"], "@grunvald")
        refresh_manager_notifications.assert_called_once()
        notify_client.assert_called_once()
        self.assertIn("подтверждена", callback_ack.call_args.args[1].lower())

    @patch.object(bot, "callback_ack")
    def test_non_manager_cannot_change_booking_status(self, callback_ack):
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(bot, "DATA", Path(temp_dir)):
            bot.append_jsonl(
                Path(temp_dir) / "bookings.jsonl",
                {"chat_id": 100, "request_code": "MKR-TEST", "status": "received"},
            )
            bot.on_callback(self.query("bst:cancelled:MKR-TEST", username="visitor", user_id=999))
            unchanged = bot.booking_by_code("MKR-TEST")
        self.assertEqual(unchanged["status"], "received")
        self.assertTrue(callback_ack.call_args.args[2])

    def test_qr_caption_explains_storage_and_confirmation(self):
        caption = bot.request_caption(
            {
                "request_code": "MKR-TEST",
                "kind": "Рестобар",
                "datetime": "28 августа 2026, 21:00",
                "status": "received",
            }
        )
        self.assertIn("Мои QR", caption)
        self.assertIn("не подтверждает бронь", caption)

    def test_no_omsk_content_remains(self):
        texts = [value for name, value in vars(bot).items() if name.endswith("_TEXT") and isinstance(value, str)]
        combined = "\n".join(texts)
        self.assertNotIn("Омск", combined)
        self.assertNotIn("Кемеровская", combined)
        self.assertNotIn("3812", combined)
        self.assertIn("Краснодар", combined)
        self.assertIn("Лаперуза", combined)

    def test_official_links_and_message_limits(self):
        self.assertEqual(bot.SITE_URL, "https://mishkinkrd.ru")
        self.assertEqual(bot.TELEGRAM_URL, "https://t.me/mishkinkrd")
        self.assertIn("zchn0245", bot.LOYALTY_URL)
        texts = [value for name, value in vars(bot).items() if name.endswith("_TEXT") and isinstance(value, str)]
        for text in texts:
            self.assertLessEqual(len(text), 4096)

    def test_pdf_menus_and_food_details_are_current(self):
        expected_files = {
            "restobar_menu.pdf",
            "kids_menu.pdf",
            "food_menu_july_2026.pdf",
            "bar_menu_august_2026.pdf",
        }
        actual_files = {item[0].name for item in bot.MENU_DOCUMENTS.values()}
        self.assertEqual(actual_files, expected_files)
        for path, _caption, _return_to in bot.MENU_DOCUMENTS.values():
            self.assertTrue(path.is_file(), path)
            self.assertGreater(path.stat().st_size, 100_000)
        self.assertIn("10:00–22:00", bot.FOOD_TEXT)
        self.assertIn("+7 (966) 740-03-03", bot.FOOD_TEXT)
        self.assertIn("+7 (966) 740-03-03", bot.CONTACTS_TEXT)

    @patch.object(bot, "api_multipart")
    def test_send_document_uses_telegram_upload(self, api_multipart):
        path = bot.ASSETS / "restobar_menu.pdf"
        bot.send_document(100, path, "Меню", bot.back("restobar"))
        method, fields, file_field, sent_path = api_multipart.call_args.args
        self.assertEqual(method, "sendDocument")
        self.assertEqual(fields["chat_id"], 100)
        self.assertEqual(file_field, "document")
        self.assertEqual(sent_path, path)
        self.assertIn("reply_markup", fields)

    @patch.object(bot, "api")
    def test_edit_message_uses_telegram_edit_api(self, api):
        bot.edit_message(100, 777, "Календарь", bot.booking_calendar(2026, 8, dt.date(2026, 8, 21)))
        method, payload = api.call_args.args
        self.assertEqual(method, "editMessageText")
        self.assertEqual(payload["message_id"], 777)


if __name__ == "__main__":
    unittest.main()
