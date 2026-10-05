#!/usr/bin/env python3
"""Telegram bot for Mishkin&Mishkin Krasnodar.

Content and links are adapted from https://mishkinkrd.ru and the linked
Krasnodar Drive Karting website. Only Python's standard library is required.
"""

from __future__ import annotations

import calendar
import datetime as dt
import html
import json
import mimetypes
import os
import pathlib
import re
import shutil
import sys
import time
import urllib.error
import urllib.request
import uuid

from qrmini import write_png
from storage import LEGACY_DATASETS, SQLiteStorage


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent
DATA = ROOT / "data"
ASSETS = ROOT / "assets"
DATA.mkdir(exist_ok=True)

_STORAGE: SQLiteStorage | None = None
_STORAGE_ROOT: pathlib.Path | None = None


def storage() -> SQLiteStorage:
    """Return storage for the current DATA directory (tests replace DATA)."""
    global _STORAGE, _STORAGE_ROOT
    current_root = pathlib.Path(DATA).resolve()
    if _STORAGE is None or _STORAGE_ROOT != current_root:
        _STORAGE = SQLiteStorage(current_root)
        _STORAGE_ROOT = current_root
    return _STORAGE


def reset_storage_cache() -> None:
    """Forget the repository instance; primarily useful for migration tests."""
    global _STORAGE, _STORAGE_ROOT
    _STORAGE = None
    _STORAGE_ROOT = None


def load_env(path: pathlib.Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env(ROOT / "settings.env")
TOKEN = <REDACTED>
ADMIN_CHAT_ID = os.environ.get("ADMIN_CHAT_ID", "").strip()
NOTIFICATION_USERNAMES = {
    value.strip().lstrip("@").lower()
    for value in os.environ.get("NOTIFICATION_USERNAMES", "studio_goroda,grunvald").split(",")
    if value.strip()
}
BOT_API = f"https://api.telegram.org/bot{TOKEN}"

SITE_URL = "https://mishkinkrd.ru"
KARTING_URL = "https://krasnodar.drivekarting.ru/kartingdrive"
MAP_URL = "https://yandex.ru/maps/-/CHhcFGPj"
TELEGRAM_URL = "https://t.me/mishkinkrd"
VK_URL = "https://vk.com/mishkinkrasnodar"
LOYALTY_URL = "https://mishkinmishkin.uds.app/c/join?ref=zchn0245"
GIFT_URL = "https://mishkinkrd.ru/gift-certificate"
BOT_USERNAME = "Mishkinkrd_bot"
BOT_API_TARGET_VERSION = "10.3"
BACKUP_RETENTION_DAYS = 14


def button(
    text: str,
    *,
    callback: str | None = None,
    url: str | None = None,
    style: str | None = None,
    disabled: bool = False,
) -> dict:
    if disabled and (callback is not None or url is not None):
        raise ValueError("Отключённая кнопка не может содержать действие")
    item = {"text": text}
    if callback is not None:
        item["callback_data"] = callback
    if url is not None:
        item["url"] = url
    if disabled:
        item["disabled"] = {}
    if style is None and not disabled and callback != "noop" and (callback is not None or url is not None):
        lowered = text.lower()
        if any(word in lowered for word in ("назад", "отмен", "удал", "главное меню")):
            style = "danger"
        elif any(
            word in lowered
            for word in ("бронь", "заброн", "оставить", "подтверд", "согласен", "получить", "сохранить", "рассчитать")
        ):
            style = "success"
        else:
            style = "primary"
    if style:
        if style not in {"primary", "success", "danger"}:
            raise ValueError(f"Неизвестный стиль кнопки: {style}")
        item["style"] = style
    return item


def keyboard(*rows: list[dict], force_reply: bool = False) -> dict:
    markup: dict = {"inline_keyboard": list(rows)}
    if force_reply:
        markup["force_reply"] = True
    return markup


def back(callback: str = "main", label: str = "Назад", *, force_reply: bool = False) -> dict:
    return keyboard([button(label, callback=callback, style="danger")], force_reply=force_reply)


MAIN_KB = keyboard(
    [button("Рестобар", callback="restaurant"), button("Банкеты и ДР", callback="banquets")],
    [button("Танцевальные выходные", callback="dance")],
    [button("Караоке-холл", callback="karaoke"), button("Картинг", callback="karting")],
    [button("Арена VR и автосимуляторы", callback="arena")],
    [button("Мишкин Парк", callback="park"), button("Фуд Мишкин", callback="food")],
    [button("Дым Мишкин", callback="lounge"), button("Подарочный сертификат", callback="gift")],
    [button("О нас", callback="about"), button("Мои QR", callback="my_qr")],
    [button("Знакомства", callback="dating")],
    [button("Поддержка", callback="support")],
    [button("Карта лояльности UDS", callback="loyalty")],
)

MAIN_TEXT = (
    "Добро пожаловать в событийный комплекс Mishkin&amp;Mishkin Краснодар 🌟\n\n"
    f'Быть в курсе Мишкина всегда — <a href="{TELEGRAM_URL}">подписывайтесь на Telegram</a>.\n\n'
    "📞 Написать и позвонить нам: +7 (989) 021-03-03\n"
    "📍 Краснодар, ул. Лаперуза, 3\n\n"
    "Забронировать | узнать подробности | участвовать в акциях ⬇️"
)

PRIVACY_TEXT = (
    "🔐 <b>Согласие на обработку данных</b>\n\n"
    "Для бронирования и анкет бот может запросить имя, телефон и сведения о событии. "
    "Они используются только для связи с вами и организации выбранной услуги.\n\n"
    "Нажимая «Согласен», вы разрешаете обработку переданных вами данных. "
    "Не отправляйте в бот паспортные, банковские и другие лишние сведения. "
    "После отдельного сохранения анкета знакомств (имя, возраст, пол, описание и фото) "
    "становится видна другим совершеннолетним участникам раздела. Контакт Telegram открывается "
    "только при взаимной симпатии. Анкету можно изменить или удалить в любое время."
)

RESTOBAR_TEXT = (
    "🍽 <b>Рестобар Mishkin&amp;Mishkin</b>\n\n"
    "Танцевальный рестобар и место событий. В меню — блюда европейской и южной кухни, "
    "большой контактный бар и библиотека пенного.\n\n"
    "Вечером атмосферу создают вокалисты и диджеи, а по выходным проходит насыщенная "
    "программа с приглашёнными артистами. Площадка подходит для индивидуальных событий, "
    "корпоративов, концертов и мероприятий любого формата.\n\n"
    "🕒 Вс–Чт: 12:00–00:00\n"
    "🕒 Пт–Сб: 12:00–05:00\n"
    "📞 Бронь: +7 (989) 021-03-03"
)

BANQUETS_TEXT = (
    "🎉 <b>Банкеты и дни рождения</b>\n\n"
    "В Mishkin&amp;Mishkin можно провести семейный праздник, детский день рождения, банкет, "
    "корпоратив, тимбилдинг или индивидуальное событие.\n\n"
    "Доступны рестобар, караоке-холл, Мишкин Парк, картинг и VR Arena. Команда поможет "
    "подобрать пространство, программу и меню под формат события.\n\n"
    "📞 +7 (989) 021-03-03"
)

DANCE_TEXT = (
    "💃 <b>Танцевальные выходные</b>\n\n"
    "По пятницам, субботам и в праздничные дни в рестобаре проходят вечеринки, "
    "Mishkin Show, диджей-сеты и выступления приглашённых артистов.\n\n"
    "🕒 Пт–Сб: 19:00–05:00\n"
    "📞 Бронь столов: +7 (989) 021-03-03"
)

ARENA_TEXT = (
    "🥽 <b>Арена VR и автосимуляторы</b>\n\n"
    "VR-арена площадью 160 м² принимает до 10 игроков одновременно, возраст — от 7 лет. "
    "Также в Мишкин Парке доступны автосимуляторы с заездами на 15, 30 и 60 минут.\n\n"
    "📞 +7 (995) 202-03-03\n"
    "📍 Краснодар, ул. Лаперуза, 3"
)

RESTAURANT_PROMO_TEXT = (
    "🎁 <b>Акции рестобара</b>\n\n"
    "Актуальные акции, вечеринки и специальные события публикуются в официальном Telegram-канале "
    "и в афише комплекса. Для условий на выбранную дату можно оставить заявку менеджеру."
)

BANQUETS_PROMO_TEXT = (
    "🎂 <b>Готовые решения для событий</b>\n\n"
    "Для детских праздников доступны пакеты Мишкин Парка и VR Arena, а для банкетов и "
    "корпоративов — индивидуальный подбор зала, меню и программы.\n\n"
    "Оставьте заявку — менеджер уточнит актуальную стоимость и свободные даты."
)

DANCE_PROMO_TEXT = (
    "🔥 <b>Афиша и акции танцевальных выходных</b>\n\n"
    "Программа меняется каждую неделю. Актуальные артисты, время начала и специальные предложения "
    "размещаются в афише и официальном Telegram-канале."
)

KARAOKE_PROMO_TEXT = (
    "🎤 <b>События в караоке-холле</b>\n\n"
    "Караоке подходит для дней рождения, девичников, мальчишников и частных мероприятий. "
    "Менеджер подберёт формат и рассчитает условия на выбранную дату."
)

KARAOKE_TEXT = (
    "🎤 <b>Караоке-холл</b>\n\n"
    "Караоке-холл с профессиональной звуковой и видеоаппаратурой. Камерная атмосфера, "
    "мягкий свет софитов и сцена помогают раскрыть вокальные способности при деликатной "
    "поддержке опытных вокалистов.\n\n"
    "🕒 Вс–Чт: по запросу\n"
    "🕒 Пт–Сб: 19:00–05:00\n"
    "📞 Бронь: +7 (989) 021-03-03"
)

KARTING_TEXT = (
    "🏎 <b>Картинг-центр «Драйв»</b>\n\n"
    "Самый драйвовый картинг Краснодара: 4000 м² крытой трассы, трек длиной 450 метров, "
    "17 поворотов и современный парк взрослых, детских и двухместных картов Explorer.\n\n"
    "Профессиональный хронометраж фиксирует результат с точностью до 0,001 секунды. "
    "Можно проводить командные соревнования, тимбилдинги, корпоративы и дни рождения.\n\n"
    "🕒 Вс–Чт: 12:00–00:00\n"
    "🕒 Пт–Сб: 12:00–02:00\n"
    "📞 +7 (995) 202-03-03\n"
    "📍 Краснодар, ул. Лаперуза, 3"
)

KARTING_PRICES = (
    "🏁 <b>Цены картинга</b>\n\n"
    "<b>Пн–Пт до 18:00</b>\n"
    "• взрослый/детский карт, 10 мин — 1200 ₽\n"
    "• взрослый/детский карт, 15 мин — 1750 ₽\n"
    "• двухместный карт, 10 мин — 1600 ₽\n"
    "• аренда трассы, 30 мин — 13 500 ₽\n"
    "• аренда трассы, 60 мин — 26 000 ₽\n\n"
    "<b>После 18:00, выходные и праздники</b>\n"
    "• взрослый/детский карт, 10 мин — 1300 ₽\n"
    "• взрослый/детский карт, 15 мин — 1900 ₽\n"
    "• двухместный карт, 10 мин — 1800 ₽\n"
    "• аренда трассы, 30 мин — 18 500 ₽\n"
    "• аренда трассы, 60 мин — 36 000 ₽\n\n"
    "Аренда включает 5 картов. Доплата за каждый дополнительный карт — 3500 ₽. "
    "Общий вес пассажиров двухместного карта — не более 120 кг."
)

KARTING_ACADEMY = (
    "🏆 <b>Академия картинга</b>\n\n"
    "• пробное занятие: 10 минут заезда + 10 минут разбора — 2500 ₽\n"
    "• одно занятие в группе: 3 заезда по 10 минут + 30 минут теории — 4000 ₽\n"
    "• стандартная индивидуальная тренировка — 5000 ₽\n"
    "• расширенная индивидуальная тренировка — 6000 ₽\n"
    "• абонемент на 4 занятия — 14 000 ₽\n"
    "• абонемент на 8 занятий — 22 000 ₽\n\n"
    "Экипировка предоставляется центром. При покупке абонемента пробное занятие бесплатно."
)

PARK_TEXT = (
    "🎠 <b>Мишкин Парк</b>\n\n"
    "Территория детства и семейного отдыха в Mishkin&amp;Mishkin. Здесь работают картинг, "
    "дрифт-картинг, верёвочный парк, VR-арена, лазертаг, лабиринт, автосимуляторы, "
    "электромашинки, RC-джим, пинг-понг, бильярд и аэрохоккей.\n\n"
    "Для дней рождения доступны готовые пакеты, шоу-программы, интеллектуальные игры и мастер-классы."
)

PARK_PRICES_1 = (
    "🎟 <b>Мишкин Парк — активности</b>\n\n"
    "<b>Картинг, от 6 лет</b> — будни / выходные\n"
    "• 10 мин — 1200 / 1300 ₽\n"
    "• 15 мин — 1750 / 1900 ₽\n"
    "• двухместный, 10 мин — 1600 / 1800 ₽\n"
    "• школа картинга, 60 мин — 5000 ₽\n\n"
    "<b>Электродрифт</b>\n"
    "• 7 мин — 600 / 700 ₽\n"
    "• 14 мин — 1100 / 1300 ₽\n"
    "• 21 мин — 1650 / 1950 ₽\n"
    "• 28 мин — 2200 / 2600 ₽\n\n"
    "<b>Дополнительно</b>\n"
    "• верёвочный парк — 300 / 500 ₽\n"
    "• бильярд — 200 / 300 ₽\n"
    "• аэрохоккей — 300 / 500 ₽\n"
    "• детские электромашинки, 5 мин — 300 / 500 ₽\n"
    "• RC-машинки, 15 мин — 500 / 700 ₽; 30 мин — 700 / 1000 ₽\n"
    "• PlayStation, 1 час — 300 / 500 ₽\n"
    "• пинг-понг, 1 час — 500 / 700 ₽\n"
    "• караоке-холл, 1 час — 3000 / 5000 ₽"
)

PARK_PRICES_2 = (
    "🥽 <b>VR и автосимуляторы в Мишкин Парке</b>\n\n"
    "<b>VR-арена, от 7 лет</b>\n"
    "• аренда до 10 человек, 1 час — 10 000 / 12 000 ₽\n"
    "• один игрок, 1 час — 1000 / 1200 ₽\n\n"
    "<b>Автосимуляторы</b>\n"
    "• 15 мин — 400 ₽\n"
    "• 30 мин — 600 ₽\n"
    "• 60 мин — 800 ₽\n"
    "• 60 мин по абонементу — 650 ₽\n\n"
    "Первая цена действует в будни до 18:00, вторая — после 18:00, в выходные и праздники. "
    "В выходные и праздники картинг-заезды проводятся только по 10 минут."
)

PARK_PACKAGES = (
    "🎈 <b>Пакеты праздников Мишкин Парка</b>\n\n"
    "Цены: Пн–Чт / Пт–Вс и праздники.\n\n"
    "<b>Старт</b>: 6 чел — 15 000 / 18 000 ₽; 10 чел — 20 000 / 24 000 ₽; "
    "15 чел — 26 000 / 30 000 ₽.\n\n"
    "<b>Вечеринка</b>: 6 чел — 18 000 / 24 000 ₽; 10 чел — 26 000 / 30 000 ₽; "
    "15 чел — 30 000 / 34 000 ₽.\n\n"
    "<b>Праздник</b>: 6 чел — 24 000 / 28 000 ₽; 10 чел — 28 000 / 30 000 ₽; "
    "15 чел — 35 000 / 39 000 ₽.\n\n"
    "<b>VIP</b>: 10 чел — 50 000 / 60 000 ₽; 15 чел — 65 000 / 70 000 ₽.\n\n"
    "При заказе любого пакета: зона ресторана, нейропесня и встреча гостей фирменным Мишкой.\n\n"
    "Корпоратив «Стандарт» до 15 человек — 35 000 / 45 000 ₽. "
    "Корпоратив «Премиум» — 70 000 / 90 000 ₽."
)

PARK_PROGRAMS = (
    "🎉 <b>Программы Мишкин Парка</b>\n\n"
    "<b>Шоу:</b> Тренд-шоу (10–17 лет), Мега баттл (9–12 лет), Бумбокс шоу (18+), "
    "«Мам, я блоггер» (10–16 лет), Мафия (9+) и Бункер (9+).\n\n"
    "<b>Интеллектуальные игры:</b> Квиз, Музлото и Крейзи-квиз.\n\n"
    "<b>Мастер-классы:</b> Мишкин значок, Мишкин стиль, Трендовый мишка, Мишкин слайм, "
    "авторские брелки и бомбочки для ванны.\n\n"
    "Команда поможет подобрать программу под возраст и интересы ребёнка."
)

FOOD_TEXT = (
    "🍔 <b>Фуд Мишкин</b>\n\n"
    "Кафе быстрого питания навынос. В актуальном меню: завтраки, выпечка, салаты, супы, "
    "гриль-боксы, горячие блюда, греческий фастфуд, хот-доги, шаурма, десерты и напитки.\n\n"
    "🕒 Ежедневно: 10:00–22:00\n"
    "📞 Предзаказ и доставка: +7 (966) 740-03-03\n"
    "📍 Краснодар, ул. Лаперуза, 3\n\n"
    "Доступна доставка через Яндекс Доставку."
)

LOUNGE_TEXT = (
    "💨 <b>Дым Мишкин</b>\n\n"
    "Пространство вкусов и ароматов.\n\n"
    "🕒 Вс–Чт: 12:00–00:00\n"
    "🕒 Пт–Сб: 21:00–05:00\n"
    "📞 Бронь: +7 (989) 021-03-03"
)

VR_TEXT = (
    "🥽 <b>VR Arena</b>\n\n"
    "Центр VR-развлечений и спорта: арена площадью 160 м², до 10 игроков одновременно, "
    "возраст участников — от 7 лет. Есть отдельная комната для праздников.\n\n"
    "Игры: «Вечеринка», «Батл», «Зомби», «Тактикс», «Побег из комнаты», «Зомби-Вегас» и другие.\n\n"
    "🕒 Ежедневно: 11:00–21:00\n"
    "📞 +7 (995) 202-03-03\n"
    "📍 Краснодар, ул. Лаперуза, 3"
)

VR_PRICES = (
    "🥽 <b>Цены VR Arena</b>\n\n"
    "Стоимость указана за одного игрока за 1 час:\n"
    "• Пн–Чт, 12:00–17:00 — 1000 ₽\n"
    "• Пн–Чт, 17:00–22:00 — 1200 ₽\n"
    "• Пт–Вс, 12:00–22:00 — 1200 ₽\n\n"
    "При организации застолья бронирование обязательно."
)

VR_PACKAGES = (
    "🎂 <b>Праздник под ключ в VR Arena</b>\n\n"
    "<b>Базовый</b> — 2 часа, 8 игроков и 8 сопровождающих: "
    "12 600 ₽ Пн–Чт / 15 600 ₽ Пт–Вс.\n\n"
    "<b>Премиум</b> — 2 часа, 12 игроков и 12 сопровождающих: "
    "16 600 ₽ / 19 600 ₽.\n\n"
    "<b>Элитный</b> — 3 часа, 16 игроков и 16 сопровождающих: "
    "24 200 ₽ / 29 600 ₽.\n\n"
    "В пакетах: командные VR-игры, комната отдыха, мастер-классы, праздничное оформление, "
    "сервировка стола, фотографии и музыкальное сопровождение."
)

EVENTS_TEXT = (
    "🎉 <b>Дни рождения и события</b>\n\n"
    "В Mishkin&amp;Mishkin можно провести детский день рождения, семейный праздник, "
    "корпоратив, тимбилдинг, концерт или индивидуальное событие.\n\n"
    "• рестобар оснащён для мероприятий любого формата;\n"
    "• в Мишкин Парке есть готовые пакеты и программы;\n"
    "• VR Arena предлагает праздники под ключ;\n"
    "• картинг проводит командные соревнования.\n\n"
    "Выберите подходящий формат или оставьте общую заявку."
)

GIFT_TEXT = (
    "🎁 <b>Подарочный сертификат Mishkin&amp;Mishkin</b>\n\n"
    "Сертификат действует 6 месяцев с момента покупки. После оплаты он автоматически "
    "приходит на указанную электронную почту и получает индивидуальный номер.\n\n"
    "Его можно распечатать, использовать частями и предъявлять несколько раз, пока на карте "
    "остаются средства. Сертификат нельзя обменять на деньги; он действует только в городе покупки.\n\n"
    "📞 Вопросы: +7 (995) 202-03-03"
)

ABOUT_TEXT = (
    "⭐ <b>Mishkin&amp;Mishkin Краснодар</b>\n\n"
    "Новое пространство для отдыха в Краснодаре: 5000 м² развлечений для всей семьи. "
    "Под одной крышей находятся рестобар, караоке, картинг, Мишкин Парк, Фуд Мишкин, "
    "Дым Мишкин и VR Arena.\n\n"
    "📍 Краснодар, ул. Лаперуза, 3\n"
    "📞 +7 (989) 021-03-03"
)

CONTACTS_TEXT = (
    "📍 <b>Контакты</b>\n\n"
    "Адрес: Краснодар, ул. Лаперуза, 3\n\n"
    "Общий номер и бронь рестобара/караоке:\n+7 (989) 021-03-03\n\n"
    "Картинг, VR и сертификаты:\n+7 (995) 202-03-03\n\n"
    "Фуд Мишкин — предзаказ и доставка:\n+7 (966) 740-03-03\n\n"
    f'<a href="{TELEGRAM_URL}">Telegram</a> · '
    f'<a href="{VK_URL}">ВКонтакте</a> · '
    f'<a href="{MAP_URL}">Открыть на карте</a>'
)

CONTACTS_RICH_HTML = (
    "<h3>Контакты Mishkin&amp;Mishkin Краснодар</h3>"
    "<p>Краснодар, ул. Лаперуза, 3</p>"
    "<table compact>"
    "<tr><th>Направление</th><th>Телефон</th></tr>"
    "<tr><td>Общий номер, рестобар и караоке</td><td>+7 (989) 021-03-03</td></tr>"
    "<tr><td>Картинг, VR и сертификаты</td><td>+7 (995) 202-03-03</td></tr>"
    "<tr><td>Фуд Мишкин: предзаказ и доставка</td><td>+7 (966) 740-03-03</td></tr>"
    "</table>"
    "<tg-button-row align=\"center\">"
    f'<tg-button type="url" style="primary" url="{MAP_URL}">Открыть карту</tg-button>'
    f'<tg-button type="url" style="primary" url="{TELEGRAM_URL}">Telegram</tg-button>'
    "</tg-button-row>"
)

LOYALTY_TEXT = (
    "💳 <b>Карта постоянного гостя</b>\n\n"
    "Присоединяйтесь к системе лояльности Mishkin&amp;Mishkin и получите 500 приветственных бонусных рублей.\n\n"
    "Карта оформляется по официальной ссылке UDS."
)


def api(method: str, payload: dict | None = None) -> dict:
    body = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"{BOT_API}/{method}", data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=40) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("ok"):
        raise RuntimeError(f"Telegram API {method}: {result}")
    return result["result"]


def api_multipart(method: str, fields: dict, file_field: str, file_path: pathlib.Path) -> dict:
    """Call Telegram Bot API with one uploaded file using only the standard library."""
    boundary = f"MishkinBotBoundary{uuid.uuid4().hex}"
    body = bytearray()

    for name, value in fields.items():
        body.extend(f"--{boundary}\r\n".encode("ascii"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        body.extend(str(value).encode("utf-8"))
        body.extend(b"\r\n")

    content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    body.extend(f"--{boundary}\r\n".encode("ascii"))
    body.extend(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{file_path.name}"\r\n'.encode("utf-8")
    )
    body.extend(f"Content-Type: {content_type}\r\n\r\n".encode("ascii"))
    body.extend(file_path.read_bytes())
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("ascii"))

    request = urllib.request.Request(
        f"{BOT_API}/{method}",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not result.get("ok"):
        raise RuntimeError(f"Telegram API {method}: {result}")
    return result["result"]


def send(chat_id: int | str, text: str, reply_markup: dict | None = None) -> dict:
    payload: dict = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return api("sendMessage", payload)


def send_rich(
    chat_id: int | str,
    rich_html: str,
    fallback_text: str,
    reply_markup: dict | None = None,
) -> dict:
    """Send a Bot API 10.3 rich message, falling back after an API-level rejection."""
    if not TOKEN:<REDACTED>
        return send(chat_id, fallback_text, reply_markup)
    payload: dict = {"chat_id": chat_id, "rich_message": {"html": rich_html}}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    try:
        return api("sendRichMessage", payload)
    except urllib.error.HTTPError as exc:
        if exc.code not in {400, 404}:
            raise
        print(f"Rich Message отклонено Telegram ({exc.code}), использован обычный текст", file=sys.stderr)
    except RuntimeError as exc:
        print(f"Rich Message недоступно, использован обычный текст: {exc}", file=sys.stderr)
    return send(chat_id, fallback_text, reply_markup)


def edit_message(chat_id: int | str, message_id: int, text: str, reply_markup: dict | None = None) -> dict:
    payload: dict = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return api("editMessageText", payload)


def send_document(
    chat_id: int | str,
    file_path: pathlib.Path,
    caption: str,
    reply_markup: dict | None = None,
) -> dict:
    if not file_path.is_file():
        raise FileNotFoundError(f"Файл меню не найден: {file_path}")
    fields: dict = {"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"}
    if reply_markup:
        fields["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    return api_multipart("sendDocument", fields, "document", file_path)


def send_photo(
    chat_id: int | str,
    file_path: pathlib.Path,
    caption: str,
    reply_markup: dict | None = None,
) -> dict:
    if not file_path.is_file():
        raise FileNotFoundError(f"Изображение не найдено: {file_path}")
    fields: dict = {"chat_id": chat_id, "caption": caption, "parse_mode": "HTML"}
    if reply_markup:
        fields["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False)
    return api_multipart("sendPhoto", fields, "photo", file_path)


def send_photo_by_id(
    chat_id: int | str,
    file_id: str,
    caption: str,
    reply_markup: dict | None = None,
) -> dict:
    """Reuse a Telegram-hosted photo without downloading or duplicating it locally."""
    payload: dict = {
        "chat_id": chat_id,
        "photo": file_id,
        "caption": caption,
        "parse_mode": "HTML",
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return api("sendPhoto", payload)


MENU_DOCUMENTS = {
    "restobar_kitchen": (
        ASSETS / "restobar_menu.pdf",
        "🍽 <b>Меню рестобара</b>\nАктуальные блюда и цены для Краснодара.",
        "restaurant",
    ),
    "restobar_kids": (
        ASSETS / "kids_menu.pdf",
        "🧸 <b>Детское меню</b>\nБоксы, блюда, напитки и десерты для детей.",
        "restaurant",
    ),
    "restobar_bar": (
        ASSETS / "bar_menu_august_2026.pdf",
        "🍸 <b>Барная карта</b>\nАктуальная версия: август 2026 года.",
        "restaurant",
    ),
    "restaurant_kitchen": (
        ASSETS / "restobar_menu.pdf",
        "🍽 <b>Меню рестобара</b>\nАктуальные блюда и цены для Краснодара.",
        "restaurant",
    ),
    "restaurant_kids": (
        ASSETS / "kids_menu.pdf",
        "🧸 <b>Детское меню</b>\nБоксы, блюда, напитки и десерты для детей.",
        "restaurant",
    ),
    "restaurant_bar": (
        ASSETS / "bar_menu_august_2026.pdf",
        "🍸 <b>Барная карта</b>\nАктуальная версия: август 2026 года.",
        "restaurant",
    ),
    "banquet_kitchen": (
        ASSETS / "restobar_menu.pdf",
        "🍽 <b>Основное меню для событий</b>\nАктуальные блюда и цены комплекса.",
        "banquets",
    ),
    "banquet_kids": (
        ASSETS / "kids_menu.pdf",
        "🧸 <b>Детское меню для праздников</b>\nБоксы, блюда, напитки и десерты для детей.",
        "banquets",
    ),
    "banquet_bar": (
        ASSETS / "bar_menu_august_2026.pdf",
        "🍸 <b>Барная карта для событий</b>\nАктуальная версия: август 2026 года.",
        "banquets",
    ),
    "karaoke_kitchen": (
        ASSETS / "restobar_menu.pdf",
        "🍽 <b>Меню кухни для караоке</b>\nАктуальные блюда и цены комплекса.",
        "karaoke",
    ),
    "karaoke_kids": (
        ASSETS / "kids_menu.pdf",
        "🧸 <b>Детское меню</b>\nБоксы, блюда, напитки и десерты для детей.",
        "karaoke",
    ),
    "karaoke_bar": (
        ASSETS / "bar_menu_august_2026.pdf",
        "🍸 <b>Барная карта для караоке</b>\nАктуальная версия: август 2026 года.",
        "karaoke",
    ),
    "food_menu": (
        ASSETS / "food_menu_july_2026.pdf",
        "🍔 <b>Меню «Фуд Мишкин»</b>\nЕда, напитки и актуальные цены. Версия: июль 2026 года.",
        "food",
    ),
}


def send_menu_document(chat_id: int | str, document_key: str) -> None:
    file_path, caption, return_to = MENU_DOCUMENTS[document_key]
    send_document(chat_id, file_path, caption, back(return_to))


def load_consents(path: pathlib.Path) -> set[int]:
    result: set[int] = set()
    if not path.is_file():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
            result.add(int(value["chat_id"]))
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            continue
    return result


CONSENTED_CHAT_IDS = load_consents(DATA / "consents.jsonl")


def request_consent(chat_id: int | str) -> None:
    send(
        chat_id,
        PRIVACY_TEXT,
        keyboard([button("✅ Согласен", callback="consent_accept")]),
    )


def has_consent(chat_id: int | str) -> bool:
    numeric_chat_id = int(chat_id)
    if numeric_chat_id in CONSENTED_CHAT_IDS:
        return True
    if storage().has_consent(numeric_chat_id):
        CONSENTED_CHAT_IDS.add(numeric_chat_id)
        return True
    return False


def show_main(chat_id: int) -> None:
    send(chat_id, MAIN_TEXT, MAIN_KB)


def show_contacts(chat_id: int) -> None:
    send_rich(
        chat_id,
        CONTACTS_RICH_HTML,
        CONTACTS_TEXT,
        keyboard(
            [button("ВКонтакте ↗", url=VK_URL)],
            [button("Назад", callback="main")],
        ),
    )


FLOWS: dict[int, dict] = {}
PHONE_CANCEL_TEXT = "❌ Отменить ввод"
DATING_BROWSE: dict[int, str] = {}
DATING_CARD_MESSAGE_IDS: dict[int, int] = {}
DATING_OWN_MESSAGE_IDS: dict[int, list[int]] = {}
DATING_LIKE_TEXT = "👍"
DATING_DISLIKE_TEXT = "👎"
DATING_SLEEP_TEXT = "💤"
DATING_REACTION_TEXTS = {DATING_LIKE_TEXT, DATING_DISLIKE_TEXT, DATING_SLEEP_TEXT}
DATING_PRIVATE_ONLY_TEXT = (
    "🔒 Раздел знакомств доступен только в личном чате с ботом. "
    "Так другие участники чата не смогут изменить или удалить вашу анкету."
)


def dating_reply_keyboard() -> dict:
    return {
        "keyboard": [
            [
                {"text": DATING_LIKE_TEXT, "style": "success"},
                {"text": DATING_DISLIKE_TEXT, "style": "danger"},
            ],
            [{"text": DATING_SLEEP_TEXT, "style": "primary"}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
        "input_field_placeholder": "Оцените анкету",
    }


def phone_reply_keyboard() -> dict:
    return {
        "keyboard": [
            [
                {
                    "text": "📱 Поделиться номером телефона",
                    "request_contact": True,
                    "style": "success",
                }
            ],
            [{"text": PHONE_CANCEL_TEXT, "style": "danger"}],
        ],
        "resize_keyboard": True,
        "one_time_keyboard": True,
        "input_field_placeholder": "+7 999 000-00-00",
    }


def remember_flow_message(flow: dict, result: dict | None) -> None:
    if not isinstance(result, dict):
        return
    try:
        message_id = int(result["message_id"])
    except (KeyError, TypeError, ValueError):
        return
    flow.setdefault("cleanup_message_ids", []).append(message_id)


def send_flow_prompt(chat_id: int, flow: dict, text: str, reply_markup: dict) -> dict:
    result = send(chat_id, text, reply_markup)
    remember_flow_message(flow, result)
    return result


def delete_messages_safely(chat_id: int | str, message_ids: list[int | None]) -> None:
    identifiers = sorted({int(value) for value in message_ids if value})
    if not identifiers or not TOKEN:<REDACTED>
        return
    for index in range(0, len(identifiers), 100):
        try:
            api("deleteMessages", {"chat_id": chat_id, "message_ids": identifiers[index : index + 100]})
        except Exception as exc:
            print(f"Не удалось очистить промежуточные сообщения: {exc}", file=sys.stderr)


def result_message_id(result: dict | None) -> int | None:
    if not isinstance(result, dict):
        return None
    try:
        return int(result["message_id"])
    except (KeyError, TypeError, ValueError):
        return None


def remember_dating_own_message(chat_id: int, result: dict | None) -> None:
    message_id = result_message_id(result)
    if message_id is not None:
        DATING_OWN_MESSAGE_IDS.setdefault(int(chat_id), []).append(message_id)


def cleanup_dating_own_messages(chat_id: int, *message_ids: int | None) -> None:
    stored = DATING_OWN_MESSAGE_IDS.pop(int(chat_id), [])
    delete_messages_safely(chat_id, [*stored, *message_ids])


def callback_matches_flow_message(flow: dict | None, message_id: int | None) -> bool:
    if not flow:
        return False
    expected = flow.get("form_message_id")
    if expected is None:
        return False
    try:
        return message_id is not None and int(message_id) == int(expected)
    except (TypeError, ValueError):
        return False


def is_private_chat(chat: dict | None) -> bool:
    return str((chat or {}).get("type", "private")) == "private"


def is_dating_callback_data(data: str) -> bool:
    return data == "dating" or data.startswith("dating_")


def show_dating_private_only(chat_id: int) -> None:
    send(
        chat_id,
        DATING_PRIVATE_ONLY_TEXT,
        keyboard([button("Открыть личный чат", url=f"https://t.me/{BOT_USERNAME}", style="primary")]),
    )


def dating_callback_validation_error(chat_id: int, data: str, message_id: int | None) -> str | None:
    flow = FLOWS.get(int(chat_id))
    flow_requirements = {
        "dating_gender:": ("create", "gender"),
        "dating_edit_gender:": ("edit", "gender"),
    }
    for prefix, (mode, step) in flow_requirements.items():
        if data.startswith(prefix):
            if (
                not flow
                or flow.get("type") != "dating"
                or flow.get("mode", "create") != mode
                or flow.get("step") != step
                or not callback_matches_flow_message(flow, message_id)
            ):
                return "Эта форма уже устарела. Откройте раздел знакомств заново."
            return None
    if data == "dating_photo_skip":
        if (
            not flow
            or flow.get("type") != "dating"
            or flow.get("mode", "create") != "create"
            or flow.get("step") != "photo"
            or not callback_matches_flow_message(flow, message_id)
        ):
            return "Эта форма уже устарела. Откройте раздел знакомств заново."
        return None
    if data == "dating_confirm":
        if (
            not flow
            or flow.get("type") != "dating"
            or flow.get("mode", "create") != "create"
            or flow.get("step") != "confirm"
            or not callback_matches_flow_message(flow, message_id)
        ):
            return "Эта форма уже устарела. Откройте раздел знакомств заново."
        return None

    profile_code = ""
    if data.startswith("dating_edit:"):
        parts = data.split(":")
        if len(parts) == 3 and parts[1] in {"name", "gender", "age", "about", "photo"}:
            profile_code = parts[2].upper()
        else:
            return "Эта кнопка устарела. Откройте свою анкету заново."
    elif data.startswith("dating_publish:"):
        profile_code = data.split(":", 1)[1].upper()
    elif data.startswith("dating_delete_confirm:"):
        profile_code = data.split(":", 1)[1].upper()
    elif data.startswith("dating_delete:"):
        profile_code = data.split(":", 1)[1].upper()
    elif data in {"dating_publish", "dating_delete_confirm", "dating_delete"}:
        return "Эта кнопка устарела. Откройте свою анкету заново."

    if profile_code:
        profile = latest_dating_profile(chat_id)
        own_message_ids = DATING_OWN_MESSAGE_IDS.get(int(chat_id), [])
        try:
            source_is_current = message_id is not None and int(message_id) in {int(value) for value in own_message_ids}
        except (TypeError, ValueError):
            source_is_current = False
        if not profile or profile["profile_code"] != profile_code or not source_is_current:
            return "Эта кнопка устарела. Откройте свою анкету заново."
    return None


def cleanup_flow_messages(chat_id: int, flow: dict, *message_ids: int | None) -> None:
    stored = flow.pop("cleanup_message_ids", [])
    delete_messages_safely(chat_id, [*stored, *message_ids])


def cleanup_flow_form(chat_id: int, flow: dict) -> None:
    form_message_id = flow.pop("form_message_id", None)
    delete_messages_safely(chat_id, [form_message_id])


def clear_active_flow(chat_id: int, flow: dict | None, message_id: int | None = None) -> None:
    if flow:
        stored = flow.pop("cleanup_message_ids", [])
        form_message_id = flow.pop("form_message_id", None)
        delete_messages_safely(chat_id, [*stored, form_message_id, message_id])
    hide_custom_reply_keyboard(chat_id)


def cancel_active_flow(chat_id: int, flow: dict | None, message_id: int | None = None) -> None:
    clear_active_flow(chat_id, flow, message_id)
    show_main(chat_id)


def dismiss_reply_keyboard(chat_id: int) -> int | None:
    result = send(chat_id, "✅ Номер принят", {"remove_keyboard": True})
    try:
        return int(result["message_id"])
    except (KeyError, TypeError, ValueError):
        return None


def set_dating_reply_keyboard(chat_id: int) -> None:
    result = send(chat_id, "❤️", dating_reply_keyboard())
    marker_id = result.get("message_id") if isinstance(result, dict) else None
    delete_messages_safely(chat_id, [marker_id])


def hide_custom_reply_keyboard(chat_id: int) -> None:
    result = send(chat_id, "↩️", {"remove_keyboard": True})
    marker_id = result.get("message_id") if isinstance(result, dict) else None
    delete_messages_safely(chat_id, [marker_id])


def normalize_russian_mobile_phone(value: str) -> str | None:
    raw = value.strip()
    if not raw or not re.fullmatch(r"\+?[\d\s().\-–—]+", raw):
        return None
    digits = "".join(character for character in raw if character.isdigit())
    if len(digits) == 11 and digits[0] in {"7", "8"}:
        national = digits[1:]
    elif len(digits) == 10:
        national = digits
    else:
        return None
    if not national.startswith("9"):
        return None
    return "+7" + national


def prompt_for_phone(chat_id: int, flow: dict, error: bool = False) -> None:
    prefix = "Не удалось распознать российский мобильный номер.\n\n" if error else ""
    send_flow_prompt(
        chat_id,
        flow,
        prefix
        + "Введите номер телефона или нажмите кнопку ниже.\n\n"
        + "Подходящие форматы:\n"
        + "• +7 999 000-00-00\n"
        + "• 8 999 000-00-00\n"
        + "• 999 000-00-00",
        phone_reply_keyboard(),
    )


def accept_booking_phone(chat_id: int, flow: dict, value: str, message_id: int | None = None) -> bool:
    normalized = normalize_russian_mobile_phone(value)
    cleanup_flow_messages(chat_id, flow, message_id)
    if normalized is None:
        prompt_for_phone(chat_id, flow, error=True)
        return False
    flow["data"]["phone"] = normalized
    flow["step"] = "date"
    keyboard_message_id = dismiss_reply_keyboard(chat_id)
    show_booking_calendar(chat_id, flow)
    delete_messages_safely(chat_id, [keyboard_message_id])
    return True

MONTH_NAMES = (
    "",
    "Январь",
    "Февраль",
    "Март",
    "Апрель",
    "Май",
    "Июнь",
    "Июль",
    "Август",
    "Сентябрь",
    "Октябрь",
    "Ноябрь",
    "Декабрь",
)
MONTH_NAMES_GENITIVE = (
    "",
    "января",
    "февраля",
    "марта",
    "апреля",
    "мая",
    "июня",
    "июля",
    "августа",
    "сентября",
    "октября",
    "ноября",
    "декабря",
)
WEEKDAY_NAMES = ("Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс")


def start_booking(chat_id: int, kind: str) -> None:
    flow = {"type": "booking", "kind": kind, "step": "name", "data": {}}
    FLOWS[chat_id] = flow
    send_flow_prompt(chat_id, flow, "Введите имя на бронь:", back("main", "Главное меню", force_reply=True))


def shift_month(year: int, month: int, delta: int) -> tuple[int, int]:
    absolute = year * 12 + month - 1 + delta
    return absolute // 12, absolute % 12 + 1


def booking_date_is_allowed(value: dt.date, today: dt.date | None = None) -> bool:
    today = today or dt.date.today()
    return today <= value <= today + dt.timedelta(days=366)


def booking_calendar(year: int, month: int, today: dt.date | None = None) -> dict:
    today = today or dt.date.today()
    current = (today.year, today.month)
    previous = shift_month(year, month, -1)
    following = shift_month(year, month, 1)
    max_month = shift_month(today.year, today.month, 12)
    rows: list[list[dict]] = [
        [
            button("‹", callback=f"calm:{previous[0]:04d}-{previous[1]:02d}")
            if previous >= current
            else button("‹", disabled=True),
            button(f"{MONTH_NAMES[month]} {year}", style="primary", disabled=True),
            button("›", callback=f"calm:{following[0]:04d}-{following[1]:02d}")
            if following <= max_month
            else button("›", disabled=True),
        ],
        [button(name, disabled=True) for name in WEEKDAY_NAMES],
    ]
    for week in calendar.Calendar(firstweekday=0).monthdayscalendar(year, month):
        row: list[dict] = []
        for day in week:
            if not day:
                row.append(button(" ", disabled=True))
                continue
            value = dt.date(year, month, day)
            if not booking_date_is_allowed(value, today):
                row.append(button(str(day), disabled=True))
                continue
            label = f"•{day}" if value == today else str(day)
            row.append(button(label, callback=f"cald:{value.isoformat()}", style="primary"))
        rows.append(row)
    rows.append([button("Отменить бронирование", callback="main", style="danger")])
    return keyboard(*rows)


def show_booking_calendar(
    chat_id: int,
    flow: dict,
    year: int | None = None,
    month: int | None = None,
    message_id: int | None = None,
) -> None:
    today = dt.date.today()
    year = year or today.year
    month = month or today.month
    flow["calendar"] = {"year": year, "month": month}
    text = "📅 <b>Выберите желаемую дату</b>\n\nДоступны даты на ближайшие 12 месяцев."
    markup = booking_calendar(year, month, today)
    if message_id:
        edit_message(chat_id, message_id, text, markup)
        flow["form_message_id"] = message_id
    else:
        result = send(chat_id, text, markup)
        if isinstance(result, dict) and result.get("message_id"):
            flow["form_message_id"] = int(result["message_id"])


def booking_time_range(kind: str) -> tuple[int, int]:
    lowered = kind.lower()
    if "танцев" in lowered or "караоке" in lowered:
        return 19, 23
    if any(word in lowered for word in ("картинг", "vr", "автосим", "мишкин парк")):
        return 10, 22
    if "банкет" in lowered or "день рождения" in lowered:
        return 10, 23
    return 12, 23


def available_booking_times(
    kind: str,
    selected_date: dt.date,
    now: dt.datetime | None = None,
) -> list[str]:
    now = now or dt.datetime.now()
    start_hour, end_hour = booking_time_range(kind)
    result: list[str] = []
    for minutes in range(start_hour * 60, end_hour * 60 + 31, 30):
        hour, minute = divmod(minutes, 60)
        candidate = dt.datetime.combine(selected_date, dt.time(hour=hour, minute=minute))
        if selected_date == now.date() and candidate < now + dt.timedelta(minutes=60):
            continue
        result.append(f"{hour:02d}:{minute:02d}")
    return result


def booking_time_keyboard(kind: str, selected_date: dt.date) -> dict:
    times = available_booking_times(kind, selected_date)
    rows = [
        [button(value, callback=f"btime:{value.replace(':', '')}", style="primary") for value in times[index : index + 4]]
        for index in range(0, len(times), 4)
    ]
    rows.append([button("← Выбрать другую дату", callback="calshow", style="danger")])
    return keyboard(*rows)


def booking_guests_keyboard() -> dict:
    values = ["1", "2", "3", "4", "5", "6", "7", "8", "10", "15", "20"]
    rows = [
        [button(value, callback=f"bguest:{value}", style="primary") for value in values[index : index + 4]]
        for index in range(0, len(values), 4)
    ]
    rows.append([button("Другое количество", callback="bguest:other", style="primary")])
    rows.append([button("Отменить", callback="main", style="danger")])
    return keyboard(*rows)


def booking_comment_keyboard() -> dict:
    return keyboard(
        [button("Без комментария", callback="bcomment:none", style="success")],
        [button("Ввести комментарий", callback="bcomment:manual", style="primary")],
        [button("Отменить", callback="main", style="danger")],
    )


def show_booking_summary(chat_id: int, flow: dict) -> None:
    cleanup_flow_messages(chat_id, flow)
    cleanup_flow_form(chat_id, flow)
    flow["step"] = "confirm"
    data = flow["data"]
    summary = (
        "Проверьте заявку:\n\n"
        f"Раздел: {html.escape(flow['kind'])}\n"
        f"Имя: {html.escape(data['name'])}\n"
        f"Телефон: {html.escape(data['phone'])}\n"
        f"Дата и время: {html.escape(data['datetime'])}\n"
        f"Гостей: {html.escape(data['guests'])}\n"
        f"Комментарий: {html.escape(data['comment'])}"
    )
    result = send(
        chat_id,
        summary,
        keyboard(
            [button("Подтвердить заявку", callback="booking_confirm", style="success")],
            [button("Отменить", callback="main", style="danger")],
        ),
    )
    if isinstance(result, dict) and result.get("message_id"):
        flow["form_message_id"] = int(result["message_id"])


def start_dating(chat_id: int) -> None:
    if latest_dating_profile(chat_id):
        show_dating_profile(chat_id)
        return
    DATING_BROWSE.pop(chat_id, None)
    old_card_id = DATING_CARD_MESSAGE_IDS.pop(chat_id, None)
    delete_messages_safely(chat_id, [old_card_id])
    cleanup_dating_own_messages(chat_id)
    hide_custom_reply_keyboard(chat_id)
    flow = {
        "type": "dating",
        "mode": "create",
        "step": "name",
        "data": {"profile_code": new_dating_profile_code()},
    }
    FLOWS[chat_id] = flow
    send_flow_prompt(chat_id, flow, "Введите ваше имя 👀", back("main", "Главное меню", force_reply=True))


def append_jsonl(path: pathlib.Path, record: dict) -> None:
    """Legacy helper retained for import tools and backward-compatible tests.

    Runtime bot code writes through SQLite.  When this helper targets the active
    data directory, mirror the manual record into SQLite as well.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    try:
        if path.name in LEGACY_DATASETS and path.parent.resolve() == pathlib.Path(DATA).resolve():
            storage().import_legacy_record(path.name, record)
    except (OSError, ValueError):
        raise


def read_jsonl(path: pathlib.Path) -> list[dict]:
    """Read legacy JSONL, exposing current SQLite records for known datasets."""
    if path.name in LEGACY_DATASETS and path.parent.resolve() == pathlib.Path(DATA).resolve():
        return storage().records_for_legacy(path.name)
    if not path.is_file():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
        except json.JSONDecodeError:
            continue
    return records


def belongs_to_chat(record: dict, chat_id: int) -> bool:
    try:
        return int(record.get("chat_id", 0)) == int(chat_id)
    except (TypeError, ValueError):
        return False


def register_notification_recipient(user: dict | None) -> bool:
    """Remember a whitelisted private Telegram account after it contacts the bot."""
    if not user or user.get("is_bot"):
        return False
    username = str(user.get("username", "")).strip().lstrip("@").lower()
    if username not in NOTIFICATION_USERNAMES:
        return False
    try:
        chat_id = int(user["id"])
    except (KeyError, TypeError, ValueError):
        return False
    result = storage().register_recipient(username, chat_id)
    if result == "conflict":
        print(f"Отклонена попытка перепривязки @{username} к другому chat_id", file=sys.stderr)
    return result == "created"


def notification_recipients() -> dict[str, int | str]:
    result: dict[str, int | str] = {
        username: chat_id
        for username, chat_id in storage().recipients().items()
        if username in NOTIFICATION_USERNAMES
    }
    if ADMIN_CHAT_ID:
        try:
            result["admin_chat_id"] = int(ADMIN_CHAT_ID)
        except ValueError:
            result["admin_chat_id"] = ADMIN_CHAT_ID
    return result


def manager_actor(user: dict | None) -> dict | None:
    """Authenticate a manager by immutable Telegram user ID."""
    if not user or user.get("is_bot"):
        return None
    try:
        user_id = int(user["id"])
    except (KeyError, TypeError, ValueError):
        return None
    current_username = str(user.get("username", "")).strip().lstrip("@").lower()
    for registered_username, registered_chat_id in notification_recipients().items():
        try:
            matches = int(registered_chat_id) == user_id
        except (TypeError, ValueError):
            matches = str(registered_chat_id) == str(user_id)
        if not matches:
            continue
        display_username = current_username or str(registered_username).lstrip("@")
        return {
            "id": user_id,
            "username": display_username,
            "label": f"@{display_username}" if display_username else "ответственный менеджер",
        }
    return None


def manager_identity(user: dict | None) -> str | None:
    actor = manager_actor(user)
    return str(actor["label"]) if actor else None


def is_manager_chat(chat_id: int | str) -> bool:
    for registered_chat_id in notification_recipients().values():
        try:
            if int(registered_chat_id) == int(chat_id):
                return True
        except (TypeError, ValueError):
            if str(registered_chat_id) == str(chat_id):
                return True
    return False


def booking_status_label(record: dict) -> str:
    statuses = {
        "received": "🟡 Новая — ожидает ответственного",
        "in_progress": "🔵 В работе",
        "contacted": "🟣 С гостем связались",
        "no_answer": "🟠 Не дозвонились",
        "confirmed": "🟢 Бронь подтверждена",
        "cancelled": "🔴 Заявка отменена",
    }
    return statuses.get(str(record.get("status", "received")), "🟡 Новая")


def format_manager_time(value) -> str:
    try:
        moment = dt.datetime.fromtimestamp(int(value), tz=dt.timezone(dt.timedelta(hours=3)))
    except (TypeError, ValueError, OSError):
        return "—"
    return moment.strftime("%d.%m.%Y %H:%M")


def booking_history_text(record: dict, limit: int = 10) -> str:
    events = storage().booking_history(str(record.get("request_code", "")), limit)
    if not events:
        return "История пока пуста."
    labels = {
        "received": "заявка создана",
        "in_progress": "взята в работу",
        "contacted": "с гостем связались",
        "no_answer": "не дозвонились",
        "confirmed": "бронь подтверждена",
        "cancelled": "заявка отменена",
    }
    lines: list[str] = []
    for event in reversed(events):
        actor = str(event.get("actor_label") or "бот")
        action = labels.get(str(event.get("new_status")), str(event.get("new_status", "—")))
        lines.append(
            f"• {format_manager_time(event.get('created_at'))} — {html.escape(action)} ({html.escape(actor)})"
        )
    return "\n".join(lines)


def manager_booking_text(record: dict) -> str:
    status = str(record.get("status", "received"))
    titles = {
        "received": "🆕 Новая заявка Mishkin&amp;Mishkin Краснодар",
        "in_progress": "🔵 Заявка в работе",
        "contacted": "📞 С гостем связались",
        "no_answer": "📵 Не удалось дозвониться",
        "confirmed": "✅ Заявка подтверждена",
        "cancelled": "❌ Заявка отменена",
    }
    title = titles.get(status, titles["received"])
    username = str(record.get("telegram_username", "")).strip().lstrip("@")
    telegram_line = f"\n<b>Telegram:</b> @{html.escape(username)}" if username else ""
    assigned = str(record.get("assigned_manager") or "").strip()
    assigned_line = (
        f"\n<b>Ответственный:</b> {html.escape(assigned)}"
        if assigned
        else "\n<b>Ответственный:</b> ещё не назначен"
    )
    history = booking_history_text(record, 3)
    return (
        f"<b>{title}</b>\n\n"
        f"<b>Код:</b> <code>{html.escape(str(record.get('request_code', '—')))}</code>\n"
        f"<b>Статус:</b> {html.escape(booking_status_label(record))}"
        f"{assigned_line}\n"
        f"<b>Получена:</b> {format_manager_time(record.get('created_at'))}\n\n"
        f"<b>Направление:</b> {html.escape(str(record.get('kind', '—')))}\n"
        f"<b>Гость:</b> {html.escape(str(record.get('name', '—')))}\n"
        f"<b>Телефон:</b> {html.escape(str(record.get('phone', '—')))}\n"
        f"<b>Дата и время:</b> {html.escape(str(record.get('datetime', '—')))}\n"
        f"<b>Количество гостей:</b> {html.escape(str(record.get('guests', '—')))}\n"
        f"<b>Комментарий:</b> {html.escape(str(record.get('comment', 'нет')))}"
        f"{telegram_line}\n\n"
        f"<b>Последние действия:</b>\n{history}\n\n"
        "<b>Что сделать:</b> сначала возьмите заявку в работу, затем отмечайте результат связи."
    )


def manager_booking_keyboard(record: dict) -> dict:
    code = str(record.get("request_code", ""))
    status = str(record.get("status", "received"))
    version = int(record.get("status_version", 1) or 1)
    rows: list[list[dict]] = []
    if status == "received":
        rows.append([button("🙋 Взять в работу", callback=f"bm:claim:{code}:{version}", style="success")])
    elif status in {"in_progress", "contacted", "no_answer"}:
        contact_buttons: list[dict] = []
        if status == "in_progress":
            contact_buttons.append(
                button("📞 Связались", callback=f"bm:contacted:{code}:{version}", style="primary")
            )
        if status == "no_answer":
            contact_buttons.append(
                button("📞 Попробовать ещё раз", callback=f"bm:retry:{code}:{version}", style="primary")
            )
        else:
            contact_buttons.append(
                button("📵 Не дозвонились", callback=f"bm:no_answer:{code}:{version}", style="primary")
            )
        rows.append(contact_buttons)
        rows.append([button("✅ Подтвердить бронь", callback=f"bm:confirmed:{code}:{version}", style="success")])
        rows.append([button("❌ Отменить заявку", callback=f"bmc:{code}:{version}", style="danger")])
    rows.append(
        [
            button("🧾 История", callback=f"bmh:{code}:{version}", style="primary"),
            button("🔄 Обновить", callback=f"bmr:{code}:{version}", style="primary"),
        ]
    )
    rows.append(
        [
            button(
                "Открыть карточку заявки ↗",
                url=f"https://t.me/{BOT_USERNAME}?start=qr_{code}",
                style="primary",
            )
        ]
    )
    rows.append([button("🗂 Рабочее место менеджера", callback="mgr:home", style="primary")])
    return keyboard(*rows)


def notify_booking(record: dict) -> int:
    admin_text = manager_booking_text(record)
    admin_markup = manager_booking_keyboard(record)
    delivered = 0
    sent_chat_ids: set[int | str] = set()
    for label, chat_id in notification_recipients().items():
        if chat_id in sent_chat_ids:
            continue
        last_error: Exception | None = None
        for attempt in range(1, 3):
            try:
                result = send(chat_id, admin_text, admin_markup)
                sent_chat_ids.add(chat_id)
                delivered += 1
                storage().add_delivery(
                    {
                        "created_at": int(time.time()),
                        "request_code": record.get("request_code"),
                        "recipient": label,
                        "chat_id": chat_id,
                        "status": "delivered",
                        "attempts": attempt,
                        "telegram_message_id": result.get("message_id") if isinstance(result, dict) else None,
                    },
                )
                break
            except Exception as exc:
                last_error = exc
                if attempt == 1:
                    time.sleep(0.5)
        if last_error and chat_id not in sent_chat_ids:
            storage().add_delivery(
                {
                    "created_at": int(time.time()),
                    "request_code": record.get("request_code"),
                    "recipient": label,
                    "chat_id": chat_id,
                    "status": "failed",
                    "attempts": 2,
                    "error": str(last_error)[:300],
                },
            )
            print(f"Не удалось отправить заявку получателю {label}: {last_error}", file=sys.stderr)
    return delivered


def update_booking_status(
    code: str,
    status: str,
    manager: str,
    manager_id: int | None = None,
    *,
    expected_version: int | None = None,
    callback_query_id: str | None = None,
) -> dict | None:
    """Compatibility wrapper around the transactional status transition."""
    username = manager.strip().lstrip("@").lower()
    if manager_id is None:
        manager_id = next(
            (
                int(chat_id)
                for label, chat_id in notification_recipients().items()
                if str(label).lower() == username
            ),
            0,
        )
    result, record = storage().transition_booking(
        code,
        status,
        actor_id=int(manager_id),
        actor_username=username,
        actor_label=manager,
        expected_version=expected_version,
        callback_query_id=callback_query_id,
    )
    return record if result in {"updated", "unchanged"} else None


def refresh_manager_notifications(record: dict) -> None:
    code = str(record.get("request_code", ""))
    refreshed: set[tuple[str, int]] = set()
    for delivery in storage().deliveries(code):
        if delivery.get("status") != "delivered" or str(delivery.get("request_code", "")) != code:
            continue
        try:
            message_id = int(delivery["telegram_message_id"])
            chat_id = delivery["chat_id"]
        except (KeyError, TypeError, ValueError):
            continue
        key = (str(chat_id), message_id)
        if key in refreshed:
            continue
        refreshed.add(key)
        try:
            edit_message(chat_id, message_id, manager_booking_text(record), manager_booking_keyboard(record))
        except Exception as exc:
            print(f"Не удалось обновить карточку заявки {code} у менеджера: {exc}", file=sys.stderr)


def notify_client_booking_status(record: dict) -> None:
    try:
        chat_id = int(record["chat_id"])
    except (KeyError, TypeError, ValueError):
        return
    status = str(record.get("status", "received"))
    code = html.escape(str(record.get("request_code", "—")))
    when = html.escape(str(record.get("datetime", "—")))
    if status == "confirmed":
        send(
            chat_id,
            "✅ <b>Ваша бронь подтверждена</b>\n\n"
            f"Код: <code>{code}</code>\n"
            f"Дата и время: {when}\n\n"
            "QR хранится в разделе «Мои QR». Покажите его сотруднику при входе или по просьбе менеджера.",
        )
        try:
            send_request_qr(chat_id, record, MAIN_KB)
        except Exception as exc:
            print(f"Не удалось повторно отправить QR {record.get('request_code')}: {exc}", file=sys.stderr)
    elif status == "cancelled":
        send(
            chat_id,
            "❌ <b>Заявка отменена менеджером</b>\n\n"
            f"Код: <code>{code}</code>\n"
            "Если это произошло по ошибке, свяжитесь с нами: +7 (989) 021-03-03.",
            MAIN_KB,
        )


def rewrite_without_chat(path: pathlib.Path, chat_id: int) -> bool:
    records = read_jsonl(path)
    kept = [record for record in records if not belongs_to_chat(record, chat_id)]
    if len(kept) == len(records):
        return False
    temporary = path.with_suffix(path.suffix + ".tmp")
    text = "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in kept)
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)
    return True


def rewrite_filtered_jsonl(path: pathlib.Path, keep) -> bool:
    records = read_jsonl(path)
    kept = [record for record in records if keep(record)]
    if len(kept) == len(records):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in kept),
        encoding="utf-8",
    )
    temporary.replace(path)
    return True


def dating_code_from_number(value: int) -> str:
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    result = []
    for _ in range(5):
        result.append(alphabet[value % len(alphabet)])
        value //= len(alphabet)
    return "".join(result)


def dating_profile_code(record: dict) -> str:
    existing = str(record.get("profile_code", "")).strip().upper()
    if re.fullmatch(r"[A-Z0-9]{5}", existing):
        return existing
    seed = f"mishkin-dating:{record.get('chat_id', '')}:{record.get('created_at', '')}"
    return dating_code_from_number(uuid.uuid5(uuid.NAMESPACE_URL, seed).int)


def new_dating_profile_code() -> str:
    existing = {dating_profile_code(record) for record in storage().profiles()}
    for _ in range(100):
        candidate = dating_code_from_number(uuid.uuid4().int)
        if candidate not in existing:
            return candidate
    raise RuntimeError("Не удалось создать уникальный код анкеты")


def normalized_dating_profile(record: dict) -> dict:
    result = dict(record)
    result["profile_code"] = dating_profile_code(result)
    result["gender"] = str(result.get("gender") or result.get("sex") or "Не указан")
    result["published"] = result.get("published") is True
    return result


def dating_profile_is_complete(profile: dict) -> bool:
    try:
        age_is_valid = 18 <= int(profile.get("age")) <= 100
    except (TypeError, ValueError):
        age_is_valid = False
    return bool(
        str(profile.get("name", "")).strip()
        and str(profile.get("about", "")).strip()
        and profile.get("gender") in {"Муж", "Жен"}
        and age_is_valid
    )


def latest_dating_profile(chat_id: int) -> dict | None:
    record = storage().profile_for_chat(chat_id)
    return normalized_dating_profile(record) if record else None


def latest_dating_profiles() -> list[dict]:
    return [normalized_dating_profile(record) for record in storage().profiles()]


def dating_profile_by_code(profile_code: str) -> dict | None:
    wanted = profile_code.upper()
    for profile in latest_dating_profiles():
        if profile["profile_code"] == wanted:
            return profile
    return None


def save_dating_profile(profile: dict) -> dict:
    record = dict(profile)
    chat_id = int(record["chat_id"])
    record["profile_code"] = dating_profile_code(record)
    record["updated_at"] = int(time.time())
    storage().save_profile(record)
    return normalized_dating_profile(record)


def dating_reactions_for(chat_id: int) -> list[dict]:
    return storage().reactions_for(chat_id)


def available_dating_profiles(chat_id: int) -> list[dict]:
    seen_codes = {
        str(record.get("target_profile_code", "")).upper()
        for record in dating_reactions_for(chat_id)
    }
    candidates: list[dict] = []
    for profile in latest_dating_profiles():
        try:
            candidate_chat_id = int(profile.get("chat_id"))
            age = int(profile.get("age"))
        except (TypeError, ValueError):
            continue
        if candidate_chat_id == int(chat_id) or not profile.get("published") or age < 18:
            continue
        if profile["profile_code"] in seen_codes:
            continue
        candidates.append(profile)
    return sorted(candidates, key=lambda item: (int(item.get("created_at", 0) or 0), item["profile_code"]))


def delete_dating_profile(chat_id: int) -> bool:
    profile = latest_dating_profile(chat_id)
    profile_code = profile["profile_code"] if profile else ""
    deleted, deleted_code = storage().delete_profile(chat_id)
    if deleted_code:
        profile_code = deleted_code
    for viewer, target_code in list(DATING_BROWSE.items()):
        if viewer == int(chat_id) or (profile_code and target_code == profile_code):
            DATING_BROWSE.pop(viewer, None)
            viewer_card_id = DATING_CARD_MESSAGE_IDS.pop(viewer, None)
            delete_messages_safely(viewer, [viewer_card_id])
    owner_card_id = DATING_CARD_MESSAGE_IDS.pop(int(chat_id), None)
    delete_messages_safely(chat_id, [owner_card_id])
    cleanup_dating_own_messages(chat_id)
    return deleted


def booking_by_code(code: str) -> dict | None:
    return storage().booking_by_code(code)


def bookings_for_chat(chat_id: int, limit: int = 5) -> list[dict]:
    return storage().bookings_for_chat(chat_id, limit)


def is_recent_duplicate(chat_id: int, flow: dict, now: int, window: int = 600) -> dict | None:
    expected = flow["data"]
    expected_phone = "".join(character for character in expected.get("phone", "") if character.isdigit())
    for record in storage().recent_bookings(now - window):
        record_phone = "".join(character for character in str(record.get("phone", "")) if character.isdigit())
        if (
            belongs_to_chat(record, chat_id)
            and record.get("kind") == flow.get("kind")
            and record_phone == expected_phone
            and record.get("datetime") == expected.get("datetime")
            and str(record.get("guests")) == str(expected.get("guests"))
        ):
            return record
    return None


def request_status_text(record: dict) -> str:
    statuses = {
        "received": "🟡 Получена, ожидает подтверждения менеджера",
        "in_progress": "🔵 Менеджер взял заявку в работу",
        "contacted": "🟣 Менеджер связался с вами, детали уточняются",
        "no_answer": "🟠 Менеджер не смог дозвониться — проверьте телефон",
        "confirmed": "🟢 Подтверждена менеджером",
        "cancelled": "🔴 Отменена менеджером",
    }
    return statuses.get(str(record.get("status", "received")), "Получена ботом")


def request_caption(record: dict) -> str:
    return (
        "🎟 <b>QR вашей заявки</b>\n\n"
        f"Код: <code>{html.escape(str(record['request_code']))}</code>\n"
        f"Раздел: {html.escape(str(record.get('kind', '—')))}\n"
        f"Дата и время: {html.escape(str(record.get('datetime', '—')))}\n"
        f"Статус: {html.escape(request_status_text(record))}\n\n"
        "QR нужен для быстрого поиска заявки. Он хранится в разделе «Мои QR» — покажите его сотруднику "
        "при входе или по просьбе менеджера. Пока статус не стал «Подтверждена», QR не подтверждает бронь."
    )


def send_request_qr(chat_id: int | str, record: dict, reply_markup: dict | None = None) -> None:
    code = str(record["request_code"])
    path = DATA / "qr" / f"{code}.png"
    if not path.is_file():
        link = f"https://t.me/{BOT_USERNAME}?start=qr_{code}"
        write_png(link, path)
    send_photo(chat_id, path, request_caption(record), reply_markup)


LAST_MAINTENANCE = 0


def perform_maintenance(force: bool = False) -> None:
    global LAST_MAINTENANCE
    now = int(time.time())
    if not force and now - LAST_MAINTENANCE < 3600:
        return
    repository = storage()
    integrity = repository.integrity_check()
    if integrity != "ok":
        raise OSError(f"SQLite integrity check failed: {integrity}")
    backup_root = DATA / "backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    day = time.strftime("%Y-%m-%d", time.localtime(now))
    destination = backup_root / day
    complete_backup = destination / "backup.json"
    if not complete_backup.is_file() or not (destination / "bot.sqlite3").is_file():
        staging = backup_root / f".{day}.tmp-{uuid.uuid4().hex}"
        staging.mkdir(parents=True, exist_ok=False)
        try:
            repository.backup_to(staging / "bot.sqlite3")
            backup_integrity = SQLiteStorage(staging).integrity_check()
            if backup_integrity != "ok":
                raise OSError(f"Backup integrity check failed: {backup_integrity}")
            for name in LEGACY_DATASETS:
                records = repository.records_for_legacy(name)
                (staging / name).write_text(
                    "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records),
                    encoding="utf-8",
                )
            (staging / "backup.json").write_text(
                json.dumps(
                    {
                        "created_at": now,
                        "city": "Краснодар",
                        "database": "bot.sqlite3",
                        "integrity": backup_integrity,
                        "counts": repository.counts(),
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            if destination.exists():
                shutil.rmtree(destination)
            staging.replace(destination)
        except Exception:
            if staging.exists():
                shutil.rmtree(staging)
            raise
    if backup_root.is_dir():
        backups = sorted(
            (
                item
                for item in backup_root.iterdir()
                if item.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", item.name)
            ),
            key=lambda item: item.name,
        )
        for expired in backups[:-BACKUP_RETENTION_DAYS]:
            shutil.rmtree(expired)
    health = DATA / "health.json"
    temporary = DATA / "health.json.tmp"
    temporary.write_text(
        json.dumps(
            {
                "updated_at": now,
                "status": "ok",
                "city": "Краснодар",
                "database": "bot.sqlite3",
                "database_integrity": integrity,
                "counts": repository.counts(),
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    temporary.replace(health)
    LAST_MAINTENANCE = now


def handle_booking_message(chat_id: int, text: str, flow: dict, message_id: int | None = None) -> None:
    value = text.strip()
    step = flow["step"]
    if step == "phone":
        accept_booking_phone(chat_id, flow, value, message_id)
        return
    if not value:
        cleanup_flow_messages(chat_id, flow, message_id)
        send_flow_prompt(
            chat_id,
            flow,
            "Пожалуйста, заполните поле.",
            back("main", "Главное меню", force_reply=True),
        )
        return
    limits = {"name": 80, "datetime": 120, "comment": 1000}
    if step in limits and len(value) > limits[step]:
        cleanup_flow_messages(chat_id, flow, message_id)
        send_flow_prompt(
            chat_id,
            flow,
            f"Слишком длинный ответ. Максимум {limits[step]} символов:",
            back("main", "Главное меню", force_reply=True),
        )
        return
    if step == "guests" and (not value.isdigit() or not 1 <= int(value) <= 1000):
        cleanup_flow_messages(chat_id, flow, message_id)
        send_flow_prompt(
            chat_id,
            flow,
            "Укажите количество гостей числом от 1 до 1000:",
            back("main", "Отменить", force_reply=True),
        )
        return
    if step == "name":
        cleanup_flow_messages(chat_id, flow, message_id)
        flow["data"]["name"] = value
        flow["step"] = "phone"
        prompt_for_phone(chat_id, flow)
        return
    if step == "date":
        cleanup_flow_messages(chat_id, flow, message_id)
        calendar_state = flow.get("calendar") or {}
        show_booking_calendar(
            chat_id,
            flow,
            calendar_state.get("year"),
            calendar_state.get("month"),
            flow.get("form_message_id"),
        )
        return
    if step == "time":
        cleanup_flow_messages(chat_id, flow, message_id)
        selected_date = dt.date.fromisoformat(flow["data"]["date_iso"])
        form_message_id = flow.get("form_message_id")
        if form_message_id:
            edit_message(
                chat_id,
                form_message_id,
                "Выберите время кнопкой:",
                booking_time_keyboard(flow["kind"], selected_date),
            )
        else:
            result = send(chat_id, "Выберите время кнопкой:", booking_time_keyboard(flow["kind"], selected_date))
            if isinstance(result, dict) and result.get("message_id"):
                flow["form_message_id"] = int(result["message_id"])
        return
    if step == "guests":
        cleanup_flow_messages(chat_id, flow, message_id)
        flow["data"]["guests"] = value
        flow["step"] = "comment"
        form_message_id = flow.get("form_message_id")
        if form_message_id:
            edit_message(chat_id, form_message_id, "Добавить комментарий к заявке?", booking_comment_keyboard())
        else:
            result = send(chat_id, "Добавить комментарий к заявке?", booking_comment_keyboard())
            if isinstance(result, dict) and result.get("message_id"):
                flow["form_message_id"] = int(result["message_id"])
        return
    if step == "comment":
        cleanup_flow_messages(chat_id, flow, message_id)
        flow["data"]["comment"] = value
        show_booking_summary(chat_id, flow)


def dating_gender_keyboard(prefix: str = "dating_gender") -> dict:
    return keyboard(
        [
            button("Муж", callback=f"{prefix}:male", style="primary"),
            button("Жен", callback=f"{prefix}:female", style="primary"),
        ],
        [button("Главное меню", callback="main", style="danger")],
    )


def dating_photo_keyboard(skip_allowed: bool) -> dict:
    rows: list[list[dict]] = []
    if skip_allowed:
        rows.append([button("Продолжить без фото", callback="dating_photo_skip", style="primary")])
    rows.append([button("Главное меню", callback="main", style="danger")])
    return keyboard(*rows, force_reply=True)


def shortened_dating_about(value: object, limit: int = 650) -> str:
    text = str(value or "—").strip() or "—"
    if len(text.encode("utf-16-le")) // 2 <= limit:
        return text
    result: list[str] = []
    units = 0
    for character in text:
        character_units = len(character.encode("utf-16-le")) // 2
        if units + character_units > limit - 1:
            break
        result.append(character)
        units += character_units
    return "".join(result).rstrip() + "…"


def dating_profile_text(profile: dict, prefix: str = "") -> str:
    code = html.escape(dating_profile_code(profile))
    name = html.escape(shortened_dating_about(profile.get("name"), 80))
    age = html.escape(shortened_dating_about(profile.get("age"), 3))
    gender = html.escape(shortened_dating_about(profile.get("gender") or profile.get("sex") or "Не указан", 20))
    body = (
        f"Анкета #{code}\n\n"
        f"Имя: {name}\n"
        f"Возраст: {age}\n"
        f"Пол: {gender}\n"
        f"О себе: {html.escape(shortened_dating_about(profile.get('about')))}"
    )
    return prefix + body


def dating_profile_actions_keyboard(profile: dict) -> dict:
    profile_code = dating_profile_code(profile)
    rows: list[list[dict]] = []
    if not profile.get("published"):
        rows.append([button("Опубликовать анкету", callback=f"dating_publish:{profile_code}", style="success")])
    rows.extend(
        [
            [
                button("👤 Имя", callback=f"dating_edit:name:{profile_code}", style="primary"),
                button("⚧️ Пол", callback=f"dating_edit:gender:{profile_code}", style="primary"),
            ],
            [
                button("🎂 Возраст", callback=f"dating_edit:age:{profile_code}", style="primary"),
                button("📝 О себе", callback=f"dating_edit:about:{profile_code}", style="primary"),
            ],
            [button("🖼️ Фото", callback=f"dating_edit:photo:{profile_code}", style="primary")],
            [button("🗑️ Удалить анкету", callback=f"dating_delete_confirm:{profile_code}", style="danger")],
            [button("Главное меню", callback="main", style="danger")],
        ]
    )
    return keyboard(*rows)


def send_dating_card(
    chat_id: int,
    profile: dict,
    reply_markup: dict | None = None,
    prefix: str = "",
) -> dict:
    text = dating_profile_text(profile, prefix)
    photo_file_id = str(profile.get("photo_file_id", "")).strip()
    if photo_file_id:
        try:
            return send_photo_by_id(chat_id, photo_file_id, text, reply_markup)
        except Exception as exc:
            print(f"Не удалось показать фото анкеты {dating_profile_code(profile)}: {exc}", file=sys.stderr)
    return send(chat_id, text, reply_markup)


def show_dating_confirmation(chat_id: int, flow: dict) -> None:
    cleanup_flow_messages(chat_id, flow)
    cleanup_flow_form(chat_id, flow)
    flow["step"] = "confirm"
    result = send_dating_card(
        chat_id,
        flow["data"],
        keyboard(
            [button("Сохранить анкету", callback="dating_confirm", style="success")],
            [button("Отменить", callback="main", style="danger")],
        ),
        prefix="Проверьте анкету:\n\n",
    )
    if isinstance(result, dict) and result.get("message_id"):
        flow["form_message_id"] = int(result["message_id"])


def prompt_dating_photo(chat_id: int, flow: dict, error: bool = False) -> None:
    prefix = "Нужно отправить именно фотографию.\n\n" if error else ""
    result = send(
        chat_id,
        prefix + "Отправьте фотографию для анкеты 🖼️",
        dating_photo_keyboard(skip_allowed=flow.get("mode") == "create"),
    )
    flow["form_message_id"] = int(result["message_id"]) if isinstance(result, dict) and result.get("message_id") else None


def start_dating_edit(chat_id: int, field: str) -> bool:
    profile = latest_dating_profile(chat_id)
    if not profile or field not in {"name", "gender", "age", "about", "photo"}:
        return False
    hide_custom_reply_keyboard(chat_id)
    flow = {"type": "dating", "mode": "edit", "step": field, "data": dict(profile)}
    FLOWS[chat_id] = flow
    if field == "gender":
        result = send(chat_id, "Выберите пол:", dating_gender_keyboard("dating_edit_gender"))
        if isinstance(result, dict) and result.get("message_id"):
            flow["form_message_id"] = int(result["message_id"])
    elif field == "photo":
        prompt_dating_photo(chat_id, flow)
    else:
        prompts = {
            "name": "Введите новое имя:",
            "age": "Укажите возраст числом (18+):",
            "about": "Расскажите о себе:",
        }
        send_flow_prompt(chat_id, flow, prompts[field], back("dating_profile", "Назад", force_reply=True))
    return True


def finish_dating_edit(chat_id: int, flow: dict, sender: dict | None = None) -> None:
    profile = dict(flow["data"])
    if sender and sender.get("username"):
        profile["telegram_username"] = sender["username"]
    saved = save_dating_profile(profile)
    FLOWS.pop(chat_id, None)
    cleanup_flow_messages(chat_id, flow)
    cleanup_flow_form(chat_id, flow)
    show_dating_profile(chat_id, saved)


def handle_dating_message(
    chat_id: int,
    text: str,
    flow: dict,
    message_id: int | None = None,
    photo_file_id: str | None = None,
    sender: dict | None = None,
) -> None:
    step = flow["step"]
    mode = flow.get("mode", "create")
    if text.strip() in DATING_REACTION_TEXTS:
        delete_messages_safely(chat_id, [message_id])
        result = send(
            chat_id,
            "Сначала завершите или отмените редактирование анкеты — кнопки 👍, 👎 и 💤 сейчас не применяются.",
            back("dating_profile", "Отменить редактирование", force_reply=step not in {"gender", "photo", "confirm"}),
        )
        remember_flow_message(flow, result)
        return
    if step == "confirm":
        delete_messages_safely(chat_id, [message_id])
        result = send(chat_id, "Используйте кнопки «Сохранить анкету» или «Отменить» под карточкой.")
        remember_flow_message(flow, result)
        return
    if step == "photo":
        if not photo_file_id:
            delete_messages_safely(chat_id, [message_id])
            cleanup_flow_form(chat_id, flow)
            prompt_dating_photo(chat_id, flow, error=True)
            return
        cleanup_flow_messages(chat_id, flow, message_id)
        cleanup_flow_form(chat_id, flow)
        flow["data"]["photo_file_id"] = photo_file_id
        if mode == "edit":
            finish_dating_edit(chat_id, flow, sender)
        else:
            show_dating_confirmation(chat_id, flow)
        return

    value = text.strip()
    if step == "gender":
        delete_messages_safely(chat_id, [message_id])
        return
    if not value:
        cleanup_flow_messages(chat_id, flow, message_id)
        send_flow_prompt(chat_id, flow, "Пожалуйста, заполните поле.", back("main", "Главное меню", force_reply=True))
        return
    if step == "name" and len(value) > 80:
        cleanup_flow_messages(chat_id, flow, message_id)
        send_flow_prompt(chat_id, flow, "Имя слишком длинное. Максимум 80 символов:", back("main", "Главное меню", force_reply=True))
        return
    if step == "about" and len(value) > 1000:
        cleanup_flow_messages(chat_id, flow, message_id)
        send_flow_prompt(chat_id, flow, "Описание слишком длинное. Максимум 1000 символов:", back("main", "Главное меню", force_reply=True))
        return
    if step == "age" and (not re.fullmatch(r"[0-9]{1,3}", value) or not 18 <= int(value) <= 100):
        cleanup_flow_messages(chat_id, flow, message_id)
        send_flow_prompt(
            chat_id,
            flow,
            "Раздел доступен совершеннолетним. Укажите возраст числом от 18 до 100:",
            back("main", "Главное меню", force_reply=True),
        )
        return

    cleanup_flow_messages(chat_id, flow, message_id)
    flow["data"][step] = value
    if mode == "edit":
        finish_dating_edit(chat_id, flow, sender)
        return
    if step == "name":
        flow["step"] = "age"
        send_flow_prompt(chat_id, flow, "Сколько вам лет?", back("main", "Главное меню", force_reply=True))
    elif step == "age":
        flow["step"] = "gender"
        result = send(chat_id, "Выберите пол:", dating_gender_keyboard())
        if isinstance(result, dict) and result.get("message_id"):
            flow["form_message_id"] = int(result["message_id"])
    elif step == "about":
        flow["step"] = "photo"
        prompt_dating_photo(chat_id, flow)


def show_my_qr(chat_id: int) -> bool:
    records = bookings_for_chat(chat_id)
    if not records:
        return False
    send(chat_id, f"🎟 Найдено заявок с QR: {len(records)}. Показываю последние.")
    for index, record in enumerate(records):
        markup = back("main", "Главное меню") if index == len(records) - 1 else None
        send_request_qr(chat_id, record, markup)
    return True


def show_qr_lookup(chat_id: int, code: str) -> None:
    record = booking_by_code(code)
    if not record:
        send(chat_id, "QR-код не найден или заявка была удалена.", back())
        return
    if is_manager_chat(chat_id):
        send(chat_id, manager_booking_text(record), manager_booking_keyboard(record))
    else:
        send_request_qr(chat_id, record, back())


def show_dating_profile(chat_id: int, profile: dict | None = None) -> bool:
    profile = normalized_dating_profile(profile) if profile else latest_dating_profile(chat_id)
    if not profile:
        cleanup_dating_own_messages(chat_id)
        old_card_id = DATING_CARD_MESSAGE_IDS.pop(chat_id, None)
        delete_messages_safely(chat_id, [old_card_id])
        hide_custom_reply_keyboard(chat_id)
        send(chat_id, "У вас пока нет анкеты знакомств.", back("dating"))
        return False
    DATING_BROWSE.pop(chat_id, None)
    old_card_id = DATING_CARD_MESSAGE_IDS.pop(chat_id, None)
    delete_messages_safely(chat_id, [old_card_id])
    cleanup_dating_own_messages(chat_id)
    card_result = send_dating_card(chat_id, profile, dating_reply_keyboard())
    remember_dating_own_message(chat_id, card_result)
    note = "Выберите действие ниже:"
    if not profile.get("published"):
        note = (
            "Эта анкета создана в старой версии и пока не показывается другим гостям. "
            "Проверьте данные и нажмите «Опубликовать анкету».\n\n" + note
        )
    actions_result = send(
        chat_id,
        note,
        dating_profile_actions_keyboard(profile),
    )
    remember_dating_own_message(chat_id, actions_result)
    return True


def show_next_dating_profile(chat_id: int) -> bool:
    own_profile = latest_dating_profile(chat_id)
    if not own_profile:
        show_dating_menu(chat_id)
        return False
    if not own_profile.get("published"):
        show_dating_profile(chat_id, own_profile)
        return False
    old_card_id = DATING_CARD_MESSAGE_IDS.pop(chat_id, None)
    delete_messages_safely(chat_id, [old_card_id])
    cleanup_dating_own_messages(chat_id)
    candidates = available_dating_profiles(chat_id)
    if not candidates:
        DATING_BROWSE.pop(chat_id, None)
        status_result = send(
            chat_id,
            "Пока нет новых анкет. Загляните позже или откройте настройки своей анкеты через 💤.",
            dating_reply_keyboard(),
        )
        status_message_id = result_message_id(status_result)
        if status_message_id is not None:
            DATING_CARD_MESSAGE_IDS[chat_id] = status_message_id
        actions_result = send(
            chat_id,
            "Выберите действие ниже:",
            keyboard(
                [button("Моя анкета", callback="dating_profile", style="primary")],
                [button("Главное меню", callback="main", style="danger")],
            ),
        )
        remember_dating_own_message(chat_id, actions_result)
        return False
    candidate = candidates[0]
    DATING_BROWSE[chat_id] = candidate["profile_code"]
    result = send_dating_card(chat_id, candidate, dating_reply_keyboard())
    if isinstance(result, dict) and result.get("message_id"):
        DATING_CARD_MESSAGE_IDS[chat_id] = int(result["message_id"])
    return True


def reaction_exists(chat_id: int, target_profile_code: str) -> bool:
    return any(
        str(record.get("target_profile_code", "")).upper() == target_profile_code.upper()
        for record in dating_reactions_for(chat_id)
    )


def dating_match_key(first_code: str, second_code: str) -> str:
    return ":".join(sorted((first_code.upper(), second_code.upper())))


def notify_dating_match(first: dict, second: dict) -> None:
    key = dating_match_key(first["profile_code"], second["profile_code"])
    if storage().match_exists(key):
        return
    if not storage().add_match(
        {
            "created_at": int(time.time()),
            "match_key": key,
            "profile_codes": [first["profile_code"], second["profile_code"]],
        },
    ):
        return
    for recipient, partner in ((first, second), (second, first)):
        try:
            partner_name = str(partner.get("name", "участником"))
            partner_chat_id = int(partner["chat_id"])
            contact_url = f"tg://user?id={partner_chat_id}"
            button_name = shortened_dating_about(partner_name, 40)
            send(
                int(recipient["chat_id"]),
                "💞 <b>Взаимная симпатия!</b>\n\n"
                f"Вы понравились друг другу с анкетой #{html.escape(partner['profile_code'])} "
                f"({html.escape(partner_name)}). Контакт доступен только вам двоим.",
                keyboard([button(f"Написать {button_name}", url=contact_url, style="success")]),
            )
        except Exception as exc:
            print(f"Не удалось отправить уведомление о совпадении {key}: {exc}", file=sys.stderr)


def record_dating_reaction(chat_id: int, action: str) -> bool:
    target_code = DATING_BROWSE.pop(chat_id, None)
    if not target_code:
        return False
    target = dating_profile_by_code(target_code)
    own = latest_dating_profile(chat_id)
    if not target or not target.get("published") or not own or not own.get("published"):
        return False
    if reaction_exists(chat_id, target_code):
        return False
    inserted = storage().add_reaction(
        {
            "created_at": int(time.time()),
            "chat_id": int(chat_id),
            "actor_profile_code": own["profile_code"],
            "target_profile_code": target_code,
            "action": action,
        },
    )
    if not inserted:
        return False
    if action == "like":
        reverse_like = any(
            str(record.get("target_profile_code", "")).upper() == own["profile_code"]
            and str(record.get("action", "")) == "like"
            for record in dating_reactions_for(int(target["chat_id"]))
        )
        if reverse_like:
            notify_dating_match(own, target)
    return True


def handle_dating_reaction(chat_id: int, text: str, message_id: int | None = None) -> None:
    previous_card_id = DATING_CARD_MESSAGE_IDS.pop(chat_id, None)
    delete_messages_safely(chat_id, [message_id, previous_card_id])
    if text == DATING_SLEEP_TEXT:
        DATING_BROWSE.pop(chat_id, None)
        show_dating_profile(chat_id)
        return
    if text not in {DATING_LIKE_TEXT, DATING_DISLIKE_TEXT}:
        return
    target_exists = bool(DATING_BROWSE.get(chat_id))
    if target_exists:
        record_dating_reaction(chat_id, "like" if text == DATING_LIKE_TEXT else "skip")
    show_next_dating_profile(chat_id)


def show_dating_menu(chat_id: int) -> None:
    profile = latest_dating_profile(chat_id)
    if profile:
        if profile.get("published"):
            show_next_dating_profile(chat_id)
        else:
            show_dating_profile(chat_id, profile)
        return
    DATING_BROWSE.pop(chat_id, None)
    old_card_id = DATING_CARD_MESSAGE_IDS.pop(chat_id, None)
    delete_messages_safely(chat_id, [old_card_id])
    cleanup_dating_own_messages(chat_id)
    hide_custom_reply_keyboard(chat_id)
    send(
        chat_id,
        "❤️ <b>Знакомства в Mishkin&amp;Mishkin</b>\n\n"
        "Раздел для совершеннолетних гостей комплекса. После сохранения анкету увидят другие "
        "участники, а контакт откроется только при взаимной симпатии. Анкету можно изменить или удалить.",
        keyboard(
            [button("Заполнить анкету", callback="dating_start", style="success")],
            [button("Главное меню", callback="main", style="danger")],
        ),
    )


def manager_dashboard_keyboard(actor: dict) -> dict:
    counts = storage().booking_status_counts()
    own_counts = storage().booking_status_counts(int(actor["id"]))
    mine = sum(own_counts.get(status, 0) for status in ("in_progress", "contacted", "no_answer"))
    return keyboard(
        [button(f"🆕 Новые · {counts.get('received', 0)}", callback="mgr:new", style="primary")],
        [button(f"🙋 Мои в работе · {mine}", callback="mgr:mine", style="primary")],
        [button(f"📵 Не дозвонились · {counts.get('no_answer', 0)}", callback="mgr:no_answer", style="primary")],
        [button("✅ Подтверждены сегодня", callback="mgr:today", style="primary")],
        [button("🔄 Обновить", callback="mgr:home", style="primary")],
        [button("Главное меню", callback="main", style="danger")],
    )


def show_manager_dashboard(chat_id: int, actor: dict, message_id: int | None = None) -> None:
    text = (
        "🗂 <b>Рабочее место менеджера</b>\n\n"
        f"Менеджер: {html.escape(str(actor['label']))}\n"
        "Здесь заявки распределяются между менеджерами без двойных звонков. "
        "Сначала нажмите «Взять в работу» в карточке заявки."
    )
    markup = manager_dashboard_keyboard(actor)
    if message_id is not None:
        try:
            edit_message(chat_id, message_id, text, markup)
            return
        except Exception:
            pass
    send(chat_id, text, markup)


def manager_queue_records(mode: str, actor: dict) -> tuple[str, list[dict]]:
    if mode == "new":
        return "🆕 Новые заявки", storage().bookings_by_status({"received"}, limit=10)
    if mode == "mine":
        return (
            "🙋 Мои активные заявки",
            storage().bookings_by_status(
                {"in_progress", "contacted", "no_answer"},
                assigned_manager_id=int(actor["id"]),
                limit=10,
            ),
        )
    if mode == "no_answer":
        return "📵 Требуют повторного звонка", storage().bookings_by_status({"no_answer"}, limit=10)
    if mode == "today":
        moscow = dt.timezone(dt.timedelta(hours=3))
        start = dt.datetime.now(moscow).replace(hour=0, minute=0, second=0, microsecond=0)
        return (
            "✅ Подтверждены сегодня",
            storage().bookings_by_status({"confirmed"}, since=int(start.timestamp()), limit=10),
        )
    return "Заявки", []


def show_manager_queue(chat_id: int, actor: dict, mode: str, message_id: int | None = None) -> None:
    title, records = manager_queue_records(mode, actor)
    lines = [f"<b>{title}</b>", ""]
    rows: list[list[dict]] = []
    if not records:
        lines.append("Сейчас здесь нет заявок.")
    for record in records:
        code = str(record.get("request_code", "—"))
        kind = str(record.get("kind", "—"))
        when = str(record.get("datetime", "—"))
        assigned = str(record.get("assigned_manager") or "не назначен")
        lines.append(
            f"<code>{html.escape(code)}</code> · {html.escape(kind)}\n"
            f"{html.escape(when)} · {html.escape(assigned)}"
        )
        rows.append([button(f"Открыть {code}", callback=f"mgr:open:{code}", style="primary")])
    rows.append([button("← Рабочее место", callback="mgr:home", style="danger")])
    text = "\n\n".join(lines)
    markup = keyboard(*rows)
    if message_id is not None:
        try:
            edit_message(chat_id, message_id, text, markup)
            return
        except Exception:
            pass
    send(chat_id, text, markup)


def refresh_manager_card_message(query: dict, record: dict) -> None:
    message = query.get("message") or {}
    chat_id = (message.get("chat") or {}).get("id")
    message_id = message.get("message_id")
    if chat_id is None or message_id is None:
        return
    try:
        edit_message(chat_id, int(message_id), manager_booking_text(record), manager_booking_keyboard(record))
    except Exception:
        pass


def run_manager_transition(
    query: dict,
    action: str,
    code: str,
    expected_version: int | None,
) -> None:
    actor = manager_actor(query.get("from"))
    callback_id = str(query.get("id", ""))
    if not actor:
        callback_ack(callback_id, "Изменять заявки могут только подключённые менеджеры.", True)
        return
    target_status = {
        "claim": "in_progress",
        "retry": "in_progress",
        "contacted": "contacted",
        "no_answer": "no_answer",
        "confirmed": "confirmed",
        "cancelled": "cancelled",
    }.get(action)
    if not target_status:
        callback_ack(callback_id, "Некорректное действие.", True)
        return
    result, record = storage().transition_booking(
        code,
        target_status,
        actor_id=int(actor["id"]),
        actor_username=str(actor["username"]),
        actor_label=str(actor["label"]),
        expected_version=expected_version,
        callback_query_id=callback_id or None,
    )
    if result == "updated" and record:
        notices = {
            "in_progress": "Заявка закреплена за вами 🙋",
            "contacted": "Отметили, что с гостем связались 📞",
            "no_answer": "Отметили неудачный звонок 📵",
            "confirmed": "Бронь подтверждена ✅",
            "cancelled": "Заявка отменена ❌",
        }
        callback_ack(callback_id, notices[target_status], True)
        refresh_manager_notifications(record)
        refresh_manager_card_message(query, record)
        if target_status in {"confirmed", "cancelled"}:
            notify_client_booking_status(record)
        return
    if record:
        refresh_manager_notifications(record)
        refresh_manager_card_message(query, record)
    if result == "assigned_to_other":
        owner = str((record or {}).get("assigned_manager") or "другой менеджер")
        callback_ack(callback_id, f"Заявка уже в работе у {owner}.", True)
    elif result == "stale":
        callback_ack(callback_id, "Карточка устарела — показано актуальное состояние.", True)
    elif result == "terminal":
        callback_ack(callback_id, "Заявка уже закрыта. Состояние не изменено.", True)
    elif result == "unchanged":
        callback_ack(callback_id, "Это действие уже выполнено.", True)
    else:
        callback_ack(callback_id, "Заявка не найдена или переход статуса недоступен.", True)


def notification_status_text() -> str:
    registered = notification_recipients()
    lines = ["📨 <b>Получатели заявок</b>", ""]
    for username in sorted(NOTIFICATION_USERNAMES):
        marker = "✅" if username in registered else "⏳"
        suffix = "подключён" if username in registered else "нужно нажать /start"
        lines.append(f"{marker} @{html.escape(username)} — {suffix}")
    if ADMIN_CHAT_ID:
        lines.append("✅ Дополнительный ADMIN_CHAT_ID подключён")
    return "\n".join(lines)


def on_message(message: dict) -> None:
    chat = message["chat"]
    chat_id = chat["id"]
    message_id = message.get("message_id")
    text = (message.get("text") or "").strip()
    contact = message.get("contact") or None
    photo_sizes = message.get("photo") or []
    photo_file_id = str(photo_sizes[-1].get("file_id", "")) if photo_sizes else None
    recipient_registered = register_notification_recipient(message.get("from"))
    active_flow = FLOWS.get(chat_id)
    if not is_private_chat(chat) and (
        text.startswith("/profile")
        or text in DATING_REACTION_TEXTS
        or (active_flow and active_flow.get("type") == "dating")
    ):
        show_dating_private_only(chat_id)
        return
    if text.startswith("/privacy"):
        send(chat_id, PRIVACY_TEXT, back())
        return
    if text.startswith("/start"):
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            clear_active_flow(chat_id, previous_flow, message_id)
        else:
            hide_custom_reply_keyboard(chat_id)
        parts = text.split(maxsplit=1)
        if len(parts) == 2 and parts[1].startswith("qr_"):
            show_qr_lookup(chat_id, parts[1][3:])
            return
        if not has_consent(chat_id):
            request_consent(chat_id)
            if recipient_registered:
                send(chat_id, "✅ Этот аккаунт подключён к получению новых заявок.")
            return
        show_main(chat_id)
        if recipient_registered:
            send(chat_id, "✅ Этот аккаунт подключён к получению новых заявок.")
        return
    if text.startswith("/menu"):
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            clear_active_flow(chat_id, previous_flow, message_id)
        else:
            hide_custom_reply_keyboard(chat_id)
        if not has_consent(chat_id):
            request_consent(chat_id)
            return
        show_main(chat_id)
        return
    if text.startswith("/contacts"):
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            clear_active_flow(chat_id, previous_flow, message_id)
        else:
            hide_custom_reply_keyboard(chat_id)
        show_contacts(chat_id)
        return
    if text.startswith("/cancel"):
        previous_flow = FLOWS.pop(chat_id, None)
        cancel_active_flow(chat_id, previous_flow, message_id)
        return
    if text.startswith("/myqr"):
        if not has_consent(chat_id):
            request_consent(chat_id)
            return
        if not show_my_qr(chat_id):
            send(chat_id, "Вы ещё не зарегистрированы ни на одно мероприятие!", back())
        return
    if text.startswith("/profile"):
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            clear_active_flow(chat_id, previous_flow, message_id)
        if not has_consent(chat_id):
            request_consent(chat_id)
            return
        show_dating_profile(chat_id)
        return
    if text.startswith("/manager"):
        actor = manager_actor(message.get("from"))
        if actor:
            show_manager_dashboard(chat_id, actor)
        else:
            send(chat_id, "Рабочее место доступно только подключённым менеджерам.", back())
        return
    if text.startswith("/notifications"):
        if manager_actor(message.get("from")):
            send(chat_id, notification_status_text(), back())
        else:
            send(chat_id, "Эта команда доступна только ответственным аккаунтам.", back())
        return
    if not has_consent(chat_id):
        request_consent(chat_id)
        return
    flow = FLOWS.get(chat_id)
    if flow and text == PHONE_CANCEL_TEXT:
        FLOWS.pop(chat_id, None)
        cancel_active_flow(chat_id, flow, message_id)
        return
    if flow and flow.get("type") == "booking":
        if flow.get("step") == "phone" and isinstance(contact, dict):
            sender_id = (message.get("from") or {}).get("id")
            contact_user_id = contact.get("user_id")
            if sender_id and contact_user_id and int(sender_id) != int(contact_user_id):
                cleanup_flow_messages(chat_id, flow, message_id)
                prompt_for_phone(chat_id, flow, error=True)
                return
            accept_booking_phone(chat_id, flow, str(contact.get("phone_number", "")), message_id)
            return
        handle_booking_message(chat_id, text, flow, message_id)
    elif flow and flow.get("type") == "dating":
        handle_dating_message(
            chat_id,
            text,
            flow,
            message_id,
            photo_file_id,
            message.get("from"),
        )
    elif text in DATING_REACTION_TEXTS:
        handle_dating_reaction(chat_id, text, message_id)
    else:
        send(chat_id, "Выберите нужный раздел в меню 👇", MAIN_KB)


def callback_ack(callback_id: str, text: str | None = None, show_alert: bool = False) -> None:
    payload: dict = {"callback_query_id": callback_id, "show_alert": show_alert}
    if text:
        payload["text"] = text
    api("answerCallbackQuery", payload)


def on_callback(query: dict) -> None:
    chat = query["message"]["chat"]
    chat_id = chat["id"]
    data = query.get("data", "")
    callback_id = query["id"]
    register_notification_recipient(query.get("from"))

    if data == "consent_accept":
        callback_ack(callback_id)
        if not has_consent(chat_id):
            storage().save_consent(int(chat_id))
            CONSENTED_CHAT_IDS.add(int(chat_id))
        send(chat_id, "✅ Согласие получено")
        show_main(chat_id)
        return

    if data == "my_qr":
        if not has_consent(chat_id):
            callback_ack(callback_id)
            request_consent(chat_id)
            return
        if not bookings_for_chat(chat_id):
            callback_ack(callback_id, "Вы ещё не зарегистрированы ни на одно мероприятие!", True)
            return
        callback_ack(callback_id)
        show_my_qr(chat_id)
        return

    if data == "notification_test_ack":
        callback_ack(callback_id, "Тестовое уведомление подтверждено ✅", True)
        return

    if data.startswith("bst:"):
        # Backward compatibility for cards sent before the manager workspace upgrade.
        try:
            _prefix, status, code = data.split(":", 2)
        except ValueError:
            callback_ack(callback_id, "Некорректная команда.", True)
            return
        record = booking_by_code(code)
        if not record:
            callback_ack(callback_id, "Заявка не найдена.", True)
            return
        if status == "cancelled":
            actor = manager_actor(query.get("from"))
            if not actor:
                callback_ack(callback_id, "Изменять заявки могут только подключённые менеджеры.", True)
                return
            callback_ack(callback_id)
            send(
                chat_id,
                f"⚠️ Подтвердите отмену заявки <code>{html.escape(code.upper())}</code>.",
                keyboard(
                    [
                        button(
                            "Да, отменить заявку",
                            callback=f"bm:cancelled:{code.upper()}:{int(record.get('status_version', 1))}",
                            style="danger",
                        )
                    ],
                    [button("Не отменять", callback=f"bmr:{code.upper()}:{int(record.get('status_version', 1))}")],
                ),
            )
            return
        run_manager_transition(query, status, code, int(record.get("status_version", 1)))
        return

    if data.startswith("bm:"):
        try:
            _prefix, action, code, version_text = data.split(":", 3)
            version = int(version_text)
        except (TypeError, ValueError):
            callback_ack(callback_id, "Некорректная команда.", True)
            return
        run_manager_transition(query, action, code, version)
        return

    if data.startswith("bmc:"):
        actor = manager_actor(query.get("from"))
        if not actor:
            callback_ack(callback_id, "Изменять заявки могут только подключённые менеджеры.", True)
            return
        try:
            _prefix, code, version_text = data.split(":", 2)
            version = int(version_text)
        except (TypeError, ValueError):
            callback_ack(callback_id, "Некорректная команда.", True)
            return
        record = booking_by_code(code)
        if not record:
            callback_ack(callback_id, "Заявка не найдена.", True)
            return
        if int(record.get("status_version", 1)) != version:
            callback_ack(callback_id, "Карточка устарела — показано актуальное состояние.", True)
            refresh_manager_notifications(record)
            refresh_manager_card_message(query, record)
            return
        assigned_id = record.get("assigned_manager_id")
        if assigned_id is not None and int(assigned_id) != int(actor["id"]):
            callback_ack(callback_id, f"Заявка уже в работе у {record.get('assigned_manager', 'другого менеджера')}.", True)
            return
        callback_ack(callback_id)
        send(
            chat_id,
            f"⚠️ <b>Точно отменить заявку?</b>\n\nКод: <code>{html.escape(code.upper())}</code>\n"
            "Клиент сразу получит уведомление об отмене.",
            keyboard(
                [button("Да, отменить", callback=f"bm:cancelled:{code.upper()}:{version}", style="danger")],
                [button("Нет, оставить", callback=f"bmr:{code.upper()}:{version}", style="primary")],
            ),
        )
        return

    if data.startswith("bmh:") or data.startswith("bmr:"):
        actor = manager_actor(query.get("from"))
        if not actor:
            callback_ack(callback_id, "Команда доступна только подключённым менеджерам.", True)
            return
        try:
            _prefix, code, _version_text = data.split(":", 2)
        except ValueError:
            callback_ack(callback_id, "Некорректная команда.", True)
            return
        record = booking_by_code(code)
        if not record:
            callback_ack(callback_id, "Заявка не найдена.", True)
            return
        callback_ack(callback_id)
        if data.startswith("bmh:"):
            send(
                chat_id,
                f"🧾 <b>История заявки {html.escape(code.upper())}</b>\n\n{booking_history_text(record, 10)}",
                keyboard(
                    [
                        button(
                            "Вернуться к карточке",
                            callback=f"bmr:{code.upper()}:{int(record.get('status_version', 1))}",
                            style="primary",
                        )
                    ]
                ),
            )
        else:
            refresh_manager_notifications(record)
            refresh_manager_card_message(query, record)
        return

    if data.startswith("mgr:"):
        actor = manager_actor(query.get("from"))
        if not actor:
            callback_ack(callback_id, "Рабочее место доступно только подключённым менеджерам.", True)
            return
        parts = data.split(":", 2)
        action = parts[1] if len(parts) > 1 else "home"
        message_id = (query.get("message") or {}).get("message_id")
        callback_ack(callback_id)
        if action == "home":
            show_manager_dashboard(chat_id, actor, message_id)
        elif action == "open" and len(parts) == 3:
            record = booking_by_code(parts[2])
            if record:
                try:
                    edit_message(chat_id, message_id, manager_booking_text(record), manager_booking_keyboard(record))
                except Exception:
                    send(chat_id, manager_booking_text(record), manager_booking_keyboard(record))
            else:
                send(chat_id, "Заявка не найдена.", manager_dashboard_keyboard(actor))
        else:
            show_manager_queue(chat_id, actor, action, message_id)
        return

    message_id = query.get("message", {}).get("message_id")
    if is_dating_callback_data(data) and not is_private_chat(chat):
        callback_ack(callback_id, "Знакомства доступны только в личном чате с ботом.", True)
        show_dating_private_only(chat_id)
        return
    dating_validation_error = dating_callback_validation_error(chat_id, data, message_id)
    if dating_validation_error:
        callback_ack(callback_id, dating_validation_error, True)
        return

    callback_ack(callback_id)
    if not has_consent(chat_id):
        request_consent(chat_id)
        return
    if data == "noop":
        return
    flow = FLOWS.get(chat_id)
    if data.startswith("calm:"):
        if not flow or flow.get("type") != "booking" or flow.get("step") != "date":
            send(chat_id, "Форма бронирования уже закрыта. Откройте нужный раздел заново.", MAIN_KB)
            return
        try:
            year, month = (int(value) for value in data.split(":", 1)[1].split("-", 1))
            first_day = dt.date(year, month, 1)
        except (ValueError, TypeError):
            show_booking_calendar(chat_id, flow)
            return
        today = dt.date.today()
        min_month = dt.date(today.year, today.month, 1)
        max_year, max_month = shift_month(today.year, today.month, 12)
        if not min_month <= first_day <= dt.date(max_year, max_month, 1):
            show_booking_calendar(chat_id, flow)
            return
        show_booking_calendar(chat_id, flow, year, month, message_id)
        return
    if data == "calshow":
        if not flow or flow.get("type") != "booking":
            show_main(chat_id)
            return
        flow["step"] = "date"
        state = flow.get("calendar") or {}
        show_booking_calendar(chat_id, flow, state.get("year"), state.get("month"), message_id)
        return
    if data.startswith("cald:"):
        if not flow or flow.get("type") != "booking" or flow.get("step") != "date":
            send(chat_id, "Форма бронирования уже закрыта. Откройте нужный раздел заново.", MAIN_KB)
            return
        try:
            selected_date = dt.date.fromisoformat(data.split(":", 1)[1])
        except ValueError:
            show_booking_calendar(chat_id, flow)
            return
        if not booking_date_is_allowed(selected_date):
            show_booking_calendar(chat_id, flow)
            return
        flow["data"]["date_iso"] = selected_date.isoformat()
        flow["step"] = "time"
        text = (
            f"🕒 <b>{selected_date.day} {MONTH_NAMES_GENITIVE[selected_date.month]} {selected_date.year}</b>\n\n"
            "Выберите желаемое время:"
        )
        markup = booking_time_keyboard(flow["kind"], selected_date)
        if message_id:
            edit_message(chat_id, message_id, text, markup)
            flow["form_message_id"] = message_id
        else:
            result = send(chat_id, text, markup)
            if isinstance(result, dict) and result.get("message_id"):
                flow["form_message_id"] = int(result["message_id"])
        return
    if data.startswith("btime:"):
        if not flow or flow.get("type") != "booking" or flow.get("step") != "time":
            show_main(chat_id)
            return
        compact = data.split(":", 1)[1]
        if len(compact) != 4 or not compact.isdigit():
            return
        selected_time = f"{compact[:2]}:{compact[2:]}"
        selected_date = dt.date.fromisoformat(flow["data"]["date_iso"])
        if selected_time not in available_booking_times(flow["kind"], selected_date):
            if message_id:
                edit_message(
                    chat_id,
                    message_id,
                    "Это время уже недоступно. Выберите другое:",
                    booking_time_keyboard(flow["kind"], selected_date),
                )
                flow["form_message_id"] = message_id
            else:
                result = send(
                    chat_id,
                    "Это время уже недоступно. Выберите другое:",
                    booking_time_keyboard(flow["kind"], selected_date),
                )
                if isinstance(result, dict) and result.get("message_id"):
                    flow["form_message_id"] = int(result["message_id"])
            return
        flow["data"]["time"] = selected_time
        flow["data"]["datetime"] = (
            f"{selected_date.day} {MONTH_NAMES_GENITIVE[selected_date.month]} {selected_date.year}, {selected_time}"
        )
        flow["step"] = "guests"
        text = f"✅ Дата и время: <b>{html.escape(flow['data']['datetime'])}</b>\n\nСколько будет гостей?"
        markup = booking_guests_keyboard()
        if message_id:
            edit_message(chat_id, message_id, text, markup)
            flow["form_message_id"] = message_id
        else:
            result = send(chat_id, text, markup)
            if isinstance(result, dict) and result.get("message_id"):
                flow["form_message_id"] = int(result["message_id"])
        return
    if data.startswith("bguest:"):
        if not flow or flow.get("type") != "booking" or flow.get("step") != "guests":
            show_main(chat_id)
            return
        value = data.split(":", 1)[1]
        if value == "other":
            send_flow_prompt(
                chat_id,
                flow,
                "Введите количество гостей числом:",
                back("main", "Отменить", force_reply=True),
            )
            return
        if not value.isdigit() or not 1 <= int(value) <= 1000:
            return
        flow["data"]["guests"] = value
        flow["step"] = "comment"
        text = f"✅ Гостей: <b>{value}</b>\n\nДобавить комментарий к заявке?"
        markup = booking_comment_keyboard()
        if message_id:
            edit_message(chat_id, message_id, text, markup)
            flow["form_message_id"] = message_id
        else:
            result = send(chat_id, text, markup)
            if isinstance(result, dict) and result.get("message_id"):
                flow["form_message_id"] = int(result["message_id"])
        return
    if data.startswith("bcomment:"):
        if not flow or flow.get("type") != "booking" or flow.get("step") != "comment":
            show_main(chat_id)
            return
        value = data.split(":", 1)[1]
        if value == "manual":
            send_flow_prompt(
                chat_id,
                flow,
                "Введите комментарий к бронированию:",
                back("main", "Отменить", force_reply=True),
            )
            return
        if value == "none":
            flow["data"]["comment"] = "нет"
            show_booking_summary(chat_id, flow)
        return
    if data.startswith("dating_gender:"):
        if not flow or flow.get("type") != "dating" or flow.get("mode", "create") != "create" or flow.get("step") != "gender":
            show_dating_menu(chat_id)
            return
        gender = {"male": "Муж", "female": "Жен"}.get(data.split(":", 1)[1])
        if not gender:
            return
        cleanup_flow_form(chat_id, flow)
        flow["data"]["gender"] = gender
        flow["step"] = "about"
        send_flow_prompt(
            chat_id,
            flow,
            "Расскажите немного о себе 👀",
            back("main", "Главное меню", force_reply=True),
        )
        return
    if data.startswith("dating_edit_gender:"):
        if not flow or flow.get("type") != "dating" or flow.get("mode") != "edit" or flow.get("step") != "gender":
            show_dating_profile(chat_id)
            return
        gender = {"male": "Муж", "female": "Жен"}.get(data.split(":", 1)[1])
        if not gender:
            return
        cleanup_flow_form(chat_id, flow)
        flow["data"]["gender"] = gender
        finish_dating_edit(chat_id, flow, query.get("from"))
        return
    if data == "dating_photo_skip":
        if not flow or flow.get("type") != "dating" or flow.get("mode", "create") != "create" or flow.get("step") != "photo":
            show_dating_menu(chat_id)
            return
        cleanup_flow_form(chat_id, flow)
        flow["data"].pop("photo_file_id", None)
        show_dating_confirmation(chat_id, flow)
        return
    if data == "main":
        active_flow = FLOWS.pop(chat_id, None)
        if active_flow:
            clear_active_flow(chat_id, active_flow, message_id)
            menu_message_id = None
        else:
            hide_custom_reply_keyboard(chat_id)
            menu_message_id = message_id
        DATING_BROWSE.pop(chat_id, None)
        old_card_id = DATING_CARD_MESSAGE_IDS.pop(chat_id, None)
        cleanup_dating_own_messages(chat_id)
        delete_messages_safely(chat_id, [old_card_id, menu_message_id])
        show_main(chat_id)
    elif data in {"restaurant", "restobar"}:
        send(
            chat_id,
            RESTOBAR_TEXT,
            keyboard(
                [button("Меню", callback="restaurant_menu")],
                [button("Бронь", callback="booking:Рестобар")],
                [button("Акции", callback="restaurant_promo")],
                [button("Подробнее ↗", url=f"{SITE_URL}/restobar")],
                [button("Назад", callback="main")],
            ),
        )
    elif data in {"restaurant_menu", "restobar_menu"}:
        send(
            chat_id,
            "Выберите меню рестобара:",
            keyboard(
                [button("Меню рестобара (PDF)", callback="menu:restaurant_kitchen")],
                [button("Детское меню (PDF)", callback="menu:restaurant_kids")],
                [button("Барная карта (PDF)", callback="menu:restaurant_bar")],
                [button("Назад", callback="restaurant")],
            ),
        )
    elif data == "restaurant_promo":
        send(
            chat_id,
            RESTAURANT_PROMO_TEXT,
            keyboard(
                [button("Афиша ↗", url=f"{SITE_URL}/karaoke-show"), button("Telegram ↗", url=TELEGRAM_URL)],
                [button("Оставить заявку", callback="booking:Акция рестобара")],
                [button("Назад", callback="restaurant")],
            ),
        )
    elif data in {"banquets", "events"}:
        send(
            chat_id,
            BANQUETS_TEXT,
            keyboard(
                [button("Меню", callback="banquet_menu")],
                [button("Бронь", callback="booking:Банкеты и дни рождения")],
                [button("Акции и форматы", callback="banquet_promo")],
                [button("Подарочный сертификат", callback="gift")],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "banquet_menu":
        send(
            chat_id,
            "Выберите меню для события:",
            keyboard(
                [button("Основное меню (PDF)", callback="menu:banquet_kitchen")],
                [button("Детское меню (PDF)", callback="menu:banquet_kids")],
                [button("Барная карта (PDF)", callback="menu:banquet_bar")],
                [button("Назад", callback="banquets")],
            ),
        )
    elif data == "banquet_promo":
        send(
            chat_id,
            BANQUETS_PROMO_TEXT,
            keyboard(
                [button("Пакеты Мишкин Парка", callback="park_packages")],
                [button("Пакеты VR Arena", callback="arena_packages")],
                [button("Оставить заявку", callback="booking:Банкет или день рождения")],
                [button("Назад", callback="banquets")],
            ),
        )
    elif data == "dance":
        send(
            chat_id,
            DANCE_TEXT,
            keyboard(
                [button("Афиша", callback="dance_poster")],
                [button("Бронь", callback="booking:Танцевальные выходные")],
                [button("Акции", callback="dance_promos")],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "dance_poster":
        send(
            chat_id,
            DANCE_PROMO_TEXT,
            keyboard(
                [button("Открыть афишу ↗", url=f"{SITE_URL}/karaoke-show")],
                [button("Telegram ↗", url=TELEGRAM_URL)],
                [button("Назад", callback="dance")],
            ),
        )
    elif data == "dance_promos":
        send(
            chat_id,
            DANCE_PROMO_TEXT,
            keyboard(
                [button("Уточнить условия", callback="booking:Акция танцевальных выходных")],
                [button("Назад", callback="dance")],
            ),
        )
    elif data == "karaoke":
        send(
            chat_id,
            KARAOKE_TEXT,
            keyboard(
                [button("Меню", callback="karaoke_menu")],
                [button("Бронь", callback="booking:Караоке-холл")],
                [button("Акции", callback="karaoke_promo")],
                [button("Схема зала ↗", url=f"{SITE_URL}/karaoke#popup:scheme")],
                [button("Подробнее ↗", url=f"{SITE_URL}/karaoke")],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "karaoke_menu":
        send(
            chat_id,
            "Выберите меню караоке:",
            keyboard(
                [button("Меню кухни (PDF)", callback="menu:karaoke_kitchen")],
                [button("Детское меню (PDF)", callback="menu:karaoke_kids")],
                [button("Барная карта (PDF)", callback="menu:karaoke_bar")],
                [button("Назад", callback="karaoke")],
            ),
        )
    elif data == "karaoke_promo":
        send(
            chat_id,
            KARAOKE_PROMO_TEXT,
            keyboard(
                [button("Афиша ↗", url=f"{SITE_URL}/karaoke-show")],
                [button("Рассчитать событие", callback="booking:Событие в караоке")],
                [button("Назад", callback="karaoke")],
            ),
        )
    elif data == "karting":
        send(
            chat_id,
            KARTING_TEXT,
            keyboard(
                [button("Цены", callback="karting_prices")],
                [button("Аренда", callback="booking:Аренда картинга")],
                [button("Акции", callback="karting_promo")],
                [button("Академия", callback="karting_academy")],
                [button("Подарочный сертификат ↗", url="https://krasnodar.drivekarting.ru/gift-certificate")],
                [button("Подробнее ↗", url=KARTING_URL)],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "karting_prices":
        send(chat_id, KARTING_PRICES, back("karting"))
    elif data == "karting_academy":
        send(chat_id, KARTING_ACADEMY, back("karting"))
    elif data == "karting_promo":
        send(
            chat_id,
            "🏁 <b>Акции и события картинга</b>\n\n"
            "Доступны командные соревнования, тимбилдинги, дни рождения, академия картинга и "
            "подарочные сертификаты. Актуальный расчёт зависит от даты, состава участников и длительности аренды.",
            keyboard(
                [button("Рассчитать мероприятие", callback="booking:Событие на картинге")],
                [button("Академия", callback="karting_academy")],
                [button("Назад", callback="karting")],
            ),
        )
    elif data in {"arena", "vr"}:
        send(
            chat_id,
            ARENA_TEXT,
            keyboard(
                [button("Цены", callback="arena_prices")],
                [button("Бронирование VR", callback="booking:Арена VR")],
                [button("Бронирование автосимуляторов", callback="booking:Автосимуляторы")],
                [button("Праздник под ключ", callback="arena_packages")],
                [button("Подробнее ↗", url=f"{SITE_URL}/vr")],
                [button("Назад", callback="main")],
            ),
        )
    elif data in {"arena_prices", "vr_prices"}:
        send(chat_id, PARK_PRICES_2, back("arena"))
    elif data in {"arena_packages", "vr_packages"}:
        send(
            chat_id,
            VR_PACKAGES,
            keyboard(
                [button("Забронировать", callback="booking:Праздник в VR Arena")],
                [button("Назад", callback="arena")],
            ),
        )
    elif data == "park":
        send(
            chat_id,
            PARK_TEXT,
            keyboard(
                [button("Цены и активности", callback="park_prices")],
                [button("Пакеты праздников", callback="park_packages")],
                [button("Шоу и мастер-классы", callback="park_programs")],
                [button("Забронировать", callback="booking:Мишкин Парк")],
                [button("Подробнее ↗", url=f"{SITE_URL}/park")],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "park_prices":
        send(chat_id, PARK_PRICES_1)
        send(chat_id, PARK_PRICES_2, back("park"))
    elif data == "park_packages":
        send(
            chat_id,
            PARK_PACKAGES,
            keyboard(
                [button("Забронировать", callback="booking:Праздник в Мишкин Парке")],
                [button("Назад", callback="park")],
            ),
        )
    elif data == "park_programs":
        send(chat_id, PARK_PROGRAMS, back("park"))
    elif data == "food":
        send(
            chat_id,
            FOOD_TEXT,
            keyboard(
                [button("Открыть меню (PDF)", callback="menu:food_menu")],
                [button("Подробнее ↗", url=f"{SITE_URL}/food")],
                [button("Назад", callback="main")],
            ),
        )
    elif data.startswith("menu:"):
        document_key = data.split(":", 1)[1]
        if document_key in MENU_DOCUMENTS:
            send_menu_document(chat_id, document_key)
        else:
            show_main(chat_id)
    elif data == "lounge":
        send(
            chat_id,
            LOUNGE_TEXT,
            keyboard(
                [button("Прайс-лист ↗", url="https://disk.yandex.ru/i/Y9lZvw-fWh70qA")],
                [button("Забронировать", callback="booking:Дым Мишкин")],
                [button("Подробнее ↗", url=f"{SITE_URL}/lounge")],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "gift":
        send(
            chat_id,
            GIFT_TEXT,
            keyboard(
                [button("Выбрать сертификат ↗", url=GIFT_URL)],
                [button("Сертификат картинга ↗", url="https://krasnodar.drivekarting.ru/gift-certificate")],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "about":
        send(
            chat_id,
            ABOUT_TEXT,
            keyboard(
                [button("Официальный сайт ↗", url=SITE_URL)],
                [button("Открыть на карте ↗", url=MAP_URL)],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "contacts":
        show_contacts(chat_id)
    elif data == "support":
        send(
            chat_id,
            CONTACTS_TEXT,
            keyboard(
                [button("Telegram ↗", url=TELEGRAM_URL), button("ВКонтакте ↗", url=VK_URL)],
                [button("Оставить заявку", callback="booking:Общий вопрос")],
                [button("Открыть на карте ↗", url=MAP_URL)],
                [button("Назад", callback="main")],
            ),
        )
    elif data == "loyalty":
        send(
            chat_id,
            LOYALTY_TEXT,
            keyboard(
                [button("Получить 500 бонусов ↗", url=LOYALTY_URL)],
                [button("Назад", callback="main")],
            ),
        )
    elif data.startswith("booking:"):
        start_booking(chat_id, data.split(":", 1)[1])
    elif data == "dating":
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            clear_active_flow(chat_id, previous_flow)
        show_dating_menu(chat_id)
    elif data == "dating_start":
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            clear_active_flow(chat_id, previous_flow)
        cleanup_dating_own_messages(chat_id, message_id)
        start_dating(chat_id)
    elif data.startswith("dating_edit:"):
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            cleanup_flow_messages(chat_id, previous_flow)
            cleanup_flow_form(chat_id, previous_flow)
        cleanup_dating_own_messages(chat_id, message_id)
        _prefix, field, _profile_code = data.split(":", 2)
        if not start_dating_edit(chat_id, field):
            show_dating_menu(chat_id)
    elif data == "dating_profile":
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            cleanup_flow_messages(chat_id, previous_flow)
            cleanup_flow_form(chat_id, previous_flow)
        delete_messages_safely(chat_id, [message_id])
        show_dating_profile(chat_id)
    elif data.startswith("dating_publish:"):
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            cleanup_flow_messages(chat_id, previous_flow)
            cleanup_flow_form(chat_id, previous_flow)
        cleanup_dating_own_messages(chat_id, message_id)
        profile = latest_dating_profile(chat_id)
        if not profile:
            show_dating_menu(chat_id)
        elif not dating_profile_is_complete(profile):
            if profile.get("gender") not in {"Муж", "Жен"}:
                missing_field, instruction = "gender", "Перед публикацией укажите пол."
            else:
                try:
                    age_is_valid = 18 <= int(profile.get("age")) <= 100
                except (TypeError, ValueError):
                    age_is_valid = False
                if not age_is_valid:
                    missing_field, instruction = "age", "Перед публикацией укажите корректный возраст."
                elif not str(profile.get("name", "")).strip():
                    missing_field, instruction = "name", "Перед публикацией укажите имя."
                else:
                    missing_field, instruction = "about", "Перед публикацией заполните поле «О себе»."
            start_dating_edit(chat_id, missing_field)
        else:
            profile["published"] = True
            saved = save_dating_profile(profile)
            show_dating_profile(chat_id, saved)
    elif data.startswith("dating_delete_confirm:"):
        profile_code = data.split(":", 1)[1].upper()
        confirmation_text = (
            "Удалить анкету знакомств? Имя, возраст, пол, описание, фото и история реакций "
            "будут удалены из активного хранилища бота."
        )
        confirmation_markup = keyboard(
            [button("Да, удалить", callback=f"dating_delete:{profile_code}", style="danger")],
            [button("Отмена", callback="dating_profile", style="primary")],
        )
        if message_id:
            edit_message(chat_id, message_id, confirmation_text, confirmation_markup)
        else:
            send(chat_id, confirmation_text, confirmation_markup)
    elif data.startswith("dating_delete:"):
        previous_flow = FLOWS.pop(chat_id, None)
        if previous_flow:
            cleanup_flow_messages(chat_id, previous_flow)
            cleanup_flow_form(chat_id, previous_flow)
        deleted = delete_dating_profile(chat_id)
        delete_messages_safely(chat_id, [message_id])
        hide_custom_reply_keyboard(chat_id)
        send(chat_id, "Анкета удалена." if deleted else "Анкета уже удалена.", MAIN_KB)
    elif data == "booking_confirm":
        flow = FLOWS.pop(chat_id, None)
        if not flow or flow.get("type") != "booking":
            show_main(chat_id)
            return
        cleanup_flow_messages(chat_id, flow)
        cleanup_flow_form(chat_id, flow)
        now = int(time.time())
        duplicate = is_recent_duplicate(chat_id, flow, now)
        if duplicate:
            send(chat_id, "Похожая заявка уже была сохранена недавно. Повторно создавать её не стали.")
            try:
                send_request_qr(chat_id, duplicate, MAIN_KB)
            except Exception as exc:
                print(f"Не удалось отправить QR {duplicate.get('request_code')}: {exc}", file=sys.stderr)
                send(chat_id, f"Код заявки: <code>{html.escape(str(duplicate.get('request_code', '—')))}</code>", MAIN_KB)
            return
        user = query.get("from") or {}
        record = {
            "created_at": now,
            "chat_id": chat_id,
            "city": "Краснодар",
            "kind": flow["kind"],
            "request_code": "MKR-" + uuid.uuid4().hex[:<REDACTED>
            "status": "received",
            **flow["data"],
        }
        if user.get("username"):
            record["telegram_username"] = user["username"]
        record = storage().create_booking(record)
        delivered = notify_booking(record)
        if delivered:
            send(
                chat_id,
                "✅ <b>Заявка передана менеджерам</b>\n\n"
                "Это ещё не подтверждение брони — дождитесь сообщения менеджера. Ниже находится QR заявки; "
                "он также всегда доступен в разделе «Мои QR».",
            )
        else:
            send(
                chat_id,
                "✅ <b>Заявка сохранена</b>\n\n"
                "Это ещё не подтверждение брони. Ниже находится QR заявки; он также доступен в разделе «Мои QR». "
                "Сейчас уведомление менеджерам не доставлено — пожалуйста, позвоните по номеру +7 (989) 021-03-03.",
            )
        try:
            send_request_qr(chat_id, record, MAIN_KB)
        except Exception as exc:
            print(f"Не удалось отправить QR {record['request_code']}: {exc}", file=sys.stderr)
            send(chat_id, f"Код заявки: <code>{record['request_code']}</code>", MAIN_KB)
    elif data == "dating_confirm":
        flow = FLOWS.get(chat_id)
        if (
            not flow
            or flow.get("type") != "dating"
            or flow.get("mode", "create") != "create"
            or flow.get("step") != "confirm"
            or not callback_matches_flow_message(flow, message_id)
        ):
            return
        FLOWS.pop(chat_id, None)
        cleanup_flow_messages(chat_id, flow)
        cleanup_flow_form(chat_id, flow)
        data = flow.get("data") or {}
        if not dating_profile_is_complete(data):
            send(chat_id, "Анкета заполнена не полностью. Начните заполнение ещё раз.", MAIN_KB)
            return
        user = query.get("from") or {}
        record = {
            "created_at": int(time.time()),
            "chat_id": chat_id,
            "city": "Краснодар",
            "published": True,
            **data,
        }
        if user.get("username"):
            record["telegram_username"] = user["username"]
        saved = save_dating_profile(record)
        show_dating_profile(chat_id, saved)
    else:
        show_main(chat_id)


def configure_bot() -> None:
    settings = [
        (
            "setMyCommands",
            {
                "commands": [
                    {"command": "start", "description": "Начать и открыть главное меню"},
                    {"command": "menu", "description": "Открыть меню"},
                    {"command": "contacts", "description": "Контакты"},
                    {"command": "myqr", "description": "Мои QR-коды заявок"},
                    {"command": "profile", "description": "Моя анкета знакомств"},
                    {"command": "cancel", "description": "Отменить текущий ввод"},
                    {"command": "manager", "description": "Рабочее место менеджера"},
                    {"command": "notifications", "description": "Статус получателей заявок"},
                    {"command": "privacy", "description": "Обработка персональных данных"},
                ]
            },
        ),
        ("setMyName", {"name": "Mishkin&Mishkin Краснодар"}),
        (
            "setMyShortDescription",
            {"short_description": "Меню, цены, бронирование и события Mishkin&Mishkin Краснодар."},
        ),
        (
            "setMyDescription",
            {
                "description": (
                    "Официальный бот событийного комплекса Mishkin&Mishkin Краснодар. "
                    "Рестобар, караоке, картинг, Мишкин Парк, VR Arena, меню, цены, события и бронирование. "
                    "Краснодар, ул. Лаперуза, 3."
                )
            },
        ),
    ]
    for method, payload in settings:
        try:
            api(method, payload)
        except RuntimeError as exc:
            print(f"Не удалось применить настройку {method}: {exc}", file=sys.stderr)


def run() -> None:
    if not TOKEN:<REDACTED>
        print("Не задан BOT_TOKEN. Скопируйте settings.env.example в settings.env и вставьте токен.")
        raise SystemExit(2)
    me = api("getMe")
    print(f"Бот @{me.get('username')} запущен. Для остановки нажмите Ctrl+C.")
    configure_bot()
    try:
        perform_maintenance(force=True)
    except OSError as exc:
        print(f"Не удалось выполнить резервное копирование: {exc}", file=sys.stderr)
    offset = 0
    while True:
        try:
            try:
                perform_maintenance()
            except OSError as exc:
                print(f"Ошибка обслуживания данных: {exc}", file=sys.stderr)
            updates = api(
                "getUpdates",
                {"offset": offset, "timeout": 25, "allowed_updates": ["message", "callback_query"]},
            )
            for update in updates:
                offset = max(offset, update["update_id"] + 1)
                try:
                    if "message" in update:
                        on_message(update["message"])
                    elif "callback_query" in update:
                        on_callback(update["callback_query"])
                except Exception as exc:
                    print(f"Ошибка обработки update {update.get('update_id')}: {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nБот остановлен.")
            return
        except (urllib.error.URLError, TimeoutError, RuntimeError) as exc:
            print(f"Ошибка соединения: {exc}. Повтор через 3 секунды.", file=sys.stderr)
            time.sleep(3)


if __name__ == "__main__":
    if "--migrate-only" in sys.argv:
        repository = storage()
        report = {
            "database": str(repository.path),
            "integrity": repository.integrity_check(),
            "counts": repository.counts(),
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if report["integrity"] != "ok":
            raise SystemExit(1)
    else:
        run()
