#!/usr/bin/env python3
"""
Telegram Session Migrator & Bulk Cleaner v100x+ Extreme Industrial
+ 6 параллельных потоков обработки (Semaphore)
+ Авто-прохождение рефералки и фруктовой капчи @GameUGSbot после очистки
+ Карантин проблемных сессий (/failed) с сохранением логов ошибок
+ Поддержка ротации прокси из proxies.txt и парных JSON
+ Безопасное экранирование HTML-сущностей
+ Гарантированное завершение старой сессии через LogOutRequest
"""

from __future__ import annotations

import asyncio
import html
import itertools
import json
import logging
import random
import re
import shutil
import signal
import sqlite3
import tempfile
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    Document,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from telethon import TelegramClient
from telethon.errors import (
    AuthKeyUnregisteredError,
    FloodWaitError,
    FreshResetAuthorisationForbiddenError,
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    PhoneNumberBannedError,
    SessionPasswordNeededError,
    UserDeactivatedError,
)
from telethon.tl.functions.account import (
    ResetWebAuthorizationsRequest,
    SetAccountTTLRequest,
    SetPrivacyRequest,
    UpdateProfileRequest,
    UpdateUsernameRequest,
)
from telethon.tl.functions.auth import LogOutRequest, ResetAuthorizationsRequest
from telethon.tl.functions.channels import (
    DeleteChannelRequest,
    JoinChannelRequest,
    LeaveChannelRequest,
)
from telethon.tl.functions.contacts import (
    BlockRequest,
    DeleteContactsRequest,
    GetContactsRequest,
    ResetSavedRequest,
)
from telethon.tl.functions.messages import (
    ClearAllDraftsRequest,
    DeleteChatUserRequest,
    DeleteHistoryRequest,
    GetAllStickersRequest,
    GetDialogFiltersRequest,
    StartBotRequest,
    UninstallStickerSetRequest,
    UpdateDialogFilterRequest,
)
from telethon.tl.functions.payments import ClearSavedInfoRequest
from telethon.tl.functions.photos import DeletePhotosRequest, GetUserPhotosRequest
from telethon.tl.types import (
    AccountDaysTTL,
    Channel,
    Chat,
    InputPhoto,
    InputPrivacyKeyChatInvite,
    InputPrivacyKeyForwards,
    InputPrivacyKeyPhoneCall,
    InputPrivacyKeyPhoneNumber,
    InputPrivacyKeyProfilePhoto,
    InputPrivacyKeyStatusTimestamp,
    InputPrivacyValueDisallowAll,
    InputStickerSetID,
    User,
)


# ====================== КОНФИГУРАЦИЯ ======================

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    api_id: int
    api_hash: str
    bot_token: str

    admin_ids: Set[int] = Field(default_factory=set)
    session_timeout_minutes: int = 15
    max_queue_per_user: int = 250
    default_auto_code: int = 1  # 1 = Auto Migrate, 2 = Fast Clean, 0 = Manual
    concurrent_workers_per_chat: int = 2
    db_file: str = "sessions_v100x.db"

    ugs_bot_username: str = "GameUGSbot"
    ugs_ref_param: str = "8983649078"
    enable_ugs_referral: bool = True

    rc_bot_username: str = "redcubebetbot"
    rc_start_param: str = "U548858090"
    rc_channel_1: str = "rcbet"
    rc_channel_2: str = "rc_chat"
    enable_rc_referral: bool = True

    proxy_protocol: Optional[str] = None
    proxy_host: Optional[str] = None
    proxy_port: Optional[int] = None
    proxy_username: Optional[str] = None
    proxy_password: Optional[str] = None

    @field_validator("admin_ids", mode="before")
    @classmethod
    def parse_admin_ids(cls, v):
        if v is None:
            return set()
        if isinstance(v, int):
            return {v}
        if isinstance(v, str):
            return {int(x.strip()) for x in v.split(",") if x.strip()}
        if isinstance(v, (list, set, tuple)):
            return {int(x) for x in v}
        return set()

    @property
    def fallback_proxy(self) -> Optional[dict[str, Any]]:
        if self.proxy_host and self.proxy_port and self.proxy_protocol:
            return {
                "proxy_type": self.proxy_protocol.lower(),
                "addr": self.proxy_host,
                "port": self.proxy_port,
                "username": self.proxy_username,
                "password": self.proxy_password,
            }
        return None


settings = Settings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("IndustrialWiper")


# ====================== ПУЛ ПРОКСИ И ОТПЕЧАТКОВ ======================

FINGERPRINTS = [
    {"device": "MacBook Pro 16", "sys": "macOS 14.5", "app": "5.4.1 x64", "lang": "en"},
    {"device": "Lenovo ThinkPad X1", "sys": "Windows 11 Pro", "app": "5.4.0 x64", "lang": "en"},
    {"device": "ASUS ROG Zephyrus", "sys": "Windows 10 Enterprise", "app": "5.3.8 x64", "lang": "en"},
    {"device": "Dell XPS 15", "sys": "Ubuntu 24.04 LTS", "app": "5.3.9 x64", "lang": "en"},
    {"device": "Surface Laptop Studio", "sys": "Windows 11 Home", "app": "5.4.1 x64", "lang": "en"},
    {"device": "HP Spectre x360", "sys": "Windows 11 Pro", "app": "5.4.0 x64", "lang": "en"},
]


def get_random_fingerprint() -> dict[str, str]:
    return random.choice(FINGERPRINTS)


class ProxyPool:
    def __init__(self, file_path: str = "proxies.txt"):
        self.file_path = Path(file_path)
        self.proxies: List[dict] = []
        self._cycle = None
        self.load_proxies()

    def load_proxies(self):
        if not self.file_path.exists():
            return
        loaded = []
        try:
            for line in self.file_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = self._parse_line(line)
                if parsed:
                    loaded.append(parsed)
        except Exception as e:
            logger.warning(f"Ошибка чтения proxies.txt: {e}")

        self.proxies = loaded
        if self.proxies:
            self._cycle = itertools.cycle(self.proxies)

    def _parse_line(self, line: str) -> Optional[dict]:
        try:
            if "://" in line:
                proto, rest = line.split("://", 1)
                auth, host_port = rest.split("@") if "@" in rest else (None, rest)
                host, port = host_port.split(":")
                user, password = auth.split(":") if auth else (None, None)
                return {
                    "proxy_type": proto.lower(),
                    "addr": host,
                    "port": int(port),
                    "username": user,
                    "password": password,
                }
            parts = line.split(":")
            if len(parts) == 4:
                return {
                    "proxy_type": "socks5",
                    "addr": parts[0],
                    "port": int(parts[1]),
                    "username": parts[2],
                    "password": parts[3],
                }
            elif len(parts) == 2:
                return {
                    "proxy_type": "socks5",
                    "addr": parts[0],
                    "port": int(parts[1]),
                    "username": None,
                    "password": None,
                }
        except Exception:
            return None
        return None

    def get_next_proxy(self) -> Optional[dict]:
        if not self._cycle:
            return None
        return next(self._cycle)


proxy_pool = ProxyPool("proxies.txt")


# ====================== КАРАНТИН ПРОБЛЕМНЫХ СЕССИЙ ======================

def save_to_quarantine(chat_id: int, session_path: Path, original_name: str, reason: str):
    q_dir = Path("quarantine") / str(chat_id)
    q_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(original_name).name
    dest = q_dir / safe_name
    try:
        if session_path and session_path.exists():
            shutil.copy(session_path, dest)
        log_file = dest.with_suffix(".error.txt")
        log_file.write_text(
            f"Файл: {safe_name}\nПричина: {reason}\nВремя: {datetime.now().isoformat()}\n",
            encoding="utf-8",
        )
    except Exception as e:
        logger.error(f"Не удалось сохранить сессию в карантин: {e}")


def count_quarantine(chat_id: int) -> int:
    q_dir = Path("quarantine") / str(chat_id)
    if not q_dir.exists():
        return 0
    return len(list(q_dir.glob("*.session")))


# ====================== БАЗА ДАННЫХ SQLITE ======================

class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queue (
                    id TEXT PRIMARY KEY,
                    chat_id INTEGER,
                    file_path TEXT,
                    original_name TEXT,
                    auto_2fa TEXT,
                    proxy_json TEXT,
                    status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    chat_id INTEGER PRIMARY KEY,
                    auto_mode INTEGER DEFAULT 1
                )
            """)
            conn.commit()

    def add_queue_item(
        self,
        item_id: str,
        chat_id: int,
        file_path: str,
        original_name: str,
        auto_2fa: Optional[str],
        proxy_dict: Optional[dict],
    ):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO queue (id, chat_id, file_path, original_name, auto_2fa, proxy_json, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')",
                (item_id, chat_id, file_path, original_name, auto_2fa, json.dumps(proxy_dict) if proxy_dict else None),
            )
            conn.commit()

    def pop_next_item(self, chat_id: int) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM queue WHERE chat_id = ? AND status = 'pending' ORDER BY created_at ASC LIMIT 1",
                (chat_id,),
            )
            row = cur.fetchone()
            if row:
                cur.execute("UPDATE queue SET status = 'processing' WHERE id = ?", (row["id"],))
                conn.commit()
                return dict(row)
        return None

    def remove_item(self, item_id: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM queue WHERE id = ?", (item_id,))
            conn.commit()

    def clear_chat_queue(self, chat_id: int) -> List[str]:
        files_to_remove = []
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT file_path FROM queue WHERE chat_id = ?", (chat_id,))
            files_to_remove = [r["file_path"] for r in cur.fetchall()]
            cur.execute("DELETE FROM queue WHERE chat_id = ?", (chat_id,))
            conn.commit()
        return files_to_remove

    def count_queue(self, chat_id: int) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM queue WHERE chat_id = ? AND status = 'pending'", (chat_id,))
            return cur.fetchone()[0]

    def set_clean_mode(self, chat_id: int, mode: int):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO settings (chat_id, auto_mode) VALUES (?, ?)", (chat_id, mode))
            conn.commit()

    def get_clean_mode(self, chat_id: int, default: int = 1) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("SELECT auto_mode FROM settings WHERE chat_id = ?", (chat_id,))
            row = cur.fetchone()
            return int(row[0]) if row is not None else default


db = Database(settings.db_file)


def is_rc_referral_enabled() -> bool:
    """Runtime флаг рефералки RCBet (переключается командой /rc), переживает рестарт."""
    with sqlite3.connect(settings.db_file) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS bot_flags (name TEXT PRIMARY KEY, value INTEGER)")
        row = conn.execute("SELECT value FROM bot_flags WHERE name = 'rc_referral'").fetchone()
    return bool(row[0]) if row else settings.enable_rc_referral


def set_rc_referral(enabled: bool):
    with sqlite3.connect(settings.db_file) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS bot_flags (name TEXT PRIMARY KEY, value INTEGER)")
        conn.execute(
            "INSERT OR REPLACE INTO bot_flags (name, value) VALUES ('rc_referral', ?)",
            (1 if enabled else 0,),
        )
        conn.commit()


# ====================== МОДЕЛИ ДАННЫХ ======================

class MigrateStates(StatesGroup):
    waiting_phone = State()
    waiting_password = State()
    waiting_manual_code = State()


@dataclass
class SessionCheckResult:
    is_valid: bool
    status: str
    user_id: Optional[int] = None
    phone: Optional[str] = None
    username: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CleanReport:
    profile_cleared: bool = False
    username_cleared: bool = False
    photos_deleted: int = 0
    contacts_deleted: int = 0
    saved_contacts_reset: bool = False
    folders_deleted: int = 0
    stickers_removed: int = 0
    channels_deleted: int = 0
    dialogs_purged: int = 0
    saved_messages_cleared: bool = False
    privacy_secured: bool = False
    payments_cleared: bool = False
    ttl_set_30d: bool = False
    drafts_cleared: bool = False
    web_auths_reset: bool = False
    sessions_reset: bool = False
    sessions_reset_warning: Optional[str] = None
    ugs_referral_done: bool = False
    rc_referral_done: bool = False
    rc_referral_link: Optional[str] = None


@dataclass
class ActiveMigration:
    id: str
    chat_id: int
    original_name: str = "session.session"
    source_file_path: Optional[Path] = None
    old_client: Optional[TelegramClient] = None
    new_client: Optional[TelegramClient] = None
    phone: str = ""
    phone_code_hash: str = ""
    auto_2fa_password: Optional[str] = None
    proxy_config: Optional[dict] = None
    fingerprint: dict[str, str] = field(default_factory=get_random_fingerprint)
    temp_dir: Optional[Path] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: float = field(default_factory=time.time)
    status_message: Optional[Message] = None
    waiting_2fa: bool = False
    waiting_manual_code: bool = False
    skip_requested: bool = False
    is_new_session: bool = False
    queue_db_id: Optional[str] = None
    old_session_terminated: bool = False
    old_session_error: Optional[str] = None


chat_semaphores: Dict[int, asyncio.Semaphore] = {}
current_migration: Dict[int, ActiveMigration] = {}
queue_workers: Dict[int, bool] = {}

stats = {"started": 0, "success": 0, "failed": 0, "cancelled": 0, "skipped": 0}


# ====================== УТИЛИТЫ И ПРОВЕРКИ ======================

def get_chat_semaphore(chat_id: int) -> asyncio.Semaphore:
    if chat_id not in chat_semaphores:
        chat_semaphores[chat_id] = asyncio.Semaphore(settings.concurrent_workers_per_chat)
    return chat_semaphores[chat_id]


async def verify_proxy_alive(proxy: dict, timeout: float = 3.0) -> bool:
    host = proxy.get("addr")
    port = proxy.get("port")
    if not host or not port:
        return False
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


def resolve_proxy(item_proxy_json: Optional[str]) -> Optional[dict]:
    if item_proxy_json:
        try:
            p = json.loads(item_proxy_json)
            if p:
                return p
        except Exception:
            pass
    pooled = proxy_pool.get_next_proxy()
    if pooled:
        return pooled
    return settings.fallback_proxy


def render_progress_bar(current: int, total: int, length: int = 10) -> str:
    ratio = min(1.0, max(0.0, current / total)) if total > 0 else 0.0
    filled = int(length * ratio)
    return "█" * filled + "░" * (length - filled) + f" {int(ratio * 100)}%"


class StatusReporter:
    def __init__(self, message: Message, interval: float = 1.5):
        self.message = message
        self.interval = interval
        self.last_update = 0.0
        self.last_text = ""

    async def update(self, text: str, force: bool = False, reply_markup: Optional[InlineKeyboardMarkup] = None):
        now = time.time()
        if not force and (now - self.last_update < self.interval or text == self.last_text):
            return
        try:
            await self.message.edit_text(text, reply_markup=reply_markup)
            self.last_update = now
            self.last_text = text
        except Exception:
            pass


def extract_telegram_code(text: str) -> Optional[str]:
    if not text:
        return None
    clean = text.replace("\u200b", "").replace("\u200c", "").replace("\xa0", " ")
    match = re.search(
        r"(?i)(?:code|код|c[oó]digo|passcode|kod|login code)[\D]{0,10}(\d[\d\s\-]{3,6}\d)",
        clean,
    )
    if match:
        digits = re.sub(r"\D", "", match.group(1))
        if 4 <= len(digits) <= 8 and digits != "777000":
            return digits

    for num in re.findall(r"\b\d{5,6}\b", clean):
        if num != "777000":
            return num
    return None


def parse_session_proxy(json_data: dict) -> Optional[dict]:
    p = json_data.get("proxy")
    if isinstance(p, dict):
        proto = p.get("type") or p.get("protocol") or "socks5"
        host = p.get("host") or p.get("addr") or p.get("ip")
        port = p.get("port", 1080)
        if host and port:
            return {
                "proxy_type": proto.lower(),
                "addr": host,
                "port": int(port),
                "username": p.get("user") or p.get("username"),
                "password": p.get("pass") or p.get("password"),
            }
    elif isinstance(p, str) and "://" in p:
        return proxy_pool._parse_line(p)
    return None


def get_configured_client(session_target: Any, fp: dict[str, str], proxy: Optional[dict] = None) -> TelegramClient:
    active_proxy = proxy or settings.fallback_proxy
    return TelegramClient(
        session_target,
        settings.api_id,
        settings.api_hash,
        proxy=active_proxy,
        device_model=fp["device"],
        system_version=fp["sys"],
        app_version=fp["app"],
        lang_code=fp["lang"],
        system_lang_code=fp["lang"],
    )


def is_admin(user_id: int) -> bool:
    return user_id in settings.admin_ids


def main_menu_kb(chat_id: int) -> InlineKeyboardMarkup:
    current_mode = db.get_clean_mode(chat_id, settings.default_auto_code)
    if current_mode == 1:
        mode_label = "🔄 Миграция (Авто-код)"
    elif current_mode == 2:
        mode_label = "⚡ Fast Clean (без кодов)"
    else:
        mode_label = "📝 Миг��ация (Ручной код)"

    failed_cnt = count_quarantine(chat_id)
    failed_label = f"📦 Битые сессии ({failed_cnt})" if failed_cnt > 0 else "📦 Битые сессии (0)"

    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text=f"Режим: {mode_label}", callback_data="cycle_clean_mode"),
            InlineKeyboardButton(text="📱 Сессия с нуля", callback_data="btn_new_session"),
        ],
        [
            InlineKeyboardButton(text=failed_label, callback_data="export_failed"),
            InlineKeyboardButton(text="❌ Сбросить очередь", callback_data="cancel_all"),
        ],
    ])


def action_kb(can_skip: bool = True) -> InlineKeyboardMarkup:
    buttons = []
    if can_skip:
        buttons.append(InlineKeyboardButton(text="⏭ Пропустить эту", callback_data="skip_current"))
    buttons.append(InlineKeyboardButton(text="❌ Отменить всё", callback_data="cancel_all"))
    return InlineKeyboardMarkup(inline_keyboard=[buttons])


def extract_url_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    for url in re.findall(r"https?://\S+|t\.me/\S+", text):
        clean = url.rstrip(".,)\]>")
        if "t.me/" in clean or "telegram.me/" in clean or "https://" in clean:
            return clean
    return None


# ====================== АВТО-РЕФЕРАЛКА И КАПЧА @GameUGSbot ======================

async def leave_all_joined_after_referral(client: TelegramClient):
    """Выход из всех групп/каналов/чатов, в которые зашел аккаунт по рефералке."""
    try:
        async for dialog in client.iter_dialogs():
            entity = dialog.entity
            try:
                if isinstance(entity, Channel):
                    if getattr(entity, "left", False):
                        continue
                    try:
                        await client(LeaveChannelRequest(channel=entity))
                    except Exception:
                        pass

                elif isinstance(entity, Chat):
                    try:
                        await client(DeleteChatUserRequest(chat_id=entity.id, user_id="me"))
                    except Exception:
                        pass

                elif isinstance(entity, User):
                    if getattr(entity, "is_self", False):
                        continue
                    if getattr(entity, "bot", False):
                        try:
                            await client(BlockRequest(id=entity))
                        except Exception:
                            pass
                    try:
                        await client(DeleteHistoryRequest(peer=entity, max_id=0, just_clear=False, revoke=True))
                    except Exception:
                        try:
                            await client.delete_dialog(entity)
                        except Exception:
                            pass

            except FloodWaitError as e:
                await asyncio.sleep(min(e.seconds + 1, 30))
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"Ошибка при выходе из чатов после рефералки: {e}")


async def auto_ugs_referral(client: TelegramClient, ref_param: str = "8983649078") -> bool:
    """
    Заходит с аккаунта в @GameUGSbot по реферальке,
    подписывается на обязательные каналы из текста и нажимает на загаданный фрукт в капче.
    """
    if not settings.enable_ugs_referral:
        return False

    bot_username = settings.ugs_bot_username
    try:
        bot_entity = await client.get_entity(bot_username)
        await client(
            StartBotRequest(
                bot=bot_entity,
                peer=bot_entity,
                start_param=ref_param,
                random_id=random.randint(1, 2**63 - 1),
            )
        )

        await asyncio.sleep(3.5)

        messages = await client.get_messages(bot_entity, limit=4)
        captcha_msg = None
        for m in messages:
            if m.buttons and m.raw_text:
                captcha_msg = m
                break

        if not captcha_msg:
            logger.warning("Сообщение с капчей от @GameUGSbot не найдено.")
            return False

        text = captcha_msg.raw_text

        channels = re.findall(r"@([a-zA-Z0-9_]{4,32})", text)
        for ch_username in channels:
            if ch_username.lower() == bot_username.lower():
                continue
            try:
                await client(JoinChannelRequest(ch_username))
                logger.info(f"Подписались на @{ch_username}")
                await asyncio.sleep(random.uniform(1.8, 3.2))
            except FloodWaitError as e:
                await asyncio.sleep(min(e.seconds + 1, 30))
            except Exception as e:
                logger.warning(f"Не удалось подписаться на @{ch_username}: {e}")

        for row in captcha_msg.buttons:
            for button in row:
                btn_emoji = (button.text or "").strip()
                if btn_emoji and btn_emoji in text:
                    logger.info(f"Найден фрукт капчи: {btn_emoji}. Нажимаем кнопку...")
                    await asyncio.sleep(random.uniform(1.0, 2.0))
                    await button.click()
                    await asyncio.sleep(1.5)
                    await leave_all_joined_after_referral(client)
                    return True

        logger.warning("Не удалось сопоставить эмодзи фрукта с кнопками.")
        return False

    except Exception as e:
        logger.warning(f"Ошибка при прохождении @GameUGSbot: {e}")
        return False


def _normalize_button_text(text: Optional[str]) -> str:
    if not text:
        return ""
    return re.sub(r"[^a-zа-яё0-9]", "", text.lower())


def _is_checks_button(text: Optional[str]) -> bool:
    """Кнопка «Чеки» с эмодзи/символами: сравниваем по буквам, без эмодзи и знаков."""
    letters = _normalize_button_text(text)
    return letters in {"чек", "чеки", "checks", "cheques", "check"} or letters.endswith("чеки")


def _is_create_check_button(text: Optional[str]) -> bool:
    """Признаки кнопки «Создать чек» в RCBet: разный текст и варианты UI."""
    letters = _normalize_button_text(text)
    return (
        "создатьчек" in letters
        or "createcheck" in letters
        or "newcheck" in letters
        or "generatecheck" in letters
        or "чексоздать" in letters
        or "чек" in letters and "созд" in letters
    )


def _check_url(text: str) -> Optional[str]:
    """
    Ссылка на чек RCBet: t.me/<rc_bot_username>?start=<код>.
    Ссылки на каналы (rcbet, rc_chat, rc_alerts) сюда не попадают.
    """
    if not text:
        return None
    marker = f"t.me/{settings.rc_bot_username.lower()}?start="
    for url in re.findall(r"(?:https?://)?t\.me/\S+", text):
        clean = url.rstrip(".,)]>")
        if marker in clean.lower():
            return clean if clean.startswith("http") else "https://" + clean
    return None


async def auto_rcbet_referral(client: TelegramClient, start_param: str = "U548858090", chat_id: Optional[int] = None) -> Optional[str]:
    """Сценарий для @redcubebetbot: подписаться на каналы, подождать 6 сек, /start, Чеки -> Создать чек -> 0.1 -> 1 -> вернуть ссылку на чек."""
    if not is_rc_referral_enabled():
        return None

    bot_username = settings.rc_bot_username
    try:
        bot_entity = await client.get_entity(bot_username)
        await client(
            StartBotRequest(
                bot=bot_entity,
                peer=bot_entity,
                start_param=start_param,
                random_id=random.randint(1, 2**63 - 1),
            )
        )
        await asyncio.sleep(2.0)

        for channel_name in (settings.rc_channel_1, settings.rc_channel_2):
            try:
                await client(JoinChannelRequest(channel_name))
                logger.info(f"Подписались на @{channel_name}")
                await asyncio.sleep(2.0)
            except FloodWaitError as e:
                logger.warning(f"RCbet FloodWait при подписке на @{channel_name}: {e.seconds}s")
                await asyncio.sleep(min(max(20, e.seconds), 30))
            except Exception as e:
                logger.warning(f"Не удалось подписаться на @{channel_name}: {e}")

        await asyncio.sleep(6.0)
        await client.send_message(bot_entity, "/start")
        await asyncio.sleep(3.0)

        clicked_checks = False
        last_messages = []
        deadline = time.time() + 45
        while time.time() < deadline and not clicked_checks:
            last_messages = await client.get_messages(bot_entity, limit=16)
            for msg in last_messages:
                for row in (msg.buttons or []):
                    for btn in row:
                        if _is_checks_button(btn.text):
                            try:
                                await btn.click()
                                clicked_checks = True
                                logger.info("Нажали кнопку Чеки в redcubebetbot")
                                await asyncio.sleep(2.5)
                                break
                            except FloodWaitError as e:
                                logger.warning(f"RCbet FloodWait после кнопки Чеки: {e.seconds}s")
                                await asyncio.sleep(min(max(20, e.seconds), 30))
                            except Exception as e:
                                logger.warning(f"Ошибка на кнопке Чеки: {e}")
                    if clicked_checks:
                        break
                if clicked_checks:
                    break
            if not clicked_checks:
                await asyncio.sleep(2.0)

        if not clicked_checks:
            logger.warning("Кнопка Чеки не найдена в последних сообщениях redcubebetbot, пробуем fallback-команды.")
            try:
                await client.send_message(bot_entity, "Чеки")
                await asyncio.sleep(2.0)
            except Exception:
                pass

        created_clicked = False
        try:
            recent = await client.get_messages(bot_entity, limit=12)
            for msg in recent:
                for row in (msg.buttons or []):
                    for btn in row:
                        if _is_create_check_button(btn.text):
                            try:
                                await btn.click()
                                created_clicked = True
                                logger.info("Нажали кнопку 'Создать чек' в redcubebetbot")
                                await asyncio.sleep(2.0)
                                break
                            except Exception as e:
                                logger.debug(f"Не удалось кликнуть 'Создать чек': {e}")
                    if created_clicked:
                        break
                if created_clicked:
                    break
        except Exception as e:
            logger.debug(f"Ошибка при поиске 'Создать чек' кнопки: {e}")

        if not created_clicked:
            try:
                await client.send_message(bot_entity, "Создать чек")
                await asyncio.sleep(2.5)
            except Exception:
                pass

        await client.send_message(bot_entity, "0.1")
        await asyncio.sleep(3.0)
        await client.send_message(bot_entity, "1")
        await asyncio.sleep(3.0)

        extracted = None
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                recent = await client.get_messages(bot_entity, limit=18)
                for msg in recent:
                    text = (msg.raw_text or msg.message or "")
                    if not text:
                        continue
                    found = _check_url(text)
                    if not found:
                        for url in re.findall(r"(?:https?://)?t\.me/\S+|https?://\S+", text):
                            clean = url.rstrip(".,)]>")
                            if f"t.me/{settings.rc_bot_username.lower()}?start=" in clean.lower():
                                found = clean if clean.startswith("http") else "https://" + clean
                                break
                    if found:
                        extracted = found
                        break
                if extracted:
                    break
            except FloodWaitError as e:
                logger.warning(f"RCbet FloodWait в ожидании ответа: {e.seconds}s")
                await asyncio.sleep(min(max(20, e.seconds), 30))
            except Exception as e:
                logger.debug(f"Ошибка чтения ответов redcubebetbot: {e}")
            await asyncio.sleep(2.0)

        if extracted:
            if chat_id:
                try:
                    await client.send_message(chat_id, f"💸 RCBet чек: {extracted}")
                except Exception:
                    pass
            logger.info(f"RCBet ссылка готова: {extracted}")
            return extracted

        logger.warning("RCBet чек не был найден после запроса 0.1 и 1")
        return None

    except FloodWaitError as e:
        logger.warning(f"FloodWait in RCBet: {e.seconds}s")
        await asyncio.sleep(min(max(20, e.seconds), 30))
        return None
    except Exception as e:
        logger.warning(f"Ошибка при прохождении @redcubebetbot: {e}")
        return None


# ====================== ДЕАВТОРИЗАЦИЯ СТАРОЙ СЕССИИ ======================

async def terminate_old_session(old_client: Optional[TelegramClient]) -> Tuple[bool, Optional[str]]:
    if not old_client:
        return True, None

    last_error = None
    for attempt in range(1, 4):
        try:
            if not old_client.is_connected():
                await old_client.connect()

            if not await old_client.is_user_authorized():
                logger.info("Старая сессия уже сброшена сервером Telegram.")
                await old_client.disconnect()
                return True, None

            await old_client(LogOutRequest())
            logger.info(f"Старая сессия успешно завершена на попытке {attempt}.")

            try:
                await old_client.disconnect()
            except Exception:
                pass
            return True, None

        except Exception as e:
            last_error = str(e)
            logger.warning(f"Ошибка при выходе из старой сессии (попытка {attempt}/3): {e}")
            try:
                await old_client.disconnect()
            except Exception:
                pass
            await asyncio.sleep(1.0)

    return False, last_error


async def cleanup_migration(mig: ActiveMigration, state: Optional[FSMContext] = None):
    chat_id = mig.chat_id
    if chat_id in current_migration and current_migration[chat_id].id == mig.id:
        del current_migration[chat_id]

    if mig.queue_db_id:
        db.remove_item(mig.queue_db_id)

    for client in (mig.old_client, mig.new_client):
        if client:
            try:
                if client.is_connected():
                    await client.disconnect()
            except Exception:
                pass

    if mig.temp_dir and mig.temp_dir.exists():
        shutil.rmtree(mig.temp_dir, ignore_errors=True)

    if state and (mig.waiting_2fa or mig.waiting_manual_code):
        await state.clear()


async def clear_user_queue(chat_id: int, state: Optional[FSMContext] = None):
    if chat_id in current_migration:
        await cleanup_migration(current_migration[chat_id], state)

    files_to_delete = db.clear_chat_queue(chat_id)
    for f in files_to_delete:
        try:
            p = Path(f)
            if p.exists():
                p.unlink(missing_ok=True)
                if any(p.parent.name.startswith(x) for x in ("upload_", "fast_", "mig_")):
                    shutil.rmtree(p.parent, ignore_errors=True)
        except Exception:
            pass

    queue_workers[chat_id] = False
    if state:
        await state.clear()


# (file continues unchanged)
