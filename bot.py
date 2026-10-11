import asyncio
import aiohttp
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
import sqlite3
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F
from aiogram.types import (
    Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton, LabeledPrice, PreCheckoutQuery,
    ReplyKeyboardMarkup, KeyboardButton, ReplyKeyboardRemove,
)
from aiogram.filters import Command, CommandObject
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

load_dotenv()

# ==================== НАСТРОЙКИ ====================
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
CRYPTO_BOT_TOKEN = os.getenv("CRYPTO_BOT_TOKEN", "")
ADMIN_ID = int(os.getenv("ADMIN_ID", "7967127624"))

FIREBASE_PRIVATE_KEY = os.getenv("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n")
FIREBASE_CLIENT_EMAIL = os.getenv("FIREBASE_CLIENT_EMAIL", "")
FIREBASE_DATABASE_URL = os.getenv("FIREBASE_DATABASE_URL", "https://swift-35c10-default-rtdb.firebaseio.com")

CRYPTO_API = "https://pay.crypt.bot/api"
VERIFY_PRICE = 1.0
STARS_PRICE = 50  # 50 Telegram Stars ≈ $0.5–1

# ---- привязка номера / 2FA ----
# Мастер-ключ шифрования (base64, минимум 32 байта). Сгенерировать:
#   python -c "import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
# ВАЖНО: сохрани ключ в надёжном месте. Без него номера расшифровать нельзя.
PHONE_ENC_KEY = os.getenv("PHONE_ENC_KEY", "")
PHONE_POLL_SEC = float(os.getenv("PHONE_POLL_SEC", "1.5"))   # как часто бот проверяет запросы из приложения
CODE_TTL = 300                 # код входа живёт 5 минут
CODE_MAX_TRIES = 5             # попыток ввода на один код
CODE_RESEND_SEC = 30           # пауза между отправками кода
CODE_HOURLY_LIMIT = 6          # отправок кода в час на один аккаунт
FAIL_HOURLY_LIMIT = 10         # неверных кодов в час на один аккаунт
PENDING_TTL = 600              # заявка на привязку ждёт подтверждения в приложении 10 минут
GRANT_TTL_MS = 365 * 24 * 3600 * 1000   # «доверенное устройство» после входа по коду
REQ_MAX_AGE_MS = 120_000       # запросы старше 2 минут игнорируем

FB_UID_RE = re.compile(r"^[A-Za-z0-9]{20,40}$")
RID_RE = re.compile(r"^[A-Za-z0-9]{4,64}$")

logging.basicConfig(level=logging.INFO)
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())

# ==================== SQLITE ====================
def init_db():
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            invoice_id TEXT PRIMARY KEY,
            user_id INTEGER,
            chat_uid TEXT,
            status TEXT DEFAULT 'pending',
            method TEXT DEFAULT 'crypto',
            created_at INTEGER DEFAULT (strftime('%s','now'))
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_codes (
            uid TEXT NOT NULL,
            fb_uid TEXT NOT NULL,
            mac TEXT NOT NULL,
            exp INTEGER NOT NULL,
            tries INTEGER NOT NULL DEFAULT 0,
            created INTEGER NOT NULL,
            PRIMARY KEY (uid, fb_uid)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS code_log (
            uid TEXT NOT NULL,
            kind TEXT NOT NULL,
            ts INTEGER NOT NULL
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_code_log ON code_log (uid, kind, ts)")
    conn.commit()
    conn.close()

def save_payment(invoice_id, user_id, chat_uid, method="crypto"):
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO payments (invoice_id, user_id, chat_uid, method) VALUES (?, ?, ?, ?)",
              (invoice_id, user_id, chat_uid, method))
    conn.commit()
    conn.close()

def get_payment(invoice_id):
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("SELECT * FROM payments WHERE invoice_id = ?", (invoice_id,))
    row = c.fetchone()
    conn.close()
    return row

def mark_paid(invoice_id):
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("UPDATE payments SET status = 'paid' WHERE invoice_id = ?", (invoice_id,))
    conn.commit()
    conn.close()

def count_payments():
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM payments WHERE status = 'paid'")
    count = c.fetchone()[0]
    conn.close()
    return count

# ==================== FSM ====================
class VerifyStates(StatesGroup):
    waiting_uid = State()

class AdminStates(StatesGroup):
    waiting_free_uid = State()

class BindStates(StatesGroup):
    waiting_uid = State()
    waiting_contact = State()

# ==================== ВАЛИДАЦИЯ UID ====================
def is_valid_uid(uid: str) -> bool:
    """user_ + минимум 4 цифры"""
    if not uid.startswith("user_"):
        return False
    suffix = uid[5:]
    return suffix.isdigit() and len(suffix) >= 4

# ==================== FIREBASE TOKEN ====================
_firebase_token = None
_firebase_token_exp = 0

async def get_firebase_token() -> str:
    global _firebase_token, _firebase_token_exp
    now = int(time.time())
    if _firebase_token and now < _firebase_token_exp - 60:
        return _firebase_token

    import jwt

    now = int(time.time())
    payload = {
        "iss": FIREBASE_CLIENT_EMAIL,
        "sub": FIREBASE_CLIENT_EMAIL,
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
        "scope": "https://www.googleapis.com/auth/firebase https://www.googleapis.com/auth/userinfo.email"
    }
    signed = jwt.encode(payload, FIREBASE_PRIVATE_KEY, algorithm="RS256")

    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": signed
            },
            timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            data = await resp.json()
            if "access_token" not in data:
                raise Exception(f"Firebase auth error: {data}")
            _firebase_token = data["access_token"]
            _firebase_token_exp = now + data.get("expires_in", 3600)
            return _firebase_token

# ==================== FIREBASE ====================
async def check_user_exists(uid: str) -> bool:
    try:
        token = await get_firebase_token()
        url = f"{FIREBASE_DATABASE_URL}/users/{uid}.json"
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()
                return data is not None
    except Exception as e:
        logging.error(f"check_user_exists error: {e}")
        return False

async def verify_user(uid: str) -> bool:
    try:
        token = await get_firebase_token()
        url = f"{FIREBASE_DATABASE_URL}/verified_users/{uid}.json"
        async with aiohttp.ClientSession() as session:
            async with session.put(
                url,
                json=True,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                return resp.status == 200
    except Exception as e:
        logging.error(f"verify_user error: {e}")
        return False

# ==================== FIREBASE: общие запросы ====================
_http_session = None

def get_session() -> aiohttp.ClientSession:
    global _http_session
    if _http_session is None or _http_session.closed:
        _http_session = aiohttp.ClientSession()
    return _http_session

async def fb_req(method: str, path: str, body=None):
    """Запрос к Realtime Database от имени сервисного аккаунта (правила безопасности не применяются)."""
    token = await get_firebase_token()
    url = f"{FIREBASE_DATABASE_URL}/{path}.json"
    kwargs = {"headers": {"Authorization": f"Bearer {token}"}, "timeout": aiohttp.ClientTimeout(total=10)}
    if method in ("PUT", "PATCH", "POST"):
        kwargs["json"] = body
    async with get_session().request(method, url, **kwargs) as resp:
        if resp.status >= 400:
            text = await resp.text()
            raise RuntimeError(f"Firebase {method} /{path}: {resp.status} {text[:200]}")
        if method == "DELETE":
            return None
        return await resp.json()

async def fb_get(path: str):
    return await fb_req("GET", path)

async def fb_put(path: str, value):
    return await fb_req("PUT", path, value)

async def fb_patch(path: str, value):
    """PATCH. Для path="" — атомарное обновление нескольких путей сразу (None удаляет узел)."""
    return await fb_req("PATCH", path, value)

async def fb_delete(path: str):
    return await fb_req("DELETE", path)

# ==================== ШИФРОВАНИЕ ====================
ENC_KEY = b""
MAC_KEY = b""
PHONE_ENABLED = False   # включается в main(), если задан PHONE_ENC_KEY
PHONE_OFF_TEXT = "📱 Привязка номера сейчас недоступна. Попробуй позже."

def init_crypto():
    """Из мастер-ключа получаем два независимых ключа: для AES-GCM (номера) и для HMAC (коды)."""
    global ENC_KEY, MAC_KEY
    raw = PHONE_ENC_KEY.strip()
    if not raw:
        raise RuntimeError(
            "Не задан PHONE_ENC_KEY. Сгенерируй: "
            "python -c \"import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).decode())\" "
            "и добавь в .env"
        )
    try:
        master = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception:
        raise RuntimeError("PHONE_ENC_KEY должен быть в base64")
    if len(master) < 32:
        raise RuntimeError("PHONE_ENC_KEY слишком короткий (нужно минимум 32 байта)")
    ENC_KEY = hmac.new(master, b"swifty-phone-enc-v1", hashlib.sha256).digest()
    MAC_KEY = hmac.new(master, b"swifty-code-mac-v1", hashlib.sha256).digest()

def enc_str(plain: str, aad: str) -> str:
    """AES-256-GCM. aad = uid аккаунта: зашифрованное значение нельзя подсунуть другому аккаунту."""
    nonce = os.urandom(12)
    ct = AESGCM(ENC_KEY).encrypt(nonce, plain.encode("utf-8"), aad.encode("utf-8"))
    return "v1:" + base64.urlsafe_b64encode(nonce + ct).decode()

def dec_str(token: str, aad: str) -> str:
    if not isinstance(token, str) or not token.startswith("v1:"):
        raise ValueError("bad token")
    raw = base64.urlsafe_b64decode(token[3:])
    return AESGCM(ENC_KEY).decrypt(raw[:12], raw[12:], aad.encode("utf-8")).decode("utf-8")

def code_mac(uid: str, fb_uid: str, code: str) -> str:
    """Код входа хранится только как HMAC-SHA256 с секретным ключом. Восстановить код из базы нельзя."""
    return hmac.new(MAC_KEY, f"{uid}|{fb_uid}|{code}".encode(), hashlib.sha256).hexdigest()

# ==================== ТЕЛЕФОН: утилиты ====================
def normalize_phone(raw: str):
    digits = re.sub(r"\D", "", raw or "")
    if not (8 <= len(digits) <= 15):
        return None
    return "+" + digits

def mask_phone(phone: str) -> str:
    d = re.sub(r"\D", "", phone)
    if len(d) == 11 and d.startswith("7"):
        return f"+7 *** *** ** {d[-2:]}"
    if len(d) <= 4:
        return "+" + "*" * len(d)
    return "+" + d[:2] + "*" * (len(d) - 4) + d[-2:]

# ==================== SQLITE: коды входа ====================
DB_FILE = "verify.db"

def _sql(query, params=(), fetch=None, commit=False):
    conn = sqlite3.connect(DB_FILE)
    try:
        c = conn.cursor()
        c.execute(query, params)
        res = None
        if fetch == "one":
            res = c.fetchone()
        elif fetch == "all":
            res = c.fetchall()
        if commit:
            conn.commit()
        return res
    finally:
        conn.close()

def code_store(uid, fb_uid, mac, exp, now):
    _sql("INSERT OR REPLACE INTO login_codes (uid, fb_uid, mac, exp, tries, created) VALUES (?, ?, ?, ?, 0, ?)",
         (uid, fb_uid, mac, exp, now), commit=True)

def code_get(uid, fb_uid):
    return _sql("SELECT mac, exp, tries FROM login_codes WHERE uid = ? AND fb_uid = ?", (uid, fb_uid), fetch="one")

def code_inc_tries(uid, fb_uid):
    _sql("UPDATE login_codes SET tries = tries + 1 WHERE uid = ? AND fb_uid = ?", (uid, fb_uid), commit=True)
    row = _sql("SELECT tries FROM login_codes WHERE uid = ? AND fb_uid = ?", (uid, fb_uid), fetch="one")
    return row[0] if row else CODE_MAX_TRIES

def code_delete(uid, fb_uid):
    _sql("DELETE FROM login_codes WHERE uid = ? AND fb_uid = ?", (uid, fb_uid), commit=True)

def log_event(uid, kind, now):
    _sql("INSERT INTO code_log (uid, kind, ts) VALUES (?, ?, ?)", (uid, kind, now), commit=True)

def count_events(uid, kind, since):
    row = _sql("SELECT COUNT(*) FROM code_log WHERE uid = ? AND kind = ? AND ts >= ?", (uid, kind, since), fetch="one")
    return row[0] if row else 0

def last_event(uid, kind):
    row = _sql("SELECT MAX(ts) FROM code_log WHERE uid = ? AND kind = ?", (uid, kind), fetch="one")
    return row[0] if row and row[0] else 0

def cleanup_db(now):
    _sql("DELETE FROM login_codes WHERE exp < ?", (now - 3600,), commit=True)
    _sql("DELETE FROM code_log WHERE ts < ?", (now - 86400,), commit=True)

# ==================== ПРИВЯЗКА НОМЕРА: логика ====================
async def get_phone_info(uid: str):
    return await fb_get(f"user_phone_info/{uid}")

async def get_pending(uid: str):
    p = await fb_get(f"phone_pending/{uid}")
    if not isinstance(p, dict):
        return None
    if int(p.get("exp", 0)) < int(time.time() * 1000):
        return None
    return p

async def create_pending(uid: str, tg_id: int, phone: str):
    """Заявка на привязку. Номер лежит зашифрованным, в приложение уходит только маска."""
    now_ms = int(time.time() * 1000)
    exp = now_ms + PENDING_TTL * 1000
    await fb_patch("", {
        f"phone_pending/{uid}": {
            "p": enc_str(phone, uid),
            "t": enc_str(str(tg_id), uid),
            "exp": exp, "ts": now_ms,
        },
        f"user_phone_pending/{uid}": {"masked": mask_phone(phone), "exp": exp, "ts": now_ms},
    })

async def finalize_bind(uid: str, pending: dict):
    phone = dec_str(pending["p"], uid)
    tg_id = int(dec_str(pending["t"], uid))
    now_ms = int(time.time() * 1000)
    await fb_patch("", {
        f"phone_secure/{uid}": {"p": pending["p"], "t": pending["t"], "ts": now_ms},
        f"phone_by_tg/{tg_id}/{uid}": True,
        f"user_phone_info/{uid}": {"masked": mask_phone(phone), "show": False, "ts": now_ms},
        f"phone_pending/{uid}": None,
        f"user_phone_pending/{uid}": None,
    })
    return phone, tg_id

async def remove_pending(uid: str):
    await fb_patch("", {f"phone_pending/{uid}": None, f"user_phone_pending/{uid}": None})

async def unbind_phone(uid: str, tg_id=None):
    """Полностью отвязывает номер: шифрованная копия, публичная копия, индекс."""
    if tg_id is None:
        sec = await fb_get(f"phone_secure/{uid}")
        if isinstance(sec, dict) and sec.get("t"):
            try:
                tg_id = int(dec_str(sec["t"], uid))
            except Exception:
                tg_id = None
    upd = {
        f"phone_secure/{uid}": None,
        f"user_phone_info/{uid}": None,
        f"user_phone_pub/{uid}": None,
        f"phone_pending/{uid}": None,
        f"user_phone_pending/{uid}": None,
    }
    if tg_id is not None:
        upd[f"phone_by_tg/{tg_id}/{uid}"] = None
    await fb_patch("", upd)
    return tg_id

# ---------- запросы из приложения (почтовый ящик в Firebase) ----------
async def _mapped_to(fb_uid: str, uid: str) -> bool:
    """Приложение действительно вошло в этот аккаунт (запись uid_map разрешена только после кода)."""
    return (await fb_get(f"uid_map/{fb_uid}")) == uid

async def h_send_code(fb_uid, uid, req):
    info = await get_phone_info(uid)
    sec = await fb_get(f"phone_secure/{uid}")
    if not info or not isinstance(sec, dict):
        return {"ok": False, "code": "no_phone"}
    now = int(time.time())
    last = last_event(uid, "send")
    if last and now - last < CODE_RESEND_SEC:
        return {"ok": False, "code": "wait", "wait": CODE_RESEND_SEC - (now - last)}
    if count_events(uid, "send", now - 3600) >= CODE_HOURLY_LIMIT or count_events(uid, "fail", now - 3600) >= FAIL_HOURLY_LIMIT:
        return {"ok": False, "code": "too_many"}
    tg_id = int(dec_str(sec["t"], uid))
    code = f"{secrets.randbelow(100000):05d}"
    if req.get("purpose") == "reset":
        title = "🔑 <b>Код восстановления пароля Swifty Chat</b>"
        tail = ("Этот код нужен, чтобы задать новый пароль. Если вы ничего не запрашивали, "
                "проигнорируйте сообщение: без кода пароль не сменить.")
    else:
        title = "🔐 <b>Код входа в Swifty Chat</b>"
        tail = "Если вход пытаетесь выполнить не вы, проигнорируйте это сообщение и смените пароль."
    try:
        await bot.send_message(
            tg_id,
            f"{title}\n\n"
            f"<code>{code}</code>\n\n"
            f"Аккаунт: <code>{uid}</code>\n"
            "Код действует 5 минут. Никому его не сообщайте, даже сотрудникам Swifty Chat.\n"
            f"{tail}",
            parse_mode="HTML",
        )
    except Exception as e:
        logging.error(f"send_code telegram error for {uid}: {e}")
        return {"ok": False, "code": "tg_fail"}
    code_store(uid, fb_uid, code_mac(uid, fb_uid, code), now + CODE_TTL, now)
    log_event(uid, "send", now)
    return {"ok": True, "code": "sent", "masked": info.get("masked", "") if isinstance(info, dict) else ""}

async def h_verify(fb_uid, uid, req):
    code_in = str(req.get("code", "")).strip()
    if not re.fullmatch(r"\d{5}", code_in):
        return {"ok": False, "code": "bad_format"}
    now = int(time.time())
    if count_events(uid, "fail", now - 3600) >= FAIL_HOURLY_LIMIT:
        return {"ok": False, "code": "too_many"}
    row = code_get(uid, fb_uid)
    if not row or row[1] < now:
        if row:
            code_delete(uid, fb_uid)
        return {"ok": False, "code": "expired"}
    mac, _exp, tries = row
    if tries >= CODE_MAX_TRIES:
        code_delete(uid, fb_uid)
        return {"ok": False, "code": "expired"}
    if not hmac.compare_digest(mac, code_mac(uid, fb_uid, code_in)):
        tries = code_inc_tries(uid, fb_uid)
        log_event(uid, "fail", now)
        left = max(0, CODE_MAX_TRIES - tries)
        if left == 0:
            code_delete(uid, fb_uid)
        return {"ok": False, "code": "bad_code", "left": left}
    code_delete(uid, fb_uid)
    await fb_put(f"login_grants/{fb_uid}/{uid}", now * 1000 + GRANT_TTL_MS)
    try:
        sec = await fb_get(f"phone_secure/{uid}")
        tg_id = int(dec_str(sec["t"], uid))
        await bot.send_message(
            tg_id,
            f"✅ Выполнен вход в аккаунт <code>{uid}</code> в Swifty Chat.\n"
            "Если это были не вы, срочно смените пароль.",
            parse_mode="HTML",
        )
    except Exception as e:
        logging.warning(f"login notice failed for {uid}: {e}")
    return {"ok": True, "code": "verified"}

async def h_set_show(fb_uid, uid, req):
    if not await _mapped_to(fb_uid, uid):
        return {"ok": False, "code": "forbidden"}
    info = await get_phone_info(uid)
    sec = await fb_get(f"phone_secure/{uid}")
    if not info or not isinstance(sec, dict):
        return {"ok": False, "code": "no_phone"}
    show = bool(req.get("show"))
    upd = {f"user_phone_info/{uid}/show": show}
    # Открытая копия номера существует только пока владелец сам разрешил его показывать.
    upd[f"user_phone_pub/{uid}"] = dec_str(sec["p"], uid) if show else None
    await fb_patch("", upd)
    return {"ok": True, "code": "done", "show": show}

async def h_confirm_bind(fb_uid, uid, req):
    if not await _mapped_to(fb_uid, uid):
        return {"ok": False, "code": "forbidden"}
    pending = await get_pending(uid)
    if not pending:
        await remove_pending(uid)
        return {"ok": False, "code": "no_pending"}
    if await get_phone_info(uid):
        await remove_pending(uid)
        return {"ok": False, "code": "already"}
    try:
        tg_id = int(dec_str(pending["t"], uid))
    except Exception:
        await remove_pending(uid)
        return {"ok": False, "code": "no_pending"}
    if req.get("ok") is True:
        await finalize_bind(uid, pending)
        try:
            await bot.send_message(
                tg_id,
                f"✅ Номер привязан к аккаунту <code>{uid}</code>.\n"
                "Теперь при входе в аккаунт Swifty Chat сюда приходит код подтверждения.",
                parse_mode="HTML",
            )
        except Exception:
            pass
        return {"ok": True, "code": "bound"}
    await remove_pending(uid)
    try:
        await bot.send_message(tg_id, f"❌ Привязка номера к аккаунту <code>{uid}</code> отклонена в приложении.", parse_mode="HTML")
    except Exception:
        pass
    return {"ok": True, "code": "rejected"}

async def h_revoke(fb_uid, uid, req):
    """Завершение сеанса другого устройства: убираем его право входить без кода из Telegram."""
    if not await _mapped_to(fb_uid, uid):
        return {"ok": False, "code": "forbidden"}
    target = req.get("target")
    if not isinstance(target, str) or not FB_UID_RE.match(target) or target == fb_uid:
        return {"ok": False, "code": "bad_request"}
    upd = {f"login_grants/{target}/{uid}": None}
    if (await fb_get(f"uid_map/{target}")) == uid:
        upd[f"uid_map/{target}"] = None
        upd[f"user_sessions/{uid}/{target}"] = None
    await fb_patch("", upd)
    return {"ok": True, "code": "revoked"}

REQ_HANDLERS = {
    "revoke": h_revoke,
    "send_code": h_send_code,
    "verify": h_verify,
    "set_show": h_set_show,
    "confirm_bind": h_confirm_bind,
}
_processed = {}

async def process_request(fb_uid, req):
    if not isinstance(fb_uid, str) or not FB_UID_RE.match(fb_uid):
        return
    if not isinstance(req, dict):
        await fb_delete(f"phone_req/{fb_uid}")
        return
    rid, typ, uid = req.get("rid"), req.get("type"), req.get("uid")
    if not isinstance(rid, str) or not RID_RE.match(rid):
        await fb_delete(f"phone_req/{fb_uid}")
        return
    key = f"{fb_uid}:{rid}"
    if key in _processed:
        return
    now_ms = int(time.time() * 1000)
    _processed[key] = now_ms
    if len(_processed) > 5000:
        for k in sorted(_processed, key=_processed.get)[:2500]:
            _processed.pop(k, None)

    ts = req.get("ts")
    if typ not in REQ_HANDLERS or not isinstance(uid, str) or not is_valid_uid(uid):
        result = {"ok": False, "code": "bad_request"}
    elif not isinstance(ts, (int, float)) or abs(now_ms - ts) > REQ_MAX_AGE_MS:
        result = {"ok": False, "code": "stale"}
    else:
        try:
            result = await REQ_HANDLERS[typ](fb_uid, uid, req)
        except Exception as e:
            logging.error(f"phone request {typ} failed: {e}")
            result = {"ok": False, "code": "server_error"}
    result["rid"] = rid
    result["ts"] = now_ms
    await fb_put(f"phone_resp/{fb_uid}", result)
    await fb_delete(f"phone_req/{fb_uid}")

async def phone_worker():
    """Раз в секунду-полторы забирает запросы приложения из phone_req и отвечает в phone_resp."""
    n = 0
    while True:
        try:
            reqs = await fb_get("phone_req")
            if isinstance(reqs, dict):
                for fb_uid, req in list(reqs.items()):
                    await process_request(fb_uid, req)
            n += 1
            if n % 400 == 0:
                cleanup_db(int(time.time()))
        except Exception as e:
            logging.error(f"phone_worker error: {e}")
            await asyncio.sleep(5)
        await asyncio.sleep(PHONE_POLL_SEC)

# ==================== CRYPTOBOT ====================
async def create_invoice(user_id: int, chat_uid: str):
    headers = {"Crypto-Pay-API-Token": CRYPTO_BOT_TOKEN}
    payload = {
        "asset": "USDT",
        "amount": str(VERIFY_PRICE),
        "description": f"Swifty Chat — верификация {chat_uid}",
        "payload": f"{user_id}:{chat_uid}",
        "allow_comments": False,
        "allow_anonymous": False,
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{CRYPTO_API}/createInvoice",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()
                if data.get("ok"):
                    return data["result"]
                logging.error(f"CryptoBot response: {data}")
    except Exception as e:
        logging.error(f"CryptoBot error: {e}")
    return None

async def check_invoice(invoice_id: str) -> str:
    headers = {"Crypto-Pay-API-Token": CRYPTO_BOT_TOKEN}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{CRYPTO_API}/getInvoices",
                params={"invoice_ids": invoice_id},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                data = await resp.json()
                if data.get("ok"):
                    items = data["result"].get("items", [])
                    if items:
                        return items[0]["status"]
    except Exception as e:
        logging.error(f"check_invoice error: {e}")
    return "unknown"

# ==================== КЛАВИАТУРЫ ====================
def main_menu_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Купить подписку", callback_data="buy_verify")],
        [InlineKeyboardButton(text="📱 Привязать номер", callback_data="bind_phone")],
        [InlineKeyboardButton(text="🔓 Отвязать номер", callback_data="unbind_menu")],
        [InlineKeyboardButton(text="👤 Профиль", callback_data="profile")],
        [InlineKeyboardButton(text="ℹ️ О боте", callback_data="about")],
    ])

def admin_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 Статистика", callback_data="admin_stats")],
        [InlineKeyboardButton(text="🎁 Выдать галочку бесплатно", callback_data="admin_free_verify")],
    ])

def back_kb(data="back_main", text="🔙 Назад"):
    return InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=text, callback_data=data)]])

def contact_kb():
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="📱 Поделиться контактом", request_contact=True)],
            [KeyboardButton(text="❌ Отмена")],
        ],
        resize_keyboard=True,
        one_time_keyboard=True,
    )

# ==================== ХЭНДЛЕРЫ ====================
@dp.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext, command: CommandObject):
    await state.clear()
    hint = ""
    args = (command.args or "").strip()
    if args.startswith("bind_") and is_valid_uid(args[5:]):
        await state.update_data(suggest_uid=args[5:])
        hint = "\n\n📱 Чтобы привязать номер, нажми <b>«Привязать номер»</b>."
    await message.answer(
        "👋 Добро пожаловать в <b>Swifty Chat Verify</b>!\n\n"
        "✅ Купи подписку (галочку) для своего аккаунта в <b>Swifty Chat</b>.\n"
        "📱 Или привяжи номер телефона: вход в аккаунт будет защищён кодом из Telegram.\n\n"
        "💰 Подписка: <b>1 USDT</b>\n"
        "🔐 Оплата через CryptoBot"
        + hint,
        reply_markup=main_menu_kb(),
        parse_mode="HTML"
    )

@dp.message(Command("admin"))
async def cmd_admin(message: Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.clear()
    await message.answer(
        "👑 <b>Админ панель</b>\n\n"
        "Отвязать номер у пользователя: <code>/unbind user_1234</code>",
        reply_markup=admin_kb(), parse_mode="HTML"
    )

@dp.message(Command("unbind"))
async def cmd_unbind_admin(message: Message, command: CommandObject):
    if message.from_user.id != ADMIN_ID:
        return
    if not PHONE_ENABLED:
        await message.answer("Привязка номера отключена: не задан PHONE_ENC_KEY.")
        return
    uid = (command.args or "").strip()
    if not is_valid_uid(uid):
        await message.answer("Формат: <code>/unbind user_1234</code>", parse_mode="HTML")
        return
    try:
        await unbind_phone(uid)
        await message.answer(f"✅ Номер у <code>{uid}</code> отвязан.", parse_mode="HTML")
    except Exception as e:
        logging.error(f"admin unbind error: {e}")
        await message.answer("❌ Ошибка записи в Firebase. Проверь логи.")

@dp.callback_query(F.data == "admin_stats")
async def admin_stats(call: CallbackQuery):
    if call.from_user.id != ADMIN_ID:
        return
    paid = count_payments()
    await call.message.edit_text(
        f"📊 <b>Статистика</b>\n\n"
        f"✅ Выдано галочек: <b>{paid}</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")]
        ]),
        parse_mode="HTML"
    )

@dp.callback_query(F.data == "admin_free_verify")
async def admin_free_verify(call: CallbackQuery, state: FSMContext):
    if call.from_user.id != ADMIN_ID:
        return
    await state.set_state(AdminStates.waiting_free_uid)
    await call.message.edit_text(
        "🎁 <b>Бесплатная выдача галочки</b>\n\n"
        "Введи ID пользователя из Swifty Chat:\n"
        "Формат: <code>user_1234</code>",
        parse_mode="HTML"
    )

@dp.callback_query(F.data == "admin_back")
async def admin_back(call: CallbackQuery):
    if call.from_user.id != ADMIN_ID:
        return
    await call.message.edit_text("👑 <b>Админ панель</b>", reply_markup=admin_kb(), parse_mode="HTML")

@dp.callback_query(F.data == "profile")
async def show_profile(call: CallbackQuery):
    user = call.from_user
    await call.message.edit_text(
        f"👤 <b>Профиль</b>\n\n"
        f"🆔 Telegram ID: <code>{user.id}</code>\n"
        f"👤 Имя: {user.full_name}",
        reply_markup=back_kb(),
        parse_mode="HTML"
    )

@dp.callback_query(F.data == "about")
async def show_about(call: CallbackQuery):
    await call.message.edit_text(
        "ℹ️ <b>О боте</b>\n\n"
        "Этот бот выдаёт верификацию (галочку ✅) для аккаунта в <b>Swifty Chat</b>.\n"
        "После оплаты галочка появится в профиле автоматически.\n\n"
        "📱 Ещё здесь можно привязать номер телефона. После этого при входе в аккаунт "
        "бот присылает 5-значный код, и даже с украденным паролем в аккаунт не войти.\n\n"
        "💰 Подписка: <b>1 USDT</b>\n"
        "🔐 Оплата через CryptoBot",
        reply_markup=back_kb(),
        parse_mode="HTML"
    )

@dp.callback_query(F.data == "back_main")
async def back_main(call: CallbackQuery, state: FSMContext):
    await state.clear()
    await call.message.edit_text(
        "🏠 <b>Главное меню</b>",
        reply_markup=main_menu_kb(),
        parse_mode="HTML"
    )

@dp.callback_query(F.data == "buy_verify")
async def buy_verify(call: CallbackQuery, state: FSMContext):
    await state.set_state(VerifyStates.waiting_uid)
    await call.message.edit_text(
        "✅ <b>Купить подписку</b>\n\n"
        "Введи свой ID из <b>Swifty Chat</b>.\n"
        "Формат: <code>user_1234</code>",
        reply_markup=back_kb("back_main", "🔙 Отмена"),
        parse_mode="HTML"
    )

# ---------- ПРИВЯЗКА НОМЕРА ----------
@dp.callback_query(F.data == "bind_phone")
async def bind_phone(call: CallbackQuery, state: FSMContext):
    if not PHONE_ENABLED:
        await call.answer(PHONE_OFF_TEXT, show_alert=True)
        return
    data = await state.get_data()
    suggest = data.get("suggest_uid")
    await state.set_state(BindStates.waiting_uid)
    rows = []
    if suggest:
        rows.append([InlineKeyboardButton(text=f"✅ Это мой ID: {suggest}", callback_data=f"bind_use:{suggest}")])
    rows.append([InlineKeyboardButton(text="🔙 Отмена", callback_data="back_main")])
    await call.message.edit_text(
        "📱 <b>Привязка номера</b>\n\n"
        "Введи свой ID из <b>Swifty Chat</b>.\n"
        "Формат: <code>user_1234</code>\n\n"
        "ID виден в приложении: Настройки → профиль.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows),
        parse_mode="HTML"
    )

async def begin_bind(message: Message, state: FSMContext, uid: str):
    if not is_valid_uid(uid):
        await message.answer("❌ Неверный формат!\n\nID должен быть в формате <code>user_1234</code>", parse_mode="HTML")
        return
    await message.answer("⏳ Проверяю пользователя в Swifty Chat...")
    if not await check_user_exists(uid):
        await message.answer(
            f"❌ Пользователь <code>{uid}</code> не найден в Swifty Chat.\n\nПроверь ID и попробуй снова.",
            parse_mode="HTML"
        )
        return
    try:
        if await get_phone_info(uid):
            await state.clear()
            await message.answer(
                f"🔒 К аккаунту <code>{uid}</code> уже привязан номер.\n\n"
                "Сменить его можно только с того Telegram-аккаунта, к которому он привязан: "
                "меню → «Отвязать номер».",
                reply_markup=back_kb("back_main", "🏠 Главное меню"),
                parse_mode="HTML"
            )
            return
        pending = await get_pending(uid)
        if pending:
            try:
                same = int(dec_str(pending["t"], uid)) == message.from_user.id
            except Exception:
                same = False
            if not same:
                await message.answer(
                    f"⏳ Для <code>{uid}</code> уже есть незавершённая привязка.\n"
                    "Подожди 10 минут или попроси владельца аккаунта отклонить её в приложении.",
                    parse_mode="HTML"
                )
                return
    except Exception as e:
        logging.error(f"begin_bind error: {e}")
        await message.answer("❌ Ошибка связи с базой. Попробуй позже.")
        return
    await state.set_state(BindStates.waiting_contact)
    await state.update_data(uid=uid)
    await message.answer(
        f"✅ Аккаунт <code>{uid}</code> найден.\n\n"
        "Нажми кнопку <b>«Поделиться контактом»</b> внизу, чтобы привязать номер этого Telegram-аккаунта.",
        reply_markup=contact_kb(),
        parse_mode="HTML"
    )

@dp.callback_query(F.data.startswith("bind_use:"))
async def bind_use(call: CallbackQuery, state: FSMContext):
    if not PHONE_ENABLED:
        await call.answer(PHONE_OFF_TEXT, show_alert=True)
        return
    uid = call.data.split(":", 1)[1]
    await call.answer()
    await begin_bind(call.message, state, uid)

@dp.message(BindStates.waiting_uid)
async def bind_uid_input(message: Message, state: FSMContext):
    await begin_bind(message, state, (message.text or "").strip())

@dp.message(BindStates.waiting_contact, F.contact)
async def bind_got_contact(message: Message, state: FSMContext):
    data = await state.get_data()
    uid = data.get("uid")
    contact = message.contact
    if not uid or not is_valid_uid(uid):
        await state.clear()
        await message.answer("Сессия устарела. Начни заново: /start", reply_markup=ReplyKeyboardRemove())
        return
    # Принимаем только собственный контакт: чужой номер привязать нельзя.
    if contact.user_id != message.from_user.id:
        await message.answer("❌ Это чужой контакт. Нажми кнопку «Поделиться контактом» и отправь свой.")
        return
    phone = normalize_phone(contact.phone_number)
    if not phone:
        await message.answer("❌ Не удалось распознать номер. Попробуй ещё раз.")
        return
    try:
        if await get_phone_info(uid):
            await state.clear()
            await message.answer("🔒 К этому аккаунту уже привязан номер.", reply_markup=ReplyKeyboardRemove())
            return
        await create_pending(uid, message.from_user.id, phone)
    except Exception as e:
        logging.error(f"create_pending error: {e}")
        await message.answer("❌ Ошибка записи в базу. Попробуй позже.", reply_markup=ReplyKeyboardRemove())
        return
    await state.clear()
    await message.answer(
        f"📲 Номер <b>{mask_phone(phone)}</b> принят.\n\n"
        f"Осталось подтвердить, что аккаунт <code>{uid}</code> твой: открой <b>Swifty Chat → Настройки → "
        "Привязать номер</b> и нажми «Подтвердить». Заявка действует 10 минут.\n\n"
        "Это нужно, чтобы никто не мог привязать свой номер к чужому аккаунту.",
        reply_markup=ReplyKeyboardRemove(),
        parse_mode="HTML"
    )
    await message.answer("🏠 Главное меню", reply_markup=main_menu_kb())

@dp.message(BindStates.waiting_contact)
async def bind_contact_other(message: Message, state: FSMContext):
    if (message.text or "").strip() == "❌ Отмена":
        await state.clear()
        await message.answer("Отменено.", reply_markup=ReplyKeyboardRemove())
        await message.answer("🏠 Главное меню", reply_markup=main_menu_kb())
        return
    await message.answer("Нажми кнопку «📱 Поделиться контактом» внизу или «❌ Отмена».")

# ---------- ОТВЯЗКА НОМЕРА ----------
@dp.callback_query(F.data == "unbind_menu")
async def unbind_menu(call: CallbackQuery):
    if not PHONE_ENABLED:
        await call.answer(PHONE_OFF_TEXT, show_alert=True)
        return
    try:
        bound = await fb_get(f"phone_by_tg/{call.from_user.id}")
    except Exception as e:
        logging.error(f"unbind_menu error: {e}")
        await call.answer("Ошибка связи с базой", show_alert=True)
        return
    uids = [u for u, v in bound.items() if v and is_valid_uid(u)] if isinstance(bound, dict) else []
    if not uids:
        await call.answer("К этому Telegram не привязан ни один аккаунт", show_alert=True)
        return
    rows = [[InlineKeyboardButton(text=f"🔓 {u}", callback_data=f"unbind_ask:{u}")] for u in uids[:10]]
    rows.append([InlineKeyboardButton(text="🔙 Назад", callback_data="back_main")])
    await call.message.edit_text(
        "🔓 <b>Отвязать номер</b>\n\nВыбери аккаунт. После отвязки вход в него снова будет только по паролю.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=rows),
        parse_mode="HTML"
    )

@dp.callback_query(F.data.startswith("unbind_ask:"))
async def unbind_ask(call: CallbackQuery):
    uid = call.data.split(":", 1)[1]
    if not is_valid_uid(uid):
        return
    await call.message.edit_text(
        f"Отвязать номер от <code>{uid}</code>?\n\nКод из Telegram перестанет требоваться при входе.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="✅ Да, отвязать", callback_data=f"unbind_do:{uid}")],
            [InlineKeyboardButton(text="🔙 Отмена", callback_data="unbind_menu")],
        ]),
        parse_mode="HTML"
    )

@dp.callback_query(F.data.startswith("unbind_do:"))
async def unbind_do(call: CallbackQuery):
    uid = call.data.split(":", 1)[1]
    if not is_valid_uid(uid):
        return
    try:
        # Отвязать может только тот Telegram-аккаунт, к которому номер привязан.
        if (await fb_get(f"phone_by_tg/{call.from_user.id}/{uid}")) is not True:
            await call.answer("Этот аккаунт привязан не к вашему Telegram", show_alert=True)
            return
        await unbind_phone(uid, call.from_user.id)
    except Exception as e:
        logging.error(f"unbind_do error: {e}")
        await call.answer("Ошибка записи в базу", show_alert=True)
        return
    await call.message.edit_text(
        f"✅ Номер отвязан от <code>{uid}</code>.",
        reply_markup=back_kb("back_main", "🏠 Главное меню"),
        parse_mode="HTML"
    )

# ---------- ОПЛАТА STARS: успешный платёж (должен идти раньше общего обработчика) ----------
@dp.message(F.successful_payment)
async def successful_payment_handler(message: Message):
    payload = message.successful_payment.invoice_payload
    # payload формат: stars:user_id:uid
    parts = payload.split(":")
    if len(parts) != 3 or parts[0] != "stars":
        return
    _, user_id, uid = parts
    stars_count = message.successful_payment.total_amount
    invoice_id = f"stars_{user_id}_{uid}_{int(time.time())}"
    save_payment(invoice_id, int(user_id), uid, method="stars")
    mark_paid(invoice_id)
    success = await verify_user(uid)
    if success:
        await message.answer(
            f"🎉 <b>Оплата Stars прошла!</b>\n\n"
            f"⭐ Списано: <b>{stars_count} Stars</b>\n"
            f"✅ Галочка выдана аккаунту <code>{uid}</code>!\n"
            f"Обнови приложение Swifty Chat 🚀",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="🏠 Главное меню", callback_data="back_main")]
            ]),
            parse_mode="HTML"
        )
    else:
        await message.answer(
            "✅ Оплата Stars прошла, но ошибка при выдаче галочки.\n"
            "Напиши администратору — выдадут вручную."
        )

# ---------- ОБЩИЙ ОБРАБОТЧИК (ID для покупки / выдача админом) ----------
@dp.message()
async def handle_message(message: Message, state: FSMContext):
    current_state = await state.get_state()
    text = (message.text or "").strip()

    # Админ выдаёт бесплатно
    if current_state == AdminStates.waiting_free_uid and message.from_user.id == ADMIN_ID:
        uid = text
        if not is_valid_uid(uid):
            await message.answer(
                "❌ Неверный формат!\nФормат: <code>user_1234</code>",
                parse_mode="HTML"
            )
            return
        await message.answer("⏳ Проверяю пользователя...")
        exists = await check_user_exists(uid)
        if not exists:
            await message.answer(
                f"❌ Пользователь <code>{uid}</code> не найден в Swifty Chat.",
                parse_mode="HTML"
            )
            return
        success = await verify_user(uid)
        await state.clear()
        if success:
            await message.answer(
                f"✅ Галочка бесплатно выдана аккаунту <code>{uid}</code>!",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🔙 Админ панель", callback_data="admin_back")]
                ]),
                parse_mode="HTML"
            )
        else:
            await message.answer("❌ Ошибка записи в Firebase. Проверь логи.")
        return

    # Пользователь вводит UID для покупки
    if current_state == VerifyStates.waiting_uid:
        uid = text
        if not is_valid_uid(uid):
            await message.answer(
                "❌ Неверный формат!\n\n"
                "ID должен быть в формате <code>user_1234</code>",
                parse_mode="HTML"
            )
            return

        await message.answer("⏳ Проверяю пользователя в Swifty Chat...")
        exists = await check_user_exists(uid)
        if not exists:
            await message.answer(
                f"❌ Пользователь <code>{uid}</code> не найден в Swifty Chat.\n\n"
                "Проверь ID и попробуй снова.",
                parse_mode="HTML"
            )
            return

        await message.answer("✅ Пользователь найден! Выбери способ оплаты:")
        await state.update_data(uid=uid)
        await message.answer(
            f"💳 <b>Выбери способ оплаты</b>\n\n"
            f"👤 Аккаунт: <code>{uid}</code>\n\n"
            f"• CryptoBot — <b>1 USDT</b> (крипта)\n"
            f"• Telegram Stars — <b>{STARS_PRICE} ⭐</b>",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="💳 CryptoBot (1 USDT)", callback_data=f"pay_crypto:{uid}")],
                [InlineKeyboardButton(text="⭐ Telegram Stars", callback_data=f"pay_stars:{uid}")],
                [InlineKeyboardButton(text="🔙 Отмена", callback_data="back_main")],
            ]),
            parse_mode="HTML"
        )
        await state.clear()
        return

@dp.callback_query(F.data.startswith("check_"))
async def check_payment(call: CallbackQuery):
    invoice_id = call.data.split("_", 1)[1]
    payment = get_payment(invoice_id)
    if not payment:
        await call.answer("❌ Счёт не найден", show_alert=True)
        return

    _, user_id, chat_uid, status, _ = payment
    if status == "paid":
        await call.answer("✅ Галочка уже выдана!", show_alert=True)
        return

    status_now = await check_invoice(invoice_id)
    if status_now == "paid":
        mark_paid(invoice_id)
        success = await verify_user(chat_uid)
        if success:
            await call.message.edit_text(
                f"🎉 <b>Оплата прошла!</b>\n\n"
                f"✅ Галочка выдана аккаунту <code>{chat_uid}</code>!\n"
                f"Обнови приложение Swifty Chat 🚀",
                reply_markup=InlineKeyboardMarkup(inline_keyboard=[
                    [InlineKeyboardButton(text="🏠 Главное меню", callback_data="back_main")]
                ]),
                parse_mode="HTML"
            )
        else:
            await call.message.edit_text(
                "✅ Оплата прошла, но ошибка при выдаче галочки.\n"
                "Напиши администратору — выдадут вручную.",
                parse_mode="HTML"
            )
    else:
        await call.answer("⏳ Оплата не найдена. Оплати и попробуй снова.", show_alert=True)

# ==================== ОПЛАТА CRYPTOBOT ====================
@dp.callback_query(F.data.startswith("pay_crypto:"))
async def pay_crypto_handler(call: CallbackQuery):
    uid = call.data.split(":", 1)[1]
    await call.message.edit_text("⏳ Создаю счёт в CryptoBot...")
    invoice = await create_invoice(call.from_user.id, uid)
    if not invoice:
        await call.message.edit_text("❌ Ошибка создания счёта. Попробуй позже.")
        return
    invoice_id = str(invoice["invoice_id"])
    pay_url = invoice["pay_url"]
    save_payment(invoice_id, call.from_user.id, uid, method="crypto")
    await call.message.edit_text(
        f"💳 <b>Счёт на оплату (CryptoBot)</b>\n\n"
        f"👤 Аккаунт: <code>{uid}</code>\n"
        f"💰 Сумма: <b>1 USDT</b>\n\n"
        f"1. Нажми <b>Оплатить</b>\n"
        f"2. Оплати через CryptoBot\n"
        f"3. Нажми <b>Проверить оплату</b>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="💳 Оплатить 1 USDT", url=pay_url)],
            [InlineKeyboardButton(text="✅ Проверить оплату", callback_data=f"check_{invoice_id}")],
            [InlineKeyboardButton(text="🔙 Отмена", callback_data="back_main")],
        ]),
        parse_mode="HTML"
    )

# ==================== ОПЛАТА TELEGRAM STARS ====================
@dp.callback_query(F.data.startswith("pay_stars:"))
async def pay_stars_handler(call: CallbackQuery):
    uid = call.data.split(":", 1)[1]
    await call.answer()
    await bot.send_invoice(
        chat_id=call.from_user.id,
        title="✅ Верификация в Swifty Chat",
        description=f"Галочка для аккаунта {uid}",
        payload=f"stars:{call.from_user.id}:{uid}",
        currency="XTR",
        prices=[LabeledPrice(label="Верификация", amount=STARS_PRICE)],
    )

@dp.pre_checkout_query()
async def pre_checkout_handler(pre_checkout: PreCheckoutQuery):
    await pre_checkout.answer(ok=True)

# ==================== ЗАПУСК ====================
async def main():
    global PHONE_ENABLED
    init_db()
    worker = None
    try:
        init_crypto()
        PHONE_ENABLED = True
        worker = asyncio.create_task(phone_worker())
    except RuntimeError as e:
        # Без ключа бот всё равно запускается: покупки работают, привязка номера отключена.
        logging.error(f"Привязка номера ОТКЛЮЧЕНА: {e}")
    logging.info("Swifty Verify bot started!")
    try:
        await dp.start_polling(bot, skip_updates=True)
    finally:
        if worker is not None:
            worker.cancel()
        if _http_session is not None and not _http_session.closed:
            await _http_session.close()

if __name__ == "__main__":
    asyncio.run(main())
