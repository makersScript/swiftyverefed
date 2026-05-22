import asyncio
import aiohttp
import logging
import os
import time
import sqlite3
from dotenv import load_dotenv
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message, CallbackQuery, InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.filters import Command
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
            created_at INTEGER DEFAULT (strftime('%s','now'))
        )
    """)
    conn.commit()
    conn.close()

def save_payment(invoice_id, user_id, chat_uid):
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO payments (invoice_id, user_id, chat_uid) VALUES (?, ?, ?)",
              (invoice_id, user_id, chat_uid))
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
        [InlineKeyboardButton(text="✅ Купить галочку", callback_data="buy_verify")],
        [InlineKeyboardButton(text="👤 Профиль", callback_data="profile")],
        [InlineKeyboardButton(text="ℹ️ О боте", callback_data="about")],
    ])

def admin_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📊 Статистика", callback_data="admin_stats")],
        [InlineKeyboardButton(text="🎁 Выдать галочку бесплатно", callback_data="admin_free_verify")],
    ])

# ==================== ХЭНДЛЕРЫ ====================
@dp.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "👋 Добро пожаловать в <b>Swifty Chat Verify</b>!\n\n"
        "✅ Купи верификацию (галочку) для своего аккаунта в <b>Swifty Chat</b>.\n\n"
        "💰 Стоимость: <b>1 USDT</b>\n"
        "🔐 Оплата через CryptoBot",
        reply_markup=main_menu_kb(),
        parse_mode="HTML"
    )

@dp.message(Command("admin"))
async def cmd_admin(message: Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    await state.clear()
    await message.answer("👑 <b>Админ панель</b>", reply_markup=admin_kb(), parse_mode="HTML")

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
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_main")]
        ]),
        parse_mode="HTML"
    )

@dp.callback_query(F.data == "about")
async def show_about(call: CallbackQuery):
    await call.message.edit_text(
        "ℹ️ <b>О боте</b>\n\n"
        "Этот бот выдаёт верификацию (галочку ✅) для аккаунта в <b>Swifty Chat</b>.\n\n"
        "После оплаты галочка появится в профиле автоматически.\n\n"
        "💰 Стоимость: <b>1 USDT</b>\n"
        "🔐 Оплата через CryptoBot",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Назад", callback_data="back_main")]
        ]),
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
        "✅ <b>Купить галочку</b>\n\n"
        "Введи свой ID из <b>Swifty Chat</b>.\n"
        "Формат: <code>user_1234</code>",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Отмена", callback_data="back_main")]
        ]),
        parse_mode="HTML"
    )

@dp.message()
async def handle_message(message: Message, state: FSMContext):
    current_state = await state.get_state()

    # Админ выдаёт бесплатно
    if current_state == AdminStates.waiting_free_uid and message.from_user.id == ADMIN_ID:
        uid = message.text.strip()
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
        uid = message.text.strip()
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

        await message.answer("✅ Пользователь найден! Создаю счёт...")
        invoice = await create_invoice(message.from_user.id, uid)
        if not invoice:
            await message.answer("❌ Ошибка создания счёта. Попробуй позже.")
            await state.clear()
            return

        invoice_id = str(invoice["invoice_id"])
        pay_url = invoice["pay_url"]
        save_payment(invoice_id, message.from_user.id, uid)
        await state.clear()

        await message.answer(
            f"💳 <b>Счёт на оплату</b>\n\n"
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

# ==================== ЗАПУСК ====================
async def main():
    init_db()
    logging.info("Swifty Verify bot started!")
    await dp.start_polling(bot, skip_updates=True)

if __name__ == "__main__":
    asyncio.run(main())
