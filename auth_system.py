import sqlite3
import hashlib
import secrets
import time
import smtplib
import base64
import hmac
import struct
from email.message import EmailMessage
from datetime import datetime, timedelta

DB_NAME = "users.db"

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "vip.safonov2007@gmail.com"
SMTP_PASS = "kpgg vqph zyqn yckr"
FROM_EMAIL = SMTP_USER if SMTP_USER else "no-reply@example.com"

DEFAULT_MASTER_KEY = "7427Hasdfg6dfvcds76gvas856cfdhsvb7idfvg"

def _connect():
    return sqlite3.connect(DB_NAME)


def _hash(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def hash_with_salt(password: str, salt: str) -> str:
    return hashlib.sha256((password + salt).encode()).hexdigest()


def generate_2fa_secret():
    return base64.b32encode(secrets.token_bytes(10)).decode()


def verify_totp(secret, code, interval=30):
    if not secret:
        return False
    try:
        key = base64.b32decode(secret)
        t = int(time.time()) // interval
        for offset in [-1, 0, +1]:
            msg = struct.pack(">Q", t + offset)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            number = (struct.unpack(">I", h[o:o + 4])[0] & 0x7fffffff) % 1_000_000
            if f"{number:06d}" == code:
                return True
        return False
    except Exception:
        return False

def _column_exists(c, table, column):
    c.execute(f"PRAGMA table_info({table})")
    cols = [row[1] for row in c.fetchall()]
    return column in cols


def init_db():
    """
    Создание таблиц и лёгкая миграция, чтобы не заставлять сносить БД.
    """
    conn = _connect()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            twofa_secret TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    if not _column_exists(c, "users", "salt"):
        c.execute("ALTER TABLE users ADD COLUMN salt TEXT")
    if not _column_exists(c, "users", "role"):
        c.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if not _column_exists(c, "users", "twofa_secret"):
        c.execute("ALTER TABLE users ADD COLUMN twofa_secret TEXT")

    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_uid TEXT UNIQUE NOT NULL,
            owner_user_id INTEGER,
            nickname TEXT,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP,
            FOREIGN KEY(owner_user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event TEXT,
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            meta TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS home_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            home_id INTEGER,
            user_id INTEGER,
            event TEXT,
            ts TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            meta TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS room_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id INTEGER NOT NULL,
            kind TEXT NOT NULL,      -- тип: light / outlet / door / siren / custom
            label TEXT NOT NULL,     -- как подписано в UI (например "Лампа у кровати")
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(room_id) REFERENCES rooms(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    c.execute("SELECT value FROM settings WHERE key='master_key_hash'")
    row = c.fetchone()
    if not row:
        c.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            ("master_key_hash", _hash(DEFAULT_MASTER_KEY))
        )

    conn.commit()
    conn.close()

def verify_master_key(raw_key: str) -> bool:
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key='master_key_hash'")
    row = c.fetchone()
    conn.close()
    return bool(row) and _hash(raw_key) == row[0]


def is_admin(username: str) -> bool:
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT role FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    return bool(row) and row[0] == "admin"

def register_user(username: str, email: str, password: str, master_key: str = None):
    username = username.strip()
    email = email.strip().lower()
    if not username or not email or not password:
        return False, "Заполните все поля."
    role = "user"
    if master_key:
        if verify_master_key(master_key):
            role = "admin"
        else:
            return False, "Неверный мастер-ключ."

    salt = secrets.token_hex(8)
    pw_hash = hash_with_salt(password, salt)

    conn = _connect()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO users (username, email, password_hash, salt, role)
            VALUES (?, ?, ?, ?, ?)
        """, (username, email, pw_hash, salt, role))
        conn.commit()
        conn.close()
        return True, "Пользователь зарегистрирован."
    except sqlite3.IntegrityError as e:
        conn.close()
        msg = str(e).lower()
        if "username" in msg:
            return False, "Логин уже занят."
        if "email" in msg:
            return False, "Email уже зарегистрирован."
        return False, "Ошибка при регистрации."


def get_user_by_username(username: str):
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, username, email, role, created_at
        FROM users
        WHERE username=?
    """, (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "role": row[3],
        "created_at": row[4]
    }


def get_user_by_email(email: str):
    email = email.strip().lower()
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, username, email, role, created_at
        FROM users
        WHERE email=?
    """, (email,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "role": row[3],
        "created_at": row[4]
    }


def login_user(username: str, password: str, twofa_code: str = None):
    conn = _connect()
    c = conn.cursor()
    c.execute(
        "SELECT id, password_hash, salt, role, twofa_secret FROM users WHERE username=?",
        (username,)
    )
    row = c.fetchone()
    conn.close()

    if not row:
        return False, "Пользователь не найден."

    user_id, pw_hash, salt, role, twofa_secret = row

    if salt:
        calc = hash_with_salt(password, salt)
    else:
        calc = _hash(password)

    if calc != pw_hash:
        add_login_history(user_id, "login_failed")
        return False, "Неверный пароль."

    if twofa_secret:
        if not twofa_code or not verify_totp(twofa_secret, twofa_code):
            return False, "Неверный 2FA код."

    add_login_history(user_id, "login_success")
    return True, role


def get_device_by_uid(device_uid: str):
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, device_uid, owner_user_id, nickname, created_at, last_seen
        FROM devices
        WHERE device_uid=?
    """, (device_uid,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "device_uid": row[1],
        "owner_user_id": row[2],
        "nickname": row[3],
        "created_at": row[4],
        "last_seen": row[5]
    }


def get_devices_by_owner(user_id: int):
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, device_uid, nickname, created_at, last_seen
        FROM devices
        WHERE owner_user_id=?
    """, (user_id,))
    rows = c.fetchall()
    conn.close()
    devices = []
    for r in rows:
        devices.append({
            "id": r[0],
            "device_uid": r[1],
            "nickname": r[2],
            "created_at": r[3],
            "last_seen": r[4]
        })
    return devices


def get_all_devices():
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT d.id, d.device_uid, d.nickname, d.owner_user_id,
               u.username, d.created_at, d.last_seen
        FROM devices d
        LEFT JOIN users u ON d.owner_user_id = u.id
    """)
    rows = c.fetchall()
    conn.close()
    devices = []
    for r in rows:
        devices.append({
            "id": r[0],
            "device_uid": r[1],
            "nickname": r[2],
            "owner_user_id": r[3],
            "owner_username": r[4],
            "created_at": r[5],
            "last_seen": r[6]
        })
    return devices


def get_device_by_id(dev_id: int):
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, device_uid, owner_user_id, nickname, created_at, last_seen
        FROM devices
        WHERE id=?
    """, (dev_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "device_uid": row[1],
        "owner_user_id": row[2],
        "nickname": row[3],
        "created_at": row[4],
        "last_seen": row[5]
    }


def get_or_claim_device(device_uid: str, user_id: int):
    """
    Логика:
    - если device_uid нет в БД → создать и привязать к user_id
    - если есть и owner_user_id is NULL → привязать к user_id
    - если есть и owner_user_id == user_id → ок
    - если есть и owner_user_id != user_id → отказ
    Возвращает (ok: bool, device: dict | None, message: str)
    """
    now = datetime.utcnow().isoformat()

    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT id, owner_user_id FROM devices WHERE device_uid=?", (device_uid,))
    row = c.fetchone()

    if not row:
        c.execute("""
            INSERT INTO devices (device_uid, owner_user_id, created_at, last_seen)
            VALUES (?, ?, ?, ?)
        """, (device_uid, user_id, now, now))
        conn.commit()
        dev_id = c.lastrowid
        conn.close()
        dev = get_device_by_id(dev_id)
        return True, dev, "Плата успешно привязана к вашему аккаунту."

    dev_id, owner_id = row

    if owner_id is None:
        c.execute(
            "UPDATE devices SET owner_user_id=?, last_seen=? WHERE id=?",
            (user_id, now, dev_id)
        )
        conn.commit()
        conn.close()
        dev = get_device_by_id(dev_id)
        return True, dev, "Плата была свободна и привязана к вашему аккаунту."

    if owner_id == user_id:
        c.execute("UPDATE devices SET last_seen=? WHERE id=?", (now, dev_id))
        conn.commit()
        conn.close()
        dev = get_device_by_id(dev_id)
        return True, dev, "Плата уже привязана к вашему аккаунту."

    conn.close()
    return False, None, "Эта плата уже привязана к другому аккаунту."

def add_login_history(user_id: int, event: str, meta: str = None):
    conn = _connect()
    c = conn.cursor()
    c.execute(
        "INSERT INTO login_history (user_id, event, meta) VALUES (?, ?, ?)",
        (user_id, event, meta)
    )
    conn.commit()
    conn.close()


def get_login_history(username: str, limit: int = 50):
    user = get_user_by_username(username)
    if not user:
        return []
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT event, ts, meta
        FROM login_history
        WHERE user_id=?
        ORDER BY ts DESC
        LIMIT ?
    """, (user["id"], limit))
    rows = c.fetchall()
    conn.close()
    return [{"event": r[0], "ts": r[1], "meta": r[2]} for r in rows]


def add_home_log(home_id: int, user_id: int, event: str, meta: str = None):
    """
    home_id здесь — это ID устройства (device_id).
    """
    conn = _connect()
    c = conn.cursor()
    c.execute(
        "INSERT INTO home_logs (home_id, user_id, event, meta) VALUES (?, ?, ?, ?)",
        (home_id, user_id, event, meta)
    )
    conn.commit()
    conn.close()


def get_home_logs(home_id: int, limit: int = 100):
    """
    Логи по конкретной плате (для админа / анализа).
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT event, ts, meta
        FROM home_logs
        WHERE home_id=?
        ORDER BY ts DESC
        LIMIT ?
    """, (home_id, limit))
    rows = c.fetchall()
    conn.close()
    return rows


def get_user_home_logs(user_id: int, limit: int = 100):
    """
    Логи только по этому юзеру (для обычного пользователя).
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT event, ts, meta
        FROM home_logs
        WHERE user_id=?
        ORDER BY ts DESC
        LIMIT ?
    """, (user_id, limit))
    rows = c.fetchall()
    conn.close()
    return rows


def get_all_home_logs(limit: int = 1000):
    """
    Глобальные логи умного дома (для админа).
    Возвращает список словарей с инфой о юзере и устройстве.
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT h.event, h.ts, h.meta,
               h.home_id, h.user_id,
               u.username,
               d.device_uid
        FROM home_logs h
        LEFT JOIN users u ON h.user_id = u.id
        LEFT JOIN devices d ON h.home_id = d.id
        ORDER BY h.ts DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    result = []
    for ev, ts, meta, home_id, user_id, username, device_uid in rows:
        result.append({
            "event": ev,
            "ts": ts,
            "meta": meta,
            "home_id": home_id,
            "user_id": user_id,
            "username": username,
            "device_uid": device_uid
        })
    return result


def clear_all_logs():
    """
    Полная очистка всех логов умного дома (только для админа, вызывать из GUI).
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("DELETE FROM home_logs")
    conn.commit()
    conn.close()

def _generate_reset_code() -> str:
    """6-значный код, как в Telegram."""
    return f"{secrets.randbelow(1_000_000):06d}"


def create_password_reset_token(email: str, expire_minutes: int = 10):
    """
    Создаёт код для сброса пароля и отправляет его на email.
    Код хранится в таблице password_resets.
    """
    email = email.strip().lower()
    user = get_user_by_email(email)
    if not user:
        return False, "Email не найден."

    user_id = user["id"]
    code = _generate_reset_code()
    expires_at = datetime.utcnow() + timedelta(minutes=expire_minutes)

    conn = _connect()
    c = conn.cursor()
    c.execute("""
        INSERT INTO password_resets (user_id, token, expires_at)
        VALUES (?, ?, ?)
    """, (user_id, code, expires_at.isoformat()))
    conn.commit()
    conn.close()

    sent = send_reset_email(email, code)
    if sent:
        return True, "Код для сброса пароля отправлен на email."
    else:
        return True, f"SMTP не настроен — используйте код: {code}"


def verify_reset_token(username: str, token: str) -> bool:
    """
    Проверка введённого кода (token) для данного пользователя.
    """
    user = get_user_by_username(username)
    if not user:
        return False
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, expires_at, used
        FROM password_resets
        WHERE user_id=? AND token=?
        ORDER BY id DESC
        LIMIT 1
    """, (user["id"], token))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    rid, expires_at, used = row
    if used:
        return False
    if datetime.fromisoformat(expires_at) < datetime.utcnow():
        return False
    return True


def reset_password(username: str, token: str, new_password: str):
    """
    Сбрасывает пароль, если код верный и не истёк.
    """
    if not verify_reset_token(username, token):
        return False, "Код неверен или истёк."
    user = get_user_by_username(username)
    if not user:
        return False, "Пользователь не найден."

    salt = secrets.token_hex(8)
    pw_hash = hash_with_salt(new_password, salt)

    conn = _connect()
    c = conn.cursor()
    c.execute(
        "UPDATE users SET password_hash=?, salt=? WHERE id=?",
        (pw_hash, salt, user["id"])
    )
    c.execute(
        "UPDATE password_resets SET used=1 WHERE user_id=? AND token=?",
        (user["id"], token)
    )
    conn.commit()
    conn.close()

    add_login_history(user["id"], "password_reset")
    return True, "Пароль успешно сброшен."

def create_room(user_id: int, name: str):
    """
    Создаёт комнату для пользователя.
    Возвращает (ok, room_id | None, message).
    """
    name = name.strip()
    if not name:
        return False, None, "Название комнаты не может быть пустым."

    conn = _connect()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO rooms (user_id, name)
            VALUES (?, ?)
        """, (user_id, name))
        room_id = c.lastrowid
        conn.commit()
        conn.close()
        return True, room_id, "Комната создана."
    except Exception as e:
        conn.close()
        return False, None, f"Ошибка создания комнаты: {e}"


def rename_room(user_id: int, room_id: int, new_name: str):
    """
    Переименовывает комнату (только свою).
    """
    new_name = new_name.strip()
    if not new_name:
        return False, "Название не может быть пустым."

    conn = _connect()
    c = conn.cursor()
    c.execute("""
        UPDATE rooms
        SET name=?
        WHERE id=? AND user_id=?
    """, (new_name, room_id, user_id))
    conn.commit()
    updated = c.rowcount
    conn.close()
    if updated:
        return True, "Название обновлено."
    return False, "Комната не найдена или не принадлежит вам."


def delete_room(user_id: int, room_id: int):
    """
    Удаляет комнату и все её устройства (только свою).
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT id FROM rooms WHERE id=? AND user_id=?", (room_id, user_id))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "Комната не найдена или не принадлежит вам."
    c.execute("DELETE FROM room_items WHERE room_id=?", (room_id,))
    c.execute("DELETE FROM rooms WHERE id=?", (room_id,))
    conn.commit()
    conn.close()
    return True, "Комната и её устройства удалены."


def get_rooms_for_user(user_id: int):
    """
    Возвращает список комнат пользователя:
    [{id, name, created_at}, ...]
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, name, created_at
        FROM rooms
        WHERE user_id=?
        ORDER BY created_at ASC, id ASC
    """, (user_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "name": r[1], "created_at": r[2]}
        for r in rows
    ]


def add_room_item(room_id: int, kind: str, label: str):
    """
    Добавляет устройство в комнату.
    kind: 'light', 'outlet', 'door', 'siren', 'custom', ...
    label: как показываем в интерфейсе ("Люстра", "Сирена", ...)
    """
    kind = kind.strip().lower()
    label = label.strip()
    if not kind or not label:
        return False, "Тип и название устройства обязателны."

    conn = _connect()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO room_items (room_id, kind, label)
            VALUES (?, ?, ?)
        """, (room_id, kind, label))
        conn.commit()
        conn.close()
        return True, "Устройство добавлено в комнату."
    except Exception as e:
        conn.close()
        return False, f"Ошибка добавления устройства: {e}"


def get_room_items(room_id: int):
    """
    Возвращает список устройств комнаты:
    [{id, kind, label, created_at}, ...]
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("""
        SELECT id, kind, label, created_at
        FROM room_items
        WHERE room_id=?
        ORDER BY created_at ASC, id ASC
    """, (room_id,))
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "kind": r[1], "label": r[2], "created_at": r[3]}
        for r in rows
    ]


def delete_room_item(item_id: int):
    """
    Удаляет конкретное устройство из комнаты.
    (Проверку "чья комната" можно делать выше по стеку, через join.)
    """
    conn = _connect()
    c = conn.cursor()
    c.execute("DELETE FROM room_items WHERE id=?", (item_id,))
    conn.commit()
    deleted = c.rowcount
    conn.close()
    return bool(deleted)

def send_reset_email(to_email: str, code: str) -> bool:
    """
    Отправка 6-значного кода на email.
    Если SMTP_HOST пустой — просто печатает код в консоль и возвращает False.
    """
    if not SMTP_HOST:
        print("[auth_system] SMTP not configured — reset code:", code)
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = "Ваш код для сброса пароля — SmartHome"
        msg["From"] = f"SmartHome Security <{SMTP_USER}>"
        msg["To"] = to_email

        msg.set_content(
            f"Здравствуйте!\n\n"
            f"Вы запросили сброс пароля в системе SmartHome.\n\n"
            f"Ваш код подтверждения:\n"
            f"🔐 {code}\n\n"
            f"Код действует ограниченное время.\n\n"
            f"Если вы не отправляли запрос — проигнорируйте это письмо.\n\n"
            f"С уважением,\n"
            f"SmartHome Security"
        )

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
            <div style="max-width: 420px; margin:auto; background:white; padding:25px;
                        border-radius:12px; box-shadow:0 4px 14px rgba(0,0,0,0.12);">

                <h2 style="text-align:center; color:#333; margin-bottom: 6px;">
                    🏠 SmartHome — Сброс пароля
                </h2>

                <p style="font-size: 15px; color:#444;">
                    Здравствуйте!<br><br>
                    Вы запросили сброс пароля для вашей учётной записи SmartHome.
                </p>

                <div style="text-align:center; margin: 28px 0;">
                    <div style="display:inline-block; background:#2c7efc; color:white; padding:14px 24px;
                                border-radius:10px; font-size:26px; font-weight:bold;">
                        {code}
                    </div>
                </div>

                <p style="font-size: 14px; color:#555;">
                    Код действует ограниченное время.
                    Если запрос сделали не вы — просто проигнорируйте письмо.
                </p>

                <hr style="margin-top: 25px; opacity:0.25;">

                <p style="text-align:center; font-size:13px; color:#888;">
                    SmartHome Security System<br>
                    Это сообщение отправлено автоматически.
                </p>
            </div>
        </body>
        </html>
        """
        def delete_room_item(item_id: int):
            conn = _connect()
            c = conn.cursor()
            try:
                c.execute("DELETE FROM room_items WHERE id=?", (item_id,))
                conn.commit()
                conn.close()
                return True
            except:
                conn.close()
                return False

        msg.add_alternative(html, subtype="html")

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print("[auth_system] send_reset_email error:", e)
        return False
