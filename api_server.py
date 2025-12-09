from flask import Flask, request, jsonify
from auth_system import (
    init_db,
    register_user,
    login_user,
    get_user_by_username,
    get_user_by_email,
    create_password_reset_token,
    reset_password,
    get_rooms_for_user,
    get_room_items,
    create_room,
    delete_room,
    add_room_item,
    delete_room_item,
)
from tg_backend import broadcast_json

app = Flask(__name__)

init_db()

@app.post("/api/login")
def api_login():
    """
    Вход пользователя.
    body: { "username": "...", "password": "..." }
    resp: { ok, msg?, user? }
    """
    d = request.json or {}
    username = d.get("username", "").strip()
    password = d.get("password", "").strip()

    if not username or not password:
        return jsonify({"ok": False, "msg": "Введите логин и пароль"}), 400

    ok, role_or_msg = login_user(username, password)
    if not ok:
        return jsonify({"ok": False, "msg": role_or_msg}), 401

    user = get_user_by_username(username)
    return jsonify({"ok": True, "user": user})


@app.post("/api/register")
def api_register():
    """
    Регистрация пользователя.
    body: { "username", "email", "password", "master_key"? }
    resp: { ok, msg, user? }
    """
    d = request.json or {}
    username = d.get("username", "")
    email = d.get("email", "")
    password = d.get("password", "")
    master_key = d.get("master_key")

    ok, msg = register_user(username, email, password, master_key)
    if not ok:
        return jsonify({"ok": False, "msg": msg}), 400

    user = get_user_by_username(username)
    return jsonify({"ok": True, "msg": msg, "user": user})


@app.post("/api/reset_request")
def api_reset_request():
    """
    Запрос на сброс пароля.
    body: { "email": "..." }
    resp: { ok, msg }
    """
    d = request.json or {}
    email = d.get("email", "").strip()
    if not email:
        return jsonify({"ok": False, "msg": "Укажите email"}), 400

    ok, msg = create_password_reset_token(email)
    status = 200 if ok else 400
    return jsonify({"ok": ok, "msg": msg}), status


@app.post("/api/reset_confirm")
def api_reset_confirm():
    """
    Подтверждение сброса пароля.
    body: { "email": "...", "code": "...", "new_password": "..." }
    resp: { ok, msg }
    """
    d = request.json or {}
    email = d.get("email", "").strip()
    code = d.get("code", "").strip()
    new_password = d.get("new_password", "").strip()

    if not (email and code and new_password):
        return jsonify({"ok": False, "msg": "Заполните все поля"}), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({"ok": False, "msg": "Пользователь не найден"}), 404

    ok, msg = reset_password(user["username"], code, new_password)
    status = 200 if ok else 400
    return jsonify({"ok": ok, "msg": msg}), status

@app.post("/api/rooms")
def api_rooms():
    """
    Список комнат пользователя.
    body: { "user_id": int }
    resp: { rooms: [ {id, name, devices_count} ] }
    """
    d = request.json or {}
    user_id = d.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "msg": "user_id обязателен"}), 400

    rooms = get_rooms_for_user(user_id)
    result = []
    for r in rooms:
        items = get_room_items(r["id"])
        result.append({
            "id": r["id"],
            "name": r["name"],
            "created_at": r["created_at"],
            "devices_count": len(items),
        })
    return jsonify({"ok": True, "rooms": result})


@app.post("/api/create_room")
def api_create_room():
    """
    Создание комнаты.
    body: { "user_id": int, "name": "Bedroom" }
    resp: { ok, msg, room_id? }
    """
    d = request.json or {}
    user_id = d.get("user_id")
    name = d.get("name", "")

    if not user_id or not name:
        return jsonify({"ok": False, "msg": "user_id и name обязательны"}), 400

    ok, room_id, msg = create_room(int(user_id), name)
    status = 200 if ok else 400
    return jsonify({"ok": ok, "msg": msg, "room_id": room_id}), status


@app.post("/api/delete_room")
def api_delete_room():
    """
    Удаление комнаты.
    body: { "user_id": int, "room_id": int }
    resp: { ok, msg }
    """
    d = request.json or {}
    user_id = d.get("user_id")
    room_id = d.get("room_id")

    if not user_id or not room_id:
        return jsonify({"ok": False, "msg": "user_id и room_id обязательны"}), 400

    ok, msg = delete_room(int(user_id), int(room_id))
    status = 200 if ok else 400
    return jsonify({"ok": ok, "msg": msg}), status


@app.post("/api/room_items")
def api_room_items():
    """
    Список устройств в комнате.
    body: { "room_id": int }
    resp: { items: [ {id, kind, label, created_at} ] }
    """
    d = request.json or {}
    room_id = d.get("room_id")
    if not room_id:
        return jsonify({"ok": False, "msg": "room_id обязателен"}), 400

    items = get_room_items(int(room_id))
    return jsonify({"ok": True, "items": items})


@app.post("/api/add_device")
def api_add_device():
    """
    Добавить устройство в комнату.
    body: { "room_id": int, "kind": "Light", "label": "Лампа у кровати" }
    resp: { ok, msg }
    """
    d = request.json or {}
    room_id = d.get("room_id")
    kind = d.get("kind", "")
    label = d.get("label", "")

    if not room_id or not kind or not label:
        return jsonify({"ok": False, "msg": "room_id, kind и label обязательны"}), 400

    ok, msg = add_room_item(int(room_id), kind, label)
    status = 200 if ok else 400
    return jsonify({"ok": ok, "msg": msg}), status


@app.post("/api/delete_device")
def api_delete_device():
    """
    Удалить устройство из комнаты.
    body: { "item_id": int }
    resp: { ok, msg }
    """
    d = request.json or {}
    item_id = d.get("item_id")
    if not item_id:
        return jsonify({"ok": False, "msg": "item_id обязателен"}), 400

    ok = delete_room_item(int(item_id))
    if not ok:
        return jsonify({"ok": False, "msg": "Не удалось удалить устройство"}), 400
    return jsonify({"ok": True, "msg": "Устройство удалено"})

@app.post("/api/action")
def api_action():
    """
    Отправка команды устройству.
    body: любой payload, который ты собираешь на фронте, например:
      {
        "user": "alex",
        "room": "Bedroom",
        "device": "Лампа у кровати",
        "kind": "light",
        "action": "on"
      }

    На выход через broadcast_json летит:
      { "type": "device_action", ... }
    """
    d = request.json or {}
    payload = {
        "type": "device_action",
        **d,
    }

    try:
        broadcast_json(payload)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "msg": f"Ошибка отправки команды: {e}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
