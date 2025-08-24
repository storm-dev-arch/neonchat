# main.py
import time
import random
import string
from datetime import datetime, timedelta
from typing import Dict, Any, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, constr
from jose import jwt, JWTError

APP_NAME = "NeonChat"
JWT_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
JWT_ALG = "HS256"
OTP_TTL_SECONDS = 300

app = FastAPI(title=APP_NAME)

# CORS (если откроешь из другого домена)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# In-memory "БД"
users: Dict[str, Dict[str, Any]] = {}          # phone -> {id, phone, created_at}
otps: Dict[str, Dict[str, Any]] = {}           # phone -> {code, expires}
connections: Dict[str, WebSocket] = {}         # user_id -> websocket
messages: List[Dict[str, Any]] = []            # simple timeline

# Модели
PhoneStr = constr(strip_whitespace=True, min_length=8, max_length=20)

class SendOTP(BaseModel):
    phone: PhoneStr

class VerifyOTP(BaseModel):
    phone: PhoneStr
    code: constr(min_length=4, max_length=8)

class MessageIn(BaseModel):
    text: constr(min_length=1, max_length=2000)

def gen_user_id() -> str:
    return "u_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))

def gen_otp() -> str:
    # Для демо можно вернуть "123456", чтобы упростить тест.
    return "123456"
    # Для реального кода:
    # return "".join(random.choices(string.digits, k=6))

def issue_token(user: Dict[str, Any]) -> str:
    payload = {
        "sub": user["id"],
        "phone": user["phone"],
        "exp": datetime.utcnow() + timedelta(days=7),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_token(token: str) -> Dict[str, Any]:
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid = data.get("sub")
        phone = data.get("phone")
        if not uid or not phone:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"id": uid, "phone": phone}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_auth_user(request: Request) -> Dict[str, Any]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(" ", 1)[1].strip()
    return verify_token(token)

# Страницы
@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse(url="/static/login.html")

@app.get("/api/policy", response_class=FileResponse)
def policy():
    return FileResponse("static/privacy.html")

@app.get("/api/faq", response_class=FileResponse)
def faq():
    return FileResponse("static/faq.html")

# Аутентификация
@app.post("/api/send_otp")
def send_otp(payload: SendOTP):
    phone = payload.phone
    code = gen_otp()
    otps[phone] = {
        "code": code,
        "expires": time.time() + OTP_TTL_SECONDS
    }
    # Интеграцию с SMS-провайдером (Twilio / Vonage) добавишь тут.
    # Для демо вернём код явно:
    return {"ok": True, "dev_otp": code, "ttl": OTP_TTL_SECONDS}

@app.post("/api/verify_otp")
def verify_otp(payload: VerifyOTP):
    phone = payload.phone
    record = otps.get(phone)
    if not record:
        raise HTTPException(status_code=400, detail="No OTP requested")
    if time.time() > record["expires"]:
        raise HTTPException(status_code=400, detail="OTP expired")
    if payload.code != record["code"]:
        raise HTTPException(status_code=400, detail="Invalid code")

    # Создаём пользователя при первом входе
    if phone not in users:
        users[phone] = {
            "id": gen_user_id(),
            "phone": phone,
            "created_at": datetime.utcnow().isoformat()
        }
    user = users[phone]
    token = issue_token(user)
    return {"ok": True, "token": token, "user": {"id": user["id"], "phone": user["phone"]}}

@app.get("/api/me")
def me(user=Depends(get_auth_user)):
    return {"ok": True, "user": user}

# WebSocket чат (общая комната)
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    # Авторизация через query: /ws?token=...
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=4401)
        return
    try:
        user = verify_token(token)
    except HTTPException:
        await ws.close(code=4401)
        return

    uid = user["id"]
    await ws.accept()
    connections[uid] = ws

    # Отправим историю (последние 50)
    recent = messages[-50:]
    await ws.send_json({"type": "history", "messages": recent})

    try:
        while True:
            data = await ws.receive_json()
            if data.get("type") == "message":
                text = data.get("text", "").strip()
                if not text:
                    continue
                msg = {
                    "id": "m_" + "".join(random.choices(string.ascii_letters + string.digits, k=10)),
                    "sender_id": uid,
                    "sender": user["phone"],
                    "text": text,
                    "ts": datetime.utcnow().isoformat()
                }
                messages.append(msg)
                # Broadcast
                dead = []
                for cid, conn in connections.items():
                    try:
                        await conn.send_json({"type": "message", "message": msg})
                    except Exception:
                        dead.append(cid)
                for cid in dead:
                    connections.pop(cid, None)
            else:
                # Игнора неизвестных типов
                pass
    except WebSocketDisconnect:
        pass
    finally:
        connections.pop(uid, None)
