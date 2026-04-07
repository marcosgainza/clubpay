"""
ClubPay — Pasarela de Pago Crypto
Gateway de pagos con criptomonedas. Sin intermediarios.
Los pagos van a la wallet de ClubPay, se descuenta el 1.5% de comisión,
y el comercio puede retirar su saldo cuando quiera.

Endpoints públicos:
  GET  /                            → info
  GET  /checkout/{id}               → página de pago
  GET  /v1/payments/{id}/public     → estado de pago (sin auth)

Endpoints comercio:
  POST /v1/auth/register            → registrar comercio
  POST /v1/auth/login               → login
  GET  /v1/merchant/me              → datos del comercio
  POST /v1/merchant/wallets         → configurar wallet de retiro
  POST /v1/payments/create          → crear cobro
  GET  /v1/payments/{id}            → detalle de pago
  GET  /v1/payments                 → listar pagos
  GET  /v1/merchant/balance         → saldo disponible
  POST /v1/merchant/withdraw        → solicitar retiro
  GET  /dashboard                   → panel del comercio

Endpoints admin (dueño):
  GET  /admin                       → panel admin
  GET  /v1/admin/stats              → estadísticas globales
  GET  /v1/admin/merchants          → listar comercios
  GET  /v1/admin/payments           → todos los pagos
  GET  /v1/admin/withdrawals        → solicitudes de retiro
  POST /v1/admin/withdrawals/{id}/approve → aprobar retiro
  POST /v1/admin/withdrawals/{id}/reject  → rechazar retiro
"""

import math
import os
import time
import secrets
import sqlite3
import hashlib
import threading
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, HTTPException, Header, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

try:
    import requests as req
except ImportError:
    raise ImportError("pip install requests")

# ════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════
BASE_URL = os.getenv("BASE_URL", "http://localhost:8001")
DB_PATH = os.getenv("DB_PATH", "./clubpay.db")
CLUBPAY_FEE = float(os.getenv("CLUBPAY_FEE", "1.5"))  # porcentaje

# WALLETS DE CLUBPAY — acá llegan TODOS los pagos
CLUBPAY_WALLET_USDT = os.getenv("CLUBPAY_WALLET_USDT", "")  # TRC-20
CLUBPAY_WALLET_BTC = os.getenv("CLUBPAY_WALLET_BTC", "")

# Admin credentials
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

# APIs blockchain
TRONGRID_URL = "https://api.trongrid.io"
BLOCKSTREAM_URL = "https://blockstream.info/api"
COINGECKO_URL = "https://api.coingecko.com/api/v3"
CHECK_INTERVAL = 30

# Cache de precios
PRICES = {"btc_usd": None, "usdt_usd": 1.0, "blue_ars": None, "oficial_ars": None, "last_update": None}

app = FastAPI(
    title="ClubPay — Pasarela Crypto",
    description="Gateway de pagos crypto. Comisión 1.5%. Sin intermediarios.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ════════════════════════════════════════════
# DATABASE
# ════════════════════════════════════════════
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS merchants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            business_name TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            api_secret TEXT UNIQUE NOT NULL,
            wallet_usdt_trc20 TEXT DEFAULT '',
            wallet_btc TEXT DEFAULT '',
            webhook_url TEXT DEFAULT '',
            balance_usd REAL DEFAULT 0,
            total_received_usd REAL DEFAULT 0,
            total_fees_usd REAL DEFAULT 0,
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            merchant_id INTEGER NOT NULL,
            amount_usd REAL NOT NULL,
            amount_ars REAL DEFAULT 0,
            fee_usd REAL DEFAULT 0,
            net_usd REAL DEFAULT 0,
            amount_crypto REAL,
            crypto TEXT NOT NULL,
            description TEXT DEFAULT '',
            customer_email TEXT DEFAULT '',
            clubpay_wallet TEXT NOT NULL,
            expected_amount TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            tx_hash TEXT DEFAULT '',
            paid_at TEXT DEFAULT '',
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            webhook_sent INTEGER DEFAULT 0,
            metadata TEXT DEFAULT '{}',
            FOREIGN KEY (merchant_id) REFERENCES merchants(id)
        );

        CREATE TABLE IF NOT EXISTS withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            merchant_id INTEGER NOT NULL,
            amount_usd REAL NOT NULL,
            crypto TEXT NOT NULL,
            destination_wallet TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            tx_hash TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            processed_at TEXT DEFAULT '',
            FOREIGN KEY (merchant_id) REFERENCES merchants(id)
        );
    """)
    db.commit()

    # Auto-migrate: agregar columnas si no existen
    migrations = [
        ("payments", "fee_usd", "REAL DEFAULT 0"),
        ("payments", "net_usd", "REAL DEFAULT 0"),
        ("payments", "amount_ars", "REAL DEFAULT 0"),
    ]
    for table, col, col_type in migrations:
        try:
            db.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            db.commit()
        except Exception:
            pass  # columna ya existe

    db.close()


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


init_db()


# ════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def gen_api_key():
    return f"cpk_{secrets.token_hex(20)}"


def gen_api_secret():
    return f"cps_{secrets.token_hex(24)}"


def gen_payment_id():
    return f"pay_{secrets.token_hex(12)}"


def verify_merchant(api_key):
    db = get_db()
    m = db.execute("SELECT * FROM merchants WHERE api_key = ? AND active = 1", (api_key,)).fetchone()
    db.close()
    if not m:
        raise HTTPException(401, "API key inválida")
    return dict(m)


def get_api_key(authorization: str = Header(default=None)):
    if not authorization:
        raise HTTPException(401, "Header: Authorization: Bearer <api_key>")
    return authorization.replace("Bearer ", "").strip()


def verify_admin(authorization: str = Header(default=None)):
    if not authorization:
        raise HTTPException(401, "Admin auth required")
    key = authorization.replace("Bearer ", "").strip()
    if key != ADMIN_PASSWORD:
        raise HTTPException(403, "Credenciales admin incorrectas")
    return True


class AdminLoginReq(BaseModel):
    email: str
    password: str


# ════════════════════════════════════════════
# PRECIOS
# ════════════════════════════════════════════
def fetch_prices():
    try:
        r = req.get(f"{COINGECKO_URL}/simple/price?ids=bitcoin&vs_currencies=usd", timeout=10)
        PRICES["btc_usd"] = r.json()["bitcoin"]["usd"]
    except Exception:
        pass
    try:
        r = req.get("https://api.bluelytics.com.ar/v2/latest", timeout=10)
        d = r.json()
        PRICES["blue_ars"] = d["blue"]["value_sell"]
        PRICES["oficial_ars"] = d["oficial"]["value_sell"]
    except Exception:
        pass
    PRICES["last_update"] = datetime.now(timezone.utc).isoformat()


def usd_to_ars(usd):
    if PRICES["blue_ars"]:
        return round(usd * PRICES["blue_ars"], 2)
    return 0


def ars_to_usd(ars):
    if PRICES["blue_ars"] and PRICES["blue_ars"] > 0:
        return round(ars / PRICES["blue_ars"], 2)
    return 0


def ars_to_crypto(amount_ars, crypto):
    """Convierte pesos argentinos a crypto usando dólar blue."""
    usd = ars_to_usd(amount_ars)
    if usd <= 0:
        raise HTTPException(503, "No se pudo obtener cotización del dólar blue")
    if crypto == "usdt_trc20":
        unique = secrets.randbelow(99) + 1
        return round(usd + unique / 10000, 4)
    elif crypto == "btc":
        if not PRICES["btc_usd"]:
            fetch_prices()
        if not PRICES["btc_usd"]:
            raise HTTPException(503, "No se pudo obtener precio de BTC")
        btc = usd / PRICES["btc_usd"]
        unique = secrets.randbelow(999) + 1
        return round(btc + unique / 100000000, 8)
    raise HTTPException(400, "Crypto no soportada. Usar: usdt_trc20, btc")


# ════════════════════════════════════════════
# MODELOS
# ════════════════════════════════════════════
class RegisterReq(BaseModel):
    email: str
    password: str
    business_name: str

class LoginReq(BaseModel):
    email: str
    password: str

class WalletReq(BaseModel):
    wallet_usdt_trc20: Optional[str] = ""
    wallet_btc: Optional[str] = ""
    webhook_url: Optional[str] = ""

class PaymentReq(BaseModel):
    amount_ars: float
    crypto: str
    description: Optional[str] = ""
    customer_email: Optional[str] = ""
    metadata: Optional[str] = "{}"

class WithdrawReq(BaseModel):
    amount_ars: float
    crypto: str  # a qué crypto quiere retirar


# ════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════
@app.post("/v1/auth/register")
def register(data: RegisterReq):
    if len(data.password) < 6:
        raise HTTPException(400, "Password mínimo 6 caracteres")
    api_key = gen_api_key()
    api_secret = gen_api_secret()
    db = get_db()
    try:
        db.execute(
            """INSERT INTO merchants (email, password_hash, business_name, api_key, api_secret, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (data.email.lower().strip(), hash_pw(data.password), data.business_name.strip(),
             api_key, api_secret, datetime.now(timezone.utc).isoformat()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        raise HTTPException(409, "Email ya registrado")
    db.close()
    return {
        "message": "Comercio registrado",
        "api_key": api_key,
        "api_secret": api_secret,
        "important": "Guardá tu api_secret, no se puede recuperar.",
    }


@app.post("/v1/auth/login")
def login(data: LoginReq):
    db = get_db()
    m = db.execute("SELECT * FROM merchants WHERE email = ?", (data.email.lower().strip(),)).fetchone()
    db.close()
    if not m or m["password_hash"] != hash_pw(data.password):
        raise HTTPException(401, "Email o password incorrectos")
    return {"message": "Login exitoso", "api_key": m["api_key"], "business_name": m["business_name"]}


# ════════════════════════════════════════════
# MERCHANT
# ════════════════════════════════════════════
@app.get("/v1/merchant/me")
def merchant_me(authorization: str = Header(default=None)):
    m = verify_merchant(get_api_key(authorization))
    return {
        "id": m["id"], "email": m["email"], "business_name": m["business_name"],
        "wallet_usdt_trc20": m["wallet_usdt_trc20"], "wallet_btc": m["wallet_btc"],
        "webhook_url": m["webhook_url"],
        "balance_usd": round(m["balance_usd"], 2),
        "balance_ars": usd_to_ars(m["balance_usd"]),
        "total_received_usd": round(m["total_received_usd"], 2),
        "total_received_ars": usd_to_ars(m["total_received_usd"]),
        "total_fees_usd": round(m["total_fees_usd"], 2),
    }


@app.post("/v1/merchant/wallets")
def update_wallets(data: WalletReq, authorization: str = Header(default=None)):
    m = verify_merchant(get_api_key(authorization))
    db = get_db()
    db.execute(
        "UPDATE merchants SET wallet_usdt_trc20=?, wallet_btc=?, webhook_url=? WHERE id=?",
        (data.wallet_usdt_trc20 or m["wallet_usdt_trc20"],
         data.wallet_btc or m["wallet_btc"],
         data.webhook_url or m["webhook_url"], m["id"]),
    )
    db.commit()
    db.close()
    return {"message": "Wallets actualizadas"}


@app.get("/v1/merchant/balance")
def merchant_balance(authorization: str = Header(default=None)):
    m = verify_merchant(get_api_key(authorization))
    return {
        "balance_usd": round(m["balance_usd"], 2),
        "balance_ars": usd_to_ars(m["balance_usd"]),
        "total_received_usd": round(m["total_received_usd"], 2),
        "total_received_ars": usd_to_ars(m["total_received_usd"]),
        "total_fees_usd": round(m["total_fees_usd"], 2),
        "total_fees_ars": usd_to_ars(m["total_fees_usd"]),
        "fee_percent": CLUBPAY_FEE,
        "blue_ars": PRICES["blue_ars"],
    }


@app.post("/v1/merchant/withdraw")
def request_withdrawal(data: WithdrawReq, authorization: str = Header(default=None)):
    m = verify_merchant(get_api_key(authorization))
    amount_usd = ars_to_usd(data.amount_ars)
    if data.amount_ars <= 0:
        raise HTTPException(400, "Monto debe ser mayor a 0")
    if amount_usd > m["balance_usd"]:
        raise HTTPException(400, f"Saldo insuficiente. Tenés ${usd_to_ars(m['balance_usd']):,.0f} ARS")
    if data.crypto == "usdt_trc20" and not m["wallet_usdt_trc20"]:
        raise HTTPException(400, "Configurá tu wallet USDT primero")
    if data.crypto == "btc" and not m["wallet_btc"]:
        raise HTTPException(400, "Configurá tu wallet BTC primero")

    dest = m["wallet_usdt_trc20"] if data.crypto == "usdt_trc20" else m["wallet_btc"]

    db = get_db()
    db.execute("UPDATE merchants SET balance_usd = balance_usd - ? WHERE id = ?", (amount_usd, m["id"]))
    db.execute(
        """INSERT INTO withdrawals (merchant_id, amount_usd, crypto, destination_wallet, created_at)
        VALUES (?, ?, ?, ?, ?)""",
        (m["id"], amount_usd, data.crypto, dest, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    db.close()
    return {
        "message": "Retiro solicitado. Se procesará en las próximas horas.",
        "amount_ars": data.amount_ars,
        "amount_usd": amount_usd,
        "crypto": data.crypto,
        "destination": dest,
    }


# ════════════════════════════════════════════
# PAYMENTS
# ════════════════════════════════════════════
@app.post("/v1/payments/create")
def create_payment(data: PaymentReq, authorization: str = Header(default=None)):
    m = verify_merchant(get_api_key(authorization))
    if data.amount_ars <= 0:
        raise HTTPException(400, "Monto debe ser mayor a 0")

    if data.crypto == "usdt_trc20" and not CLUBPAY_WALLET_USDT:
        raise HTTPException(503, "ClubPay USDT wallet no configurada")
    if data.crypto == "btc" and not CLUBPAY_WALLET_BTC:
        raise HTTPException(503, "ClubPay BTC wallet no configurada")

    wallet = CLUBPAY_WALLET_USDT if data.crypto == "usdt_trc20" else CLUBPAY_WALLET_BTC
    amount_usd = ars_to_usd(data.amount_ars)
    amount_crypto = ars_to_crypto(data.amount_ars, data.crypto)
    fee_ars = round(data.amount_ars * CLUBPAY_FEE / 100, 2)
    fee_usd = round(amount_usd * CLUBPAY_FEE / 100, 2)
    net_ars = round(data.amount_ars - fee_ars, 2)
    net_usd = round(amount_usd - fee_usd, 2)
    pid = gen_payment_id()

    db = get_db()
    db.execute(
        """INSERT INTO payments
        (id, merchant_id, amount_usd, amount_ars, fee_usd, net_usd, amount_crypto, crypto,
         description, customer_email, clubpay_wallet, expected_amount, expires_at, created_at, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (pid, m["id"], amount_usd, data.amount_ars, fee_usd, net_usd,
         amount_crypto, data.crypto, data.description, data.customer_email,
         wallet, str(amount_crypto),
         (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
         datetime.now(timezone.utc).isoformat(), data.metadata),
    )
    db.commit()
    db.close()

    return {
        "payment_id": pid,
        "status": "pending",
        "amount_ars": data.amount_ars,
        "amount_usd": amount_usd,
        "fee_ars": fee_ars,
        "fee_usd": fee_usd,
        "net_ars": net_ars,
        "net_usd": net_usd,
        "amount_crypto": amount_crypto,
        "crypto": data.crypto,
        "wallet_address": wallet,
        "checkout_url": f"{BASE_URL}/checkout/{pid}",
        "expires_in_minutes": 30,
        "blue_rate": PRICES["blue_ars"],
    }


@app.get("/v1/payments/{payment_id}")
def get_payment(payment_id: str, authorization: str = Header(default=None)):
    m = verify_merchant(get_api_key(authorization))
    db = get_db()
    p = db.execute("SELECT * FROM payments WHERE id=? AND merchant_id=?", (payment_id, m["id"])).fetchone()
    db.close()
    if not p:
        raise HTTPException(404, "Pago no encontrado")
    return dict(p)


@app.get("/v1/payments")
def list_payments(authorization: str = Header(default=None), status: Optional[str] = None, limit: int = Query(default=50, le=200)):
    m = verify_merchant(get_api_key(authorization))
    db = get_db()
    if status:
        rows = db.execute("SELECT * FROM payments WHERE merchant_id=? AND status=? ORDER BY created_at DESC LIMIT ?",
                          (m["id"], status, limit)).fetchall()
    else:
        rows = db.execute("SELECT * FROM payments WHERE merchant_id=? ORDER BY created_at DESC LIMIT ?",
                          (m["id"], limit)).fetchall()
    db.close()
    return {"payments": [dict(r) for r in rows], "count": len(rows)}


@app.get("/v1/payments/{payment_id}/public")
def get_payment_public(payment_id: str):
    db = get_db()
    p = db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
    if not p:
        db.close()
        raise HTTPException(404, "Pago no encontrado")
    m = db.execute("SELECT business_name FROM merchants WHERE id=?", (p["merchant_id"],)).fetchone()
    db.close()
    return {
        "id": p["id"], "amount_usd": p["amount_usd"], "amount_ars": p["amount_ars"],
        "amount_crypto": p["amount_crypto"], "crypto": p["crypto"],
        "description": p["description"], "merchant_wallet": p["clubpay_wallet"],
        "status": p["status"], "expires_at": p["expires_at"], "tx_hash": p["tx_hash"],
        "business_name": m["business_name"] if m else "",
    }


# ════════════════════════════════════════════
# ADMIN ENDPOINTS
# ════════════════════════════════════════════
@app.post("/v1/admin/login")
def admin_login(data: AdminLoginReq):
    if data.email.lower().strip() != ADMIN_EMAIL.lower():
        raise HTTPException(401, "Email o password incorrectos")
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(401, "Email o password incorrectos")
    return {"message": "Admin login exitoso", "token": ADMIN_PASSWORD}


@app.get("/v1/admin/stats")
def admin_stats(authorization: str = Header(default=None)):
    verify_admin(authorization)
    db = get_db()
    total_merchants = db.execute("SELECT COUNT(*) as c FROM merchants").fetchone()["c"]
    total_payments = db.execute("SELECT COUNT(*) as c FROM payments").fetchone()["c"]
    confirmed = db.execute("SELECT COUNT(*) as c FROM payments WHERE status='confirmed'").fetchone()["c"]
    pending = db.execute("SELECT COUNT(*) as c FROM payments WHERE status='pending'").fetchone()["c"]

    vol = db.execute("SELECT COALESCE(SUM(amount_usd),0) as v FROM payments WHERE status='confirmed'").fetchone()["v"]
    fees = db.execute("SELECT COALESCE(SUM(fee_usd),0) as f FROM payments WHERE status='confirmed'").fetchone()["f"]
    pending_withdrawals = db.execute("SELECT COUNT(*) as c FROM withdrawals WHERE status='pending'").fetchone()["c"]
    db.close()
    return {
        "total_merchants": total_merchants,
        "total_payments": total_payments,
        "confirmed_payments": confirmed,
        "pending_payments": pending,
        "volume_usd": round(vol, 2),
        "volume_ars": usd_to_ars(vol),
        "total_fees_usd": round(fees, 2),
        "total_fees_ars": usd_to_ars(fees),
        "pending_withdrawals": pending_withdrawals,
        "fee_percent": CLUBPAY_FEE,
        "blue_ars": PRICES["blue_ars"],
        "btc_usd": PRICES["btc_usd"],
    }


@app.get("/v1/admin/merchants")
def admin_merchants(authorization: str = Header(default=None)):
    verify_admin(authorization)
    db = get_db()
    rows = db.execute("SELECT id, email, business_name, balance_usd, total_received_usd, total_fees_usd, created_at, active FROM merchants ORDER BY created_at DESC").fetchall()
    db.close()
    return {"merchants": [dict(r) for r in rows]}


@app.get("/v1/admin/payments")
def admin_payments(authorization: str = Header(default=None), limit: int = Query(default=100, le=500)):
    verify_admin(authorization)
    db = get_db()
    rows = db.execute("""
        SELECT p.*, m.business_name FROM payments p
        JOIN merchants m ON p.merchant_id = m.id
        ORDER BY p.created_at DESC LIMIT ?""", (limit,)).fetchall()
    db.close()
    return {"payments": [dict(r) for r in rows]}


@app.get("/v1/admin/withdrawals")
def admin_withdrawals(authorization: str = Header(default=None)):
    verify_admin(authorization)
    db = get_db()
    rows = db.execute("""
        SELECT w.*, m.business_name, m.email FROM withdrawals w
        JOIN merchants m ON w.merchant_id = m.id
        ORDER BY w.created_at DESC""").fetchall()
    db.close()
    return {"withdrawals": [dict(r) for r in rows]}


@app.post("/v1/admin/withdrawals/{wid}/approve")
def approve_withdrawal(wid: int, authorization: str = Header(default=None)):
    verify_admin(authorization)
    db = get_db()
    w = db.execute("SELECT * FROM withdrawals WHERE id=? AND status='pending'", (wid,)).fetchone()
    if not w:
        db.close()
        raise HTTPException(404, "Retiro no encontrado o ya procesado")
    db.execute("UPDATE withdrawals SET status='approved', processed_at=? WHERE id=?",
               (datetime.now(timezone.utc).isoformat(), wid))
    db.commit()
    db.close()
    return {"message": f"Retiro #{wid} aprobado. Enviá {w['amount_usd']} USD en {w['crypto']} a {w['destination_wallet']}"}


@app.post("/v1/admin/withdrawals/{wid}/reject")
def reject_withdrawal(wid: int, authorization: str = Header(default=None)):
    verify_admin(authorization)
    db = get_db()
    w = db.execute("SELECT * FROM withdrawals WHERE id=? AND status='pending'", (wid,)).fetchone()
    if not w:
        db.close()
        raise HTTPException(404, "Retiro no encontrado o ya procesado")
    # Devolver saldo al comercio
    db.execute("UPDATE merchants SET balance_usd = balance_usd + ? WHERE id=?", (w["amount_usd"], w["merchant_id"]))
    db.execute("UPDATE withdrawals SET status='rejected', processed_at=? WHERE id=?",
               (datetime.now(timezone.utc).isoformat(), wid))
    db.commit()
    db.close()
    return {"message": f"Retiro #{wid} rechazado. Saldo devuelto al comercio."}


# ════════════════════════════════════════════
# BLOCKCHAIN MONITORING
# ════════════════════════════════════════════
def check_usdt_trc20(wallet, expected_amount, created_after):
    try:
        usdt_contract = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
        r = req.get(f"{TRONGRID_URL}/v1/accounts/{wallet}/transactions/trc20",
                    params={"only_to": "true", "limit": 20, "contract_address": usdt_contract}, timeout=15)
        for tx in r.json().get("data", []):
            amount = int(tx.get("value", "0")) / 1_000_000
            tx_time = datetime.fromtimestamp(tx.get("block_timestamp", 0) / 1000, tz=timezone.utc)
            if tx_time < datetime.fromisoformat(created_after):
                continue
            if abs(amount - float(expected_amount)) < 0.01:
                return tx.get("transaction_id", "")
    except Exception:
        pass
    return None


def check_btc(wallet, expected_amount, created_after):
    try:
        r = req.get(f"{BLOCKSTREAM_URL}/address/{wallet}/txs", timeout=15)
        for tx in r.json():
            if not tx.get("status", {}).get("confirmed", False):
                continue
            tx_time = datetime.fromtimestamp(tx["status"].get("block_time", 0), tz=timezone.utc)
            if tx_time < datetime.fromisoformat(created_after):
                continue
            total = sum(v.get("value", 0) for v in tx.get("vout", []) if v.get("scriptpubkey_address") == wallet)
            if abs(total / 100_000_000 - float(expected_amount)) < 0.000001:
                return tx.get("txid", "")
    except Exception:
        pass
    return None


def send_webhook(payment, merchant):
    if not merchant["webhook_url"]:
        return
    try:
        req.post(merchant["webhook_url"], json={
            "event": "payment.confirmed",
            "payment_id": payment["id"],
            "amount_usd": payment["amount_usd"],
            "amount_ars": payment["amount_ars"],
            "fee_usd": payment["fee_usd"],
            "net_usd": payment["net_usd"],
            "crypto": payment["crypto"],
            "tx_hash": payment["tx_hash"],
            "status": "confirmed",
        }, headers={"X-ClubPay-Secret": merchant["api_secret"]}, timeout=10)
    except Exception:
        pass


def payment_monitor():
    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            db = get_db()
            pending = db.execute("SELECT * FROM payments WHERE status='pending'").fetchall()
            now = datetime.now(timezone.utc)

            for p in pending:
                payment = dict(p)
                if now > datetime.fromisoformat(payment["expires_at"]):
                    db.execute("UPDATE payments SET status='expired' WHERE id=?", (payment["id"],))
                    db.commit()
                    continue

                tx_hash = None
                if payment["crypto"] == "usdt_trc20":
                    tx_hash = check_usdt_trc20(payment["clubpay_wallet"], payment["expected_amount"], payment["created_at"])
                elif payment["crypto"] == "btc":
                    tx_hash = check_btc(payment["clubpay_wallet"], payment["expected_amount"], payment["created_at"])

                if tx_hash:
                    paid_at = now.isoformat()
                    # Confirmar pago
                    db.execute("UPDATE payments SET status='confirmed', tx_hash=?, paid_at=? WHERE id=?",
                               (tx_hash, paid_at, payment["id"]))
                    # Acreditar saldo al comercio (monto - comisión)
                    db.execute("""UPDATE merchants SET
                        balance_usd = balance_usd + ?,
                        total_received_usd = total_received_usd + ?,
                        total_fees_usd = total_fees_usd + ?
                        WHERE id = ?""",
                               (payment["net_usd"], payment["amount_usd"], payment["fee_usd"], payment["merchant_id"]))
                    db.commit()

                    merchant = db.execute("SELECT * FROM merchants WHERE id=?", (payment["merchant_id"],)).fetchone()
                    if merchant:
                        payment["tx_hash"] = tx_hash
                        send_webhook(payment, dict(merchant))

            db.close()
        except Exception:
            pass
        try:
            fetch_prices()
        except Exception:
            pass


@app.on_event("startup")
def startup():
    fetch_prices()
    threading.Thread(target=payment_monitor, daemon=True).start()


# ════════════════════════════════════════════
# CHECKOUT PAGE
# ════════════════════════════════════════════
CHECKOUT_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#22C55E">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon-192.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon-192.svg">
<title>ClubPay — Pagar</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#09090B;--card:#18181B;--border:#27272A;--white:#FAFAFA;--dim:#A1A1AA;--green:#22C55E;--red:#EF4444;--blue:#3B82F6;--orange:#F59E0B}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--white);font-family:'Inter',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{max-width:480px;width:100%}
.logo{text-align:center;margin-bottom:24px}
.logo-text{font-size:24px;font-weight:800;background:linear-gradient(135deg,var(--green),var(--blue));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.2em;margin-top:4px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:32px;margin-bottom:16px}
.merchant-name{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.15em;margin-bottom:4px}
.description{font-size:14px;margin-bottom:20px}
.amount-box{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;margin-bottom:24px}
.amount-usd{font-size:32px;font-weight:800}
.amount-ars{font-family:'JetBrains Mono',monospace;font-size:14px;color:var(--dim);margin-top:4px}
.amount-crypto{font-family:'JetBrains Mono',monospace;font-size:16px;color:var(--green);margin-top:8px}
.crypto-badge{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--bg);background:var(--green);border-radius:4px;padding:2px 8px;margin-left:8px;vertical-align:middle}
.label{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.15em;margin-bottom:8px}
.wallet-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;font-family:'JetBrains Mono',monospace;font-size:12px;word-break:break-all;cursor:pointer;transition:border-color 0.2s;position:relative}
.wallet-box:hover{border-color:var(--green)}
.wallet-box::after{content:'click para copiar';position:absolute;top:-18px;right:0;font-size:9px;color:var(--dim)}
.qr-box{text-align:center;margin:20px 0}
.qr-box img{width:200px;height:200px;border-radius:8px}
.timer{text-align:center;margin-top:20px}
.timer-label{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.15em}
.timer-value{font-family:'JetBrains Mono',monospace;font-size:24px;font-weight:700;color:var(--orange);margin-top:4px}
.status{text-align:center;padding:16px;border-radius:12px;margin-top:16px;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;letter-spacing:0.1em}
.status.pending{background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);color:var(--orange)}
.status.confirmed{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:var(--green)}
.status.expired{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--red)}
.footer{text-align:center;margin-top:20px;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim)}
.copied{position:fixed;top:20px;left:50%;transform:translateX(-50%);background:var(--green);color:var(--bg);font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;padding:10px 24px;border-radius:8px;opacity:0;transition:opacity 0.3s;pointer-events:none;z-index:100}
.copied.show{opacity:1}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid var(--orange);border-top-color:transparent;border-radius:50%;animation:spin 1s linear infinite;vertical-align:middle;margin-right:8px}
.open-wallet-btn{display:block;text-align:center;background:linear-gradient(135deg,var(--green),var(--blue));color:var(--bg);font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:700;letter-spacing:0.1em;padding:14px 24px;border-radius:12px;text-decoration:none;margin:16px 0;transition:opacity 0.2s}
.open-wallet-btn:hover{opacity:0.85}
.how-to-pay{margin:20px 0;padding:20px;background:var(--bg);border:1px solid var(--border);border-radius:12px}
.pay-methods{display:flex;flex-direction:column;gap:14px}
.pay-method{padding:12px;background:var(--card);border:1px solid var(--border);border-radius:8px}
.pay-method-title{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;color:var(--green);margin-bottom:6px}
.pay-method-desc{font-size:12px;color:var(--dim);line-height:1.6}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
  <div class="logo"><div class="logo-text">ClubPay</div><div class="logo-sub">PASARELA CRYPTO</div></div>
  <div class="card">
    <div class="merchant-name" id="merchantName">CARGANDO...</div>
    <div class="description" id="desc"></div>
    <div class="amount-box">
      <div class="amount-usd" id="amountUsd">$0.00 USD</div>
      <div class="amount-ars" id="amountArs"></div>
      <div class="amount-crypto" id="amountCrypto"><span id="cryptoVal">0</span><span class="crypto-badge" id="cryptoBadge">USDT</span></div>
    </div>
    <div class="label">ENVIAR EXACTAMENTE A ESTA DIRECCION</div>
    <div class="wallet-box" id="walletBox" onclick="copyW()"><span id="walletAddr">...</span></div>
    <div class="qr-box"><a id="qrLink" href="#"><img id="qrImg" src="" alt="QR"></a></div>
    <a id="openWalletBtn" href="#" class="open-wallet-btn">ABRIR BILLETERA Y PAGAR</a>
    <div class="how-to-pay">
      <div class="label">COMO PAGAR</div>
      <div class="pay-methods">
        <div class="pay-method">
          <div class="pay-method-title">Trust Wallet / TronLink</div>
          <div class="pay-method-desc">Escaneá el QR o tocá el botón de arriba</div>
        </div>
        <div class="pay-method">
          <div class="pay-method-title">Binance / Lemon / Otra</div>
          <div class="pay-method-desc">1. Copiá la dirección (tocá arriba)<br>2. Abrí tu app → Enviar → <span id="cryptoNetwork">USDT TRC-20</span><br>3. Pegá la dirección y el monto exacto: <strong id="exactAmount">0</strong></div>
        </div>
      </div>
    </div>
    <div class="timer"><div class="timer-label">EXPIRA EN</div><div class="timer-value" id="timerVal">30:00</div></div>
    <div class="status pending" id="statusBox"><span class="spinner"></span> ESPERANDO PAGO...</div>
  </div>
  <div class="footer">Powered by ClubPay · 0% comisión al comprador</div>
</div>
<div class="copied" id="copied">DIRECCION COPIADA</div>
<script>
var pid=window.location.pathname.split('/').pop(),pd=null;
async function load(){
  try{var r=await fetch('/v1/payments/'+pid+'/public');if(!r.ok)return;pd=await r.json();render();
  if(pd.status==='pending'){setInterval(poll,15000);startTimer()}}catch(e){}}
function render(){
  document.getElementById('merchantName').textContent=pd.business_name||'COMERCIO';
  document.getElementById('desc').textContent=pd.description||'Pago';
  document.getElementById('amountUsd').textContent='$'+(pd.amount_ars||0).toLocaleString('es-AR')+' ARS';
  document.getElementById('amountArs').textContent=pd.amount_usd?'aprox $'+pd.amount_usd.toFixed(2)+' USD (blue)':'';
  document.getElementById('cryptoVal').textContent=pd.amount_crypto;
  document.getElementById('cryptoBadge').textContent=pd.crypto==='usdt_trc20'?'USDT TRC-20':'BTC';
  document.getElementById('walletAddr').textContent=pd.merchant_wallet;
  var qrData=pd.merchant_wallet;
  if(pd.crypto==='btc')qrData='bitcoin:'+pd.merchant_wallet+'?amount='+pd.amount_crypto;
  else if(pd.crypto==='usdt_trc20')qrData='tron:'+pd.merchant_wallet+'?amount='+pd.amount_crypto;
  document.getElementById('qrImg').src='https://api.qrserver.com/v1/create-qr-code/?size=200x200&data='+encodeURIComponent(qrData);
  document.getElementById('qrLink').href=qrData;
  document.getElementById('openWalletBtn').href=qrData;
  document.getElementById('cryptoNetwork').textContent=pd.crypto==='usdt_trc20'?'USDT (red TRC-20)':'BTC';
  document.getElementById('exactAmount').textContent=pd.amount_crypto+' '+(pd.crypto==='usdt_trc20'?'USDT':'BTC');
  updStatus(pd.status)}
function updStatus(s){var b=document.getElementById('statusBox');
  if(s==='confirmed'){b.className='status confirmed';b.innerHTML='PAGO CONFIRMADO'}
  else if(s==='expired'){b.className='status expired';b.innerHTML='PAGO EXPIRADO'}
  else{b.className='status pending';b.innerHTML='<span class="spinner"></span> ESPERANDO PAGO...'}}
async function poll(){try{var r=await fetch('/v1/payments/'+pid+'/public');if(r.ok){var d=await r.json();if(d.status!=='pending'){pd=d;updStatus(d.status)}}}catch(e){}}
function startTimer(){var exp=new Date(pd.expires_at).getTime();setInterval(function(){var d=exp-Date.now();if(d<=0){document.getElementById('timerVal').textContent='00:00';updStatus('expired');return}
  var m=Math.floor(d/60000),s=Math.floor((d%60000)/1000);document.getElementById('timerVal').textContent=String(m).padStart(2,'0')+':'+String(s).padStart(2,'0')},1000)}
function copyW(){if(pd){navigator.clipboard.writeText(pd.merchant_wallet);var e=document.getElementById('copied');e.classList.add('show');setTimeout(function(){e.classList.remove('show')},1500)}}
load();
</script>
<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>
</body>
</html>"""


@app.get("/checkout/{payment_id}", response_class=HTMLResponse)
def checkout_page(payment_id: str):
    db = get_db()
    p = db.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
    db.close()
    if not p:
        raise HTTPException(404, "Pago no encontrado")
    return HTMLResponse(content=CHECKOUT_HTML)


# ════════════════════════════════════════════
# DASHBOARD — COMERCIO
# ════════════════════════════════════════════
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#22C55E">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon-192.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon-192.svg">
<title>ClubPay — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#09090B;--card:#18181B;--border:#27272A;--white:#FAFAFA;--dim:#A1A1AA;--green:#22C55E;--red:#EF4444;--blue:#3B82F6;--orange:#F59E0B;--purple:#A855F7}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--white);font-family:'Inter',sans-serif;min-height:100vh;padding:20px}
.header{max-width:960px;margin:0 auto 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.logo{font-size:24px;font-weight:800;background:linear-gradient(135deg,var(--green),var(--blue));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav{display:flex;gap:6px;flex-wrap:wrap}
.nav button{font-family:'JetBrains Mono',monospace;font-size:10px;background:var(--card);color:var(--dim);border:1px solid var(--border);border-radius:8px;padding:8px 14px;cursor:pointer;transition:all 0.2s}
.nav button:hover,.nav button.active{color:var(--white);border-color:var(--green)}
.container{max-width:960px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:16px}
.card-title{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.2em;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px}
.stat-label{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dim);letter-spacing:0.1em;margin-bottom:6px}
.stat-value{font-size:22px;font-weight:800}
.stat-sub{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);margin-top:2px}
.green{color:var(--green)}.orange{color:var(--orange)}.blue{color:var(--blue)}.red{color:var(--red)}
input,select{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--bg);color:var(--white);border:1px solid var(--border);border-radius:8px;padding:10px 14px;width:100%;margin-bottom:10px;outline:none}
input:focus{border-color:var(--green)}
label{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.1em;display:block;margin-bottom:4px}
.btn{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;background:var(--green);color:var(--bg);border:none;border-radius:8px;padding:12px 24px;cursor:pointer;width:100%;margin-top:8px;transition:opacity 0.2s}
.btn:hover{opacity:0.85}
.btn.secondary{background:var(--blue)}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{font-family:'JetBrains Mono',monospace;font-size:10px;text-align:left;padding:10px;border-bottom:1px solid var(--border)}
.table th{color:var(--dim);font-size:9px;letter-spacing:0.1em}
.badge{font-family:'JetBrains Mono',monospace;font-size:9px;padding:3px 8px;border-radius:4px;font-weight:700}
.badge.confirmed{background:rgba(34,197,94,0.15);color:var(--green)}
.badge.pending{background:rgba(245,158,11,0.15);color:var(--orange)}
.badge.expired{background:rgba(239,68,68,0.15);color:var(--red)}
.section{display:none}.section.active{display:block}
.key-box{font-family:'JetBrains Mono',monospace;font-size:11px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;word-break:break-all;color:var(--green);cursor:pointer;margin-bottom:8px}
.auth-container{max-width:400px;margin:80px auto}
.auth-toggle{text-align:center;margin-top:16px;font-size:12px;color:var(--dim)}
.auth-toggle a{color:var(--green);cursor:pointer;text-decoration:none}
.hidden{display:none}
.msg{font-family:'JetBrains Mono',monospace;font-size:11px;padding:10px;border-radius:8px;margin-bottom:12px;text-align:center}
.msg.error{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--red)}
.msg.success{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:var(--green)}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media(max-width:600px){.two-col{grid-template-columns:1fr}}
</style>
</head>
<body>
<div id="authScreen" class="auth-container">
  <div style="text-align:center;margin-bottom:32px">
    <div class="logo">ClubPay</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.2em;margin-top:4px">DASHBOARD COMERCIO</div>
  </div>
  <div class="card" id="loginForm">
    <div class="card-title">INICIAR SESION</div>
    <div id="loginMsg"></div>
    <label>EMAIL</label><input type="email" id="loginEmail" placeholder="tu@email.com">
    <label>PASSWORD</label><input type="password" id="loginPass" placeholder="••••••" onkeydown="if(event.key==='Enter')doLogin()">
    <button class="btn" onclick="doLogin()">ENTRAR</button>
    <div class="auth-toggle">No tenés cuenta? <a onclick="showReg()">Registrate</a></div>
  </div>
  <div class="card hidden" id="regForm">
    <div class="card-title">REGISTRAR COMERCIO</div>
    <div id="regMsg"></div>
    <label>NOMBRE DEL NEGOCIO</label><input type="text" id="regName" placeholder="Mi Tienda">
    <label>EMAIL</label><input type="email" id="regEmail" placeholder="tu@email.com">
    <label>PASSWORD</label><input type="password" id="regPass" placeholder="mínimo 6 caracteres">
    <button class="btn" onclick="doReg()">CREAR CUENTA</button>
    <div class="auth-toggle">Ya tenés cuenta? <a onclick="showLog()">Iniciá sesión</a></div>
  </div>
</div>

<div id="dashScreen" class="hidden">
  <div class="header">
    <div class="logo">ClubPay</div>
    <div class="nav">
      <button class="active" onclick="showSec('overview',this)">RESUMEN</button>
      <button onclick="showSec('create',this)">NUEVO COBRO</button>
      <button onclick="showSec('payments',this)">PAGOS</button>
      <button onclick="showSec('withdraw',this)">RETIRAR</button>
      <button onclick="showSec('settings',this)">CONFIG</button>
      <button onclick="logout()" style="color:var(--red);border-color:var(--red)">SALIR</button>
    </div>
  </div>
  <div class="container">

    <div class="section active" id="sec-overview">
      <div class="stats">
        <div class="stat"><div class="stat-label">SALDO DISPONIBLE</div><div class="stat-value green" id="sBalanceArs">$0</div><div class="stat-sub" id="sBalance"></div></div>
        <div class="stat"><div class="stat-label">TOTAL RECIBIDO</div><div class="stat-value blue" id="sReceivedArs">$0</div><div class="stat-sub" id="sReceived"></div></div>
        <div class="stat"><div class="stat-label">COMISIONES CLUBPAY</div><div class="stat-value orange" id="sFees">$0</div><div class="stat-sub" id="sFeePct"></div></div>
        <div class="stat"><div class="stat-label">DOLAR BLUE</div><div class="stat-value" id="sBlue" style="color:var(--green)">...</div><div class="stat-sub">ARS por USD</div></div>
      </div>
      <div class="card"><div class="card-title">TU API KEY</div><div class="key-box" id="apiKeyBox" onclick="navigator.clipboard.writeText(AK)">...</div>
      <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim)">Click para copiar · Header: Authorization: Bearer &lt;key&gt;</div></div>
    </div>

    <div class="section" id="sec-create">
      <div class="card"><div class="card-title">CREAR COBRO</div><div id="createMsg"></div>
        <div class="two-col">
          <div><label>MONTO ($ PESOS)</label><input type="number" id="cAmt" placeholder="50000" step="1" min="1"></div>
          <div><label>CRYPTO</label><select id="cCrypto"><option value="usdt_trc20">USDT (TRC-20)</option><option value="btc">Bitcoin (BTC)</option></select></div>
        </div>
        <label>DESCRIPCION (opcional)</label><input type="text" id="cDesc" placeholder="Producto o servicio">
        <label>EMAIL CLIENTE (opcional)</label><input type="email" id="cEmail" placeholder="cliente@email.com">
        <button class="btn" onclick="createPay()">GENERAR COBRO</button>
      </div>
      <div class="card hidden" id="createResult"><div class="card-title">COBRO CREADO</div>
        <label>LINK DE PAGO (compartí con tu cliente)</label>
        <div class="key-box" id="payLink" onclick="navigator.clipboard.writeText(this.textContent)" style="color:var(--blue)">...</div>
        <div class="two-col" style="margin-top:12px">
          <div><div class="stat-label">MONTO</div><div id="payAmt" style="font-size:16px;font-weight:700"></div><div id="payAmtArs" style="font-size:12px;color:var(--dim)"></div></div>
          <div><div class="stat-label">COMISION CLUBPAY</div><div id="payFee" style="font-size:16px;font-weight:700;color:var(--orange)"></div><div id="payNet" style="font-size:12px;color:var(--green)"></div></div>
        </div>
        <button class="btn secondary" onclick="window.open(document.getElementById('payLink').textContent,'_blank')" style="margin-top:16px">ABRIR CHECKOUT</button>
      </div>
    </div>

    <div class="section" id="sec-payments">
      <div class="card"><div class="card-title">HISTORIAL DE PAGOS</div>
        <table class="table"><thead><tr><th>ID</th><th>MONTO ARS</th><th>USD</th><th>CRYPTO</th><th>ESTADO</th><th>FECHA</th></tr></thead>
        <tbody id="payTable"></tbody></table>
      </div>
    </div>

    <div class="section" id="sec-withdraw">
      <div class="card"><div class="card-title">RETIRAR FONDOS</div><div id="wMsg"></div>
        <div class="stat" style="margin-bottom:16px"><div class="stat-label">SALDO DISPONIBLE</div><div class="stat-value green" id="wBalance">$0</div><div class="stat-sub" id="wBalanceArs"></div></div>
        <label>MONTO A RETIRAR ($ PESOS)</label><input type="number" id="wAmt" placeholder="50000" step="1" min="1">
        <label>RETIRAR EN</label><select id="wCrypto"><option value="usdt_trc20">USDT (TRC-20)</option><option value="btc">Bitcoin (BTC)</option></select>
        <button class="btn" onclick="doWithdraw()">SOLICITAR RETIRO</button>
      </div>
    </div>

    <div class="section" id="sec-settings">
      <div class="card"><div class="card-title">WALLETS DE RETIRO — donde recibís cuando retirás</div><div id="setMsg"></div>
        <label>WALLET USDT (TRC-20)</label><input type="text" id="setUsdt" placeholder="T...">
        <label>WALLET BTC</label><input type="text" id="setBtc" placeholder="bc1...">
        <label>WEBHOOK URL (te avisamos cuando te pagan)</label><input type="url" id="setWh" placeholder="https://tu-servidor.com/webhook">
        <button class="btn" onclick="saveSet()">GUARDAR</button>
      </div>
    </div>
  </div>
</div>

<script>
var AK=localStorage.getItem('clubpay_key')||'';
function showReg(){document.getElementById('loginForm').classList.add('hidden');document.getElementById('regForm').classList.remove('hidden')}
function showLog(){document.getElementById('regForm').classList.add('hidden');document.getElementById('loginForm').classList.remove('hidden')}
function msg(id,t,c){document.getElementById(id).innerHTML='<div class="msg '+c+'">'+t+'</div>';setTimeout(function(){document.getElementById(id).innerHTML=''},4000)}
function showSec(n,b){document.querySelectorAll('.section').forEach(function(s){s.classList.remove('active')});document.getElementById('sec-'+n).classList.add('active');document.querySelectorAll('.nav button').forEach(function(x){x.classList.remove('active')});if(b)b.classList.add('active');if(n==='payments')loadPays();if(n==='withdraw')loadBal()}
async function doReg(){
  var n=document.getElementById('regName').value,e=document.getElementById('regEmail').value,p=document.getElementById('regPass').value;
  if(!n||!e||!p){msg('regMsg','Completá todo','error');return}
  var r=await fetch('/v1/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:e,password:p,business_name:n})});
  var d=await r.json();if(!r.ok){msg('regMsg',d.detail,'error');return}
  AK=d.api_key;localStorage.setItem('clubpay_key',AK);
  msg('regMsg','Cuenta creada! API Secret: '+d.api_secret+' — GUARDALO','success');setTimeout(enter,4000)}
async function doLogin(){
  var e=document.getElementById('loginEmail').value,p=document.getElementById('loginPass').value;
  if(!e||!p){msg('loginMsg','Completá todo','error');return}
  var r=await fetch('/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:e,password:p})});
  var d=await r.json();if(!r.ok){msg('loginMsg',d.detail,'error');return}
  AK=d.api_key;localStorage.setItem('clubpay_key',AK);enter()}
function logout(){AK='';localStorage.removeItem('clubpay_key');location.reload()}
async function enter(){
  document.getElementById('authScreen').classList.add('hidden');document.getElementById('dashScreen').classList.remove('hidden');
  document.getElementById('apiKeyBox').textContent=AK;loadBal();loadPays();loadSet()}
async function loadBal(){
  try{var r=await fetch('/v1/merchant/balance',{headers:{'Authorization':'Bearer '+AK}});var d=await r.json();
  document.getElementById('sBalanceArs').textContent='$'+d.balance_ars.toLocaleString('es-AR')+' ARS';
  document.getElementById('sBalance').textContent='aprox $'+d.balance_usd.toFixed(2)+' USD';
  document.getElementById('sReceivedArs').textContent='$'+d.total_received_ars.toLocaleString('es-AR')+' ARS';
  document.getElementById('sReceived').textContent='aprox $'+d.total_received_usd.toFixed(2)+' USD';
  document.getElementById('sFees').textContent='$'+d.total_fees_ars.toLocaleString('es-AR');
  document.getElementById('sFeePct').textContent=d.fee_percent+'% por tx';
  document.getElementById('sBlue').textContent='$'+(d.blue_ars||'...');
  document.getElementById('wBalance').textContent='$'+d.balance_ars.toLocaleString('es-AR')+' ARS';
  document.getElementById('wBalanceArs').textContent='aprox $'+d.balance_usd.toFixed(2)+' USD';
  }catch(e){}}
async function loadPays(){
  try{var r=await fetch('/v1/payments',{headers:{'Authorization':'Bearer '+AK}});var d=await r.json();var h='';
  d.payments.forEach(function(p){h+='<tr><td>'+p.id.slice(0,12)+'</td><td>$'+(p.amount_ars||0).toLocaleString('es-AR')+'</td><td>$'+(p.amount_usd||0).toFixed(2)+'</td><td>'+(p.crypto==='usdt_trc20'?'USDT':'BTC')+'</td><td><span class="badge '+p.status+'">'+p.status.toUpperCase()+'</span></td><td>'+new Date(p.created_at).toLocaleDateString()+'</td></tr>'});
  document.getElementById('payTable').innerHTML=h||'<tr><td colspan="6" style="text-align:center;color:var(--dim)">Sin pagos</td></tr>';}catch(e){}}
async function createPay(){
  var a=parseFloat(document.getElementById('cAmt').value),c=document.getElementById('cCrypto').value,desc=document.getElementById('cDesc').value,em=document.getElementById('cEmail').value;
  if(!a||a<=0){msg('createMsg','Monto invalido','error');return}
  var r=await fetch('/v1/payments/create',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+AK},body:JSON.stringify({amount_ars:a,crypto:c,description:desc,customer_email:em})});
  var d=await r.json();if(!r.ok){msg('createMsg',d.detail,'error');return}
  document.getElementById('createResult').classList.remove('hidden');
  document.getElementById('payLink').textContent=d.checkout_url;
  document.getElementById('payAmt').textContent='$'+d.amount_ars.toLocaleString('es-AR')+' ARS';
  document.getElementById('payAmtArs').textContent='aprox $'+d.amount_usd.toFixed(2)+' USD (blue $'+d.blue_rate+')';
  document.getElementById('payFee').textContent='-$'+d.fee_ars.toLocaleString('es-AR');
  document.getElementById('payNet').textContent='Recibis: $'+d.net_ars.toLocaleString('es-AR')+' ARS';
  loadBal();loadPays()}
async function loadSet(){
  try{var r=await fetch('/v1/merchant/me',{headers:{'Authorization':'Bearer '+AK}});var d=await r.json();
  document.getElementById('setUsdt').value=d.wallet_usdt_trc20||'';document.getElementById('setBtc').value=d.wallet_btc||'';document.getElementById('setWh').value=d.webhook_url||'';}catch(e){}}
async function saveSet(){
  var r=await fetch('/v1/merchant/wallets',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+AK},body:JSON.stringify({wallet_usdt_trc20:document.getElementById('setUsdt').value,wallet_btc:document.getElementById('setBtc').value,webhook_url:document.getElementById('setWh').value})});
  if(r.ok)msg('setMsg','Guardado!','success');else msg('setMsg','Error','error')}
async function doWithdraw(){
  var a=parseFloat(document.getElementById('wAmt').value),c=document.getElementById('wCrypto').value;
  if(!a||a<=0){msg('wMsg','Monto invalido','error');return}
  var r=await fetch('/v1/merchant/withdraw',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+AK},body:JSON.stringify({amount_ars:a,crypto:c})});
  var d=await r.json();if(!r.ok){msg('wMsg',d.detail,'error');return}
  msg('wMsg','Retiro solicitado: $'+a.toLocaleString('es-AR')+' ARS en '+c,'success');loadBal()}
if(AK)enter();
</script>
<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)


# ════════════════════════════════════════════
# ADMIN DASHBOARD
# ════════════════════════════════════════════
ADMIN_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#22C55E">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon-192.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon-192.svg">
<title>ClubPay — Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#09090B;--card:#18181B;--border:#27272A;--white:#FAFAFA;--dim:#A1A1AA;--green:#22C55E;--red:#EF4444;--blue:#3B82F6;--orange:#F59E0B;--purple:#A855F7}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--white);font-family:'Inter',sans-serif;min-height:100vh;padding:20px}
.header{max-width:960px;margin:0 auto 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.logo{font-size:24px;font-weight:800;background:linear-gradient(135deg,var(--orange),var(--red));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.container{max-width:960px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:16px}
.card-title{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.2em;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px}
.stat-label{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dim);letter-spacing:0.1em;margin-bottom:6px}
.stat-value{font-size:22px;font-weight:800}
.stat-sub{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);margin-top:2px}
.green{color:var(--green)}.orange{color:var(--orange)}.blue{color:var(--blue)}.red{color:var(--red)}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{font-family:'JetBrains Mono',monospace;font-size:10px;text-align:left;padding:10px;border-bottom:1px solid var(--border)}
.table th{color:var(--dim);font-size:9px;letter-spacing:0.1em}
.badge{font-family:'JetBrains Mono',monospace;font-size:9px;padding:3px 8px;border-radius:4px;font-weight:700}
.badge.confirmed{background:rgba(34,197,94,0.15);color:var(--green)}
.badge.pending{background:rgba(245,158,11,0.15);color:var(--orange)}
.badge.expired{background:rgba(239,68,68,0.15);color:var(--red)}
.badge.approved{background:rgba(59,130,246,0.15);color:var(--blue)}
.badge.rejected{background:rgba(239,68,68,0.15);color:var(--red)}
input{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--bg);color:var(--white);border:1px solid var(--border);border-radius:8px;padding:10px 14px;width:100%;max-width:300px;outline:none}
.btn{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;margin:2px}
.btn-approve{background:var(--green);color:var(--bg)}
.btn-reject{background:var(--red);color:var(--white)}
.auth-box{max-width:400px;margin:100px auto;text-align:center}
.hidden{display:none}
</style>
</head>
<body>
<div id="authBox" class="auth-box">
  <div class="logo" style="margin-bottom:16px">ClubPay Admin</div>
  <div id="adminMsg" style="margin-bottom:12px"></div>
  <input type="email" id="adminEmail" placeholder="Email admin" style="margin-bottom:10px">
  <br>
  <input type="password" id="adminPass" placeholder="Password" onkeydown="if(event.key==='Enter')adminLogin()">
  <br><br>
  <button class="btn btn-approve" onclick="adminLogin()" style="width:200px;padding:12px">ENTRAR</button>
</div>

<div id="adminDash" class="hidden">
  <div class="header"><div class="logo">ClubPay Admin</div><button class="btn btn-reject" onclick="localStorage.removeItem('clubpay_admin');location.reload()" style="width:auto;padding:8px 16px;font-size:11px">CERRAR SESION</button></div>
  <div class="container">
    <div class="stats" id="adminStats"></div>
    <div class="card"><div class="card-title">RETIROS PENDIENTES</div><table class="table"><thead><tr><th>ID</th><th>COMERCIO</th><th>MONTO</th><th>CRYPTO</th><th>WALLET</th><th>ESTADO</th><th>ACCIONES</th></tr></thead><tbody id="wTable"></tbody></table></div>
    <div class="card"><div class="card-title">ULTIMOS PAGOS</div><table class="table"><thead><tr><th>ID</th><th>COMERCIO</th><th>MONTO ARS</th><th>USD</th><th>COMISION</th><th>ESTADO</th><th>FECHA</th></tr></thead><tbody id="aPayTable"></tbody></table></div>
    <div class="card"><div class="card-title">COMERCIOS</div><table class="table"><thead><tr><th>ID</th><th>NEGOCIO</th><th>EMAIL</th><th>SALDO</th><th>TOTAL RECIBIDO</th><th>FEES GENERADOS</th></tr></thead><tbody id="mTable"></tbody></table></div>
  </div>
</div>

<script>
var AP=localStorage.getItem('clubpay_admin')||'';

async function loadAdmin(){
  try{
    var r=await fetch('/v1/admin/stats',{headers:{'Authorization':'Bearer '+AP}});
    if(!r.ok){localStorage.removeItem('clubpay_admin');AP='';return}
    var d=await r.json();
    document.getElementById('authBox').classList.add('hidden');document.getElementById('adminDash').classList.remove('hidden');
    document.getElementById('adminStats').innerHTML=
      '<div class="stat"><div class="stat-label">VOLUMEN TOTAL</div><div class="stat-value green">$'+(d.volume_ars||0).toLocaleString('es-AR')+' ARS</div><div class="stat-sub">aprox $'+d.volume_usd.toFixed(2)+' USD</div></div>'+
      '<div class="stat"><div class="stat-label">TUS COMISIONES</div><div class="stat-value orange">$'+(d.total_fees_ars||0).toLocaleString('es-AR')+' ARS</div><div class="stat-sub">aprox $'+d.total_fees_usd.toFixed(2)+' USD</div></div>'+
      '<div class="stat"><div class="stat-label">COMERCIOS</div><div class="stat-value blue">'+d.total_merchants+'</div></div>'+
      '<div class="stat"><div class="stat-label">PAGOS CONFIRMADOS</div><div class="stat-value green">'+d.confirmed_payments+'</div></div>'+
      '<div class="stat"><div class="stat-label">RETIROS PENDIENTES</div><div class="stat-value orange">'+d.pending_withdrawals+'</div></div>'+
      '<div class="stat"><div class="stat-label">DOLAR BLUE</div><div class="stat-value" style="color:var(--green)">$'+(d.blue_ars||'...')+'</div></div>';
    loadWithdrawals();loadAdminPays();loadMerchants();
  }catch(e){console.log(e)}}

async function adminLogin(){
  var email=document.getElementById('adminEmail').value;
  var pass=document.getElementById('adminPass').value;
  if(!email||!pass){document.getElementById('adminMsg').innerHTML='<div style="color:var(--red);font-size:12px">Completa email y password</div>';return}
  try{
    var r=await fetch('/v1/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,password:pass})});
    var d=await r.json();
    if(!r.ok){document.getElementById('adminMsg').innerHTML='<div style="color:var(--red);font-size:12px">'+d.detail+'</div>';return}
    AP=d.token;localStorage.setItem('clubpay_admin',AP);loadAdmin();
  }catch(e){document.getElementById('adminMsg').innerHTML='<div style="color:var(--red);font-size:12px">Error de conexion</div>'}
}

async function loadWithdrawals(){
  var r=await fetch('/v1/admin/withdrawals',{headers:{'Authorization':'Bearer '+AP}});var d=await r.json();var h='';
  d.withdrawals.forEach(function(w){
    var actions=w.status==='pending'?'<button class="btn btn-approve" onclick="actW('+w.id+',\\\'approve\\\')">APROBAR</button><button class="btn btn-reject" onclick="actW('+w.id+',\\\'reject\\\')">RECHAZAR</button>':'-';
    h+='<tr><td>#'+w.id+'</td><td>'+w.business_name+'</td><td>$'+w.amount_usd.toFixed(2)+'</td><td>'+w.crypto+'</td><td style="font-size:9px;word-break:break-all">'+w.destination_wallet+'</td><td><span class="badge '+w.status+'">'+w.status.toUpperCase()+'</span></td><td>'+actions+'</td></tr>'});
  document.getElementById('wTable').innerHTML=h||'<tr><td colspan="7" style="text-align:center;color:var(--dim)">Sin retiros</td></tr>'}
async function actW(id,action){
  await fetch('/v1/admin/withdrawals/'+id+'/'+action,{method:'POST',headers:{'Authorization':'Bearer '+AP}});loadAdmin()}
async function loadAdminPays(){
  var r=await fetch('/v1/admin/payments',{headers:{'Authorization':'Bearer '+AP}});var d=await r.json();var h='';
  d.payments.forEach(function(p){h+='<tr><td>'+p.id.slice(0,10)+'</td><td>'+(p.business_name||'')+'</td><td>$'+(p.amount_ars||0).toLocaleString('es-AR')+'</td><td>$'+(p.amount_usd||0).toFixed(2)+'</td><td class="orange">$'+(p.fee_usd||0).toFixed(2)+'</td><td><span class="badge '+p.status+'">'+p.status.toUpperCase()+'</span></td><td>'+new Date(p.created_at).toLocaleDateString()+'</td></tr>'});
  document.getElementById('aPayTable').innerHTML=h||'<tr><td colspan="7" style="text-align:center;color:var(--dim)">Sin pagos</td></tr>'}
async function loadMerchants(){
  var r=await fetch('/v1/admin/merchants',{headers:{'Authorization':'Bearer '+AP}});var d=await r.json();var h='';
  d.merchants.forEach(function(m){h+='<tr><td>#'+m.id+'</td><td>'+m.business_name+'</td><td>'+m.email+'</td><td class="green">$'+m.balance_usd.toFixed(2)+'</td><td>$'+m.total_received_usd.toFixed(2)+'</td><td class="orange">$'+m.total_fees_usd.toFixed(2)+'</td></tr>'});
  document.getElementById('mTable').innerHTML=h||'<tr><td colspan="6" style="text-align:center;color:var(--dim)">Sin comercios</td></tr>'}

if(AP)loadAdmin();
</script>
<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>
</body>
</html>"""


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return HTMLResponse(content=ADMIN_HTML)


# ════════════════════════════════════════════
# PWA — MANIFEST, SERVICE WORKER, ICON
# ════════════════════════════════════════════
PWA_MANIFEST = {
    "name": "ClubPay",
    "short_name": "ClubPay",
    "description": "Pasarela de pagos crypto. Sin intermediarios.",
    "start_url": "/dashboard",
    "display": "standalone",
    "background_color": "#09090B",
    "theme_color": "#22C55E",
    "orientation": "portrait-primary",
    "icons": [
        {"src": "/icon-192.svg", "sizes": "192x192", "type": "image/svg+xml", "purpose": "any maskable"},
        {"src": "/icon-512.svg", "sizes": "512x512", "type": "image/svg+xml", "purpose": "any maskable"},
    ],
}

PWA_SW_JS = """
const CACHE_NAME = 'clubpay-v1';
const PRECACHE = ['/', '/dashboard', '/admin'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(c => c.addAll(PRECACHE)));
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request)
      .then(res => {
        const clone = res.clone();
        caches.open(CACHE_NAME).then(c => c.put(e.request, clone));
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
""".strip()

PWA_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="96" fill="#09090B"/>
  <defs>
    <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#22C55E"/>
      <stop offset="100%" stop-color="#3B82F6"/>
    </linearGradient>
  </defs>
  <text x="256" y="340" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="280" fill="url(#g)">C</text>
  <text x="256" y="430" text-anchor="middle" font-family="Arial,sans-serif" font-weight="700" font-size="80" fill="#A1A1AA">PAY</text>
</svg>"""


@app.get("/manifest.json")
def pwa_manifest():
    return JSONResponse(content=PWA_MANIFEST, media_type="application/manifest+json")


@app.get("/sw.js")
def pwa_service_worker():
    return HTMLResponse(content=PWA_SW_JS, media_type="application/javascript")


@app.get("/icon-192.svg")
def pwa_icon_192():
    return HTMLResponse(content=PWA_ICON_SVG, media_type="image/svg+xml")


@app.get("/icon-512.svg")
def pwa_icon_512():
    return HTMLResponse(content=PWA_ICON_SVG, media_type="image/svg+xml")


# ════════════════════════════════════════════
# PRICES ENDPOINT
# ════════════════════════════════════════════
@app.get("/v1/prices")
def get_prices():
    return {
        "btc_usd": PRICES["btc_usd"],
        "usdt_usd": PRICES["usdt_usd"],
        "blue_ars": PRICES["blue_ars"],
        "oficial_ars": PRICES["oficial_ars"],
        "last_update": PRICES["last_update"],
    }


# ════════════════════════════════════════════
# RUN
# ════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
