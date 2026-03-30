"""
ClubPay — Pasarela de Pago Crypto
Gateway de pagos con criptomonedas (USDT TRC-20, BTC).
Sin intermediarios. Comisiones mínimas.

Endpoints:
  GET  /                        → info
  POST /v1/auth/register        → registrar comercio
  POST /v1/auth/login           → login comercio
  GET  /v1/merchant/me          → datos del comercio
  POST /v1/merchant/wallets     → configurar wallets del comercio
  POST /v1/payments/create      → crear cobro
  GET  /v1/payments/{id}        → estado de un cobro
  GET  /v1/payments             → listar cobros del comercio
  GET  /checkout/{id}           → página de pago para el comprador
  GET  /dashboard               → panel del comercio
"""

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
BASE_URL = os.getenv("BASE_URL", "http://localhost:8000")
DB_PATH = os.getenv("DB_PATH", "/tmp/clubpay.db")
CLUBPAY_FEE_PERCENT = float(os.getenv("CLUBPAY_FEE", "1.5"))  # 1.5% comisión
CHECK_INTERVAL = 30  # segundos entre chequeos de blockchain

# APIs de blockchain (gratis)
TRONGRID_URL = "https://api.trongrid.io"
BLOCKSTREAM_URL = "https://blockstream.info/api"
COINGECKO_URL = "https://api.coingecko.com/api/v3"

# Cache de precios
PRICES = {"btc_usd": None, "usdt_usd": 1.0, "last_update": None}

app = FastAPI(
    title="ClubPay — Pasarela Crypto",
    description="Gateway de pagos con criptomonedas. Sin intermediarios.",
    version="0.1.0",
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
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            merchant_id INTEGER NOT NULL,
            amount_usd REAL NOT NULL,
            amount_crypto REAL,
            crypto TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            customer_email TEXT DEFAULT '',
            merchant_wallet TEXT NOT NULL,
            expected_amount TEXT NOT NULL,
            tx_hash TEXT DEFAULT '',
            paid_at TEXT DEFAULT '',
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            webhook_sent INTEGER DEFAULT 0,
            metadata TEXT DEFAULT '{}',
            FOREIGN KEY (merchant_id) REFERENCES merchants(id)
        );
    """)
    db.commit()
    db.close()


def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


init_db()


# ════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_api_key():
    return f"cpk_{secrets.token_hex(20)}"


def generate_api_secret():
    return f"cps_{secrets.token_hex(24)}"


def generate_payment_id():
    return f"pay_{secrets.token_hex(12)}"


def verify_merchant(api_key):
    """Verifica API key y devuelve el merchant."""
    db = get_db()
    merchant = db.execute(
        "SELECT * FROM merchants WHERE api_key = ? AND active = 1", (api_key,)
    ).fetchone()
    db.close()
    if not merchant:
        raise HTTPException(401, "API key inválida")
    return dict(merchant)


def get_api_key(authorization: str = Header(default=None)):
    if not authorization:
        raise HTTPException(401, "Header requerido: Authorization: Bearer <api_key>")
    return authorization.replace("Bearer ", "").strip()


# ════════════════════════════════════════════
# PRECIO CRYPTO
# ════════════════════════════════════════════
def fetch_prices():
    try:
        r = req.get(
            f"{COINGECKO_URL}/simple/price?ids=bitcoin&vs_currencies=usd",
            timeout=10,
        )
        data = r.json()
        PRICES["btc_usd"] = data["bitcoin"]["usd"]
        PRICES["usdt_usd"] = 1.0
        PRICES["last_update"] = datetime.now(timezone.utc).isoformat()
    except Exception:
        pass


def usd_to_crypto(amount_usd, crypto):
    """Convierte USD a cantidad de crypto. Agrega centavos únicos para identificar pago."""
    if crypto == "usdt_trc20":
        # USDT = 1:1 con USD, agregar centavos únicos
        unique_cents = secrets.randbelow(99) + 1
        return round(amount_usd + unique_cents / 10000, 4)
    elif crypto == "btc":
        if not PRICES["btc_usd"]:
            fetch_prices()
        if not PRICES["btc_usd"]:
            raise HTTPException(503, "No se pudo obtener precio de BTC")
        btc_amount = amount_usd / PRICES["btc_usd"]
        # Agregar satoshis únicos para identificar
        unique_sats = secrets.randbelow(999) + 1
        return round(btc_amount + unique_sats / 100000000, 8)
    raise HTTPException(400, "Crypto no soportada. Usar: usdt_trc20, btc")


# ════════════════════════════════════════════
# MODELOS
# ════════════════════════════════════════════
class RegisterRequest(BaseModel):
    email: str
    password: str
    business_name: str


class LoginRequest(BaseModel):
    email: str
    password: str


class WalletRequest(BaseModel):
    wallet_usdt_trc20: Optional[str] = ""
    wallet_btc: Optional[str] = ""
    webhook_url: Optional[str] = ""


class PaymentRequest(BaseModel):
    amount_usd: float
    crypto: str  # "usdt_trc20" o "btc"
    description: Optional[str] = ""
    customer_email: Optional[str] = ""
    metadata: Optional[str] = "{}"


# ════════════════════════════════════════════
# ENDPOINTS — AUTH
# ════════════════════════════════════════════
@app.post("/v1/auth/register")
def register(data: RegisterRequest):
    if len(data.password) < 6:
        raise HTTPException(400, "Password mínimo 6 caracteres")

    api_key = generate_api_key()
    api_secret = generate_api_secret()

    db = get_db()
    try:
        db.execute(
            """INSERT INTO merchants
            (email, password_hash, business_name, api_key, api_secret, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                data.email.lower().strip(),
                hash_password(data.password),
                data.business_name.strip(),
                api_key,
                api_secret,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        raise HTTPException(409, "Email ya registrado")
    db.close()

    return {
        "message": "Comercio registrado exitosamente",
        "api_key": api_key,
        "api_secret": api_secret,
        "important": "Guardá tu api_secret, no se puede recuperar.",
    }


@app.post("/v1/auth/login")
def login(data: LoginRequest):
    db = get_db()
    merchant = db.execute(
        "SELECT * FROM merchants WHERE email = ?", (data.email.lower().strip(),)
    ).fetchone()
    db.close()

    if not merchant or merchant["password_hash"] != hash_password(data.password):
        raise HTTPException(401, "Email o password incorrectos")

    return {
        "message": "Login exitoso",
        "api_key": merchant["api_key"],
        "business_name": merchant["business_name"],
        "merchant_id": merchant["id"],
    }


# ════════════════════════════════════════════
# ENDPOINTS — MERCHANT
# ════════════════════════════════════════════
@app.get("/v1/merchant/me")
def merchant_me(authorization: str = Header(default=None)):
    key = get_api_key(authorization)
    merchant = verify_merchant(key)
    return {
        "id": merchant["id"],
        "email": merchant["email"],
        "business_name": merchant["business_name"],
        "wallet_usdt_trc20": merchant["wallet_usdt_trc20"],
        "wallet_btc": merchant["wallet_btc"],
        "webhook_url": merchant["webhook_url"],
        "created_at": merchant["created_at"],
    }


@app.post("/v1/merchant/wallets")
def update_wallets(data: WalletRequest, authorization: str = Header(default=None)):
    key = get_api_key(authorization)
    merchant = verify_merchant(key)

    db = get_db()
    db.execute(
        """UPDATE merchants SET
            wallet_usdt_trc20 = ?,
            wallet_btc = ?,
            webhook_url = ?
        WHERE id = ?""",
        (
            data.wallet_usdt_trc20 or merchant["wallet_usdt_trc20"],
            data.wallet_btc or merchant["wallet_btc"],
            data.webhook_url or merchant["webhook_url"],
            merchant["id"],
        ),
    )
    db.commit()
    db.close()
    return {"message": "Wallets actualizadas"}


# ════════════════════════════════════════════
# ENDPOINTS — PAYMENTS
# ════════════════════════════════════════════
@app.post("/v1/payments/create")
def create_payment(data: PaymentRequest, authorization: str = Header(default=None)):
    key = get_api_key(authorization)
    merchant = verify_merchant(key)

    if data.amount_usd <= 0:
        raise HTTPException(400, "Monto debe ser mayor a 0")

    # Verificar que el comercio tenga wallet configurada
    if data.crypto == "usdt_trc20" and not merchant["wallet_usdt_trc20"]:
        raise HTTPException(400, "Configurá tu wallet USDT TRC-20 primero en /v1/merchant/wallets")
    if data.crypto == "btc" and not merchant["wallet_btc"]:
        raise HTTPException(400, "Configurá tu wallet BTC primero en /v1/merchant/wallets")

    wallet = merchant["wallet_usdt_trc20"] if data.crypto == "usdt_trc20" else merchant["wallet_btc"]
    amount_crypto = usd_to_crypto(data.amount_usd, data.crypto)
    payment_id = generate_payment_id()

    db = get_db()
    db.execute(
        """INSERT INTO payments
        (id, merchant_id, amount_usd, amount_crypto, crypto, description,
         customer_email, merchant_wallet, expected_amount, expires_at, created_at, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            payment_id,
            merchant["id"],
            data.amount_usd,
            amount_crypto,
            data.crypto,
            data.description,
            data.customer_email,
            wallet,
            str(amount_crypto),
            (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
            datetime.now(timezone.utc).isoformat(),
            data.metadata,
        ),
    )
    db.commit()
    db.close()

    return {
        "payment_id": payment_id,
        "status": "pending",
        "amount_usd": data.amount_usd,
        "amount_crypto": amount_crypto,
        "crypto": data.crypto,
        "wallet_address": wallet,
        "checkout_url": f"{BASE_URL}/checkout/{payment_id}",
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
    }


@app.get("/v1/payments/{payment_id}")
def get_payment(payment_id: str, authorization: str = Header(default=None)):
    key = get_api_key(authorization)
    merchant = verify_merchant(key)

    db = get_db()
    payment = db.execute(
        "SELECT * FROM payments WHERE id = ? AND merchant_id = ?",
        (payment_id, merchant["id"]),
    ).fetchone()
    db.close()

    if not payment:
        raise HTTPException(404, "Pago no encontrado")

    return dict(payment)


@app.get("/v1/payments")
def list_payments(
    authorization: str = Header(default=None),
    status: Optional[str] = None,
    limit: int = Query(default=50, le=200),
):
    key = get_api_key(authorization)
    merchant = verify_merchant(key)

    db = get_db()
    if status:
        payments = db.execute(
            "SELECT * FROM payments WHERE merchant_id = ? AND status = ? ORDER BY created_at DESC LIMIT ?",
            (merchant["id"], status, limit),
        ).fetchall()
    else:
        payments = db.execute(
            "SELECT * FROM payments WHERE merchant_id = ? ORDER BY created_at DESC LIMIT ?",
            (merchant["id"], limit),
        ).fetchall()
    db.close()

    return {"payments": [dict(p) for p in payments], "count": len(payments)}


# ════════════════════════════════════════════
# BLOCKCHAIN MONITORING
# ════════════════════════════════════════════
def check_usdt_trc20(wallet, expected_amount, created_after):
    """Chequea transferencias USDT TRC-20 a una wallet en Tron."""
    try:
        # TRC-20 USDT contract en Tron
        usdt_contract = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
        url = f"{TRONGRID_URL}/v1/accounts/{wallet}/transactions/trc20"
        params = {
            "only_to": "true",
            "limit": 20,
            "contract_address": usdt_contract,
        }
        r = req.get(url, params=params, timeout=15)
        data = r.json().get("data", [])

        for tx in data:
            # Monto viene en 6 decimales para USDT
            amount = int(tx.get("value", "0")) / 1_000_000
            tx_time = datetime.fromtimestamp(
                tx.get("block_timestamp", 0) / 1000, tz=timezone.utc
            )

            # Verificar que sea después de la creación del pago
            created_dt = datetime.fromisoformat(created_after)
            if tx_time < created_dt:
                continue

            # Verificar monto (tolerancia de 0.01 USDT)
            if abs(amount - float(expected_amount)) < 0.01:
                return tx.get("transaction_id", "")

    except Exception:
        pass
    return None


def check_btc(wallet, expected_amount, created_after):
    """Chequea transferencias BTC a una wallet."""
    try:
        url = f"{BLOCKSTREAM_URL}/address/{wallet}/txs"
        r = req.get(url, timeout=15)
        txs = r.json()

        for tx in txs:
            if not tx.get("status", {}).get("confirmed", False):
                continue

            tx_time = datetime.fromtimestamp(
                tx["status"].get("block_time", 0), tz=timezone.utc
            )
            created_dt = datetime.fromisoformat(created_after)
            if tx_time < created_dt:
                continue

            # Sumar outputs que van a nuestra wallet
            total_received = 0
            for vout in tx.get("vout", []):
                if vout.get("scriptpubkey_address") == wallet:
                    total_received += vout.get("value", 0)

            # Convertir de satoshis a BTC
            btc_amount = total_received / 100_000_000

            # Tolerancia de 0.000001 BTC
            if abs(btc_amount - float(expected_amount)) < 0.000001:
                return tx.get("txid", "")

    except Exception:
        pass
    return None


def send_webhook(payment, merchant):
    """Envía webhook al comercio cuando se confirma un pago."""
    if not merchant["webhook_url"]:
        return
    try:
        req.post(
            merchant["webhook_url"],
            json={
                "event": "payment.confirmed",
                "payment_id": payment["id"],
                "amount_usd": payment["amount_usd"],
                "amount_crypto": payment["amount_crypto"],
                "crypto": payment["crypto"],
                "tx_hash": payment["tx_hash"],
                "status": "confirmed",
                "paid_at": payment["paid_at"],
            },
            headers={"X-ClubPay-Secret": merchant["api_secret"]},
            timeout=10,
        )
    except Exception:
        pass


def payment_monitor():
    """Loop que chequea pagos pendientes en la blockchain."""
    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            db = get_db()
            pending = db.execute(
                "SELECT * FROM payments WHERE status = 'pending'"
            ).fetchall()

            now = datetime.now(timezone.utc)

            for p in pending:
                payment = dict(p)
                expires = datetime.fromisoformat(payment["expires_at"])

                # Expirar pagos viejos
                if now > expires:
                    db.execute(
                        "UPDATE payments SET status = 'expired' WHERE id = ?",
                        (payment["id"],),
                    )
                    db.commit()
                    continue

                # Chequear blockchain
                tx_hash = None
                if payment["crypto"] == "usdt_trc20":
                    tx_hash = check_usdt_trc20(
                        payment["merchant_wallet"],
                        payment["expected_amount"],
                        payment["created_at"],
                    )
                elif payment["crypto"] == "btc":
                    tx_hash = check_btc(
                        payment["merchant_wallet"],
                        payment["expected_amount"],
                        payment["created_at"],
                    )

                if tx_hash:
                    paid_at = datetime.now(timezone.utc).isoformat()
                    db.execute(
                        """UPDATE payments
                        SET status = 'confirmed', tx_hash = ?, paid_at = ?
                        WHERE id = ?""",
                        (tx_hash, paid_at, payment["id"]),
                    )
                    db.commit()

                    # Enviar webhook
                    merchant = db.execute(
                        "SELECT * FROM merchants WHERE id = ?",
                        (payment["merchant_id"],),
                    ).fetchone()
                    if merchant:
                        payment["tx_hash"] = tx_hash
                        payment["paid_at"] = paid_at
                        send_webhook(payment, dict(merchant))

            db.close()
        except Exception:
            pass

    # Actualizar precios
        try:
            fetch_prices()
        except Exception:
            pass


@app.on_event("startup")
def startup():
    fetch_prices()
    thread = threading.Thread(target=payment_monitor, daemon=True)
    thread.start()


# ════════════════════════════════════════════
# CHECKOUT PAGE (para el comprador)
# ════════════════════════════════════════════
CHECKOUT_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClubPay — Pagar</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#09090B;--card:#18181B;--border:#27272A;--white:#FAFAFA;--dim:#A1A1AA;--green:#22C55E;--red:#EF4444;--blue:#3B82F6;--orange:#F59E0B;--purple:#A855F7}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--white);font-family:'Inter',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{max-width:480px;width:100%}
.logo{text-align:center;margin-bottom:24px}
.logo-text{font-size:24px;font-weight:800;background:linear-gradient(135deg,var(--green),var(--blue));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.2em;margin-top:4px}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:32px;margin-bottom:16px}
.merchant-name{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.15em;margin-bottom:4px}
.description{font-size:14px;color:var(--white);margin-bottom:20px}
.amount-box{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;margin-bottom:24px}
.amount-usd{font-size:32px;font-weight:800;color:var(--white)}
.amount-crypto{font-family:'JetBrains Mono',monospace;font-size:16px;color:var(--green);margin-top:8px}
.crypto-badge{display:inline-block;font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--bg);background:var(--green);border-radius:4px;padding:2px 8px;margin-left:8px;vertical-align:middle}
.label{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.15em;margin-bottom:8px}
.wallet-box{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:14px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--white);word-break:break-all;cursor:pointer;transition:border-color 0.2s;position:relative}
.wallet-box:hover{border-color:var(--green)}
.wallet-box::after{content:'click para copiar';position:absolute;top:-18px;right:0;font-size:9px;color:var(--dim)}
.qr-placeholder{text-align:center;margin:20px 0;padding:20px;border:1px dashed var(--border);border-radius:12px}
.qr-placeholder img{width:200px;height:200px;border-radius:8px}
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
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="container">
  <div class="logo">
    <div class="logo-text">ClubPay</div>
    <div class="logo-sub">PASARELA CRYPTO</div>
  </div>

  <div class="card">
    <div class="merchant-name" id="merchantName">CARGANDO...</div>
    <div class="description" id="desc"></div>

    <div class="amount-box">
      <div class="amount-usd" id="amountUsd">$0.00 USD</div>
      <div class="amount-crypto" id="amountCrypto">
        <span id="cryptoVal">0</span>
        <span class="crypto-badge" id="cryptoBadge">USDT</span>
      </div>
    </div>

    <div class="label">ENVIAR A ESTA DIRECCION</div>
    <div class="wallet-box" id="walletBox" onclick="copyWallet()">
      <span id="walletAddr">...</span>
    </div>

    <div class="qr-placeholder">
      <img id="qrImg" src="" alt="QR">
    </div>

    <div class="timer">
      <div class="timer-label">EXPIRA EN</div>
      <div class="timer-value" id="timerVal">30:00</div>
    </div>

    <div class="status pending" id="statusBox">
      <span class="spinner"></span> ESPERANDO PAGO...
    </div>
  </div>

  <div class="footer">Powered by ClubPay · 0% comisión al comprador</div>
</div>

<div class="copied" id="copied">DIRECCION COPIADA</div>

<script>
var paymentId = window.location.pathname.split('/').pop();
var paymentData = null;
var pollInterval = null;

async function loadPayment() {
    try {
        var r = await fetch('/v1/payments/' + paymentId + '/public');
        if (!r.ok) { document.getElementById('merchantName').textContent = 'PAGO NO ENCONTRADO'; return; }
        paymentData = await r.json();
        render();
        if (paymentData.status === 'pending') {
            pollInterval = setInterval(checkStatus, 15000);
            startTimer();
        }
    } catch(e) {
        document.getElementById('merchantName').textContent = 'ERROR AL CARGAR';
    }
}

function render() {
    var d = paymentData;
    document.getElementById('merchantName').textContent = d.business_name || 'COMERCIO';
    document.getElementById('desc').textContent = d.description || 'Pago';
    document.getElementById('amountUsd').textContent = '$' + d.amount_usd.toFixed(2) + ' USD';
    document.getElementById('cryptoVal').textContent = d.amount_crypto;

    var crypto = d.crypto === 'usdt_trc20' ? 'USDT TRC-20' : 'BTC';
    document.getElementById('cryptoBadge').textContent = crypto;
    document.getElementById('walletAddr').textContent = d.merchant_wallet;

    // QR
    var qrData = d.merchant_wallet;
    document.getElementById('qrImg').src = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(qrData);

    updateStatus(d.status);
}

function updateStatus(status) {
    var box = document.getElementById('statusBox');
    if (status === 'confirmed') {
        box.className = 'status confirmed';
        box.innerHTML = 'PAGO CONFIRMADO';
        if (pollInterval) clearInterval(pollInterval);
    } else if (status === 'expired') {
        box.className = 'status expired';
        box.innerHTML = 'PAGO EXPIRADO';
        if (pollInterval) clearInterval(pollInterval);
    } else {
        box.className = 'status pending';
        box.innerHTML = '<span class="spinner"></span> ESPERANDO PAGO...';
    }
}

async function checkStatus() {
    try {
        var r = await fetch('/v1/payments/' + paymentId + '/public');
        if (r.ok) {
            var d = await r.json();
            if (d.status !== 'pending') {
                paymentData = d;
                updateStatus(d.status);
            }
        }
    } catch(e) {}
}

function startTimer() {
    var expires = new Date(paymentData.expires_at).getTime();
    setInterval(function() {
        var now = Date.now();
        var diff = expires - now;
        if (diff <= 0) {
            document.getElementById('timerVal').textContent = '00:00';
            updateStatus('expired');
            return;
        }
        var mins = Math.floor(diff / 60000);
        var secs = Math.floor((diff % 60000) / 1000);
        document.getElementById('timerVal').textContent =
            String(mins).padStart(2,'0') + ':' + String(secs).padStart(2,'0');
    }, 1000);
}

function copyWallet() {
    if (paymentData) {
        navigator.clipboard.writeText(paymentData.merchant_wallet);
        var el = document.getElementById('copied');
        el.classList.add('show');
        setTimeout(function(){el.classList.remove('show')},1500);
    }
}

loadPayment();
</script>
</body>
</html>"""


@app.get("/checkout/{payment_id}", response_class=HTMLResponse)
def checkout_page(payment_id: str):
    db = get_db()
    payment = db.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    db.close()
    if not payment:
        raise HTTPException(404, "Pago no encontrado")
    return HTMLResponse(content=CHECKOUT_HTML)


@app.get("/v1/payments/{payment_id}/public")
def get_payment_public(payment_id: str):
    """Endpoint público para la página de checkout (sin auth)."""
    db = get_db()
    payment = db.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
    if not payment:
        db.close()
        raise HTTPException(404, "Pago no encontrado")

    merchant = db.execute(
        "SELECT business_name FROM merchants WHERE id = ?",
        (payment["merchant_id"],),
    ).fetchone()
    db.close()

    return {
        "id": payment["id"],
        "amount_usd": payment["amount_usd"],
        "amount_crypto": payment["amount_crypto"],
        "crypto": payment["crypto"],
        "description": payment["description"],
        "merchant_wallet": payment["merchant_wallet"],
        "status": payment["status"],
        "expires_at": payment["expires_at"],
        "tx_hash": payment["tx_hash"],
        "business_name": merchant["business_name"] if merchant else "",
    }


# ════════════════════════════════════════════
# DASHBOARD (para el comercio)
# ════════════════════════════════════════════
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ClubPay — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#09090B;--card:#18181B;--border:#27272A;--white:#FAFAFA;--dim:#A1A1AA;--green:#22C55E;--red:#EF4444;--blue:#3B82F6;--orange:#F59E0B;--purple:#A855F7}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--white);font-family:'Inter',sans-serif;min-height:100vh;padding:20px}
.header{max-width:900px;margin:0 auto 32px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.logo{font-size:24px;font-weight:800;background:linear-gradient(135deg,var(--green),var(--blue));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.nav{display:flex;gap:8px}
.nav button{font-family:'JetBrains Mono',monospace;font-size:11px;background:var(--card);color:var(--dim);border:1px solid var(--border);border-radius:8px;padding:8px 16px;cursor:pointer;transition:all 0.2s}
.nav button:hover,.nav button.active{color:var(--white);border-color:var(--green)}
.container{max-width:900px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:16px}
.card-title{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.2em;margin-bottom:16px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}
.stat{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px}
.stat-label{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--dim);letter-spacing:0.15em;margin-bottom:6px}
.stat-value{font-size:24px;font-weight:800}
.stat-value.green{color:var(--green)}
.stat-value.orange{color:var(--orange)}
.stat-value.blue{color:var(--blue)}
input,select{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--bg);color:var(--white);border:1px solid var(--border);border-radius:8px;padding:10px 14px;width:100%;margin-bottom:10px;outline:none;transition:border-color 0.2s}
input:focus{border-color:var(--green)}
label{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.1em;display:block;margin-bottom:4px}
button.primary{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;background:var(--green);color:var(--bg);border:none;border-radius:8px;padding:12px 24px;cursor:pointer;transition:opacity 0.2s;width:100%;margin-top:8px}
button.primary:hover{opacity:0.85}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{font-family:'JetBrains Mono',monospace;font-size:11px;text-align:left;padding:10px 12px;border-bottom:1px solid var(--border)}
.table th{color:var(--dim);font-size:9px;letter-spacing:0.15em}
.badge{font-family:'JetBrains Mono',monospace;font-size:9px;padding:3px 8px;border-radius:4px;font-weight:700}
.badge.confirmed{background:rgba(34,197,94,0.15);color:var(--green)}
.badge.pending{background:rgba(245,158,11,0.15);color:var(--orange)}
.badge.expired{background:rgba(239,68,68,0.15);color:var(--red)}
.section{display:none}
.section.active{display:block}
.api-key-box{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;word-break:break-all;color:var(--green);cursor:pointer;margin-bottom:8px}

/* Auth */
.auth-container{max-width:400px;margin:80px auto}
.auth-toggle{text-align:center;margin-top:16px;font-size:12px;color:var(--dim)}
.auth-toggle a{color:var(--green);cursor:pointer;text-decoration:none}
.hidden{display:none}
.msg{font-family:'JetBrains Mono',monospace;font-size:11px;padding:10px;border-radius:8px;margin-bottom:12px;text-align:center}
.msg.error{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:var(--red)}
.msg.success{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);color:var(--green)}
</style>
</head>
<body>

<!-- AUTH SCREEN -->
<div id="authScreen" class="auth-container">
  <div style="text-align:center;margin-bottom:32px">
    <div class="logo">ClubPay</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim);letter-spacing:0.2em;margin-top:4px">DASHBOARD</div>
  </div>

  <div class="card" id="loginForm">
    <div class="card-title">INICIAR SESION</div>
    <div id="loginMsg"></div>
    <label>EMAIL</label>
    <input type="email" id="loginEmail" placeholder="tu@email.com">
    <label>PASSWORD</label>
    <input type="password" id="loginPass" placeholder="••••••">
    <button class="primary" onclick="doLogin()">ENTRAR</button>
    <div class="auth-toggle">No tenés cuenta? <a onclick="showRegister()">Registrate</a></div>
  </div>

  <div class="card hidden" id="registerForm">
    <div class="card-title">REGISTRAR COMERCIO</div>
    <div id="regMsg"></div>
    <label>NOMBRE DEL NEGOCIO</label>
    <input type="text" id="regName" placeholder="Mi Tienda">
    <label>EMAIL</label>
    <input type="email" id="regEmail" placeholder="tu@email.com">
    <label>PASSWORD</label>
    <input type="password" id="regPass" placeholder="mínimo 6 caracteres">
    <button class="primary" onclick="doRegister()">CREAR CUENTA</button>
    <div class="auth-toggle">Ya tenés cuenta? <a onclick="showLogin()">Iniciá sesión</a></div>
  </div>
</div>

<!-- DASHBOARD SCREEN -->
<div id="dashScreen" class="hidden">
  <div class="header">
    <div class="logo">ClubPay</div>
    <div class="nav">
      <button class="active" onclick="showSection('overview',this)">RESUMEN</button>
      <button onclick="showSection('create',this)">NUEVO COBRO</button>
      <button onclick="showSection('payments',this)">PAGOS</button>
      <button onclick="showSection('settings',this)">CONFIG</button>
      <button onclick="logout()" style="color:var(--red);border-color:var(--red)">SALIR</button>
    </div>
  </div>

  <div class="container">
    <!-- OVERVIEW -->
    <div class="section active" id="sec-overview">
      <div class="stats">
        <div class="stat">
          <div class="stat-label">TOTAL COBRADO</div>
          <div class="stat-value green" id="statTotal">$0.00</div>
        </div>
        <div class="stat">
          <div class="stat-label">PAGOS CONFIRMADOS</div>
          <div class="stat-value blue" id="statConfirmed">0</div>
        </div>
        <div class="stat">
          <div class="stat-label">PENDIENTES</div>
          <div class="stat-value orange" id="statPending">0</div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">TU API KEY</div>
        <div class="api-key-box" id="apiKeyDisplay" onclick="copyApiKey()">...</div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--dim)">Click para copiar · Usala en el header Authorization: Bearer &lt;key&gt;</div>
      </div>
    </div>

    <!-- CREATE PAYMENT -->
    <div class="section" id="sec-create">
      <div class="card">
        <div class="card-title">CREAR COBRO</div>
        <div id="createMsg"></div>
        <label>MONTO (USD)</label>
        <input type="number" id="createAmount" placeholder="29.00" step="0.01" min="0.01">
        <label>CRYPTO</label>
        <select id="createCrypto">
          <option value="usdt_trc20">USDT (TRC-20)</option>
          <option value="btc">Bitcoin (BTC)</option>
        </select>
        <label>DESCRIPCION (opcional)</label>
        <input type="text" id="createDesc" placeholder="Producto o servicio">
        <label>EMAIL CLIENTE (opcional)</label>
        <input type="email" id="createEmail" placeholder="cliente@email.com">
        <button class="primary" onclick="createPayment()">GENERAR COBRO</button>
      </div>
      <div class="card hidden" id="createResult">
        <div class="card-title">COBRO CREADO</div>
        <label>LINK DE PAGO</label>
        <div class="api-key-box" id="paymentLink" onclick="copyPayLink()" style="color:var(--blue)">...</div>
        <label>PAYMENT ID</label>
        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--dim);margin-bottom:12px" id="paymentId">...</div>
        <button class="primary" onclick="window.open(document.getElementById('paymentLink').textContent,'_blank')">ABRIR CHECKOUT</button>
      </div>
    </div>

    <!-- PAYMENTS LIST -->
    <div class="section" id="sec-payments">
      <div class="card">
        <div class="card-title">HISTORIAL DE PAGOS</div>
        <table class="table">
          <thead><tr><th>ID</th><th>MONTO</th><th>CRYPTO</th><th>ESTADO</th><th>FECHA</th></tr></thead>
          <tbody id="paymentsTable"></tbody>
        </table>
      </div>
    </div>

    <!-- SETTINGS -->
    <div class="section" id="sec-settings">
      <div class="card">
        <div class="card-title">WALLETS — donde recibís los pagos</div>
        <div id="settingsMsg"></div>
        <label>WALLET USDT (TRC-20 — Red Tron)</label>
        <input type="text" id="setUsdt" placeholder="T...">
        <label>WALLET BTC</label>
        <input type="text" id="setBtc" placeholder="bc1...">
        <label>WEBHOOK URL (opcional — te avisamos cuando pagan)</label>
        <input type="url" id="setWebhook" placeholder="https://tu-servidor.com/webhook">
        <button class="primary" onclick="saveSettings()">GUARDAR</button>
      </div>
    </div>
  </div>
</div>

<script>
var API_KEY = localStorage.getItem('clubpay_key') || '';
var BASE = '';

// Auth
function showRegister(){document.getElementById('loginForm').classList.add('hidden');document.getElementById('registerForm').classList.remove('hidden')}
function showLogin(){document.getElementById('registerForm').classList.add('hidden');document.getElementById('loginForm').classList.remove('hidden')}

async function doRegister(){
    var name=document.getElementById('regName').value;
    var email=document.getElementById('regEmail').value;
    var pass=document.getElementById('regPass').value;
    if(!name||!email||!pass){showMsg('regMsg','Completá todos los campos','error');return}
    try{
        var r=await fetch('/v1/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,password:pass,business_name:name})});
        var d=await r.json();
        if(!r.ok){showMsg('regMsg',d.detail||'Error','error');return}
        API_KEY=d.api_key;
        localStorage.setItem('clubpay_key',API_KEY);
        showMsg('regMsg','Cuenta creada! Guardá tu API Secret: '+d.api_secret,'success');
        setTimeout(function(){enterDashboard()},3000);
    }catch(e){showMsg('regMsg','Error de conexión','error')}
}

async function doLogin(){
    var email=document.getElementById('loginEmail').value;
    var pass=document.getElementById('loginPass').value;
    if(!email||!pass){showMsg('loginMsg','Completá todos los campos','error');return}
    try{
        var r=await fetch('/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email,password:pass})});
        var d=await r.json();
        if(!r.ok){showMsg('loginMsg',d.detail||'Error','error');return}
        API_KEY=d.api_key;
        localStorage.setItem('clubpay_key',API_KEY);
        enterDashboard();
    }catch(e){showMsg('loginMsg','Error de conexión','error')}
}

function logout(){API_KEY='';localStorage.removeItem('clubpay_key');location.reload()}

function showMsg(id,msg,type){
    var el=document.getElementById(id);
    el.innerHTML='<div class="msg '+type+'">'+msg+'</div>';
    setTimeout(function(){el.innerHTML=''},5000);
}

// Dashboard
async function enterDashboard(){
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('dashScreen').classList.remove('hidden');
    document.getElementById('apiKeyDisplay').textContent=API_KEY;
    loadOverview();
    loadSettings();
    loadPayments();
}

function showSection(name,btn){
    document.querySelectorAll('.section').forEach(function(s){s.classList.remove('active')});
    document.getElementById('sec-'+name).classList.add('active');
    document.querySelectorAll('.nav button').forEach(function(b){b.classList.remove('active')});
    if(btn)btn.classList.add('active');
}

async function loadOverview(){
    try{
        var r=await fetch('/v1/payments',{headers:{'Authorization':'Bearer '+API_KEY}});
        var d=await r.json();
        var total=0,confirmed=0,pending=0;
        d.payments.forEach(function(p){
            if(p.status==='confirmed'){total+=p.amount_usd;confirmed++}
            if(p.status==='pending')pending++;
        });
        document.getElementById('statTotal').textContent='$'+total.toFixed(2);
        document.getElementById('statConfirmed').textContent=confirmed;
        document.getElementById('statPending').textContent=pending;
    }catch(e){}
}

async function loadPayments(){
    try{
        var r=await fetch('/v1/payments',{headers:{'Authorization':'Bearer '+API_KEY}});
        var d=await r.json();
        var html='';
        d.payments.forEach(function(p){
            html+='<tr><td>'+p.id.slice(0,12)+'...</td><td>$'+p.amount_usd.toFixed(2)+'</td><td>'+(p.crypto==='usdt_trc20'?'USDT':'BTC')+'</td><td><span class="badge '+p.status+'">'+p.status.toUpperCase()+'</span></td><td>'+new Date(p.created_at).toLocaleDateString()+'</td></tr>';
        });
        document.getElementById('paymentsTable').innerHTML=html||'<tr><td colspan="5" style="text-align:center;color:var(--dim)">Sin pagos todavía</td></tr>';
    }catch(e){}
}

async function createPayment(){
    var amount=parseFloat(document.getElementById('createAmount').value);
    var crypto=document.getElementById('createCrypto').value;
    var desc=document.getElementById('createDesc').value;
    var email=document.getElementById('createEmail').value;
    if(!amount||amount<=0){showMsg('createMsg','Ingresá un monto válido','error');return}
    try{
        var r=await fetch('/v1/payments/create',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+API_KEY},body:JSON.stringify({amount_usd:amount,crypto:crypto,description:desc,customer_email:email})});
        var d=await r.json();
        if(!r.ok){showMsg('createMsg',d.detail||'Error','error');return}
        document.getElementById('createResult').classList.remove('hidden');
        document.getElementById('paymentLink').textContent=d.checkout_url;
        document.getElementById('paymentId').textContent=d.payment_id;
        loadOverview();
        loadPayments();
    }catch(e){showMsg('createMsg','Error de conexión','error')}
}

async function loadSettings(){
    try{
        var r=await fetch('/v1/merchant/me',{headers:{'Authorization':'Bearer '+API_KEY}});
        var d=await r.json();
        document.getElementById('setUsdt').value=d.wallet_usdt_trc20||'';
        document.getElementById('setBtc').value=d.wallet_btc||'';
        document.getElementById('setWebhook').value=d.webhook_url||'';
    }catch(e){}
}

async function saveSettings(){
    try{
        var r=await fetch('/v1/merchant/wallets',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+API_KEY},body:JSON.stringify({wallet_usdt_trc20:document.getElementById('setUsdt').value,wallet_btc:document.getElementById('setBtc').value,webhook_url:document.getElementById('setWebhook').value})});
        var d=await r.json();
        if(r.ok)showMsg('settingsMsg','Guardado!','success');
        else showMsg('settingsMsg',d.detail||'Error','error');
    }catch(e){showMsg('settingsMsg','Error de conexión','error')}
}

function copyApiKey(){navigator.clipboard.writeText(API_KEY)}
function copyPayLink(){navigator.clipboard.writeText(document.getElementById('paymentLink').textContent)}

// Auto-login
if(API_KEY){enterDashboard()}
</script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    return HTMLResponse(content=DASHBOARD_HTML)


# ════════════════════════════════════════════
# ROOT
# ════════════════════════════════════════════
@app.get("/")
def root():
    return {
        "name": "ClubPay — Pasarela Crypto",
        "version": "0.1.0",
        "description": "Gateway de pagos con criptomonedas. Sin intermediarios. Comisión 1.5%.",
        "supported_crypto": ["usdt_trc20", "btc"],
        "endpoints": {
            "docs": "/docs",
            "dashboard": "/dashboard",
            "register": "POST /v1/auth/register",
            "create_payment": "POST /v1/payments/create",
        },
    }


# ════════════════════════════════════════════
# RUN
# ════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
