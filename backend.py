# backend.py - RENDER UYUMLU, HARDSHIELD EDİLMİŞ (AZ+TR ONLY, CF-GATE, IP-FLOOD BAN)
import os
import re
import json
import time
import logging
import secrets
import sqlite3
import ipaddress
import threading
from datetime import datetime, timedelta
from collections import deque, OrderedDict

import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ---------- Basic config ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')

# SECRET_KEY - set in Render env for production
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() in ('1','true','yes')
)

# CORS (limit in prod via ALLOWED_ORIGINS if needed)
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '')
if ALLOWED_ORIGINS:
    CORS(app, resources={r"/*": {"origins": [o.strip() for o in ALLOWED_ORIGINS.split(',')]}})
else:
    CORS(app, resources={r"/health": {"origins": "*"}})

# Rate limiter (route-based limits will be set using decorators too)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=os.environ.get('DEFAULT_RATE_LIMITS', "500 per day,100 per hour,30 per minute").split(','),
    storage_uri=os.environ.get('RATE_LIMIT_STORAGE', "memory://")
)

# Database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'database.db'))

# ---------- Cloudflare / geo settings ----------
STRICT_CLOUDFLARE = os.environ.get('STRICT_CLOUDFLARE', 'true').lower() in ('1','true','yes')
CF_ONLY_API_LOCK = os.environ.get('CF_ONLY_API_LOCK', 'true').lower() in ('1','true','yes')

# Allowed countries (ISO codes) - default AZ + TR
ALLOWED_COUNTRIES = [c.strip().upper() for c in os.environ.get('ALLOWED_COUNTRIES', 'AZ,TR').split(',') if c.strip()]

CF_IP_CACHE_FILE = os.environ.get('CF_IP_CACHE_FILE', os.path.join(BASE_DIR, 'cf_ips_cache.json'))
CF_IP_CACHE_TTL = int(os.environ.get('CF_IP_CACHE_TTL', 60 * 60 * 6))
CF_IP_API = "https://api.cloudflare.com/client/v4/ips"

# ---------- In-memory IP tracking (memory-safe) ----------
IP_LOG_LOCK = threading.Lock()
MAX_TRACKED_IPS = int(os.environ.get('MAX_TRACKED_IPS', 10000))
MAX_TIMESTAMPS_PER_IP = int(os.environ.get('MAX_TIMESTAMPS_PER_IP', 500))
ip_request_logs = OrderedDict()
banned_ips = {}
BANNED_LOCK = threading.Lock()

# Flood thresholds (tuneable)
# Default: everyone can do 4 requests per 5 seconds. Exceed -> ban (default 1 day)
GLOBAL_WINDOW_SECONDS = int(os.environ.get('GLOBAL_WINDOW_SECONDS', 5))
GLOBAL_THRESHOLD = int(os.environ.get('GLOBAL_THRESHOLD', 4))
GLOBAL_BAN_SECONDS = int(os.environ.get('GLOBAL_BAN_SECONDS', 86400))

API_WINDOW = int(os.environ.get('API_WINDOW', GLOBAL_WINDOW_SECONDS))
API_THRESHOLD = int(os.environ.get('API_THRESHOLD', GLOBAL_THRESHOLD))
API_BAN_SECONDS = int(os.environ.get('API_BAN_SECONDS', GLOBAL_BAN_SECONDS))

# Decoy / redirect URL for offending clients
DECOY_URL = os.environ.get('DECOY_URL', 'https://www.google.com')

# ---------- Helper functions ----------
def now_ts():
    return int(time.time())

def prune_old_ips_locked():
    while len(ip_request_logs) > MAX_TRACKED_IPS:
        ip_request_logs.popitem(last=False)

def record_request(ip):
    ts = now_ts()
    with IP_LOG_LOCK:
        if ip in ip_request_logs:
            dq = ip_request_logs.pop(ip)
        else:
            dq = deque()
        dq.append(ts)
        while len(dq) > MAX_TIMESTAMPS_PER_IP:
            dq.popleft()
        ip_request_logs[ip] = dq
        prune_old_ips_locked()

def count_requests_in_window(ip, window_seconds):
    cutoff = now_ts() - window_seconds
    with IP_LOG_LOCK:
        dq = ip_request_logs.get(ip)
        if not dq:
            return 0
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

def ban_ip(ip, seconds):
    until = now_ts() + seconds
    with BANNED_LOCK:
        banned_ips[ip] = until
    logger.warning(f"IP {ip} banned for {seconds}s (until {until})")

def is_ip_banned(ip):
    with BANNED_LOCK:
        until = banned_ips.get(ip)
        if not until:
            return False
        if now_ts() > until:
            del banned_ips[ip]
            return False
        return True

def unban_ip(ip):
    with BANNED_LOCK:
        if ip in banned_ips:
            del banned_ips[ip]
            return True
    return False

# ---------- Cloudflare CIDR helpers ----------
def fetch_cloudflare_ips():
    try:
        r = requests.get(CF_IP_API, timeout=8)
        r.raise_for_status()
        data = r.json()
        if 'result' in data:
            out = {'timestamp': int(time.time()), 'ipv4': data['result'].get('ipv4_cidrs', []), 'ipv6': data['result'].get('ipv6_cidrs', [])}
            with open(CF_IP_CACHE_FILE, 'w') as f:
                json.dump(out, f)
            return out
    except Exception as e:
        logger.warning(f"Cloudflare IP fetch error: {e}")
    try:
        with open(CF_IP_CACHE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {'timestamp': 0, 'ipv4': [], 'ipv6': []}

def get_cloudflare_cidrs():
    try:
        if os.path.exists(CF_IP_CACHE_FILE):
            with open(CF_IP_CACHE_FILE, 'r') as f:
                cached = json.load(f)
            if int(time.time()) - cached.get('timestamp', 0) < CF_IP_CACHE_TTL:
                return cached.get('ipv4', []) + cached.get('ipv6', [])
    except Exception:
        pass
    new = fetch_cloudflare_ips()
    return new.get('ipv4', []) + new.get('ipv6', [])

def ip_in_cidrs(ip, cidrs):
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in cidrs:
            try:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False

# ---------- Basic DB helpers ----------
def get_db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE,
            user_type TEXT DEFAULT 'free',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            query_count INTEGER DEFAULT 0,
            vip_expiry TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS query_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            query_type TEXT,
            query_params TEXT,
            result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        hashed = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
        c.execute('INSERT INTO users (username, password, email, user_type, is_active) VALUES (?, ?, ?, ?, ?)',
                  ('admin', hashed, 'admin@sorgupaneli.com', 'admin', 1))
        logger.info("Admin user created (password hashed)")
    conn.commit()
    conn.close()

# ---------- Security helpers ----------
SQL_INJECTION_REGEX = re.compile(r'\b(select|insert|update|delete|drop|union|--|;)\b', re.I)
def check_sql_injection(s):
    if not s:
        return False
    return bool(SQL_INJECTION_REGEX.search(s))

def sanitize_input(s):
    if not s:
        return ''
    clean = re.sub(r'<[^>]*>', '', s)
    return clean[:500]

def detect_proxy_or_forwarding(headers):
    xff = headers.get('X-Forwarded-For', '') or headers.get('x-forwarded-for', '')
    if xff:
        parts = [p.strip() for p in xff.split(',') if p.strip()]
        if len(parts) > 3:
            return True
    for h in ('Via', 'via', 'Proxy-Connection', 'Proxy-Authorization', 'Forwarded'):
        if headers.get(h):
            return True
    ua = (headers.get('User-Agent') or '').lower()
    if any(x in ua for x in ('curl', 'python-requests', 'wget')):
        return True
    return False

# New: broader bot/suspicious UA detection
SUSPICIOUS_UA_SUBSTRS = ('curl', 'python-requests', 'wget', 'bot', 'spider', 'crawler', 'libwww', 'java', 'nikto')
def is_suspicious_ua(headers):
    ua = (headers.get('User-Agent') or '').lower()
    if not ua:
        return True
    return any(s in ua for s in SUSPICIOUS_UA_SUBSTRS)

# ---------- Middleware: security + geo + ip-ban + flood protection ----------
@app.before_request
def security_checks():
    if request.path.startswith('/health'):
        return None

    require_https = os.environ.get('REQUIRE_HTTPS', 'true').lower() in ('1','true','yes')
    cf_visitor = request.headers.get('CF-Visitor', '')
    xfp = request.headers.get('X-Forwarded-Proto', '')
    scheme_https = False
    if cf_visitor and 'https' in cf_visitor.lower():
        scheme_https = True
    elif xfp and 'https' in xfp.lower():
        scheme_https = True
    elif request.scheme == 'https':
        scheme_https = True
    if require_https and not scheme_https:
        if request.method in ('GET', 'HEAD'):
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

    cf_ip = request.headers.get('CF-Connecting-IP')
    cf_country = (request.headers.get('CF-IPCountry') or '').upper()
    xff = request.headers.get('X-Forwarded-For', '')
    remote = cf_ip or (xff.split(',')[0].strip() if xff else None) or request.remote_addr or ''

    # If IP is banned -> immediately redirect to decoy
    if remote and is_ip_banned(remote):
        logger.info(f"Redirecting banned IP: {remote} -> {DECOY_URL}")
        return redirect(DECOY_URL, code=302)

    if remote:
        record_request(remote)

    # Strict CF enforcement
    if STRICT_CLOUDFLARE:
        if not cf_ip or not request.headers.get('CF-Ray'):
            logger.warning("Rejecting request without CF headers (strict mode).")
            # Ban and redirect to decoy
            if remote:
                ban_ip(remote, GLOBAL_BAN_SECONDS)
            return redirect(DECOY_URL, code=302)

    # Country restriction
    if ALLOWED_COUNTRIES:
        if cf_country:
            if cf_country not in ALLOWED_COUNTRIES:
                logger.info(f"Country {cf_country} not allowed (only {ALLOWED_COUNTRIES}) - IP {remote}")
                if remote:
                    cnt = count_requests_in_window(remote, GLOBAL_WINDOW_SECONDS)
                    if cnt > (GLOBAL_THRESHOLD // 2):
                        ban_ip(remote, GLOBAL_BAN_SECONDS)
                return redirect(DECOY_URL, code=302)
        else:
            logger.warning("No CF country header - blocking (strict country enforcement).")
            if remote:
                ban_ip(remote, GLOBAL_BAN_SECONDS)
            return redirect(DECOY_URL, code=302)

    # Bot / suspicious UA detection (global)
    if is_suspicious_ua(request.headers):
        logger.warning(f"Suspicious UA or missing UA for IP {remote} -> banning")
        if remote:
            ban_ip(remote, API_BAN_SECONDS)
        return redirect(DECOY_URL, code=302)

    # Proxy/VPN detection for API calls
    if request.path.startswith('/api/') and detect_proxy_or_forwarding(request.headers):
        logger.warning("Proxy/VPN detected for API call, banning and redirecting")
        if remote:
            ban_ip(remote, API_BAN_SECONDS)
        return redirect(DECOY_URL, code=302)

    # Basic SQL injection detection on POST
    if request.method == 'POST':
        data = request.form or request.get_json(silent=True) or {}
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and check_sql_injection(v):
                    logger.warning(f"SQL injection attempt: {k} -> {v[:80]}")
                    if remote:
                        ban_ip(remote, GLOBAL_BAN_SECONDS)
                    return redirect(DECOY_URL, code=302)

    # Global flood protection (simple per-IP rolling window)
    if remote:
        cnt = count_requests_in_window(remote, GLOBAL_WINDOW_SECONDS)
        if cnt > GLOBAL_THRESHOLD:
            logger.warning(f"IP {remote} exceeded global threshold: {cnt} in {GLOBAL_WINDOW_SECONDS}s -> ban and redirect")
            ban_ip(remote, GLOBAL_BAN_SECONDS)
            return redirect(DECOY_URL, code=302)

    # API-specific flood protection
    if request.path.startswith('/api/'):
        cnt_api = count_requests_in_window(remote, API_WINDOW)
        if cnt_api > API_THRESHOLD:
            logger.warning(f"IP {remote} exceeded API threshold: {cnt_api} in {API_WINDOW}s -> ban and redirect")
            ban_ip(remote, API_BAN_SECONDS)
            return redirect(DECOY_URL, code=302)

# ---------- After-request security headers ----------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(),camera=()'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:;"
    return response

# ---------- Auth decorators ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = get_db()
        user = conn.execute('SELECT user_type FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        if not user or user['user_type'] != 'admin':
            flash('Admin yetkisi gerekiyor!', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ---------- API endpoints list (FULL) ----------
API_ENDPOINTS = {
    # FREE sorgular
    "tc_sorgu1": "https://apinabi.onrender.com/tc/text?tc={tc}",
    "tc_sorgu2": "https://apinabi.onrender.com/tc2/text?tc={tc}",
    "adsoyad_sorgu": "https://apinabi.onrender.com/text?name={name}&surname={surname}",

    # VIP sorgular
    "plaka_sorgu": "https://plakanabi.onrender.com/plaka?plaka={plaka}",
    "plaka_ad": "https://plakanabi.onrender.com/plaka-ad?ad={ad}",
    "plaka_soyad": "https://plakanabi.onrender.com/plaka-soyad?soyad={soyad}",
    "plaka_adsoyad": "https://plakanabi.onrender.com/plaka-adsoyad?ad={ad}&soyad={soyad}",
    "plaka_text": "https://apinabi.onrender.com/plaka/text?plaka={plaka}",

    "papara_no": "https://papara.onrender.com/paparano?paparano={paparano}",
    "papara_ad": "https://papara.onrender.com/ad?ad={ad}",
    "papara_soyad": "https://papara.onrender.com/soyad?soyad={soyad}",
    "papara_adsoyad": "https://papara.onrender.com/adsoyad?ad={ad}&soyad={soyad}",

    "gsm_sorgu1": "https://apinabi.onrender.com/gsm/text?gsm={gsm}",
    "gsm_sorgu2": "https://apinabi.onrender.com/gsm2/text?gsm={gsm}",

    "aile_sorgu": "https://apinabi.onrender.com/aile/text?tc={tc}",
    "sulale_sorgu": "https://apinabi.onrender.com/sulale/text?tc={tc}",
    "hane_sorgu": "https://apinabi.onrender.com/hane/text?tc={tc}",
    "isyeri_sorgu": "https://apinabi.onrender.com/isyeri/text?tc={tc}",
    "vesika_sorgu": "https://apinabi.onrender.com/vesika/text?tc={tc}",

    "sicil_ad": "https://siciln.onrender.com/ad?ad={ad}",
    "sicil_soyad": "https://siciln.onrender.com/soyad?soyad={soyad}",
    "sicil_adsoyad": "https://siciln.onrender.com/adsoyad?ad={ad}&soyad={soyad}",
    "sicil_id": "https://siciln.onrender.com/id?id={id}",

    "nufus_sorgu": "https://panel-w6tk.onrender.com/api/v1/nufus/sorgu?tc={tc}",
    "adli_sicil": "https://panel-w6tk.onrender.com/api/v1/adli-sicil/kayit?tc={tc}",
    "pasaport_sorgu": "https://panel-w6tk.onrender.com/api/v1/pasaport/sorgu?tc={tc}",
    "ehliyet_sorgu": "https://panel-w6tk.onrender.com/api/v1/ehliyet/sorgu?tc={tc}",
    "meb_mezuniyet": "https://panel-w6tk.onrender.com/api/v1/meb/mezuniyet?tc={tc}",
    "noter_islem": "https://panel-w6tk.onrender.com/api/v1/noter/gereceklesen-islem?tc={tc}",

    "asi_kayitlari": "https://panel-w6tk.onrender.com/api/v1/saglik/asi-kayitlari?tc={tc}",
    "rontgen_listesi": "https://panel-w6tk.onrender.com/api/v1/saglik/rontgen-listesi?tc={tc}",
    "kronik_hastalik": "https://panel-w6tk.onrender.com/api/v1/saglik/kronik-hastalik?tc={tc}",
    "hasta_yatis": "https://panel-w6tk.onrender.com/api/v1/saglik/hasta-yatis-gecmisi?tc={tc}",
    "recete_gecmisi": "https://panel-w6tk.onrender.com/api/v1/eczane/recete-gecmisi?tc={tc}",

    "vergi_borc": "https://panel-w6tk.onrender.com/api/v1/vergi/borc-sorgu?tc={tc}",
    "ticaret_sikayet": "https://panel-w6tk.onrender.com/api/v1/ticaret/sikayet-kaydi?tc={tc}",
    "gayrimenkul": "https://panel-w6tk.onrender.com/api/v1/tapu/gayrimenkul?tc={tc}",
    "askerlik_durum": "https://panel-w6tk.onrender.com/api/v1/askerlik/durum?tc={tc}",

    "ibb_su": "https://panel-w6tk.onrender.com/api/v1/ibb/su-fatura?tc={tc}",
    "elektrik_fatura": "https://panel-w6tk.onrender.com/api/v1/elektrik/fatura?tc={tc}",
    "otel_rezervasyon": "https://panel-w6tk.onrender.com/api/v1/turizm/otel-rezervasyon?tc={tc}",
    "istanbulkart_bakiye": "https://panel-w6tk.onrender.com/api/v1/ulasim/istanbulkart-bakiye?tc={tc}",

    "ucak_bilet": "https://panel-w6tk.onrender.com/api/v1/udhb/ucak-bilet?tc={tc}",
    "seyahat_hareket": "https://panel-w6tk.onrender.com/api/v1/mzk/seyahat-hareket?tc={tc}",
    "spor_federasyon": "https://panel-w6tk.onrender.com/api/v1/spor/federasyon/kayit?tc={tc}",
    "kutuphane_uye": "https://panel-w6tk.onrender.com/api/v1/kutuphane/uye-durum?tc={tc}",

    "dijital_banka": "https://plakanabi.onrender.com/dijital/banka-musteri?tc={tc}",
    "kredi_risk": "https://panel-w6tk.onrender.com/api/v1/kredi/risk-raporu?tc={tc}",
    "cevre_ceza": "https://panel-w6tk.onrender.com/api/v1/cevre/sehirlerarasi-ceza?tc={tc}",
    "avci_lisans": "https://panel-w6tk.onrender.com/api/v1/ormancilik/avci-lisans?tc={tc}"
}

# ---------- QUERY_NAMES (FULL) ----------
QUERY_NAMES = {
    "TC Sorgu 1": "tc_sorgu1",
    "TC Sorgu 2": "tc_sorgu2",
    "Ad-Soyad Sorgu": "adsoyad_sorgu",
    "Plaka Sorgu": "plaka_sorgu",
    "Plaka Ad Sorgu": "plaka_ad",
    "Plaka Soyad Sorgu": "plaka_soyad",
    "Plaka Ad-Soyad Sorgu": "plaka_adsoyad",
    "Plaka Text Sorgu": "plaka_text",
    "Papara No Sorgu": "papara_no",
    "Papara Ad Sorgu": "papara_ad",
    "Papara Soyad Sorgu": "papara_soyad",
    "Papara Ad-Soyad Sorgu": "papara_adsoyad",
    "GSM Sorgu 1": "gsm_sorgu1",
    "GSM Sorgu 2": "gsm_sorgu2",
    "Aile Sorgu": "aile_sorgu",
    "Sülale Sorgu": "sulale_sorgu",
    "Hane Sorgu": "hane_sorgu",
    "İş Yeri Sorgu": "isyeri_sorgu",
    "Vesika Sorgu": "vesika_sorgu",
    "Sicil Ad Sorgu": "sicil_ad",
    "Sicil Soyad Sorgu": "sicil_soyad",
    "Sicil Ad-Soyad Sorgu": "sicil_adsoyad",
    "Sicil ID Sorgu": "sicil_id",
    "Nüfus Sorgu": "nufus_sorgu",
    "Adli Sicil Kayıt": "adli_sicil",
    "Pasaport Sorgu": "pasaport_sorgu",
    "Ehliyet Sorgu": "ehliyet_sorgu",
    "MEB Mezuniyet": "meb_mezuniyet",
    "Noter İşlem": "noter_islem",
    "Aşı Kayıtları": "asi_kayitlari",
    "Röntgen Listesi": "rontgen_listesi",
    "Kronik Hastalık": "kronik_hastalik",
    "Hasta Yatış Geçmişi": "hasta_yatis",
    "Reçete Geçmişi": "recete_gecmisi",
    "Vergi Borç Sorgu": "vergi_borc",
    "Ticaret Şikayet Kaydı": "ticaret_sikayet",
    "Gayrimenkul Sorgu": "gayrimenkul",
    "Askerlik Durum": "askerlik_durum",
    "İBB Su Fatura": "ibb_su",
    "Elektrik Fatura": "elektrik_fatura",
    "Otel Rezervasyon": "otel_rezervasyon",
    "İstanbulkart Bakiye": "istanbulkart_bakiye",
    "Uçak Bilet": "ucak_bilet",
    "Seyahat Hareket": "seyahat_hareket",
    "Spor Federasyon Kayıt": "spor_federasyon",
    "Kütüphane Üye Durum": "kutuphane_uye",
    "Dijital Banka Müşteri": "dijital_banka",
    "Kredi Risk Raporu": "kredi_risk",
    "Şehirlerarası Çevre Ceza": "cevre_ceza",
    "Avcı Lisans": "avci_lisans"
}

# (routes and the rest of the code remain unchanged from the original file)
# ---------- Routes ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ... rest of file unchanged (login, register, dashboard, api endpoints, etc.)

# NOTE: For brevity the rest of the file (routes, handlers) are unchanged and should be
# copied from your earlier backend.py. The important changes are the rate-limit,
# bot-detection, ban-and-redirect behaviour at the top of the file.

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    init_db()
    # NOTE: Use Gunicorn in production. Dev server is not suitable for high traffic.
    app.run(host='0.0.0.0', port=port, debug=False)
