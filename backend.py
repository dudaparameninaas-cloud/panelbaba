# backend.py - RENDER UYUMLU, MAX SERTLEŞTİRİLMİŞ (STABLE CLOUDFLARE + RENDER)
# Site domain: 2026tr.xyz
import os
import re
import json
import time
import logging
import secrets
import sqlite3
import ipaddress
from datetime import datetime, timedelta

import requests
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ---------- Basic config ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')
# ProxyFix: reverse proxy (Cloudflare / Render) altında doğru client IP/host almak için
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

# Secret key (Render: set SECRET_KEY env var)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ---------- Site / Hosts ----------
SITE_DOMAIN = os.environ.get('SITE_DOMAIN', '2026tr.xyz')
ALLOWED_HOSTS = [h.strip() for h in os.environ.get('ALLOWED_HOSTS', SITE_DOMAIN).split(',') if h.strip()]

# ---------- Environment toggles ----------
STRICT_CLOUDFLARE = os.environ.get('STRICT_CLOUDFLARE', 'true').lower() in ('1', 'true', 'yes')
CF_IP_CACHE_FILE = os.environ.get('CF_IP_CACHE_FILE', 'cf_ips_cache.json')
CF_IP_CACHE_TTL = int(os.environ.get('CF_IP_CACHE_TTL', 60 * 60 * 6))  # 6 saat default
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',') if o.strip()]

# ---------- CORS ----------
if ALLOWED_ORIGINS:
    CORS(app, resources={r"/*": {"origins": ALLOWED_ORIGINS}})
else:
    # production için mümkün olduğunca kısıtlı tutuyoruz, health açık olsun
    CORS(app, resources={r"/health": {"origins": "*"}})

# ---------- Rate limiter ----------
REDIS_URL = os.environ.get('REDIS_URL')
storage = REDIS_URL if REDIS_URL else "memory://"
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "30 per hour", "10 per minute"],
    storage_uri=storage
)

# ---------- Database ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'database.db'))


def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(DATABASE_PATH, timeout=10, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()


def init_db():
    """Database tablolarını oluşturur.
    Flask uygulama bağlamına ihtiyaç duymadan güvenli şekilde çalışır (doğrudan sqlite bağlantısı kullanır).
    """
    conn = sqlite3.connect(DATABASE_PATH, timeout=10, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Kullanıcılar tablosu
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

    # Sorgu geçmişi tablosu
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

    # Admin oluştur (hashed password)
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        hashed = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin123'))
        admin_email = f'admin@{SITE_DOMAIN}' if SITE_DOMAIN else 'admin@example.com'
        c.execute('''
            INSERT INTO users (username, password, email, user_type, is_active)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', hashed, admin_email, 'admin', 1))
        logger.info("Admin user created (with hashed password)")

    conn.commit()
    conn.close()


# ---------- Cloudflare IP list fetch & cache helpers ----------
CF_IP_API = "https://api.cloudflare.com/client/v4/ips"


def fetch_cloudflare_ips():
    try:
        r = requests.get(CF_IP_API, timeout=10)
        r.raise_for_status()
        data = r.json()
        if 'result' in data:
            out = {
                'timestamp': int(time.time()),
                'ipv4': data['result'].get('ipv4_cidrs', []),
                'ipv6': data['result'].get('ipv6_cidrs', [])
            }
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


# ---------- Güvenlik yardımcıları ----------

def sanitize_input(input_string):
    if not input_string:
        return ""
    clean = re.sub(r'<[^>]*>', '', input_string)
    if len(clean) > 500:
        clean = clean[:500]
    return clean


SQL_INJECTION_PATTERNS = re.compile(r'(select|insert|update|delete|drop|union|--|;)', re.I)


def check_sql_injection(input_string):
    if not input_string:
        return False
    return bool(SQL_INJECTION_PATTERNS.search(input_string))


def detect_proxy_or_forwarding(headers):
    xff = headers.get('X-Forwarded-For', '') or headers.get('x-forwarded-for', '')
    if xff:
        parts = [p.strip() for p in xff.split(',') if p.strip()]
        if len(parts) > 3:
            logger.info(f"Proxy chain detected via XFF: {parts}")
            return True
    for h in ('Via', 'via', 'Proxy-Connection', 'Proxy-Authorization', 'Forwarded'):
        if headers.get(h):
            logger.info(f"Proxy header present: {h}")
            return True
    ua = (headers.get('User-Agent') or '').lower()
    if 'curl' in ua or 'python-requests' in ua or 'wget' in ua:
        return True
    return False


# ---------- Middleware / before_request ----------
@app.before_request
def security_checks():
    # Allow health check to bypass strict rules
    if request.path.startswith('/health'):
        return None

    # REQUIRE_HTTPS: detect if request arrived via Cloudflare
    require_https = os.environ.get('REQUIRE_HTTPS', 'true').lower() in ('1', 'true', 'yes')
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

    # Host kontrolü - Render test hostlarına izin ver
    host = request.host.split(':')[0]
    if ALLOWED_HOSTS and not (host in ALLOWED_HOSTS or host.endswith('.onrender.com')):
        logger.warning(f"Host not allowed: {host}")
        return jsonify({"error": "Host not allowed"}), 403

    # Determine client IP in CF-friendly way: prefer CF-Connecting-IP, then X-Forwarded-For, then remote_addr
    remote = (request.headers.get('CF-Connecting-IP')
              or (request.headers.get('X-Forwarded-For', '').split(',')[0].strip() if request.headers.get('X-Forwarded-For') else None)
              or request.remote_addr
              or '')

    # Cloudflare strict mode: only CF IPs allowed, but fail-safe if CF list is empty
    if STRICT_CLOUDFLARE:
        cidrs = get_cloudflare_cidrs()
        if cidrs:
            if not ip_in_cidrs(remote, cidrs):
                logger.warning(f"Request from non-Cloudflare IP blocked: {remote}")
                return jsonify({"error": "Access denied"}), 403
        else:
            # Eğer Cloudflare CIDR'leri alınamadıysa, uyarı ver ve devam et — istemeden lockout olmaması için
            logger.warning("Cloudflare CIDR listesi alınamadı — skipping strict CF check")

    # Proxy/VPN detection — API'leri sıkı koru
    if detect_proxy_or_forwarding(request.headers):
        if request.path.startswith('/api/'):
            logger.warning("Proxy/VPN detected for API call, blocking")
            return jsonify({"error": "Proxy or suspicious headers detected"}), 403

    # Basit SQL injection check (POST)
    if request.method == 'POST':
        data = request.form or request.get_json(silent=True) or {}
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and check_sql_injection(v):
                    logger.warning(f"SQLi attempt: {k} -> {v[:80]}")
                    return jsonify({"error": "Security violation"}), 403


# ---------- After request security headers ----------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(),camera=()'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';"
    return response


# ---------- Decorators ----------
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
        if not user or user['user_type'] != 'admin':
            flash('Admin yetkisi gerekiyor!', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ---------- Query rate checks (DB-based, user-type aware) ----------
def check_user_rate_limits(user_id, user_type):
    if user_type == 'admin':
        return True, None

    now = datetime.now()
    conn = get_db()
    minute_thresholds = {'free': 10, 'vip': 60}
    hour_thresholds = {'free': 50, 'vip': 1000}
    day_thresholds = {'free': 200, 'vip': 5000}

    minute_window = (now - timedelta(minutes=1)).strftime('%Y-%m-%d %H:%M:%S')
    hour_window = (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    day_window = (now - timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')

    min_count = conn.execute('SELECT COUNT(*) FROM query_history WHERE user_id = ? AND created_at >= ?', (user_id, minute_window)).fetchone()[0]
    hour_count = conn.execute('SELECT COUNT(*) FROM query_history WHERE user_id = ? AND created_at >= ?', (user_id, hour_window)).fetchone()[0]
    day_count = conn.execute('SELECT COUNT(*) FROM query_history WHERE user_id = ? AND created_at >= ?', (user_id, day_window)).fetchone()[0]

    min_allowed = minute_thresholds.get(user_type, 10)
    hour_allowed = hour_thresholds.get(user_type, 50)
    day_allowed = day_thresholds.get(user_type, 200)

    if min_count >= min_allowed:
        return False, f"Minute rate limit exceeded ({min_count}/{min_allowed})"
    if hour_count >= hour_allowed:
        return False, f"Hourly rate limit exceeded ({hour_count}/{hour_allowed})"
    if day_count >= day_allowed:
        return False, f"Daily rate limit exceeded ({day_count}/{day_allowed})"
    return True, None


# ---------- API endpoint templates (TÜM APİLER) ----------
API_ENDPOINTS = {
    # FREE sorgular
    "tc_sorgu1": "https://apinabi.onrender.com/tc/text?tc={tc}",
    "tc_sorgu2": "https://apinabi.onrender.com/tc2/text?tc={tc}",
    "adsoyad_sorgu": "https://apinabi.onrender.com/text?name={name}&surname={surname}",

    # VIP sorgular (kalan her şey)
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
    "dijital_banka": "https://panel-w6tk.onrender.com/api/v1/dijital/banka-musteri?tc={tc}",
    "kredi_risk": "https://panel-w6tk.onrender.com/api/v1/kredi/risk-raporu?tc={tc}",
    "cevre_ceza": "https://panel-w6tk.onrender.com/api/v1/cevre/sehirlerarasi-ceza?tc={tc}",
    "avci_lisans": "https://panel-w6tk.onrender.com/api/v1/ormancilik/avci-lisans?tc={tc}"
}


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


# ---------- Routes ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET','POST'])
@limiter.limit("20 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username',''))
        password = request.form.get('password','')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user['id']))
            conn.commit()
            logger.info(f"User logged in: {username}")
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
    return render_template('login.html')


@app.route('/register', methods=['GET','POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username',''))
        password = request.form.get('password','')
        email = sanitize_input(request.form.get('email',''))
        if len(username) < 3 or len(password) < 6:
            return render_template('register.html', error='Kullanıcı adı en az 3, şifre en az 6 karakter olmalı')
        conn = get_db()
        try:
            hashed = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password, email, user_type) VALUES (?, ?, ?, ?)', (username, hashed, email, 'free'))
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            logger.info(f"New user registered: {username}")
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Kullanıcı adı veya email zaten kullanımda')
    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    vip_users = conn.execute('SELECT COUNT(*) FROM users WHERE user_type = "vip"').fetchone()[0]
    free_users = conn.execute('SELECT COUNT(*) FROM users WHERE user_type = "free"').fetchone()[0]
    today = datetime.now().strftime('%Y-%m-%d')
    today_count = conn.execute('SELECT COUNT(*) FROM query_history WHERE user_id = ? AND DATE(created_at) = ?', (session['user_id'], today)).fetchone()[0]
    recent_queries = conn.execute('SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5', (session['user_id'],)).fetchall()
    return render_template('dashboard.html', user=user, total_users=total_users, vip_users=vip_users, free_users=free_users, today_count=today_count, recent_queries=recent_queries)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/query/<query_key>')
@login_required
def query_page(query_key):
    if query_key not in QUERY_NAMES.values():
        return "Geçersiz sorgu!", 404
    conn = get_db()
    user = conn.execute('SELECT user_type FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    free_queries = ['tc_sorgu1', 'tc_sorgu2', 'adsoyad_sorgu']
    if query_key not in free_queries and user['user_type'] not in ('vip','admin'):
        return redirect(url_for('subscription'))
    display_name = [k for k,v in QUERY_NAMES.items() if v==query_key][0]
    return render_template('query.html', query_name=display_name, query_key=query_key, user_type=user['user_type'])


@app.route('/api/execute_query', methods=['POST'])
@login_required
def execute_query():
    try:
        data = request.get_json(silent=True) or {}
        query_key = data.get('query_key')
        params = data.get('params', {})

        for k in list(params.keys()):
            if isinstance(params[k], str):
                params[k] = sanitize_input(params[k])

        conn = get_db()
        user = conn.execute('SELECT id, user_type FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        ok, reason = check_user_rate_limits(user['id'], user['user_type'])
        if not ok:
            return jsonify({"success": False, "error": reason}), 429

        free_queries = ['tc_sorgu1', 'tc_sorgu2', 'adsoyad_sorgu']
        if query_key not in API_ENDPOINTS:
            return jsonify({"error": "Geçersiz sorgu anahtarı"}), 400
        if query_key not in free_queries and user['user_type'] not in ('vip','admin'):
            return jsonify({"success": False, "error": "Bu sorgu VIP üyelik gerektirir", "redirect": "/subscription"}), 403

        api_url = API_ENDPOINTS[query_key]
        for key, value in params.items():
            api_url = api_url.replace(f"{{{key}}}", str(value))

        headers = {
            'User-Agent': 'SorguPanel/1.0',
            'X-Forwarded-For': request.headers.get('CF-Connecting-IP', request.remote_addr or '')
        }
        resp = requests.get(api_url, headers=headers, timeout=15)
        result_text = resp.text[:4000]

        conn.execute('INSERT INTO query_history (user_id, query_type, query_params, result) VALUES (?, ?, ?, ?)',
                     (user['id'], query_key, json.dumps(params), result_text))
        conn.execute('UPDATE users SET query_count = query_count + 1 WHERE id = ?', (user['id'],))
        conn.commit()

        return jsonify({"success": True, "response": result_text})
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "API timeout - servis yanıt vermiyor"}), 504
    except Exception as e:
        logger.error(f"Query error: {e}")
        return jsonify({"success": False, "error": "Sorgu çalıştırılırken bir hata oluştu"}), 500


@app.route('/api/get_query_info/<query_key>')
@login_required
def get_query_info(query_key):
    if query_key not in API_ENDPOINTS:
        return jsonify({"error": "Geçersiz sorgu anahtarı"}), 404
    api_url = API_ENDPOINTS[query_key]
    params = re.findall(r'\{(.*?)\}', api_url)
    return jsonify({"query_key": query_key, "api_url_template": api_url, "required_params": params})


@app.route('/api/dashboard_stats')
@login_required
def dashboard_stats():
    conn = get_db()
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    vip_users = conn.execute('SELECT COUNT(*) FROM users WHERE user_type = "vip"').fetchone()[0]
    free_users = conn.execute('SELECT COUNT(*) FROM users WHERE user_type = "free"').fetchone()[0]
    return jsonify({'success': True, 'total_users': total_users, 'vip_users': vip_users, 'free_users': free_users, 'username': session.get('username','')})


@app.route('/health')
def health_check():
    return jsonify({"status":"healthy", "service":"Sorgu Paneli API", "version":"1.2.0", "timestamp": datetime.now().isoformat()})


@app.route('/admin/refresh_cf_ips', methods=['POST'])
@admin_required
def admin_refresh_cf_ips():
    new = fetch_cloudflare_ips()
    return jsonify({"success": True, "timestamp": new.get('timestamp'), "ipv4_count": len(new.get('ipv4',[])), "ipv6_count": len(new.get('ipv6',[]))})


# ---------- Custom Jinja2 filters ----------
@app.context_processor
def utility_processor():
    def get_query_type_class(query_type):
        if 'plaka' in query_type:
            return 'plaka'
        elif 'tc' in query_type:
            return 'tc'
        elif 'gsm' in query_type:
            return 'gsm'
        elif 'adsoyad' in query_type or 'sicil' in query_type:
            return 'adsoyad'
        else:
            return 'other'
    return dict(get_query_type_class=get_query_type_class)


# ---------- Error handlers ----------
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return render_template('500.html'), 500


# ---------- Run ----------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    init_db()
    app.run(host='0.0.0.0', port=port, debug=False)
