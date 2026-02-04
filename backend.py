# backend.py - RENDER UYUMLU, GÜNCELLENMİŞ (FULL)
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
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ---------- Basic config ----------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')

# SECRET_KEY: set in Render env (recommended). If not set, generate temporary (not for production).
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Session cookie hardening
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() in ('1','true','yes')
)

# CORS - production için ALLOWED_ORIGINS env ile sınırlandır
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '')
if ALLOWED_ORIGINS:
    CORS(app, resources={r"/*": {"origins": [o.strip() for o in ALLOWED_ORIGINS.split(',')]}})
else:
    CORS(app, resources={r"/health": {"origins": "*"}})

# Rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=os.environ.get('DEFAULT_RATE_LIMITS', "500 per day,100 per hour,30 per minute").split(','),
    storage_uri=os.environ.get('RATE_LIMIT_STORAGE', "memory://")
)

# Database path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.environ.get('DATABASE_PATH', os.path.join(BASE_DIR, 'database.db'))

# ---------- Cloudflare / IP protections ----------
STRICT_CLOUDFLARE = os.environ.get('STRICT_CLOUDFLARE', 'false').lower() in ('1','true','yes')
CF_ONLY_API_LOCK = os.environ.get('CF_ONLY_API_LOCK', 'true').lower() in ('1','true','yes')
CF_IP_CACHE_FILE = os.environ.get('CF_IP_CACHE_FILE', os.path.join(BASE_DIR, 'cf_ips_cache.json'))
CF_IP_CACHE_TTL = int(os.environ.get('CF_IP_CACHE_TTL', 60 * 60 * 6))
CF_IP_API = "https://api.cloudflare.com/client/v4/ips"

def fetch_cloudflare_ips():
    try:
        r = requests.get(CF_IP_API, timeout=8)
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

# ---------- Database helpers ----------
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
    logger.info("Database initialized")

# ---------- Security helpers ----------
SQL_INJECTION_REGEX = re.compile(r'\b(select|insert|update|delete|drop|union|--|;)\b', re.I)

def check_sql_injection(input_string):
    if not input_string:
        return False
    return bool(SQL_INJECTION_REGEX.search(input_string))

def sanitize_input(s):
    if not s:
        return ''
    out = re.sub(r'<[^>]*>', '', s)
    return out[:500]

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
    if any(x in ua for x in ('curl', 'python-requests', 'wget')):
        return True
    return False

# ---------- Middleware ----------
@app.before_request
def security_checks():
    # health bypass
    if request.path.startswith('/health'):
        return None

    # HTTPS redirect (Cloudflare-friendly)
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

    # host allowlist (allow Render preview hosts by default)
    host = request.host.split(':')[0]
    allowed_hosts_env = os.environ.get('ALLOWED_HOSTS', '')
    allowed_hosts = [h.strip() for h in allowed_hosts_env.split(',') if h.strip()] if allowed_hosts_env else []
    if allowed_hosts and not (host in allowed_hosts or host.endswith('.onrender.com')):
        logger.warning(f"Host not allowed: {host}")
        return jsonify({'error': 'Host not allowed'}), 403

    # real client IP
    remote = request.headers.get('CF-Connecting-IP') \
             or (request.headers.get('X-Forwarded-For', '').split(',')[0].strip() if request.headers.get('X-Forwarded-For') else None) \
             or request.remote_addr or ''

    # Cloudflare strict enforcement only for API/admin by default
    if STRICT_CLOUDFLARE:
        cidrs = get_cloudflare_cidrs()
        if cidrs:
            should_enforce = (not CF_ONLY_API_LOCK) or request.path.startswith('/api/') or request.path.startswith('/admin')
            if should_enforce:
                if request.headers.get('CF-Ray'):
                    if not ip_in_cidrs(remote, cidrs):
                        logger.warning(f"Request from non-Cloudflare IP blocked: {remote}")
                        return jsonify({'error': 'Access denied'}), 403
                else:
                    logger.warning("CF-Ray header missing while STRICT_CLOUDFLARE active - allowing request for safety")
        else:
            logger.info("Cloudflare CIDRs unavailable; skipping strict enforcement")

    # Proxy detection for API endpoints
    if request.path.startswith('/api/') and detect_proxy_or_forwarding(request.headers):
        logger.warning("Proxy/VPN detected for API call, blocking")
        return jsonify({'error': 'Proxy or suspicious headers detected'}), 403

    # POST SQLi basic check
    if request.method == 'POST':
        data = request.form or request.get_json(silent=True) or {}
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, str) and check_sql_injection(v):
                    logger.warning(f"SQLi attempt: {k} -> {v[:80]}")
                    return jsonify({'error': 'Security violation'}), 403

# ---------- After-request security headers ----------
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Permissions-Policy'] = 'geolocation=(),camera=()'
    resp.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    # Allow inline because many templates are single-file; still restrict external to https:
    resp.headers['Content-Security-Policy'] = "default-src 'self' https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:;"
    return resp

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

# ---------- API endpoints list (unchanged) ----------
API_ENDPOINTS = {
    # FREE
    "tc_sorgu1": "https://apinabi.onrender.com/tc/text?tc={tc}",
    "tc_sorgu2": "https://apinabi.onrender.com/tc2/text?tc={tc}",
    "adsoyad_sorgu": "https://apinabi.onrender.com/text?name={name}&surname={surname}",
    # VIP (rest omitted for brevity but should be kept same as your original)
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

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,)).fetchone()
        if user:
            stored = user['password']
            try:
                if check_password_hash(stored, password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['user_type'] = user['user_type']
                    conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user['id']))
                    conn.commit()
                    conn.close()
                    logger.info(f"User logged in: {username}")
                    return redirect(url_for('dashboard'))
                else:
                    # legacy plaintext fallback: rehash on success
                    if stored == password:
                        newhash = generate_password_hash(password)
                        conn.execute('UPDATE users SET password = ? WHERE id = ?', (newhash, user['id']))
                        conn.commit()
                        session['user_id'] = user['id']
                        session['username'] = user['username']
                        session['user_type'] = user['user_type']
                        conn.execute('UPDATE users SET last_login = ? WHERE id = ?', (datetime.now(), user['id']))
                        conn.commit()
                        conn.close()
                        logger.info(f"User logged in (legacy pwd rehashed): {username}")
                        return redirect(url_for('dashboard'))
            except Exception as e:
                logger.error(f"Password check error: {e}")
        conn.close()
        return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        # optional honeypot
        if request.form.get('hp_field'):
            return render_template('register.html', error='Bot tespit edildi. Kayıt engellendi')

        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        email = sanitize_input(request.form.get('email', ''))

        if len(username) < 3 or len(password) < 6:
            return render_template('register.html', error='Kullanıcı adı en az 3, şifre en az 6 karakter olmalı')

        conn = get_db()
        try:
            hashed = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password, email, user_type) VALUES (?, ?, ?, ?)',
                         (username, hashed, email, 'free'))
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            conn.close()
            logger.info(f"New user registered: {username}")
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            conn.close()
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
    today_count = conn.execute('SELECT COUNT(*) FROM query_history WHERE user_id = ? AND DATE(created_at) = ?',
                               (session['user_id'], today)).fetchone()[0]

    recent_queries = conn.execute('SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
                                  (session['user_id'],)).fetchall()
    conn.close()

    return render_template('dashboard.html', user=user, total_users=total_users, vip_users=vip_users,
                           free_users=free_users, today_count=today_count, recent_queries=recent_queries)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/subscription')
@login_required
def subscription():
    return render_template('subscription.html')

@app.route('/market')
@login_required
def market():
    return render_template('market.html')

@app.route('/profile')
@login_required
def profile():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    query_history = conn.execute('SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
                                 (session['user_id'],)).fetchall()
    conn.close()
    return render_template('profile.html', user=user, query_history=query_history)

@app.route('/history')
@login_required
def history():
    conn = get_db()
    query_history = conn.execute('SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC',
                                  (session['user_id'],)).fetchall()
    today = datetime.now().strftime('%Y-%m-%d')
    today_count = conn.execute('SELECT COUNT(*) FROM query_history WHERE user_id = ? AND DATE(created_at) = ?',
                               (session['user_id'], today)).fetchone()[0]
    week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    weekly_count = conn.execute('SELECT COUNT(*) FROM query_history WHERE user_id = ? AND DATE(created_at) >= ?',
                                (session['user_id'], week_ago)).fetchone()[0]
    conn.close()
    return render_template('history.html', query_history=query_history, today_count=today_count, weekly_count=weekly_count)

@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    total_queries = conn.execute('SELECT COUNT(*) FROM query_history').fetchone()[0]
    conn.close()
    return render_template('admin.html', users=users, total_queries=total_queries)

@app.route('/admin/refresh_cf_ips', methods=['POST'])
@admin_required
def admin_refresh_cf_ips():
    new = fetch_cloudflare_ips()
    return jsonify({"success": True, "timestamp": new.get('timestamp'), "ipv4_count": len(new.get('ipv4', [])), "ipv6_count": len(new.get('ipv6', []))})

@app.route('/query/<query_key>')
@login_required
def query_page(query_key):
    if query_key not in QUERY_NAMES.values():
        return "Geçersiz sorgu!", 404

    conn = get_db()
    user = conn.execute('SELECT user_type FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    free_queries = ['tc_sorgu1', 'tc_sorgu2', 'adsoyad_sorgu']
    if query_key not in free_queries and user['user_type'] not in ('vip', 'admin'):
        return redirect(url_for('subscription'))

    display_name = [k for k, v in QUERY_NAMES.items() if v == query_key][0]
    return render_template('query.html', query_name=display_name, query_key=query_key, user_type=user['user_type'])

@app.route('/api/execute_query', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def execute_query():
    try:
        data = request.get_json(silent=True) or {}
        query_key = data.get('query_key')
        params = data.get('params', {})

        for k in list(params.keys()):
            if isinstance(params[k], str):
                params[k] = sanitize_input(params[k])

        conn = get_db()
        user = conn.execute('SELECT user_type FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        free_queries = ['tc_sorgu1', 'tc_sorgu2', 'adsoyad_sorgu']
        if query_key not in API_ENDPOINTS:
            conn.close()
            return jsonify({"error": "Geçersiz sorgu anahtarı"}), 400
        if query_key not in free_queries and user['user_type'] not in ('vip', 'admin'):
            conn.close()
            return jsonify({"success": False, "error": "Bu sorgu VIP üyelik gerektirir", "redirect": "/subscription"}), 403

        api_url = API_ENDPOINTS[query_key]
        for key, value in params.items():
            api_url = api_url.replace(f"{{{key}}}", str(value))

        # pass client IP downstream
        client_ip = request.headers.get('CF-Connecting-IP') or request.headers.get('X-Forwarded-For', request.remote_addr)
        headers = {'User-Agent': 'SorguPanel/1.0', 'X-Forwarded-For': client_ip}

        # defensive proxy check
        if detect_proxy_or_forwarding(request.headers):
            conn.close()
            return jsonify({'error': 'Proxy or suspicious headers detected'}), 403

        response = requests.get(api_url, headers=headers, timeout=15)

        conn.execute('INSERT INTO query_history (user_id, query_type, query_params, result) VALUES (?, ?, ?, ?)',
                     (session['user_id'], query_key, json.dumps(params), response.text[:1000]))
        conn.execute('UPDATE users SET query_count = query_count + 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
        conn.close()

        return jsonify({"success": True, "response": response.text})
    except requests.exceptions.Timeout:
        return jsonify({"success": False, "error": "API timeout - servis yanıt vermiyor"}), 504
    except Exception as e:
        logger.error(f"Query error: {str(e)}")
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
    conn.close()
    return jsonify({'success': True, 'total_users': total_users, 'vip_users': vip_users, 'free_users': free_users, 'username': session.get('username', '')})

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "service": "Sorgu Paneli API", "version": "1.0.2", "timestamp": datetime.now().isoformat()})

# Admin API endpoints
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    users_list = [dict(u) for u in users]
    return jsonify(users_list)

@app.route('/api/admin/update_user', methods=['POST'])
@admin_required
def admin_update_user():
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    user_type = data.get('user_type')
    if not user_id or not user_type:
        return jsonify({'success': False, 'error': 'Eksik parametre'}), 400
    if user_type not in ['free', 'vip', 'admin']:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı tipi'}), 400
    conn = get_db()
    conn.execute('UPDATE users SET user_type = ? WHERE id = ?', (user_type, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# Jinja2 helper
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

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return render_template('500.html'), 500

# Run
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    init_db()
    app.run(host='0.0.0.0', port=port, debug=False)
