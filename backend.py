# backend.py - RENDER UYUMLU
import os
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import json
import secrets
from datetime import datetime, timedelta
import sqlite3
from functools import wraps
import logging

# Logging setup for Render
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='static', template_folder='templates')

# Render için güvenli secret key
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# CORS ayarları
CORS(app, resources={r"/*": {"origins": "*"}})

# Rate Limiter - Render için daha geniş limitler
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour", "30 per minute"],
    storage_uri="memory://"  # Render'da redis yok, memory kullan
)

# SQLite path - Render için
DATABASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')

# Database bağlantısı
def get_db():
    """Database bağlantısı - Render uyumlu"""
    conn = sqlite3.connect(DATABASE_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    # Foreign key desteği
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Database tablolarını oluştur"""
    conn = get_db()
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

    # Kurucu bilgileri - Sabit kullanıcı
    c.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if c.fetchone()[0] == 0:
        c.execute('''
            INSERT INTO users (username, password, email, user_type, is_active)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin123', 'admin@sorgupaneli.com', 'admin', 1))
        logger.info("Admin user created")

    conn.commit()
    conn.close()
    logger.info("Database initialized")

# Basitleştirilmiş güvenlik fonksiyonları - Render için
def check_sql_injection(input_string):
    """Basit SQL injection kontrolü"""
    if not input_string:
        return False
    
    sql_keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union']
    input_lower = input_string.lower()
    
    for keyword in sql_keywords:
        if f'{keyword} ' in input_lower or f' {keyword}' in input_lower:
            return True
    return False

def sanitize_input(input_string):
    """Input temizleme"""
    if not input_string:
        return ""
    
    import re
    # HTML tag'leri temizle
    clean = re.sub(r'<[^>]*>', '', input_string)
    # Max uzunluk
    if len(clean) > 500:
        clean = clean[:500]
    return clean

# Basit güvenlik middleware - Render için optimize
@app.before_request
def security_checks():
    """Basit güvenlik kontrolleri - Render için optimize"""
    # SQL injection kontrolü (sadece POST)
    if request.method == 'POST':
        if request.form:
            for key, value in request.form.items():
                if isinstance(value, str) and check_sql_injection(value):
                    logger.warning(f"SQL injection attempt: {key}={value[:50]}")
                    return jsonify({
                        'error': 'Security violation',
                        'message': 'Invalid input detected'
                    }), 403

# Decorator'lar
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db()
        user = conn.execute('SELECT user_type FROM users WHERE id = ?', 
                          (session['user_id'],)).fetchone()
        conn.close()
        
        if user and user['user_type'] != 'admin':
            flash('Admin yetkisi gerekiyor!', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# API Endpoint'leri
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
    # FREE sorgular
    "TC Sorgu 1": "tc_sorgu1",
    "TC Sorgu 2": "tc_sorgu2",
    "Ad-Soyad Sorgu": "adsoyad_sorgu",
    
    # VIP sorgular
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

# ROUTES
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = sanitize_input(request.form.get('password', ''))
        
        conn = get_db()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password = ? AND is_active = 1',
            (username, password)
        ).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['user_type'] = user['user_type']
            
            # Last login update
            conn = get_db()
            conn.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                        (datetime.now(), user['id']))
            conn.commit()
            conn.close()
            
            logger.info(f"User logged in: {username}")
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error='Geçersiz kullanıcı adı veya şifre')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username', ''))
        password = sanitize_input(request.form.get('password', ''))
        email = sanitize_input(request.form.get('email', ''))
        
        if len(username) < 3 or len(password) < 6:
            return render_template('register.html', error='Kullanıcı adı en az 3, şifre en az 6 karakter olmalı')
        
        conn = get_db()
        try:
            conn.execute(
                'INSERT INTO users (username, password, email, user_type) VALUES (?, ?, ?, ?)',
                (username, password, email, 'free')
            )
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
    today_count = conn.execute(
        'SELECT COUNT(*) FROM query_history WHERE user_id = ? AND DATE(created_at) = ?',
        (session['user_id'], today)
    ).fetchone()[0]
    
    recent_queries = conn.execute(
        'SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 5',
        (session['user_id'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html',
                         user=user,
                         total_users=total_users,
                         vip_users=vip_users,
                         free_users=free_users,
                         today_count=today_count,
                         recent_queries=recent_queries)

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
    
    query_history = conn.execute(
        'SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 10',
        (session['user_id'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('profile.html', user=user, query_history=query_history)

@app.route('/history')
@login_required
def history():
    conn = get_db()
    
    query_history = conn.execute(
        'SELECT * FROM query_history WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    
    today = datetime.now().strftime('%Y-%m-%d')
    today_count = conn.execute(
        'SELECT COUNT(*) FROM query_history WHERE user_id = ? AND DATE(created_at) = ?',
        (session['user_id'], today)
    ).fetchone()[0]
    
    week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    weekly_count = conn.execute(
        'SELECT COUNT(*) FROM query_history WHERE user_id = ? AND DATE(created_at) >= ?',
        (session['user_id'], week_ago)
    ).fetchone()[0]
    
    conn.close()
    
    return render_template('history.html', 
                         query_history=query_history,
                         today_count=today_count,
                         weekly_count=weekly_count)

@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    total_queries = conn.execute('SELECT COUNT(*) FROM query_history').fetchone()[0]
    conn.close()
    
    return render_template('admin.html', users=users, total_queries=total_queries)

@app.route('/query/<query_key>')
@login_required
def query_page(query_key):
    if query_key not in QUERY_NAMES.values():
        return "Geçersiz sorgu!", 404
    
    conn = get_db()
    user = conn.execute('SELECT user_type FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    # VIP sorgu kontrolü
    vip_queries = list(API_ENDPOINTS.keys())
    # FREE sorguları listeden çıkar
    free_queries = ['tc_sorgu1', 'tc_sorgu2', 'adsoyad_sorgu']
    vip_queries = [q for q in vip_queries if q not in free_queries]
    
    if query_key in vip_queries and user['user_type'] != 'vip' and user['user_type'] != 'admin':
        return redirect(url_for('subscription'))
    
    display_name = [k for k, v in QUERY_NAMES.items() if v == query_key][0]
    
    return render_template('query.html',
                         query_name=display_name,
                         query_key=query_key,
                         user_type=user['user_type'])

@app.route('/api/execute_query', methods=['POST'])
@login_required
@limiter.limit("30 per minute")  # Render için daha yüksek limit
def execute_query():
    try:
        data = request.json
        query_key = data.get('query_key')
        params = data.get('params', {})
        
        # Input sanitization
        for key in params:
            if isinstance(params[key], str):
                params[key] = sanitize_input(params[key])
        
        # VIP kontrolü
        vip_queries = list(API_ENDPOINTS.keys())
        free_queries = ['tc_sorgu1', 'tc_sorgu2', 'adsoyad_sorgu']
        vip_queries = [q for q in vip_queries if q not in free_queries]
        
        if query_key in vip_queries:
            conn = get_db()
            user = conn.execute('SELECT user_type FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()
            
            if user['user_type'] != 'vip' and user['user_type'] != 'admin':
                return jsonify({
                    'success': False,
                    'error': 'Bu sorgu VIP üyelik gerektirir',
                    'redirect': '/subscription'
                }), 403
        
        if query_key not in API_ENDPOINTS:
            return jsonify({"error": "Geçersiz sorgu anahtarı"}), 400
        
        api_url = API_ENDPOINTS[query_key]
        
        for key, value in params.items():
            api_url = api_url.replace(f"{{{key}}}", str(value))
        
        # API call with timeout
        response = requests.get(api_url, timeout=15)
        
        # Save to history
        conn = get_db()
        conn.execute(
            'INSERT INTO query_history (user_id, query_type, query_params, result) VALUES (?, ?, ?, ?)',
            (session['user_id'], query_key, json.dumps(params), response.text[:1000])
        )
        
        conn.execute(
            'UPDATE users SET query_count = query_count + 1 WHERE id = ?',
            (session['user_id'],)
        )
        
        conn.commit()
        conn.close()
        
        return jsonify({
            "success": True,
            "response": response.text
        })
        
    except requests.exceptions.Timeout:
        return jsonify({
            "success": False,
            "error": "API timeout - servis yanıt vermiyor"
        }), 504
    except Exception as e:
        logger.error(f"Query error: {str(e)}")
        return jsonify({
            "success": False,
            "error": "Sorgu çalıştırılırken bir hata oluştu"
        }), 500

@app.route('/api/get_query_info/<query_key>')
@login_required
def get_query_info(query_key):
    if query_key not in API_ENDPOINTS:
        return jsonify({"error": "Geçersiz sorgu anahtarı"}), 404
    
    api_url = API_ENDPOINTS[query_key]
    
    import re
    params = re.findall(r'\{(.*?)\}', api_url)
    
    return jsonify({
        "query_key": query_key,
        "api_url_template": api_url,
        "required_params": params
    })

@app.route('/api/dashboard_stats')
@login_required
def dashboard_stats():
    conn = get_db()
    total_users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    vip_users = conn.execute('SELECT COUNT(*) FROM users WHERE user_type = "vip"').fetchone()[0]
    free_users = conn.execute('SELECT COUNT(*) FROM users WHERE user_type = "free"').fetchone()[0]
    conn.close()
    
    return jsonify({
        'success': True,
        'total_users': total_users,
        'vip_users': vip_users,
        'free_users': free_users,
        'username': session.get('username', '')
    })

@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "Sorgu Paneli API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    })

# Custom Jinja2 filters
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

# Render için gerekli
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    init_db()  # Initialize database
    app.run(host='0.0.0.0', port=port, debug=False)  # Render'da debug=False olmalı
