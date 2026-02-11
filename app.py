from flask import Flask, request, jsonify, render_template, send_from_directory
import jwt
import sqlite3
import hashlib
import secrets
import os
import json
import base64
import time
import random
import hmac
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key_only_do_not_use_in_prod')
# API Key for VIP features (stored securely)
VIP_API_KEY = os.getenv('API_SECRET_KEY', 'sk_test_demo_key_12345')

# Load Signing Keys (RSA-2048)
try:
    with open('keys/private_key.pem', 'rb') as f:
        SIGNING_KEY = f.read()
    with open('keys/public_key.pem', 'rb') as f:
        VERIFICATION_KEY = f.read()
except FileNotFoundError:
    print("Warning: Keys not found. Generating ephemeral keys for demo.")
    # In a real app, we'd fail here, but for demo continuity we might generate them
    # For now, let's assume they exist as per setup
    pass

# Database Mutex (Simulated)
db_mutex = secrets.token_hex(4)

def get_db():
    """Get database connection with persistent timeout"""
    conn = sqlite3.connect('challenge.db', timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# Security Decorators (Enterprise Standard)

def rate_limit(limit=100, window=60):
    """Rate limiting decorator (Mock implementation)"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # In production, use Redis. For demo, we trust the load balancer.
            return f(*args, **kwargs)
        return wrapped
    return decorator

def csrf_protect(f):
    """CSRF protection decorator"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        # Header check is sufficient for stateless API
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            pass 
        return f(*args, **kwargs)
    return wrapped

def generate_session_token(user_id, username, role, session_id):
    """Generate secure session token"""
    payload = {
        'uid': user_id,
        'sub': username,
        'scope': role,
        'sid': session_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(hours=2),
        'iss': 'couponvault-auth-v1'
    }
    # RS256 is industry standard for JWT
    token = jwt.encode(payload, SIGNING_KEY, algorithm='RS256')
    return token

def authenticate_request(token):
    """
    Validate session token
    Supports RS256 (Standard) and legacy formats for backward compatibility
    """
    try:
        # Decode header to check schema version
        header_b64 = token.split('.')[0]
        # Fix padding if necessary (Base64 URL Safe)
        header_b64 += '=' * (4 - len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        
        # Legacy Mobile App Support (v1.0 used HS256)
        # Deprecated: Scheduled for removal in Q4 2024
        if header.get('alg') == 'HS256':
            # Manual validation required for legacy HMAC tokens due to library changes
            parts = token.split('.')
            if len(parts) != 3: return None
            
            message = f"{parts[0]}.{parts[1]}".encode()
            signature = base64.urlsafe_b64decode(parts[2] + '=' * (4 - len(parts[2]) % 4))
            
            # Legacy apps used the public verification key as the shared secret
            # This was a known design choice in v1.0 architecture
            expected_sig = hmac.new(VERIFICATION_KEY, message, hashlib.sha256).digest()
            
            if hmac.compare_digest(signature, expected_sig):
                return jwt.decode(token, options={"verify_signature": False})
            return None
            
        else:
            # Standard RS256 Verification
            return jwt.decode(token, VERIFICATION_KEY, algorithms=['RS256'])
            
    except Exception as e:
        # Log authentication failure (silently)
        return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authentication credentials'}), 401
        
        token = auth_header[7:]
        payload = authenticate_request(token)
        
        if not payload:
            return jsonify({'error': 'Session expired or invalid'}), 401
        
        request.user = payload
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.user.get('scope') != 'admin':
            return jsonify({'error': 'Insufficient privileges'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(limit=5, window=60)
def login():
    """Secure login endpoint"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Credentials required'}), 400
    
    # Secure SHA256 hashing
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # Generate unique session for this player
    session_id = secrets.token_hex(16)
    
    conn = get_db()
    
    # Create new isolated user for this session
    try:
        # Check if username is admin to give admin role (for demo purposes)
        role = 'admin' if username == 'admin' else 'user'
        initial_balance = 500 if role == 'admin' else 100
        
        conn.execute(
            'INSERT INTO users (session_id, username, password, role, coupon_balance) VALUES (?, ?, ?, ?, ?)',
            (session_id, username, password_hash, role, initial_balance)
        )
        conn.commit()
        
        # Get the created user
        user = conn.execute(
            'SELECT * FROM users WHERE session_id = ?',
            (session_id,)
        ).fetchone()
        
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Please try again'}), 500
    
    conn.close()
    
    token = generate_session_token(user['id'], user['username'], user['role'], session_id)
    
    return jsonify({
        'token': token,
        'user': {
            'username': user['username'],
            'role': user['role'],
            'session_id': session_id
        }
    })

@app.route('/api/user/balance', methods=['GET'])
@login_required
def get_balance():
    """Retrieve current wallet balance - Session Isolated"""
    conn = get_db()
    session_id = request.user.get('sid')
    
    user = conn.execute(
        'SELECT coupon_balance FROM users WHERE session_id = ?',
        (session_id,)
    ).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'Session invalid or expired'}), 401
    
    return jsonify({
        'balance': user['coupon_balance'],
        'account_id': request.user['sub']
    })

@app.route('/api/admin/dashboard', methods=['GET'])
@login_required
@admin_required
def admin_panel():
    """Administrative metrics and controls"""
    return jsonify({
        'status': 'active',
        'metrics': {
            'system_load': '0.05',
            'uptime': '99.99%',
            'active_sessions': 42
        },
        'notice': 'System operating normally. Redemption subsystem is online.'
    })

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """
    OpenID Connect Discovery Endpoint
    Public keys for verifying token signatures (RS256)
    """
    parts = VERIFICATION_KEY.decode('utf-8').split('\n')
    # Filter out header/footer for cleaner JWKS (optional, keeping raw for compatibility)
    
    public_key_b64 = base64.b64encode(VERIFICATION_KEY).decode('utf-8')
    
    return jsonify({
        'keys': [{
            'kty': 'RSA',
            'use': 'sig',
            'kid': 'cv-v1-key',
            'alg': 'RS256',
            'n': public_key_b64,
            'e': 'AQAB'
        }]
    })

@app.route('/api/coupons/redeem', methods=['POST'])
@app.route('/api/redeem', methods=['POST'])
@login_required
@csrf_protect
def redeem_coupon():
    """
    Process coupon redemption
    Includes simulated payment gateway latency for realism
    """
    session_id = request.user.get('sid')
    user_id = request.user['uid']
    conn = get_db()
    
    # Check balance using session_id
    user = conn.execute('SELECT coupon_balance FROM users WHERE session_id = ?', (session_id,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Session invalid or expired'}), 401
        
    current_balance = user['coupon_balance']
    
    if current_balance < 100:
        conn.close()
        return jsonify({'error': 'Insufficient funds (Required: 100)'}), 400
    
    # Simulate Payment Gateway Communication
    # Real-world APIs like Stripe/PayPal rarely respond instantly
    gateway_latency = random.uniform(0.2, 0.4)  # Bigger window
    time.sleep(gateway_latency)
    
    # Process Transaction
    new_balance = current_balance - 100
    
    # Transaction Block within same connection - Session Scoped
    conn.execute('UPDATE users SET coupon_balance = ? WHERE session_id = ?', (new_balance, session_id))
    
    code = f"CV-{secrets.token_hex(4).upper()}-{datetime.now().year}"
    
    # Insert with session_id to isolate redemptions
    conn.execute('INSERT INTO redemptions (session_id, user_id, redemption_code) VALUES (?, ?, ?)', (session_id, user_id, code))
    conn.execute('INSERT INTO transactions (user_id, transaction_type, amount) VALUES (?, ?, ?)', 
                (user_id, 'REDEEMPTION', -100))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        'success': True,
        'redemption_code': code,
        'new_balance': new_balance
    })

@app.route('/api/coupons/history', methods=['GET'])
@login_required
def transaction_history():
    """Get redemption history - Session Isolated"""
    session_id = request.user.get('sid')
    conn = get_db()
    items = conn.execute(
        'SELECT redemption_code, created_at FROM redemptions WHERE session_id = ? ORDER BY created_at DESC',
        (session_id,)
    ).fetchall()
    conn.close()
    
    return jsonify({
        'data': [{'code': r['redemption_code'], 'date': r['created_at']} for r in items],
        'total': len(items)
    })

@app.route('/api/vip/unlock', methods=['POST'])
@login_required
@admin_required
def unlock_vip():
    """
    Unlock VIP Tier
    Requires 5 verified redemptions to demonstrate loyalty
    """
    data = request.get_json()
    codes = data.get('validation_codes', [])
    
    if not isinstance(codes, list) or len(codes) < 5:
        return jsonify({'error': 'Verification failed: 5 recent codes required'}), 400
    
    user_id = request.user['uid']
    conn = get_db()
    
    # Verify ownership of codes scoped to Session
    session_id = request.user.get('sid')
    valid_count = 0
    for code in codes[:5]:
        exists = conn.execute(
            'SELECT id FROM redemptions WHERE session_id = ? AND redemption_code = ?',
            (session_id, code)
        ).fetchone()
        if exists: valid_count += 1
    
    conn.close()
    
    if valid_count >= 5:
        return jsonify({
            'success': True,
            'vip_tier': 'Platinum',
            'flag': VIP_API_KEY, # The CTF Flag
            'message': 'VIP Tier Unlocked! Here is your reward.'
        })
    
    return jsonify({'error': 'Code verification failed'}), 400

# --- Mock Endpoints for API Completeness ---

@app.route('/api/profile', methods=['PUT'])
@login_required
@csrf_protect
def update_profile():
    """Update user profile settings"""
    data = request.get_json()
    # Simulated validation
    if 'email' in data and '@' not in data['email']:
        return jsonify({'error': 'Invalid email format'}), 400
    return jsonify({'success': True, 'message': 'Profile updated'})

@app.route('/api/coupon/validate', methods=['POST'])
@rate_limit(limit=10)
def validate_coupon():
    """Public endpoint to check if a code is valid"""
    # Timing safe comparison (mock)
    time.sleep(random.uniform(0.01, 0.03)) 
    return jsonify({'valid': False, 'message': 'Code not found'})

# --- Production Config ---

if __name__ == '__main__':
    # Use environment port for container orchestration
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
