import os
import json
import hashlib
import base64
import requests
from datetime import datetime, timedelta, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv

load_dotenv()

# === INIT ===
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['STEAM_OPENID_RETURN_URL'] = os.environ.get('STEAM_OPENID_RETURN_URL', 'https://replaymind.onrender.com/auth/steam')
app.config['OPENROUTER_API_KEY'] = os.environ.get('OPENROUTER_API_KEY')
app.config['YOOKASSA_SHOP_ID'] = os.environ.get('YOOKASSA_SHOP_ID')
app.config['YOOKASSA_SECRET_KEY'] = os.environ.get('YOOKASSA_SECRET_KEY')
app.config['ADMIN_STEAM_ID'] = os.environ.get('ADMIN_STEAM_ID')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# === MODELS ===
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    steam_id = db.Column(db.String(20), unique=True, nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    premium_until = db.Column(db.DateTime, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    blocked_until = db.Column(db.DateTime, nullable=True)
    blocked_reason = db.Column(db.String(255))
    free_requests_used = db.Column(db.Integer, default=0)
    last_reset_week = db.Column(db.Date, default=lambda: datetime.now(timezone.utc).date())

    def reset_if_needed(self):
        today = datetime.now(timezone.utc).date()
        week_start = today - timedelta(days=today.weekday())
        if self.last_reset_week != week_start:
            self.free_requests_used = 0
            self.last_reset_week = week_start
            db.session.commit()

    @property
    def weekly_quota(self):
        if self.is_premium and (self.premium_until is None or self.premium_until > datetime.now(timezone.utc)):
            return float('inf')
        self.reset_if_needed()
        return max(0, 5 - self.free_requests_used)

    @property
    def is_blocked(self):
        if self.blocked_until is None:
            return False
        if self.blocked_until == datetime.max.replace(tzinfo=timezone.utc):
            return True
        return datetime.now(timezone.utc) < self.blocked_until

    def block_temporarily(self, days=7, reason=""):
        self.blocked_until = datetime.now(timezone.utc) + timedelta(days=days)
        self.blocked_reason = reason

    def block_permanently(self, reason=""):
        # Используем максимальную дату с временной зоной
        self.blocked_until = datetime.max.replace(tzinfo=timezone.utc)
        self.blocked_reason = reason

    def unblock(self):
        self.blocked_until = None
        self.blocked_reason = None

class AIRequest(db.Model):
    __tablename__ = 'ai_requests'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    game = db.Column(db.String(100), nullable=False)
    description_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_premium = db.Column(db.Boolean, default=False)

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    yookassa_payment_id = db.Column(db.String(100), unique=True, nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(3), default='RUB')
    status = db.Column(db.String(20), default='pending')
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# === HELPERS ===
def anonymize_text(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Доступ запрещён", "error")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# === ROUTES ===
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_blocked:
            flash("Ваш аккаунт заблокирован", "error")
            logout_user()
            return redirect(url_for('login'))
        return render_template('index.html', quota=current_user.weekly_quota, is_premium=current_user.is_premium)
    return render_template('login.html')

@app.route('/login')
def login():
    return redirect(
        "https://steamcommunity.com/openid/login?"
        "openid.ns=http://specs.openid.net/auth/2.0&"
        "openid.mode=checkid_setup&"
        f"openid.return_to={app.config['STEAM_OPENID_RETURN_URL']}&"
        "openid.realm=https://replaymind.onrender.com&"
        "openid.identity=http://specs.openid.net/auth/2.0/identifier_select&"
        "openid.claimed_id=http://specs.openid.net/auth/2.0/identifier_select"
    )

@app.route('/auth/steam')
def steam_auth():
    validate_url = "https://steamcommunity.com/openid/login"
    params = {
        'openid.assoc_handle': request.args.get('openid.assoc_handle'),
        'openid.signed': request.args.get('openid.signed'),
        'openid.sig': request.args.get('openid.sig'),
        'openid.ns': 'http://specs.openid.net/auth/2.0',
    }
    signed = request.args.get('openid.signed').split(',')
    for item in signed:
        params[f'openid.{item}'] = request.args.get(f'openid.{item}')
    params['openid.mode'] = 'check_authentication'

    response = requests.post(validate_url, data=params)
    if 'is_valid:true' in response.text:
        steam_id = request.args.get('openid.claimed_id').split('/')[-1]
        user = User.query.filter_by(steam_id=steam_id).first()
        if not user:
            user = User(steam_id=steam_id)
            if steam_id == app.config.get('ADMIN_STEAM_ID'):
                user.is_admin = True
            db.session.add(user)
            db.session.commit()
        if user.is_blocked:
            flash("Аккаунт заблокирован", "error")
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    flash("Ошибка авторизации", "error")
    return redirect(url_for('login'))

@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    if current_user.is_blocked:
        return jsonify({"error": "Аккаунт заблокирован"}), 403
    if not current_user.is_premium and current_user.weekly_quota <= 0:
        return jsonify({"error": "Лимит исчерпан"}), 429

    game = request.json.get('game')
    description = request.json.get('description')
    if not game or not description:
        return jsonify({"error": "Заполните все поля"}), 400

    req = AIRequest(
        user_id=current_user.id,
        game=game,
        description_hash=anonymize_text(description),
        is_premium=current_user.is_premium
    )
    db.session.add(req)

    prompt = f"Ты эксперт по {game}. Пользователь пишет: '{description}'. Ответь в JSON: {{\"advice\":\"...\",\"mistake\":\"...\"}}"
    headers = {"Authorization": f"Bearer {app.config['OPENROUTER_API_KEY']}", "Content-Type": "application/json"}
    payload = {"model": "meta-llama/llama-3.1-8b-instruct:free", "messages": [{"role": "user", "content": prompt}]}

    resp = requests.post("https://openrouter.ai/api/v1/chat/completions", json=payload, headers=headers)
    if resp.status_code != 200:
        return jsonify({"error": "Ошибка ИИ"}), 500

    try:
        content = resp.json()['choices'][0]['message']['content']
        result = json.loads(content)
        if not current_user.is_premium:
            current_user.free_requests_used += 1
        db.session.commit()
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": "Ошибка парсинга", "raw": content}), 500

@app.route('/premium')
@login_required
def premium():
    return render_template('premium.html')

@app.route('/create-payment', methods=['POST'])
@login_required
def create_payment():
    shop_id = app.config['YOOKASSA_SHOP_ID']
    secret = app.config['YOOKASSA_SECRET_KEY']
    auth = base64.b64encode(f"{shop_id}:{secret}".encode()).decode()
    payload = {
        "amount": {"value": "300.00", "currency": "RUB"},
        "confirmation": {"type": "redirect", "return_url": "https://replaymind.onrender.com/"},
        "description": "ReplayMind Premium — 300 ₽/мес",
        "metadata": {"user_id": str(current_user.id)},
        "capture": True
    }
    resp = requests.post(
        "https://api.yookassa.ru/v3/payments",
        json=payload,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"}
    )
    if resp.status_code == 201:
        data = resp.json()
        payment = Payment(
            user_id=current_user.id,
            yookassa_payment_id=data['id'],
            amount=float(data['amount']['value']),
            currency=data['amount']['currency'],
            status=data['status'],
            description=payload['description']
        )
        db.session.add(payment)
        db.session.commit()
        return redirect(data['confirmation']['confirmation_url'])
    flash("Ошибка создания платежа", "error")
    return redirect(url_for('premium'))

@app.route('/yookassa-webhook', methods=['POST'])
def yookassa_webhook():
    event = request.json
    if event.get('event') == 'payment.succeeded':
        obj = event['object']
        payment = Payment.query.filter_by(yookassa_payment_id=obj['id']).first()
        if payment:
            payment.status = 'succeeded'
            user = payment.user
            user.is_premium = True
            user.premium_until = datetime.now(timezone.utc) + timedelta(days=30)
            db.session.commit()
    return '', 200

# === ADMIN PANEL ===
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    from sqlalchemy import func
    total_users = User.query.count()
    premium_users = User.query.filter(User.is_premium == True).count()
    total_requests = AIRequest.query.count()
    requests_last_7d = AIRequest.query.filter(AIRequest.created_at >= datetime.now(timezone.utc) - timedelta(days=7)).count()
    total_payments = Payment.query.filter_by(status='succeeded').count()
    revenue = db.session.query(func.sum(Payment.amount)).filter_by(status='succeeded').scalar() or 0
    return render_template('admin/dashboard.html',
        total_users=total_users,
        premium_users=premium_users,
        total_requests=total_requests,
        requests_last_7d=requests_last_7d,
        total_payments=total_payments,
        revenue=round(revenue, 2)
    )

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    users = User.query.order_by(User.created_at.desc()).paginate(page=page, per_page=20)
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>/block', methods=['POST'])
@login_required
@admin_required
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    action = request.form['action']
    reason = request.form.get('reason', 'Не указано')
    if action == 'temp':
        days = int(request.form.get('days', 7))
        user.block_temporarily(days=days, reason=reason)
    elif action == 'perm':
        user.block_permanently(reason=reason)
    elif action == 'unblock':
        user.unblock()
    db.session.commit()
    flash("Изменения сохранены", "success")
    return redirect(url_for('admin_users'))

@app.route('/admin/payments')
@login_required
@admin_required
def admin_payments():
    status = request.args.get('status', 'all')
    page = request.args.get('page', 1, type=int)
    query = Payment.query
    if status != 'all':
        query = query.filter_by(status=status)
    payments = query.order_by(Payment.created_at.desc()).paginate(page=page, per_page=20)
    return render_template('admin/payments.html', payments=payments, status=status)

# === DATABASE INIT ===
# Инициализация БД при старте приложения (совместимо с Flask 3.x)
with app.app_context():
    db.create_all()
