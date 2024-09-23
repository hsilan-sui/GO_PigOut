import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, url_for, abort, redirect, session
from authlib.integrations.flask_client import OAuth
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from dotenv import load_dotenv
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

# 从 models.py 中导入 db 和模型
from models import db, Customer, DeliveryPerson, Vendor, MenuItem, Cart, CartItem, Order, OrderItem, Payment, Address

# 设定允许HTTP的环境变量（仅在本地开发环境中）
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

load_dotenv()  # 自动加载 .env 文件中的变量

app = Flask(__name__)

# 配置邮件发送服务
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # 用于发送邮件的邮箱
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # App专用密码或你的邮箱密码
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  # 默认发信人

mail = Mail(app)

# 初始化 Google OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_OAUTH_ID'),
    client_secret=os.getenv('GOOGLE_OAUTH_KEY'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={'scope': 'openid profile email'}
)

# 配置 PostgreSQL 数据库 URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres@localhost:5432/pigout_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SECRET_KEY 用于加密 session 和生成 token
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecretkey')

# 使用其生成 Token
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_confirmation_token(email):
    return serializer.dumps(email, salt='email-confirmation-salt')

def confirm_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=expiration)
    except Exception as e:
        print(f"Token confirmation error: {e}")
        return False
    return email

def send_verification_email(user_email):
    token = generate_confirmation_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('email_verification.html', confirm_url=confirm_url)
    subject = "请确认你的邮件"
    msg = Message(subject, recipients=[user_email], html=html)
    try:
        mail.send(msg)
        print(f"Email sent to {user_email}")
        return True
    except Exception as e:
        print(f"邮件发送失败: {e}")
        return False

# 初始化数据库和迁移工具
db.init_app(app)
migrate = Migrate(app, db)

# 配置 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'member_login'

@login_manager.user_loader
def load_user(user_id):
    return Customer.query.get(int(user_id))

@app.route("/")
def index():
    return render_template('index.html')

# 邮件验证路由
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        return jsonify({"error": "确认链接无效或已过期。"}), 400

    customer = Customer.query.filter_by(email=email).first_or_404()

    if customer.is_verified:
        return redirect(url_for('login'))

    customer.is_verified = True
    customer.role = 'customer'
    db.session.commit()

    return jsonify({"status": "success", "message": "账号已验证成功确认。你可以登录了。", "redirect_url": url_for('login')}), 200

# 网站登录路由
@app.route("/login", methods=["GET", "POST"])
def member_login():
    if request.method == "POST":
        data = request.json
        email = data.get("email")
        password = data.get("password")
        customer = Customer.query.filter_by(email=email).first()

        if customer and check_password_hash(customer.password, password):
            login_user(customer)
            return jsonify({"status": "success", "message": "登录成功！", "redirect_url": url_for('dashboard')}), 200
        else:
            return jsonify({"status": "fail", "message": "账号或密码错误"}), 404
    return render_template('login.html')

# Google 登录页面
@app.route("/login/google")
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

# Google OAuth 授权回调处理
@app.route("/authorize/google")
def authorize_google():
    try:
        token = google.authorize_access_token()
        app.logger.info(f"Token: {token}")
        nonce = token.get('userinfo', {}).get('nonce')
        user_info = google.parse_id_token(token, nonce=nonce)
        if user_info is None:
            resp = google.get('userinfo')
            user_info = resp.json()
        app.logger.info(f"User info: {user_info}")

        email = user_info['email']
        name = user_info['name']
        google_id = user_info['sub']

        user = Customer.query.filter_by(email=email).first()
        if not user:
            user = Customer(email=email, name=name, google_id=google_id, is_verified=True)
            db.session.add(user)
            db.session.commit()
        else:
            if user.google_id != google_id:
                user.google_id = google_id
                db.session.commit()

        login_user(user)
        session['email'] = email
        session['oauth_token'] = token

        return redirect(url_for('dashboard'))
    except Exception as e:
        app.logger.error(f"Error during Google OAuth: {e}")
        return "Authorization failed.", 500

@app.route('/page/<page_name>')
def render_page(page_name):
    allowed_pages = ['login', 'cart', 'register', 'dashboard']
    if page_name in allowed_pages:
        return render_template(f'{page_name}.html')
    else:
        return render_template('404.html'), 404

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# 注册路由
@app.route("/register", methods=["GET", "POST"])
def add_customer():
    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        role = 'pending'

        if not name or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        existing_customer = Customer.query.filter_by(email=email).first()
        if existing_customer:
            return jsonify({"error": "该 email 已被注册"}), 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_customer = Customer(
            name=name,
            email=email,
            password=hashed_password,
            role=role,
            created_at=datetime.utcnow()
        )

        db.session.add(new_customer)
        db.session.commit()

        if send_verification_email(new_customer.email):
            return jsonify({"status": "success", "message": "注册成功。确认邮件已发送到你的邮箱。"}), 201
        else:
            return jsonify({"error": "注册成功，但邮件发送失败，请稍后再试。"}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# 获取所有用户
@app.route("/customers")
def get_customers():
    try:
        customers = Customer.query.all()
        return jsonify([{
            "id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "role": customer.role,
            "created_at": customer.created_at
        } for customer in customers])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# 登出功能
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return jsonify({"message": "登出成功"}), 200

if __name__ == "__main__":
    app.run(debug=True)
