import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from dotenv import load_dotenv

load_dotenv()  # 自動加載 .env 文件中的變數

app = Flask(__name__)

# 配置郵件發送服務
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # 用來發送郵件的 Email
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # App專用密碼或你的郵箱密碼
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  # 預設發信人

mail = Mail(app)

# 配置 PostgreSQL 數據庫 URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres@localhost:5432/pigout_db')

# 禁用 SQLAlchemy 的對象修改追蹤功能
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SECRET_KEY 用於加密 session 和生成 token
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecretkey')

# 使用它來創建 Token
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
    subject = "請確認你的郵件"
    msg = Message(subject, recipients=[user_email], html=html)
    try:
        mail.send(msg)
        print(f"Email sent to {user_email}")
        return True
    except Exception as e:
        print(f"郵件發送失敗: {e}")
        return False

# 初始化資料庫和遷移工具
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# 設定 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 模型定義
class Customer(UserMixin, db.Model):
    __tablename__ = 'Customer'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=True, default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return Customer.query.get(int(user_id))

@app.route("/")
def index():
    return render_template('index.html')

# 郵件驗證路由
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        return jsonify({"error": "確認鏈接無效或已過期。"}), 400

    customer = Customer.query.filter_by(email=email).first_or_404()

    if customer.role != 'pending':
        return jsonify({"message": "帳號已確認。"}), 200

    customer.role = 'customer'  # 更新角色
    db.session.commit()

    return jsonify({"status": "success", "message": "帳號已確認。你可以登入了。"}), 200

# 登入路由
@app.route("/login", methods=["GET", "POST"])
def member_login():
    if request.method == "POST":
        data = request.json
        email = data.get("email")
        password = data.get("password")
        customer = Customer.query.filter_by(email=email).first()

        if customer and check_password_hash(customer.password, password):
            login_user(customer)
            return jsonify({"status": "success", "message": "登入成功！", "redirect_url": url_for('dashboard')}), 200
        else:
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤"}), 404
    return render_template('login.html')

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

# 註冊路由
@app.route("/register", methods=["POST"])
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
            return jsonify({"error": "該 email 已被註冊"}), 400

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
            return jsonify({"status": "success", "message": "註冊成功。確認郵件已發送到你的郵箱。"}), 201
        else:
            return jsonify({"error": "註冊成功，但郵件發送失敗，請稍後再試。"}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# 獲取所有用戶
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
