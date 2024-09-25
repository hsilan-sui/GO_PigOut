# 匯入所需的模組
import os  # 用於操作系統相關操作（例如環境變數）
from datetime import datetime  # 用於時間和日期操作
from flask import Flask, render_template, request, jsonify, url_for, abort, redirect, session  # Flask 核心功能和輔助函式
from authlib.integrations.flask_client import OAuth  # 用於 OAuth 認證（這裡用於 Google 登錄）
from werkzeug.security import generate_password_hash, check_password_hash  # 密碼加密和驗證功能
from flask_sqlalchemy import SQLAlchemy  # SQLAlchemy 物件關聯映射 (ORM) 整合
from flask_migrate import Migrate  # 用於數據庫遷移
from dotenv import load_dotenv  # 用於從 .env 檔案加載環境變數
from flask_login import LoginManager, login_user, login_required, logout_user, current_user  # 用於處理用戶登錄狀態
from flask_mail import Mail, Message  # 用於發送電子郵件
from itsdangerous import URLSafeTimedSerializer  # 用於生成和驗證安全的序列化 token（這裡用於郵件確認）

# 從 models.py 匯入數據庫實例和模型
from models import db, Customer, DeliveryPerson, Vendor, MenuItem, Cart, CartItem, Order, OrderItem, Payment, Address

# 設置環境變數，允許不安全的 HTTP 請求（通常僅用於開發環境）
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# 加載 .env 檔案中的環境變數
load_dotenv()

# 初始化 Flask 應用
app = Flask(__name__)

# 配置郵件服務（使用 Gmail 作為郵件服務提供者）
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # 郵件服務器地址
app.config['MAIL_PORT'] = 587  # 郵件服務器端口號
app.config['MAIL_USE_TLS'] = True  # 啟用傳輸層安全性 (TLS)
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')  # 發送郵件的帳戶名稱
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')  # 郵件帳戶的密碼
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')  # 郵件的預設發件人

# 初始化 Flask-Mail 郵件服務
mail = Mail(app)

# 初始化 OAuth 並設置 Google 登錄的相關配置
oauth = OAuth(app)
google = oauth.register(
    name='google',  # 註冊 OAuth 提供者名稱
    client_id=os.getenv('GOOGLE_OAUTH_ID'),  # Google OAuth 客戶端 ID
    client_secret=os.getenv('GOOGLE_OAUTH_KEY'),  # Google OAuth 客戶端密鑰
    authorize_url='https://accounts.google.com/o/oauth2/auth',  # Google 授權頁面 URL
    access_token_url='https://oauth2.googleapis.com/token',  # 用於獲取 access token 的 URL
    server_metadata_uri='https://accounts.google.com/.well-known/openid-configuration',  # Google 的元數據 URL
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',  # 用於驗證 JWT token 的證書 URI
    client_kwargs={'scope': 'openid profile email'}  # 請求的 OAuth 範圍
)

# 配置 PostgreSQL 數據庫連接
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres@localhost:5432/pigout_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 關閉對數據庫變更的訊息追蹤，提升效能

# 設置 Flask 的 SECRET_KEY 用於加密 session 和其他機密信息
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'mysecretkey')

# URLSafeTimedSerializer 用於生成和驗證 token（如郵件驗證 token）
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# 定義生成郵件驗證 token 的函數
def generate_confirmation_token(email):
    return serializer.dumps(email, salt='email-confirmation-salt')

# 定義驗證 token 的函數，並設置有效期為一小時（3600 秒）
def confirm_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='email-confirmation-salt', max_age=expiration)
    except Exception as e:
        print(f"Token confirmation error: {e}")  # 如發生錯誤則打印錯誤訊息
        return False
    return email  # 返回解碼後的 email

# 定義發送驗證郵件的函數
def send_verification_email(user_email):
    token = generate_confirmation_token(user_email)  # 生成驗證 token
    confirm_url = url_for('confirm_email', token=token, _external=True)  # 生成確認鏈接
    html = render_template('email_verification.html', confirm_url=confirm_url)  # 渲染郵件模板
    subject = "請確認你的郵件"  # 郵件主題
    msg = Message(subject, recipients=[user_email], html=html)  # 構建郵件消息
    try:
        mail.send(msg)  # 發送郵件
        print(f"Email sent to {user_email}")  # 打印發送成功訊息
        return True
    except Exception as e:
        print(f"郵件發送失敗: {e}")  # 打印錯誤訊息
        return False

# 初始化數據庫實例及數據庫遷移工具
db.init_app(app)
migrate = Migrate(app, db)

# 配置 Flask-Login 管理登錄狀態
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'member_login'  # 設置當前未登錄時，重定向到的登錄頁面

# 定義載入用戶的函數
@login_manager.user_loader
def load_user(user_id):
    return Customer.query.get(int(user_id))  # 根據用戶 ID 從數據庫中獲取用戶

# 定義首頁路由
@app.route("/")
def index():
    return render_template('index.html')  # 渲染首頁模板

# 定義郵件確認路由
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)  # 驗證 token 並獲取 email
    if not email:
        return jsonify({"error": "確認鏈接無效或已過期。"}), 400  # 如果 token 無效，返回錯誤訊息

    customer = Customer.query.filter_by(email=email).first_or_404()  # 從數據庫查找對應的用戶

    if customer.is_verified:  # 如果用戶已經驗證
        return redirect(url_for('login'))  # 直接重定向到登錄頁面

    customer.is_verified = True  # 設置用戶為已驗證狀態
    customer.role = 'customer'  # 更新角色為 customer
    db.session.commit()  # 保存修改

    return jsonify({"status": "success", "message": "帳號已驗證成功。你可以登入了。", "redirect_url": url_for('login')}), 200  # 返回成功訊息

# 定義登錄路由，支持 GET 和 POST 方法
@app.route("/login", methods=["GET", "POST"])
def member_login():
    if request.method == "POST":  # 如果是 POST 請求
        data = request.json  # 獲取 JSON 格式的請求數據
        email = data.get("email")  # 獲取 email
        password = data.get("password")  # 獲取密碼
        customer = Customer.query.filter_by(email=email).first()  # 從數據庫查找對應的用戶

        if customer and check_password_hash(customer.password, password):  # 驗證密碼是否正確
            login_user(customer)  # 登錄用戶
            return jsonify({"status": "success", "message": "登錄成功！", "redirect_url": url_for('dashboard')}), 200  # 返回成功訊息
        else:
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤"}), 404  # 返回錯誤訊息
    return render_template('login.html')  # 渲染登錄頁面

# Google 登錄的路由，重定向到 Google 授權頁面
@app.route("/login/google")
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)  # 設定 Google 回調地址
    return google.authorize_redirect(redirect_uri)  # 發送 OAuth 授權請求

# Google 授權後的回調路由
@app.route("/authorize/google")
def authorize_google():
    try:
        token = google.authorize_access_token()  # 獲取 Google OAuth token
        app.logger.info(f"Token: {token}")
        nonce = token.get('userinfo', {}).get('nonce')  # 提取 nonce 值
        user_info = google.parse_id_token(token, nonce=nonce)  # 解析 token 並提取用戶信息
        if user_info is None:
            resp = google.get('userinfo')  # 如果沒有 user_info，請求 Google 的 userinfo API
            user_info = resp.json()
        app.logger.info(f"User info: {user_info}")

        # 從 user_info 中提取用戶信息
        email = user_info['email']
        name = user_info['name']
        google_id = user_info['sub']

        # 查找用戶，若無則新建用戶
        user = Customer.query.filter_by(email=email).first()
        if not user:
            user = Customer(email=email, name=name, google_id=google_id, is_verified=True)  # 註冊新用戶
            db.session.add(user)
            db.session.commit()
        else:
            if user.google_id != google_id:  # 如果用戶已存在但 google_id 不同，則更新 google_id
                user.google_id = google_id
                db.session.commit()

        login_user(user)  # 登錄用戶
        session['email'] = email  # 設置 session
        session['oauth_token'] = token

        return redirect(url_for('dashboard'))  # 登錄成功後重定向到 dashboard
    except Exception as e:
        app.logger.error(f"Error during Google OAuth: {e}")
        return "Authorization failed.", 500  # 授權失敗，返回錯誤訊息

# 定義動態頁面渲染的路由
@app.route('/page/<page_name>')
def render_page(page_name):
    allowed_pages = ['login', 'cart', 'register', 'dashboard']  # 定義允許的頁面
    if page_name in allowed_pages:
        return render_template(f'{page_name}.html')  # 渲染相應頁面
    else:
        return render_template('404.html'), 404  # 如果頁面不存在，返回 404 頁面

# 定義用戶登錄後的個人控制台
@app.route("/dashboard")
@login_required  # 需要登錄後才能訪問
def dashboard():
    return render_template('dashboard.html')  # 渲染控制台頁面

# 自訂的 404 頁面處理
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404  # 渲染 404 頁面

# 註冊新用戶的路由，支持 GET 和 POST 方法
@app.route("/register", methods=["GET", "POST"])
def add_customer():
    try:
        data = request.json  # 獲取 JSON 格式的請求數據
        name = data.get("name")  # 獲取用戶名稱
        email = data.get("email")  # 獲取 email
        password = data.get("password")  # 獲取密碼
        role = 'pending'  # 設置默認用戶角色為 pending

        # 檢查是否缺少必要字段
        if not name or not email or not password:
            return jsonify({"error": "缺少必填欄位"}), 400  # 返回錯誤訊息

        # 檢查 email 是否已被註冊
        existing_customer = Customer.query.filter_by(email=email).first()
        if existing_customer:
            return jsonify({"error": "該 email 已被註冊"}), 400  # 返回錯誤訊息

        # 使用安全方式對密碼進行哈希加密
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # 建立新用戶
        new_customer = Customer(
            name=name,
            email=email,
            password=hashed_password,
            role=role,
            created_at=datetime.utcnow()  # 設置帳號創建時間
        )

        # 將新用戶加入數據庫
        db.session.add(new_customer)
        db.session.commit()

        # 發送驗證郵件
        if send_verification_email(new_customer.email):
            return jsonify({"status": "success", "message": "註冊成功。確認郵件已發送到你的信箱。"}), 201  # 返回成功訊息
        else:
            return jsonify({"error": "註冊成功，但郵件發送失敗，請稍後再試。"}), 500  # 返回部分成功訊息

    except Exception as e:
        db.session.rollback()  # 如果發生錯誤，回滾數據庫事務
        return jsonify({"error": str(e)}), 500  # 返回錯誤訊息

# 獲取所有用戶的路由
@app.route("/customers")
def get_customers():
    try:
        customers = Customer.query.all()  # 查詢數據庫中的所有用戶
        return jsonify([{
            "id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "role": customer.role,
            "created_at": customer.created_at
        } for customer in customers])  # 返回所有用戶的 JSON 列表
    except Exception as e:
        return jsonify({"error": str(e)}), 500  # 返回錯誤訊息

# 用戶登出功能
@app.route("/logout")
@login_required  # 需要登錄後才能訪問
def logout():
    logout_user()  # 執行登出操作
    return jsonify({"message": "登出成功"}), 200  # 返回登出成功訊息

# 主程式入口，僅在直接運行本檔案時啟動 Flask 應用
if __name__ == "__main__":
    app.run(debug=True)  # 開啟 debug 模式，便於開發期間調試
