# routes.py — 負責處理應用中的主要頁面路由
'''
包含所有普通的路由，如首頁、用戶登錄、郵件驗證等
'''

from flask import Blueprint, render_template, request, jsonify, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from extensions import db, mail, serializer
from models import Customer
from flask_mail import Message
from datetime import datetime

# 創建 Blueprint，將與應用程序的主要路由相關的操作封裝在一起。
# 'routes_bp' 是這個 Blueprint 的名字，'__name__' 是 Flask 用來定位 Blueprint 的模塊名稱。
routes_bp = Blueprint('routes', __name__)

# 定義首頁路由。這個路由用來加載應用的首頁模板。
@routes_bp.route("/", endpoint='index')
def index():
    return render_template('index.html')  # 返回渲染的首頁模板

# 定義郵件確認路由，處理用戶郵箱驗證的鏈接。
# 當用戶點擊確認鏈接時，這個路由會被觸發。
@routes_bp.route('/confirm/<token>')
def confirm_email(token):
    # 使用預定義的 serializer 來解碼郵件確認的 token
    email = serializer.loads(token, salt='email-confirmation-salt')

    # 如果 token 無效或過期，返回錯誤信息
    if not email:
        return jsonify({"error": "確認鏈接無效或已過期。"}), 400

    # 查找與該 email 對應的用戶，如果找不到則返回 404 錯誤
    customer = Customer.query.filter_by(email=email).first_or_404()

    # 如果用戶已經驗證過郵箱，則重定向到登錄頁面
    if customer.is_verified:
        return redirect(url_for('routes.member_login'))  # 使用 Blueprint 的名稱

    # 如果郵箱未驗證，則設置用戶為已驗證並更新角色為 'customer'
    customer.is_verified = True
    customer.role = 'customer'
    db.session.commit()  # 保存更新到數據庫

    return jsonify({"status": "success", "message": "帳號已驗證成功。"}), 200  # 返回驗證成功的消息

# 定義登錄路由，處理用戶的登錄操作。支持 GET 和 POST 方法。
@routes_bp.route("/login", methods=["GET", "POST"], endpoint='login')
def member_login():
    # 如果是 POST 請求，處理登錄邏輯
    if request.method == 'POST':
        data = request.json  # 獲取 POST 請求中的 JSON 數據
        email = data.get("email")  # 獲取 email
        password = data.get("password")  # 獲取密碼
        customer = Customer.query.filter_by(email=email).first()  # 查找用戶

        # 如果用戶存在且密碼匹配，則進行登錄
        if customer and check_password_hash(customer.password, password):
            login_user(customer)  # 使用 Flask-Login 的 login_user 函數進行登錄
            # 返回登錄成功的消息並跳轉到 dashboard 頁面
            return jsonify({"status": "success", "message": "登錄成功！", "redirect_url": url_for('routes.dashboard')}), 200
        else:
            # 如果用戶不存在或密碼錯誤，返回錯誤消息
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤"}), 404
    else:
        # 如果是 GET 請求，返回登錄頁面的模板
        return render_template('login.html')

# 註冊新用戶的路由，支持 GET 和 POST 方法
@routes_bp.route("/register", methods=["GET", "POST"], endpoint='register')
def add_customer():
    # 處理 POST 請求以創建新用戶
    if request.method == 'POST':
        try:
            # 獲取 POST 請求中的 JSON 數據
            data = request.json
            print(f"Received data: {data}")  # 打印接收到的數據以便調試
        except Exception as e:
            # 如果出現錯誤，返回錯誤消息
            return jsonify({"error": f"Failed to parse JSON: {str(e)}"}), 400

        # 從數據中提取 name, email 和 password
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        # 檢查是否提供了所有必填字段
        if not name or not email or not password:
            return jsonify({"error": "缺少必填字段"}), 400

        # 檢查 email 是否已經註冊
        existing_customer = Customer.query.filter_by(email=email).first()
        if existing_customer:
            return jsonify({"error": "該 email 已被註冊"}), 400

        # 對密碼進行哈希加密
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # 創建新的用戶實例
        new_customer = Customer(name=name, email=email, password=hashed_password, role='pending', created_at=datetime.utcnow())

        # 將新用戶添加到數據庫並提交事務
        db.session.add(new_customer)
        db.session.commit()

        # 發送驗證郵件
        send_verification_email(new_customer.email)

        # 返回註冊成功的消息，並包含重定向到 dashboard 的 URL
        return jsonify({"status": "success", "message": "註冊成功。驗證郵件已發送到你的信箱。", "redirect_url": url_for('routes.dashboard')}), 201
    else:
        # 如果是 GET 請求，返回註冊頁面的模板
        return render_template('register.html')

# 定義 dashboard 路由，登錄後用戶將被重定向到此頁面
@routes_bp.route("/dashboard", methods=["GET"], endpoint='dashboard')
def dashboard():
    # 返回 dashboard 頁面的模板
    return render_template('dashboard.html')

# 定義發送驗證郵件的輔助函數
def send_verification_email(user_email):
    # 生成一個用於郵箱驗證的 token
    token = serializer.dumps(user_email, salt='email-confirmation-salt')
    
    # 使用生成的 token 創建確認鏈接
    confirm_url = url_for('routes.confirm_email', token=token, _external=True)  # 使用 Blueprint 名稱
    
    # 渲染郵件模板，並將確認鏈接添加到郵件中
    html = render_template('email_verification.html', confirm_url=confirm_url)
    
    # 構建郵件對象，包括郵件主題、收件人和內容
    subject = "請確認你的郵件"
    msg = Message(subject=subject, recipients=[user_email], html=html)
    
    # 發送郵件
    mail.send(msg)
