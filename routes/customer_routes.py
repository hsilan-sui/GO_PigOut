'''
放置與訂餐客戶相關的路由
'''

from flask import Blueprint, render_template, request, jsonify, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db, mail, serializer
from models import Customer
from flask_mail import Message
from datetime import datetime, timezone

# 創建 Customer Blueprint，將與應用程序的主要路由相關的操作封裝在一起
# 'routes_bp' 是這個 Blueprint 的名字，'__name__' 是 Flask 用來定位 Blueprint 的模塊名稱
customer_bp = Blueprint('customer', __name__)

# # 定義首頁路由
# @customer_bp.route("/", endpoint='index')
# def index():
#     return render_template('index.html')

# 定義登入路由，處理用戶的登錄操作
@customer_bp.route("/login", methods=["GET", "POST"], endpoint='login')
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

            #傳遞到前端的參數一律用user
            print(url_for('customer.dashboard'))
            # 返回登錄成功的消息並跳轉到 dashboard 頁面，這裡返回 JSON 格式
            return jsonify({"status": "success", "message": "登錄成功！", "redirect_url": url_for('customer.dashboard')}), 200
        else:
            # 如果用戶不存在或密碼錯誤，返回錯誤消息
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤","redirect_url": url_for('shared.404')}), 404
    else:
        # 如果是 GET 請求，返回登錄頁面的模板
        return render_template('shared/login.html')


# 定義 dashboard 路由
@customer_bp.route("/dashboard", methods=["GET"], endpoint='dashboard')
@login_required # 確保只有登入的用戶能訪問此頁面
def dashboard():
    return render_template('customer/dashboard.html', user=current_user)

#註冊新訂餐用戶，GET ＆POST 
@customer_bp.route("/register", methods=["GET", "POST"], endpoint='register')
def add_customer():
    # 處理訂餐用戶從前端傳來的 POST 請求 => 以創建新用戶
    if request.method == 'POST':
        # 獲取 POST 請求中的 JSON 數據
        data = request.json
        name = data.get("name") # 用戶名
        email = data.get("email") # email 
        password = data.get("password") # 密碼 
        confirm_password = data.get("confirm_password")
        role = data.get("role")

         # 檢查是否提供了所有必填字段
        if not name or not email or not password:
            return jsonify({"error": "缺少必填字段"}), 400

        # 檢查 email 是否已經註冊
        existing_customer = Customer.query.filter_by(email=email).first()
        if existing_customer:
            return jsonify({"error": "該 email 已被註冊"}), 400
        
        if password != confirm_password:
            return jsonify({"error": "兩次輸入的密碼不一致"}), 400

        # 對密碼進行哈希加密 werkzeug.security 提供的generate_password_hash() method選擇使用pbkdf2:sha256
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # 創建新的用戶實例
        new_customer = Customer(name=name, email=email, password=hashed_password, role=role, created_at=datetime.now(timezone.utc))

        # 將新用戶添加到數據庫並提交事務
        db.session.add(new_customer)
        db.session.commit()

        send_verification_email(new_customer.email)

        #flash / sweetalert
        return jsonify({"status": "success", "message": "註冊成功。驗證郵件已發送到你的信箱。", "redirect_url": url_for('customer.dashboard')}), 201
    else:
        # 如果是GET 註冊頁面 就去共用模板找shared/register.html
        return render_template('shared/register.html')
    
# 定義郵件確認路由，處理用戶郵箱驗證的鏈接。
# 當用戶點擊確認鏈接時，這個路由會被觸發。

# 郵件驗證
@customer_bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        # 使用預定義的 serializer 來解碼郵件確認的 token
        email = serializer.loads(token, salt='email-confirmation-salt')
        
        # 查找與該 email 對應的用戶
        customer = Customer.query.filter_by(email=email).first_or_404()
        print(f"找到的用戶: {customer.email}, 驗證狀態: {customer.is_verified}")  # 調試

        # 如果郵箱未驗證，則設置用戶為已驗證
        if not customer.is_verified:
            customer.is_verified = True
            db.session.commit()  # 保存更新到數據庫
            print("用戶已驗證成功")  # 調試

        # 根據用戶角色生成重定向 URL
        role = customer.role
        redirect_url = url_for('customer.login', role=role)

        # 渲染驗證成功頁面，並在該頁面設置自動跳轉到登入頁面
        return render_template('shared/verification_success.html', redirect_url=redirect_url,role=role)

    except Exception as e:
        # 記錄具體的錯誤信息
        print(f"驗證失敗: {e}")
        # 渲染驗證成功頁面，並在該頁面設置自動跳轉到登入頁面
        return jsonify({"error": "確認鏈接無效或已過期"}), 400

# 定義發送驗證郵件的輔助函數
def send_verification_email(user_email):
    # 生成一個用於郵箱驗證的 token
    token = serializer.dumps(user_email, salt='email-confirmation-salt')
    
    # 使用生成的 token 創建確認鏈接
    confirm_url = url_for('customer.confirm_email', token=token, _external=True)  # 使用 Blueprint 名稱
    
    # 渲染郵件模板，並將確認鏈接添加到郵件中
    html = render_template('shared/email_verification.html', confirm_url=confirm_url)
    
    # 構建郵件對象，包括郵件主題、收件人和內容
    subject = "請確認你的郵件"
    msg = Message(subject=subject, recipients=[user_email], html=html)
    
    # 發送郵件
    mail.send(msg)


#登出路由
@customer_bp.route("/logout", methods=["GET"],endpoint='logout')
@login_required # 確保只有登入的用戶可以執行登出操作
def member_logout():
    logout_user() #Flask-Login 的 logout_user 函數進行登出
    return redirect(url_for('customer.login')) #重定向到登入頁面


# --------------------
