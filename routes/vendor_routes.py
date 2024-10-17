'''
放置與餐廳業者相關的路由
'''
from flask import Blueprint, render_template, request, jsonify, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db, mail, serializer
from models import Vendor
from flask_mail import Message
from datetime import datetime, timezone

# 創建 Vendor Blueprint
vendor_bp = Blueprint('vendor', __name__)


# 定義供應商登入路由
@vendor_bp.route("/login", methods=["GET", "POST"], endpoint='login')
def vendor_login():
    # 如果是 POST 請求，處理登錄邏輯
    if request.method == 'POST':
        data = request.json
        email = data.get("email")
        password = data.get("password")
        vendor = Vendor.query.filter_by(email=email).first()

        if vendor and check_password_hash(vendor.password, password):
            login_user(vendor,remember=True)# 使用 Flask-Login 的 login_user 函數進行登錄
            print(current_user.is_authenticated)  # 應該返回 True

            # 返回登錄成功的消息並跳轉到 dashboard 頁面
            return jsonify({"status": "success", "message": "餐廳業者登錄成功！", "redirect_url": url_for('vendor.dashboard')}), 200
        else:
            # 如果用戶不存在或密碼錯誤，返回錯誤消息
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤","redirect_url": url_for('shared.404')}), 404
    else:
        return render_template('shared/login.html')

# 定義 dashboard 路由
@vendor_bp.route("/dashboard", methods=["GET"], endpoint='dashboard')
@login_required # 確保只有登入的用戶才能訪問權限
def dashboard():
    return render_template('vendor/dashboard.html', user=current_user)

# 註冊新供應商
@vendor_bp.route("/register", methods=["GET", "POST"], endpoint='register')
def add_vendor():
    if request.method == 'POST':
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        confirm_password = data.get("confirm_password")
        role = data.get("role")
        print(data)

        if not name or not email or not password:
            return jsonify({"error": "缺少必填字段"}), 400

        existing_vendor = Vendor.query.filter_by(email=email).first()
        if existing_vendor:
            return jsonify({"error": "該 email 已被註冊"}), 400
        
        if password != confirm_password:
            return jsonify({"error": "兩次輸入的密碼不一致"}), 400
        
    
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_vendor = Vendor(name=name, email=email, password=hashed_password, role=role, created_at=datetime.now(timezone.utc))

        db.session.add(new_vendor)
        db.session.commit()

        send_verification_email(new_vendor.email)

        return jsonify({"status": "success", "message": "註冊成功。驗證郵件已發送到你的信箱。", "redirect_url": url_for('vendor.dashboard')}), 201
    else:
        return render_template('shared/register.html')

# 郵件驗證
@vendor_bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirmation-salt')
        print(f"解碼後的 email: {email}")  # 調試

        vendor = Vendor.query.filter_by(email=email).first_or_404()
        print(f"找到的用戶： {vendor.email}, 驗證狀態: {vendor.is_verified}")

        if not vendor.is_verified:
            vendor.is_verified = True
            db.session.commit()
            print("用戶已驗證成功")

        role = vendor.role
        redirect_url = url_for('customer.login',role=role)

        return render_template('shared/verification_success.html',redirect_url=redirect_url,role=role)
     
    except Exception as e:
        print(f"驗證失敗：{e}")
        return jsonify({"error": "確認連接無效或已經過期"}),400



# 發送驗證郵件
def send_verification_email(user_email):
    token = serializer.dumps(user_email, salt='email-confirmation-salt')

    confirm_url = url_for('vendor.confirm_email', token=token, _external=True)

    html = render_template('shared/email_verification.html', confirm_url=confirm_url)

    subject = "請確認你的郵件"

    msg = Message(subject=subject, recipients=[user_email], html=html)

    mail.send(msg)

# @vendor_bp.route("/edit", methods=['GET','POST'], endpoint="edit")
# @login_required
# def edit_info() 

@vendor_bp.route("/logout", methods=['GET'], endpoint="logout")
@login_required #確保登入權限
def member_logout():
    logout_user()
    return redirect(url_for('customer.login')) 