from flask import Blueprint, render_template, request, jsonify, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db, mail, serializer
from models import DeliveryPerson
from flask_mail import Message
from datetime import datetime, timezone

# 創建 DeliveryPerson Blueprint
delivery_bp = Blueprint('delivery', __name__)

# 定義外送員登入路由
@delivery_bp.route("/login", methods=["GET", "POST"], endpoint='login')
def delivery_login():
    if request.method == 'POST':
        data = request.json
        email = data.get("email")
        password = data.get("password")
        delivery_person = DeliveryPerson.query.filter_by(email=email).first()

        if delivery_person and check_password_hash(delivery_person.password, password):
            login_user(delivery_person)

            print(url_for('delivery.dashboard'))
            return jsonify({"status": "success", "message": "外送員登錄成功！", "redirect_url": url_for('delivery.dashboard')}), 200
        else:
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤","redirect_url": url_for('shared.404')}), 404
    else:
        return render_template('shared/login.html')

# 定義 dashboard 路由
@delivery_bp.route("/dashboard", methods=["GET"], endpoint='dashboard')
@login_required
def dashboard():
    return render_template('delivery/dashboard.html', user=current_user)

# 註冊新外送員
@delivery_bp.route("/register", methods=["GET", "POST"], endpoint='register')
def add_delivery():
    if request.method == 'POST':
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        confirm_password = data.get("confirm_password")
        role = data.get("role")

        if not name or not email or not password:
            return jsonify({"error": "缺少必填字段"}), 400

        existing_delivery = DeliveryPerson.query.filter_by(email=email).first()
        if existing_delivery:
            return jsonify({"error": "該 email 已被註冊"}), 400
        
        if password != confirm_password:
            return jsonify({"error": "兩次輸入的密碼不一致"}), 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_delivery_person = DeliveryPerson(name=name, email=email, password=hashed_password, role=role, created_at=datetime.now(timezone.utc))

        db.session.add(new_delivery_person)
        db.session.commit()

        send_verification_email(new_delivery_person.email)

        return jsonify({"status": "success", "message": "註冊成功。驗證郵件已發送到你的信箱。", "redirect_url": url_for('delivery.dashboard')}), 201
    else:
        return render_template('shared/register.html')

# 郵件驗證
@delivery_bp.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirmation-salt')

        delivery_person = DeliveryPerson.query.filter_by(email=email).first_or_404()

        if not delivery_person.is_verified:
            delivery_person.is_verified = True
            db.session.commit()
            print("用戶已驗證成功")  # 調試

        # 根據用戶角色生成重定向 URL
        role = delivery_person.role
        redirect_url = url_for('customer.login', role=role)

        return render_template('shared/verification_success.html', redirect_url=redirect_url,role=role)
    
    except Exception as e:
        print(f"驗證失敗: {e}")
        # 渲染驗證成功頁面，並在該頁面設置自動跳轉到登入頁面
        return jsonify({"error": "確認鏈接無效或已過期"}), 400



# 發送驗證郵件
def send_verification_email(user_email):
    token = serializer.dumps(user_email, salt='email-confirmation-salt')

    confirm_url = url_for('delivery.confirm_email', token=token, _external=True)

    html = render_template('shared/email_verification.html', confirm_url=confirm_url)

    subject = "請確認你的郵件"

    msg = Message(subject=subject, recipients=[user_email], html=html)

    mail.send(msg)

@delivery_bp.route("/logout", methods=["GET"],endpoint='logout')
@login_required
def member_logout(): 
    logout_user() #Flask-Login 的 logout_user 函數進行登出
    return redirect(url_for('customer.login')) #重定向到登入頁面