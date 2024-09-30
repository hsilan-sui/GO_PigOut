from flask import Blueprint, render_template, request, jsonify, url_for, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db, mail, serializer
from models import Vendor
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
            return jsonify({"status": "success", "message": "外送員登錄成功！", "redirect_url": url_for('delivery.dashboard')}), 200
        else:
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤"}), 404
    else:
        return render_template('shared/login.html')

# 註冊新外送員
@delivery_bp.route("/register", methods=["GET", "POST"], endpoint='register')
def add_delivery():
    if request.method == 'POST':
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({"error": "缺少必填字段"}), 400

        existing_delivery = DeliveryPerson.query.filter_by(email=email).first()
        if existing_delivery:
            return jsonify({"error": "該 email 已被註冊"}), 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_delivery_person = DeliveryPerson(name=name, email=email, password=hashed_password, role='pending', created_at=datetime.utcnow())

        db.session.add(new_delivery_person)
        db.session.commit()

        send_verification_email(new_delivery_person.email)

        return jsonify({"status": "success", "message": "註冊成功。驗證郵件已發送到你的信箱。", "redirect_url": url_for('delivery.dashboard')}), 201
    else:
        return render_template('shared/register.html')

# 郵件驗證
@delivery_bp.route('/confirm/<token>')
def confirm_email(token):
    email = serializer.loads(token, salt='email-confirmation-salt')

    if not email:
        return jsonify({"error": "確認鏈接無效或已過期。"}), 400

    delivery_person = DeliveryPerson.query.filter_by(email=email).first_or_404()

    if delivery_person.is_verified:
        return redirect(url_for('delivery.delivery_login'))

    delivery_person.is_verified = True
    delivery_person.role = 'delivery'
    db.session.commit()

    return jsonify({"status": "success", "message": "帳號已驗證成功。"}), 200

# 定義 dashboard 路由
@delivery_bp.route("/dashboard", methods=["GET"], endpoint='dashboard')
@login_required
def dashboard():
    return render_template('delivery/dashboard.html', user=current_user)

# 發送驗證郵件
def send_verification_email(user_email):
    token = serializer.dumps(user_email, salt='email-confirmation-salt')
    confirm_url = url_for('delivery.confirm_email', token=token, _external=True)
    html = render_template('delivery/email_verification.html', confirm_url=confirm_url)
    subject = "請確認你的郵件"
    msg = Message(subject=subject, recipients=[user_email], html=html)
    mail.send(msg)
