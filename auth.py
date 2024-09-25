# auth.py — Google OAuth 和普通用戶驗證
'''
此文件處理與 Google OAuth 登錄相關的路由。通過 OAuth 進行第三方身份驗證，用戶可以使用 Google 賬戶進行登錄。
'''

# 引入必要的 Flask 和擴展模塊
from flask import Blueprint, redirect, url_for, session  # Flask 的 Blueprint 用於模塊化應用, session 用於存儲用戶狀態
from extensions import oauth, db  # oauth 用於處理 Google OAuth，db 是 SQLAlchemy 對象用於與數據庫交互
from models import Customer  # 引入用戶模型 Customer，該模型與數據庫中的用戶數據相關聯
from flask_login import login_user  # Flask-Login 模塊，用於處理用戶登錄狀態
from dotenv import load_dotenv  # 用於加載 .env 環境變數
import os  # 用於從系統環境變量中獲取配置
import secrets  # 用於生成隨機 nonce 值，以加強安全性

# 加載 .env 文件，這樣我們可以使用其中的環境變量
load_dotenv()

# 創建一個 Blueprint 來組織這個模塊中的所有路由
auth_bp = Blueprint('auth', __name__)

# Google OAuth 註冊保持不變，使用 Authlib 來處理 OAuth 認證
# `oauth.register` 註冊 Google 的 OAuth 2.0 認證配置
google = oauth.register(
    name='google',  # 認證名稱
    client_id = os.getenv("GOOGLE_OAUTH_ID"),  # 從環境變量中獲取 OAuth 2.0 客戶端 ID
    client_secret = os.getenv("GOOGLE_OAUTH_KEY"),  # 從環境變量中獲取 OAuth 2.0 客戶端密鑰
    authorize_url='https://accounts.google.com/o/oauth2/auth',  # Google 授權 URL
    access_token_url='https://oauth2.googleapis.com/token',  # 用於獲取訪問令牌的 URL
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',  # 用於獲取 Google 的 OpenID 配置
    client_kwargs={'scope': 'openid profile email'}  # OAuth 請求的範圍，請求訪問用戶的 email 和個人資料
)

# 定義一個 Google 登錄路由，當用戶點擊 "使用 Google 登錄" 按鈕時會觸發
@auth_bp.route("/login/google", endpoint='login_google')
def login_google():
    # 生成一個隨機的 nonce 值，用於加強安全性，並將其存儲到 session 中
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce  # 將 nonce 存儲到 session 中

    # 重定向到 Google 授權頁面，並提供授權回調 URI 和 nonce 值
    redirect_uri = url_for('auth.authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri, nonce=nonce)

# 授權回調路由，用於處理授權完成後 Google 返回的數據
@auth_bp.route("/authorize/google", endpoint='authorize_google')
def authorize_google():
    # 獲取訪問令牌
    token = google.authorize_access_token()

    # 從 session 中獲取之前存儲的 nonce 值
    nonce = session.pop('nonce', None)
    if not nonce:
        return "Missing nonce in session", 400  # 如果沒有找到 nonce，返回錯誤

    # 使用存儲的 nonce 來解析 ID token，驗證其合法性和安全性
    user_info = google.parse_id_token(token, nonce=nonce)

    # 從返回的用戶信息中提取 email
    email = user_info['email']

    # 查找數據庫中是否已存在此 email 的用戶，如果沒有，則創建一個新用戶
    user = Customer.query.filter_by(email=email).first()
    if not user:
        # 創建新用戶並存儲到數據庫
        user = Customer(email=email, name=user_info['name'], google_id=user_info['sub'], is_verified=True)
        db.session.add(user)
        db.session.commit()

    # 使用 Flask-Login 登錄用戶
    login_user(user)

    # 在 session 中存儲用戶的 email，以便後續使用
    session['email'] = email

    # 重定向到應用的 dashboard 頁面
    return redirect(url_for('routes.dashboard'))
