# extensions.py — 統一管理擴展
'''
此文件負責初始化 Flask 應用中的所有擴展（如：SQLAlchemy, Migrate, Mail, LoginManager 等）。
這樣的好處是將擴展的初始化和應用本身的邏輯分離開來，從而避免在各個模組中直接使用 app 對象，避免循環引用的問題。
'''

# 導入各種 Flask 擴展的模組
from flask_sqlalchemy import SQLAlchemy  # SQLAlchemy 用於處理與數據庫的交互
from flask_migrate import Migrate  # Migrate 用於管理數據庫遷移
from flask_login import LoginManager  # LoginManager 用於管理用戶認證（登錄、註冊等）
from flask_mail import Mail  # Flask-Mail 用於發送郵件
from authlib.integrations.flask_client import OAuth  # OAuth 用於處理第三方身份驗證（如 Google OAuth）

# 初始化擴展對象
# 這些對象會在應用創建之初進行初始化，並與 Flask 應用綁定
db = SQLAlchemy()  # 初始化 SQLAlchemy，用於管理數據庫操作
migrate = Migrate()  # 初始化 Migrate，用於數據庫遷移，配合 Flask-Migrate 和 Alembic 使用
login_manager = LoginManager()  # 初始化 LoginManager，用於管理用戶的登入狀態和會話
mail = Mail()  # 初始化 Mail，用於發送電子郵件
oauth = OAuth()  # 初始化 OAuth，用於第三方身份驗證集成

# URLSafeTimedSerializer 是一個用於生成安全 token 的類
# 它通常用於生成和驗證 token（例如用於郵件驗證、密碼重置等），這些 token 有時效性限制。
from itsdangerous import URLSafeTimedSerializer

# 初始化 URLSafeTimedSerializer，'default_secret_key' 是加密密鑰
# 該密鑰應該保存在環境變數中，以確保應用的安全性
serializer = URLSafeTimedSerializer('default_secret_key')
