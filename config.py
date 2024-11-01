# config.py — 配置文件
'''
負責管理所有應用配置，例如數據庫 URL、郵件配置、OAuth 配置等。
這些配置分別存放在環境變數中，並根據開發和生產環境進行不同配置。
'''
import os  # 用來從操作系統讀取環境變數
from dotenv import load_dotenv  # 用來加載 .env 文件中的環境變數

# 加載環境變數
load_dotenv()

# 定義基礎配置類，包含應用程序的公共配置
class Config:
    # 應用程序的密鑰，用於加密 session 等。從環境變數讀取，若不存在則使用默認值。
    SECRET_KEY = os.getenv('SECRET_KEY', 'default_secret_key')

    # 關閉 SQLAlchemy 的事件系統追蹤，這樣能夠提高性能
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 設置 SQLAlchemy 的數據庫連接 URL，從環境變數讀取 `DATABASE_URL`
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')

    # Line Pay 配置
    LINEPAY_CHANNEL_ID = os.getenv('LINEPAY_CHANNEL_ID')
    LINEPAY_CHANNEL_SECRET = os.getenv('LINEPAY_CHANNEL_SECRET')

    # 郵件服務配置
    MAIL_SERVER = 'smtp.gmail.com'  # 郵件服務的主機地址，這裡使用 Gmail 的 SMTP 服務
    MAIL_PORT = 587  # Gmail SMTP 端口
    MAIL_USE_TLS = True  # 啟用 TLS 加密來保護郵件傳輸
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')  # 從環境變數讀取郵件帳號
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')  # 從環境變數讀取郵件密碼
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')  # 從環境變數讀取發件人的默認地址

    # Google OAuth 配置
    GOOGLE_OAUTH_ID = os.getenv('GOOGLE_OAUTH_ID')  # 從環境變數讀取 Google OAuth 的客戶端 ID
    GOOGLE_OAUTH_KEY = os.getenv('GOOGLE_OAUTH_KEY')  # 從環境變數讀取 Google OAuth 的客戶端密鑰

# 開發環境的配置繼承自基礎配置類
class DevelopmentConfig(Config):
    DEBUG = True  # 在開發環境中啟用調試模式

# 生產環境的配置繼承自基礎配置類
class ProductionConfig(Config):
    DEBUG = False  # 在生產環境中關閉調試模式
