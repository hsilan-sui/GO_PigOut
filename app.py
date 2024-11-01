from flask import Flask,render_template
from extensions import db, migrate, login_manager, mail, oauth
#from routes import routes_bp  # 匯入自定義的主路由 Blueprint
from routes import home_bp, customer_bp, vendor_bp, delivery_bp, order_bp# 匯入拆分的 Blueprint
from auth import auth_bp  # 匯入自定義的身份驗證（Google OAuth） Blueprint
from models import * # 匯入 Customer 模型，用來管理數據庫中的客戶數據

# 初始化 Flask 應用
app = Flask(__name__)

# 開發環境 加載應用配置，從 config.DevelopmentConfig 中導入配置參數
app.config.from_object('config.DevelopmentConfig')

# 生產環境
#app.config.from_object('config.ProductionConfig')

# 初始化擴展，將擴展與 Flask 應用綁定
# db: 初始化 SQLAlchemy，用來操作數據庫
db.init_app(app)

# migrate: 初始化 Flask-Migrate，用來管理數據庫遷移
migrate.init_app(app, db)

# login_manager: 初始化 Flask-Login，用來管理用戶登錄狀態
login_manager.init_app(app)

# mail: 初始化 Flask-Mail，用來發送郵件（如驗證郵件）
mail.init_app(app)

# oauth: 初始化 Authlib，用來處理 Google OAuth 認證
oauth.init_app(app)

# 註冊 Blueprint
# routes_bp: 負責處理應用的主要頁面路由（如首頁、註冊、登錄等）
#app.register_blueprint(routes_bp)
app.register_blueprint(home_bp)  # 根路徑首頁
app.register_blueprint(customer_bp, url_prefix='/customer')
app.register_blueprint(vendor_bp, url_prefix='/vendor')
app.register_blueprint(delivery_bp, url_prefix='/delivery')
app.register_blueprint(order_bp, url_prefix='/order')
# auth_bp: 負責處理身份驗證相關的路由（如 Google OAuth 登錄）
# url_prefix='/auth': 指定該 Blueprint 路由的前綴 URL
app.register_blueprint(auth_bp, url_prefix='/auth')


# 設定 Flask-Login 的默認登錄頁面路由
# 如果用戶未登錄，訪問需要登錄的頁面會重定向到這個路由
#login_manager.login_view = 'routes.member_login'
login_manager.login_view = 'customer.login'  # 修改為 customer_bp 中的 login 路由

# 定義 user_loader 函數，這個函數用於從數據庫中根據用戶 ID 加載用戶
# Flask-Login 會自動調用此函數來查找當前登錄的用戶
@login_manager.user_loader
def load_user(user_id):
    user = Customer.query.get(int(user_id)) or Vendor.query.get(int(user_id)) or DeliveryPerson.query.get(int(user_id))
    return user


# 打印應用中所有的 URL 路由規則，方便調試和確認路由設置
# for rule in app.url_map.iter_rules():
#     print(rule)

# 檢查是否以主程式的方式運行，並且啟動 Flask 應用
if __name__ == "__main__":
    # debug=True: 啟用 Flask 的調試模式，允許即時查看代碼變更
    app.run(debug=True)
