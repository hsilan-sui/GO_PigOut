import os 
from datetime import datetime
from flask import Flask, render_template,request, jsonify, url_for,abort
from flask_sqlalchemy import SQLAlchemy # 用於整合 SQLAlchemy ORM，以便更方便地與數據庫進行交互
from flask_migrate import Migrate # 數據庫遷移，幫助管理數據庫結構的變化
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash  # 用於密碼hash驗證

app = Flask(__name__)

# 配置 PostgreSQL 數據庫 URI
# 從環境變量中讀取數據庫 URI
# 用os.getenv來獲取系統的環境變數
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://postgres@localhost:5432/pigout_db')

# 禁用 SQLAlchemy 的對象修改追蹤功能，以提高性能並減少內存使用
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '123'  # 我還不知道這要幹嘛 設置應用的秘密密鑰，用於 Flask-Login 處理 session 和其他加密功能。 Flask-Login 需要 secret key 來加密 session

#1. 檢查資料庫連線配置
print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# 初始化資料庫和遷移工具
db = SQLAlchemy(app) # 初始化 SQLAlchemy 並將其與 Flask 應用綁定
migrate = Migrate(app, db) # 初始化 Flask-Migrate 並將其與 Flask 應用和 SQLAlchemy 綁定

# 設定 Flask-Login 初始化登入管理
login_manager = LoginManager() # 創建 LoginManager 實例
login_manager.init_app(app) # 將 LoginManager 實例初始化並與 Flask 應用綁定
login_manager.login_view = 'login' # 設置當用戶嘗試訪問受保護頁面但尚未登錄時，重定向的登錄頁面


# 2.建立簡單的資料庫查詢來測試連線
# Customer 模型 --- Customer 資料表(對應欄位Column)
class Customer(UserMixin, db.Model): # 加入UserMixin 是 Flask-Login 的類別，提供基本的登入登出功能
    __tablename__ = 'Customer'  # 資料庫表名
    
    id = db.Column(db.Integer, primary_key=True)  # id 欄位，主鍵，自動遞增
    name = db.Column(db.String(255), nullable=False)  # name 欄位，長度 255，不可為空
    email = db.Column(db.String(255), unique=True, nullable=False)  # email 欄位，長度 255，唯一且不可為空
    phone = db.Column(db.String(20), nullable=True)  # phone 欄位，長度 20，可選填
    password = db.Column(db.String(255), nullable=False)  # password 欄位，長度 255，不可為空
    role = db.Column(db.String(50), nullable=True)  # role 欄位，長度 50，可選填
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # created_at 欄位，默認為當前時間

# 設定 user_loader 函數 登入用戶載入函數
# @login_manager.user_loader 是 Flask-Login 要求的函數，負責根據用戶的 id 從資料庫載入該用戶。這樣 Flask-Login 可以在 session 中追蹤使用者
@login_manager.user_loader
def load_user(user_id):
    return Customer.query.get(int(user_id))


@app.route("/")
def index():
    return render_template('index.html')

@app.route("/<int:food_id>")
def food(food_id):
    return f"哈哈, {food_id}"

# RESTful API 登录端点 處理使用者登入請求
@app.route("/login", methods=["GET", "POST"])
def member_login():
    if request.method == "POST":
        data = request.json  # 獲取前端傳來的 JSON 數據
        email = data.get("email")
        password = data.get("password")

        # 從資料庫查詢對應 email 的使用者
        customer = Customer.query.filter_by(email=email).first()

        if customer and check_password_hash(customer.password, password):
            login_user(customer)  # 使用 login_user 登入使用者
            return jsonify({"status": "success", "message": "登入成功！", "redirect_url": url_for('dashboard')}), 200
        else:
            return jsonify({"status": "fail", "message": "帳號或密碼錯誤"}), 404
    return render_template('login.html')

    #     # 验证用户凭据
    # if email == me1['email'] and password == me1['password']:
    #     # 登录成功，重定向到另一个页面（例如 "/dashboard"）
    #     return jsonify({"status": "success", "message": "Login successful!", "redirect_url": url_for('dashboard')}), 200
    # else:
    #     # 登录失败，重定向到404页面
    #     abort(404)


    # 渲染靜態頁面
@app.route('/page/<page_name>')
def render_page(page_name):# href="{{ url_for('render_page', page_name='login') }}"
    allowed_pages = ['login', 'cart', 'register', 'dashboard']
    if page_name in allowed_pages:
        return render_template(f'{page_name}.html')
    else:
        # 可以考慮更詳細的錯誤處理和信息
        return render_template('404.html'), 404

# 受保護的 Dashboard 頁面，僅限已登入的用戶訪問
@app.route("/dashboard")
@login_required # @login_required 裝飾器用來保護頁面，只有已登入的用戶可以訪問這個路由。未登入的用戶會被重定向到登入頁面
def dashboard():
    return render_template('dashboard.html')

# 自定义404页面(到時還可以帶入參數 自定義不同介面)
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# 增加新的使用者
@app.route("/add_customer", methods=["POST"])
def add_customer():
    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        phone = data.get("phone")
        password = data.get("password")
        role = data.get("role", "customer")  # 暫時默認角色為 customer

        if not name or not email or not password:
            return jsonify({"error": "Missing required fields"}), 400

        #對新增使用者所填入的密碼 進行密碼雜湊(不要把密碼赤裸裸在資料庫中)
        #記得方法要改成 method='pbkdf2:sha256'
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_customer = Customer(
            name=name,
            email=email,
            phone=phone,
            password=hashed_password,
            role=role,
            created_at=datetime.utcnow()
        )

        db.session.add(new_customer)
        db.session.commit()

        return jsonify({"message": "Customer added successfully!"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/customers")
def get_customers():
    try:
        customers = Customer.query.all()
        return jsonify([{
            "id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "role": customer.role,
            "created_at": customer.created_at
        } for customer in customers])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 登出功能
@app.route("/logout")
@login_required #這個路由處理登出操作，登出成功後返回一個 JSON 格式的成功訊息
def logout():
    logout_user()
    return jsonify({"message": "登出成功"}), 200


if __name__ == "__main__":
    app.run()