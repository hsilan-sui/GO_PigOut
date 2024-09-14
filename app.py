from flask import Flask, render_template,request,jsonify, url_for,abort
from flask_login import LoginManager


app = Flask(__name__)

# 模拟的用户数据
me1 = {
    'email': 'jj@gmail.com',
    'password': '123'
}

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/<int:food_id>")
def food(food_id):
    return f"哈哈, {food_id}"


# RESTful API 登录端点
@app.route("/login", methods=["POST"])
def member_login():
    # 检查接收到的内容
    data = request.json
    print(f"Received data: {data}")
    # 从请求中获取用户提交的数据
    email = data.get("email")
    password = data.get("password")


        # 验证用户凭据
    if email == me1['email'] and password == me1['password']:
        # 登录成功，重定向到另一个页面（例如 "/dashboard"）
        return jsonify({"status": "success", "message": "Login successful!", "redirect_url": url_for('dashboard')}), 200
    else:
        # 登录失败，重定向到404页面
        abort(404)

# 返回登录页面
@app.route("/login")
def login_page():
    return render_template('login.html')

# 模拟的登录成功后的页面
@app.route("/dashboard")
def dashboard():
    return render_template('dashboard.html')

# 自定义404页面
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == "__main__":
    app.run()