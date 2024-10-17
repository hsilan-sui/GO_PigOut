from flask import Blueprint, render_template

# 定義 home Blueprint
home_bp = Blueprint('home', __name__)

# 定義首頁路由
@home_bp.route("/", endpoint='index')
def index():
    return render_template('home/index.html')  # 渲染首頁模板
    #return render_template('customer/order.html')  # 渲染首頁模板
