from flask import Blueprint, render_template
from models import Vendor

# 定義 home Blueprint
home_bp = Blueprint('home', __name__)

# 定義首頁路由
@home_bp.route("/", endpoint='index')
def index():
    return render_template('home/index.html')  # 渲染首頁模板
    #return render_template('customer/order.html')  # 渲染首頁模板

@home_bp.route('/restaurantMenu/<vendor_id>')
def restaurant_menu(vendor_id):
    # 在這裡處理對應餐廳的邏輯
    return render_template('customer/order.html', vendor_id=vendor_id)
# @home_bp.route("/restaurantMenu", methods=['GET'])
# def restaurant_menu():
#     return render_template('customer/order.html')