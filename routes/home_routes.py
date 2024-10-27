import os
from flask import Blueprint, render_template
from models import Vendor, MenuItem
from dotenv import load_dotenv


# 定義 home Blueprint
home_bp = Blueprint('home', __name__)

# 下載.env 文件中的環境變量

# 定義首頁路由
@home_bp.route("/", endpoint='index')
def index():
    # 從環境變數中取GCP key
    google_maps_api_key = os.getenv('GOOGLE_MAPS_API_KEY')
    return render_template('home/index.html', my_key = google_maps_api_key)  # 渲染首頁模板
    #return render_template('customer/order.html')  # 渲染首頁模板

@home_bp.route('/restaurantMenu/<int:vendor_id>')
def restaurant_menu(vendor_id):
    # 從資料庫中抓取屬於該餐廳vendor_id的全部菜單資料
    menu_items = MenuItem.query.filter_by(vendor_id=vendor_id, category="主食", available=True).all()

    print(menu_items)
    # 建立 data 字典
    data = {
        "vendor_id": vendor_id,
        "menu_items": menu_items
    }

    # 在這裡處理對應餐廳的邏輯  # =>記得使用解包 **  直接在order.html使用屬性取直
    return render_template('customer/order.html', **data)
# @home_bp.route("/restaurantMenu", methods=['GET'])
# def restaurant_menu():
#     return render_template('customer/order.html')