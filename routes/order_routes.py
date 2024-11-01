'''
放置與訂單相關的路由
'''
#Flask 應用或 Blueprint 中可以通過 current_app.config 訪問 Line Pay 配置
#current_app獲取當前應用的配置變量，這裡會用來讀取 Line Pay 的機密 Channel ID 和 Secret
from flask import Blueprint, request, jsonify, url_for, redirect,current_app, render_template
from datetime import datetime
from extensions import db
from models import Order, OrderItem, Payment
import requests
from flask_login import current_user, login_required
#生成加密的消息認證碼（HMAC），確保數據的完整性和來源驗證
import hmac
#提供不同的哈希算法支持，此處用於生成 SHA-256 哈希
import hashlib
#用於生成唯一識別碼（UUID），在此作為 nonce 值，用來防止重放攻擊
import uuid
import base64  # <-- 新增此行
import json

# 創建 Blueprint
order_bp = Blueprint("order", __name__)


# 結帳路由，處理訂單建立 和 linepay支付
@order_bp.route("/checkout", methods=["POST"])
@login_required
def checkout():
    data = request.get_json() # flask解析數據的方法 數據會被轉換為一個 Python 字典，方便在後端進行處理
    cart_items = data.get("cart")
    payment_method = data.get("paymentMethod","linepay")
    if not cart_items:
        return jsonify({"status": "error", "message": "購物車不能為空"}), 400

    
    # if not cart_items:
    #     return jsonify({"status": "error", "message": "購物車不能為空"}), 400
    
    #創建訂單
    new_order = Order(
        customer_id=current_user.id,
        vendor_id=4, #這到時候有餐廳資料再改
        total_price=sum(item["price"] * item["quantity"] for item in cart_items),
        status="pending",
        created_at=datetime.now()
    )
    db.session.add(new_order)
    db.session.commit()

    #添加訂單項目 
    for item in cart_items:
        order_item = OrderItem(
            order_id=new_order.id,
            menu_item_id=item["id"],
            quantity=item["quantity"],
            price=item["price"]
        )
        db.session.add(order_item)

    #創建付款紀錄
    payment = Payment(
        order_id=new_order.id,
        payment_method=payment_method,
        payment_status="pending",
        total_price=new_order.total_price,
    )
    db.session.add(payment)
    db.session.commit()

    ## 根據不同的付款方式進行處理
    if payment_method == "linepay":
        return handle_linepay_payment(new_order)
    else:
        return jsonify({"status": "error", "message": "未知的付款方式"}), 400


# Linepay 支付請求的處理
#  Line Pay 的 API 文件，請求需要進行簽名，並將相關的簽名與隨機值（nonce）添加到請求頭中
def handle_linepay_payment(order):
    #載入 Line Pay Channel ID 和 Channel Secret
    # 使用 current_app 訪問配置
    CHANNEL_ID = current_app.config["LINEPAY_CHANNEL_ID"]
    CHANNEL_SECRET = current_app.config["LINEPAY_CHANNEL_SECRET"]

    # 隨機字串 nonce 用於防止重放攻擊
    # 使用 UUID 生成隨機字符串 nonce（一次性隨機數），用於防止重放攻擊。每次請求的 nonce 值應該是唯一的
    nonce = str(uuid.uuid4())
    api_path = "/v3/payments/request" # Line Pay API 的支付請求接口
    base_url = "https://sandbox-api-pay.line.me" #定義 Line Pay 的沙盒環境基礎 URL，用於測試支付功能


    # 定義請求數據（payload）｜這個數據格式很重要！！
    payload = {
        "amount": int(order.total_price),  # 訂單的總價格 int
        "currency": "TWD",
        "orderId": str(order.id), #訂單 ID，line要字串
        "packages": [{   #包含訂單的詳細內容，包含 id、金額、名稱
            "id": "default",
            "amount": int(order.total_price),
            "name": "Order Payment",
            "products": [{
                "name": "商品名稱",
                "quantity": 1,
                "price": int(order.total_price)
            }]
        }],
        "redirectUrls": { #訂單完成或取消後的跳轉 URL，用來處理支付結果的通知
            "confirmUrl": url_for("order.linepay_confirm", _external=True),
            "cancelUrl": url_for("order.linepay_cancel", _external=True)
        }
    }
    # payload = {
    #     "amount": int(order.total_price),  # 訂單的總價格 int
    #     "currency": "TWD",
    #     "orderId": f"ORDER-{order.id}", #訂單 ID，便於後續識別訂單
    #     "packages": [{   #包含訂單的詳細內容，包含 id、金額、名稱
    #         "id": "default",
    #         "amount": int(order.total_price),
    #         "name": "Order Payment",
    #         "products": [{
    #             "name": "商品名稱",
    #             "quantity": 1,
    #             "price": int(order.total_price)
    #         }]
    #     }],
    #     "redirectUrls": { #訂單完成或取消後的跳轉 URL，用來處理支付結果的通知
    #         "confirmUrl": url_for("order.linepay_confirm", _external=True),
    #         "cancelUrl": url_for("order.linepay_cancel", _external=True)
    #     }
    # }

    # 構建簽名字串
    message = CHANNEL_SECRET + api_path + json.dumps(payload) + nonce
    signature = base64.b64encode(
        hmac.new(CHANNEL_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")


    # 設置 HTTP 請求的標頭
    headers = {
        "Content-Type": "application/json", #指定請求的內容類型為 JSON
        "X-LINE-ChannelId": CHANNEL_ID, #Line Pay 的 Channel ID，用來識別請求的來源應用
        "X-LINE-Authorization-Nonce": nonce, #唯一的 nonce 值，用於確保請求的唯一性和防止重放攻擊
        "X-LINE-Authorization": signature
    }

    # 發送 POST 支付請求到 Line Pay 的 API，包含設置的 headers 和 JSON 數據
    # 發送 POST 支付請求到 Line Pay API
    try:
        response = requests.post(
            f"{base_url}{api_path}",
            headers=headers,
            json=payload
        )
        response.raise_for_status()
    except requests.RequestException as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    # 檢查請求結果並處理回應
    response_data = response.json()
    if response_data.get("returnCode") == "0000":
        payment_url = response_data["info"]["paymentUrl"]["web"]
        return jsonify({"status": "success", "paymentUrl": payment_url})
    return jsonify({"status": "error", "message": response_data.get("returnMessage", "Linepay 請求失敗")}), 400


# 處理 Line Pay 支付回調 (Confirm 和 Cancel)
# Line Pay 支付完成後會跳轉到 confirmUrl 或 cancelUrl，需要為這些回調設置相應的路由
#系統才能根據用戶的支付行為（成功或取消）來處理後續操作

#  Line Pay 支付成功後的確認回調
@order_bp.route("/linepay/confirm", methods=["GET"])
@login_required
def linepay_confirm():
    transaction_id = request.args.get("transactionId")
    order_id = request.args.get("orderId")
    if not transaction_id:
        return jsonify({"status": "error", "message": "缺少交易 ID"}), 400

    # 嘗試將 order_id 轉換為整數
    try:
        order_id = int(order_id)
    except ValueError:
        return jsonify({"status": "error", "message": "訂單 ID 格式無效"}), 400
    
    # 確認交易並更新訂單和付款狀態
    order = Order.query.filter_by(id=order_id).first()
    if order:
        order.status = "paid"
        payment = Payment.query.filter_by(order_id=order.id).first()
        if payment:
            payment.payment_status = "paid"
        db.session.commit()
        return redirect(url_for("order.order_success"))
    
    return jsonify({"status": "error", "message": "訂單未找到"}), 404
  

# Line Pay 支付取消的回調
@order_bp.route("/linepay/cancel", methods=["GET"])
def linepay_cancel():
    # 獲取 order_id 以便更新 Payment 狀態和 Order 狀態
    order_id = request.args.get("orderId")
    if order_id:
        # 更新 Payment 的 payment_status 為 "cancelled"
        payment = Payment.query.filter_by(order_id=order_id).first()
        if payment:
            payment.payment_status = "cancelled"
        
        # 更新 Order 的狀態為 "cancelled"
        order = Order.query.filter_by(id=order_id).first()
        if order:
            order.status = "cancelled"
        
        db.session.commit()  # 提交更改到資料庫
    return redirect(url_for("order.order_cancelled"))  # 跳轉至支付取消頁面

#創建 order_success 頁面，用於向用戶展示支付成功的結果
@order_bp.route("/order/success")
def order_success():
    return render_template("shared/payment_success.html")

# 創建 order_cancelled 頁面，用於向用戶展示支付取消的結果
@order_bp.route("/order/cancelled")
def order_cancelled():
    return render_template("shared/payment_cancelled.html")