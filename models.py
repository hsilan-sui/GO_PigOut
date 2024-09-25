from datetime import datetime
from extensions import db  # 從 extensions 中匯入 db
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

# 创建数据库实例
#db = SQLAlchemy()

# Customer 模型定义
class Customer(UserMixin, db.Model):
    __tablename__ = 'Customer'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 自动递增主键
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)  # 保存 Google ID
    password = db.Column(db.String(255), nullable=True)  # 第三方登录时可以为空
    role = db.Column(db.String(50), nullable=True, default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)

    # 关联到 Cart 和 Order
    carts = db.relationship('Cart', backref='customer', lazy=True)
    orders = db.relationship('Order', backref='customer', lazy=True)

# DeliveryPerson 模型定义
class DeliveryPerson(db.Model):
    __tablename__ = 'DeliveryPerson'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联到 Order
    orders = db.relationship('Order', backref='delivery_person', lazy=True)

# Vendor 模型定义
class Vendor(db.Model):
    __tablename__ = 'Vendor'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=True)
    address_id = db.Column(db.Integer, db.ForeignKey('Address.id'), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    role = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联到 MenuItem 和 Order
    menu_items = db.relationship('MenuItem', backref='vendor', lazy=True)
    orders = db.relationship('Order', backref='vendor', lazy=True)

# MenuItem 模型定义
class MenuItem(db.Model):
    __tablename__ = 'MenuItem'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('Vendor.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text, nullable=True)
    available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联到 CartItem 和 OrderItem
    cart_items = db.relationship('CartItem', backref='menu_item', lazy=True)
    order_items = db.relationship('OrderItem', backref='menu_item', lazy=True)

# Cart 模型定义
class Cart(db.Model):
    __tablename__ = 'Cart'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('Customer.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联到 CartItem
    cart_items = db.relationship('CartItem', backref='cart', lazy=True)

# CartItem 模型定义
class CartItem(db.Model):
    __tablename__ = 'CartItem'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('Cart.id'), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('MenuItem.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Order 模型定义
class Order(db.Model):
    __tablename__ = 'Order'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('Customer.id'), nullable=False)
    delivery_person_id = db.Column(db.Integer, db.ForeignKey('DeliveryPerson.id'), nullable=True)
    vendor_id = db.Column(db.Integer, db.ForeignKey('Vendor.id'), nullable=False)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(50), nullable=True)
    order_time = db.Column(db.DateTime, nullable=True)
    delivery_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联到 OrderItem 和 Payment
    order_items = db.relationship('OrderItem', backref='order', lazy=True)
    payments = db.relationship('Payment', backref='order', lazy=True)

# OrderItem 模型定义
class OrderItem(db.Model):
    __tablename__ = 'OrderItem'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey('Order.id'), nullable=False)
    menu_item_id = db.Column(db.Integer, db.ForeignKey('MenuItem.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False, default=1)
    price = db.Column(db.Numeric(10, 2), nullable=False)

# Payment 模型定义
class Payment(db.Model):
    __tablename__ = 'Payment'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    order_id = db.Column(db.Integer, db.ForeignKey('Order.id'), nullable=False)
    payment_method = db.Column(db.String(50), nullable=True)
    payment_status = db.Column(db.String(50), nullable=True)
    total_price = db.Column(db.Numeric(10, 2), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Address 模型定义
class Address(db.Model):
    __tablename__ = 'Address'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    street = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    postal_code = db.Column(db.String(10), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 关联到 Vendor
    vendors = db.relationship('Vendor', backref='address', lazy=True)
