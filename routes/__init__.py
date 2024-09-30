'''
當你將路由或其他模塊放在文件夾中時，__init__.py 是一個必要的文件，用於告訴 Python 這個文件夾是一個模塊，並允許你從中導入內容
在 routes 文件夾中的 __init__.py 會負責導入所有的 Blueprint，這樣在 app.py 中就可以統一導入(用來匯總和導出所有的 Blueprint，這樣可以更方便地在應用中進行註冊)
'''
from .home_routes import home_bp
from .customer_routes import customer_bp
from .vendor_routes import vendor_bp
from .delivery_routes import delivery_bp

# 將 Blueprint 匯出，供其他模塊使用
__all__ = ['home_bp','customer_bp', 'vendor_bp', 'delivery_bp']