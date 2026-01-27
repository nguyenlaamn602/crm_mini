from datetime import datetime
from flask_login import UserMixin

class User(UserMixin):
    """Lớp User tương thích với Flask-Login để quản lý session."""
    def __init__(self, user_data):
        self.id = str(user_data.get('_id'))
        self.username = user_data.get('username')
        self.password_hash = user_data.get('password_hash')
        self.role = user_data.get('role', 'user')
        self.department = user_data.get('department')
        self.telegram_chat_id = user_data.get('telegram_chat_id')
        self.created_at = user_data.get('created_at', datetime.now())   