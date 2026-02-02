from datetime import datetime
from flask_login import UserMixin
from bson.objectid import ObjectId

class User(UserMixin):
    """Lớp User tương thích với Flask-Login để quản lý session."""
    def __init__(self, user_data):
        self.id = str(user_data.get('_id'))
        self.username = user_data.get('username')
        self.password_hash = user_data.get('password_hash')
        self.role = user_data.get('role', 'user')
        # ✅ Department is now a list
        self.departments = user_data.get('departments', [])
        # ✅ Thêm trường Telegram Chat ID
        self.telegram_chat_id = user_data.get('telegram_chat_id')
        self.created_at = user_data.get('created_at', datetime.now())


# ==========================
# PRICING HISTORY MODEL
# ==========================
class PricingHistory:
    """
    Helper model cho Pricing Tool History (GLOBAL).
    Không dùng ORM nặng, thao tác trực tiếp Mongo.
    """

    def __init__(self, db):
        self.collection = db.pricing_history

    def create(self, data, mode=None, user_id=None):
        record = {
            "created_at": datetime.utcnow(),
            "created_by": user_id,
            "mode": mode,
            "total_rows": len(data),
            "data": data
        }
        return self.collection.insert_one(record)

    def list_latest(self, limit=20):
        return list(
            self.collection.find({})
            .sort("created_at", -1)
            .limit(limit)
        )

    def get_by_id(self, history_id):
        try:
            # Convert string ID to ObjectId for Mongo query
            oid = ObjectId(history_id)
            return self.collection.find_one({"_id": oid})
        except:
            # Handle invalid ID format
            return None

    def delete_by_id(self, history_id):
        try:
            oid = ObjectId(history_id)
            result = self.collection.delete_one({"_id": oid})
            return result.deleted_count > 0
        except:
            return False
