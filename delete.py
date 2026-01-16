from pymongo import MongoClient
from datetime import datetime

MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"

client = MongoClient(MONGO_URI)
db = client.CRM_Production

def delete_all_pancake_leads(dry_run=True):
    """
    XOÁ TOÀN BỘ LEADS PANCAKE
    """

    query = {
        "source_platform": "Pancake"
    }

    total = db.leads.count_documents(query)
    print(f"🔍 Tổng Pancake leads tìm thấy: {total}")

    if total == 0:
        print("✅ Không có lead Pancake nào để xoá")
        return

    if dry_run:
        print("⚠️ DRY RUN – chưa xoá")
        sample = list(db.leads.find(query).limit(5))
        for s in sample:
            print({
                "psid": s.get("psid"),
                "name": s.get("full_name"),
                "page_username": s.get("page_username"),
                "conversation_id": s.get("conversation_id")
            })
        print("👉 Đổi dry_run=False để xoá thật")
        return

    # XOÁ THẬT
    result = db.leads.delete_many(query)
    print(f"🗑️ ĐÃ XOÁ {result.deleted_count} Pancake leads")

if __name__ == "__main__":
    # BƯỚC 1: chạy xem trước
    # delete_all_pancake_leads(dry_run=True)

    # BƯỚC 2: chắc chắn rồi thì mở comment dòng dưới
    delete_all_pancake_leads(dry_run=False)
