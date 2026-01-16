from pymongo import MongoClient

# Kết nối DB từ cấu hình app.py
MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"
client = MongoClient(MONGO_URI)
db = client.CRM_Production

def check_sync_results():
    total_pancake = db.leads.count_documents({"source_platform": "Pancake"})
    
    # Kiểm tra những khách vẫn còn thiếu conversation_id
    missing_conv = db.leads.count_documents({
        "source_platform": "Pancake", 
        "conversation_id": {"$exists": False}
    })
    
    # Kiểm tra những khách vẫn còn thiếu page_username
    missing_user = db.leads.count_documents({
        "source_platform": "Pancake", 
        "page_username": {"$exists": False}
    })

    # Kiểm tra trạng thái "locked" nếu bạn đã chạy script khóa khách cũ
    locked_count = db.leads.count_documents({"sync_status": "locked"})

    print("--- THỐNG KÊ DỮ LIỆU PANCAKE ---")
    print(f"Tổng số khách từ Pancake: {total_pancake}")
    print(f"Số khách THIẾU conversation_id: {missing_conv}")
    print(f"Số khách THIẾU page_username: {missing_user}")
    print(f"Số khách vẫn đang ở trạng thái LOCKED: {locked_count}")
    print("--------------------------------")

if __name__ == "__main__":
    check_sync_results()