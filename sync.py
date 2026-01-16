import requests
import os
import time
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime
from dateutil import parser  # 🔑 FIX datetime

# ======================
# LOAD ENV
# ======================
load_dotenv()

# ======================
# MONGO CONFIG (GIỐNG app.py)
# ======================
MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"
client = MongoClient(MONGO_URI)
db = client.CRM_Production
leads_col = db.leads

# ======================
# PANCAKE SCANNER
# ======================
class PancakeScanner:
    def __init__(self):
        self.user_token = os.getenv("PANCAKE_USER_TOKEN")
        self.api_v1 = "https://pages.fm/api/v1"
        self.public_v1 = "https://pages.fm/api/public_api/v1"
        self.public_v2 = "https://pages.fm/api/public_api/v2"

        if not self.user_token:
            raise ValueError("❌ Chưa cấu hình PANCAKE_USER_TOKEN")

    def get_pages(self):
        resp = requests.get(
            f"{self.api_v1}/pages",
            params={"access_token": self.user_token}
        )
        if resp.status_code != 200:
            return []
        data = resp.json().get("categorized", {})
        return data.get("activated", []) + data.get("inactivated", [])

    def get_page_token(self, page_id):
        resp = requests.post(
            f"{self.api_v1}/pages/{page_id}/generate_page_access_token",
            params={"access_token": self.user_token}
        )
        if resp.status_code != 200:
            return None
        return resp.json().get("page_access_token")

    def get_tag_map(self, page_id, page_token):
        tag_map = {}
        resp = requests.get(
            f"{self.public_v1}/pages/{page_id}/tags",
            params={"page_access_token": page_token}
        )
        if resp.status_code == 200:
            for t in resp.json().get("tags", []):
                tag_map[str(t.get("id"))] = t.get("text")
        return tag_map

    def fetch_all_conversations(self, page_id, page_token):
        all_convs = []
        last_id = None

        while True:
            params = {
                "page_access_token": page_token,
                "type": "INBOX"
            }
            if last_id:
                params["last_conversation_id"] = last_id

            resp = requests.get(
                f"{self.public_v2}/pages/{page_id}/conversations",
                params=params
            )

            if resp.status_code != 200:
                break

            data = resp.json().get("conversations", [])
            if not data:
                break

            all_convs.extend(data)
            last_id = data[-1].get("id")

            time.sleep(0.2)

            if len(data) < 60:
                break

        return all_convs


# ======================
# MAIN
# ======================
def main():
    scanner = PancakeScanner()

    print("🔥 RESET toàn bộ lead Pancake cũ (is_active=False)...")
    leads_col.update_many(
        {"source_platform": "Pancake"},
        {"$set": {"is_active": False}}
    )

    total_pages = 0
    total_convs = 0
    total_leads = 0

    print("🚀 Bắt đầu quét Pancake...")

    pages = scanner.get_pages()
    total_pages = len(pages)

    for page in pages:
        p_id = str(page.get("id"))
        p_name = page.get("name")

        print(f"\n--- PAGE: {p_name} ({p_id}) ---")

        token = scanner.get_page_token(p_id)
        if not token:
            print("⚠️ Không lấy được token")
            continue

        tag_map = scanner.get_tag_map(p_id, token)
        conversations = scanner.fetch_all_conversations(p_id, token)

        total_convs += len(conversations)
        page_leads = 0

        for conv in conversations:
            conv_tags = conv.get("tags", [])

            is_lead = False
            sector = None
            status = "Khách Mới"
            processed_tags = []

            for item in conv_tags:
                if isinstance(item, dict):
                    tag_text = item.get("text")
                else:
                    tag_text = tag_map.get(str(item))

                if not tag_text:
                    continue

                processed_tags.append(tag_text)

                # ===== TAG GROUP 1 → SECTOR =====
                if tag_text.startswith("1-"):
                    is_lead = True
                    if "Express" in tag_text:
                        sector = "Express"
                    elif "Warehouse" in tag_text:
                        sector = "Warehouse"
                    else:
                        sector = "Pod_Drop"

                # ===== TAG GROUP 2 → STATUS =====
                if tag_text.startswith("2-"):
                    raw = tag_text.split("-", 1)[-1].strip().lower()
                    if raw == "khách chốt":
                        status = "Khách hàng tiềm năng"
                    elif raw == "khách vip":
                        status = "Khách Vip"

            # Chỉ coi là lead khi có tag 1-*
            if not is_lead:
                continue

            customers = conv.get("customers", [])
            if not customers:
                continue

            customer = customers[0]
            psid = str(customer.get("id"))
            if not psid:
                continue

            # 🔑 FIX: convert updated_at -> datetime
            raw_updated_at = conv.get("updated_at")
            updated_at_dt = (
                parser.isoparse(raw_updated_at)
                if raw_updated_at else datetime.utcnow()
            )

            leads_col.update_one(
                {"psid": psid},
                {
                    "$set": {
                        "psid": psid,
                        "full_name": customer.get("name"),
                        "conversation_id": conv.get("id"),
                        "page_id": p_id,
                        "page_name": p_name,
                        "sector": sector,
                        "status": status,
                        "tags": processed_tags,
                        "source_platform": "Pancake",
                        "updated_at": updated_at_dt,
                        "is_active": True,
                        "synced_at": datetime.utcnow()
                    },
                    "$setOnInsert": {
                        "created_at": datetime.utcnow()
                    }
                },
                upsert=True
            )

            page_leads += 1
            total_leads += 1

        print(f"✅ Page lead hợp lệ: {page_leads}")

    print("\n==============================")
    print("🎉 HOÀN TẤT SYNC PANCAKE")
    print(f"Tổng Page: {total_pages}")
    print(f"Tổng hội thoại scan: {total_convs}")
    print(f"Tổng lead ghi DB: {total_leads}")


if __name__ == "__main__":
    main()
