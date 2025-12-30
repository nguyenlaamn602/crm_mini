import requests
import os
from dotenv import load_dotenv

load_dotenv()

class PancakeService:
    def __init__(self):
        self.api_v1 = "https://pages.fm/api/v1"
        self.public_v1 = "https://pages.fm/api/public_api/v1"
        self.public_v2 = "https://pages.fm/api/public_api/v2"
        self.user_token = os.getenv("PANCAKE_USER_TOKEN")

    def fetch_pages(self):
        """Lấy danh sách các Fanpage/OA đang hoạt động"""
        resp = requests.get(f"{self.api_v1}/pages", params={"access_token": self.user_token})
        if resp.status_code == 200:
            cat = resp.json().get("categorized", {})
            return cat.get("activated", []) + cat.get("inactivated", [])
        return []

    def get_token(self, page_id):
        """Tạo Token truy cập cho từng trang"""
        url = f"{self.api_v1}/pages/{page_id}/generate_page_access_token"
        resp = requests.post(url, params={"page_id": page_id, "access_token": self.user_token})
        return resp.json().get("page_access_token") if resp.status_code == 200 else None

    def get_all_leads(self, page_id, p_token):
        """Lấy khách hàng và ID hội thoại tương ứng"""
        tag_map = {}
        tag_resp = requests.get(f"{self.public_v1}/pages/{page_id}/tags", params={"page_access_token": p_token})
        if tag_resp.status_code == 200:
            for t in tag_resp.json().get("tags", []):
                tag_map[t.get("id")] = t.get("text")

        resp = requests.get(f"{self.public_v2}/pages/{page_id}/conversations", params={"page_access_token": p_token, "type": "INBOX"})
        leads = []
        if resp.status_code == 200:
            for conv in resp.json().get("conversations", []):
                cust_data = conv.get("customers", [])
                if not cust_data: continue
                
                sector, status = None, "Khách Mới"
                for item in conv.get("tags", []):
                    tag_text = item.get("text") if isinstance(item, dict) else tag_map.get(item)
                    if not tag_text or not isinstance(tag_text, str): continue

                    if tag_text.startswith("1-"):
                        if "Pod/Drop" in tag_text: sector = "Pod_Drop"
                        elif "Express" in tag_text: sector = "Express"
                        elif "Warehouse" in tag_text: sector = "Warehouse"
                    
                    if tag_text.startswith("2-"):
                        raw_status = tag_text.split("- ", 1)[-1].strip().lower()
                        if raw_status == "khách mới": status = "Khách Mới"
                        elif raw_status == "khách chốt": status = "Khách hàng tiềm năng"
                        elif raw_status == "khách vip": status = "Khách Vip"

                if sector: 
                    leads.append({
                        "name": cust_data[0].get("name", "Khách hàng"),
                        "psid": cust_data[0].get("id"),
                        "conversation_id": conv.get("id"), # Lấy ID hội thoại chuẩn
                        "phone": conv.get("recent_phone_numbers", [{}])[0].get("phone_number", "N/A"),
                        "sector": sector,
                        "status": status
                    })
        return leads