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

    # =========================
    # Helpers
    # =========================
    def _normalize_page_id(self, page_id: str) -> str:
        """
        Một số DB của bạn lưu page_id có prefix (pzl_, tl_, ...).
        API Pancake thường dùng raw id để generate token / gọi endpoint.
        """
        if not page_id:
            return page_id
        for prefix in ("pzl_", "tl_", "pfb_", "pig_"):
            if isinstance(page_id, str) and page_id.startswith(prefix):
                return page_id[len(prefix):]
        return page_id

    def _safe_phone(self, conv: dict) -> str:
        """
        recent_phone_numbers đôi khi = [] => tránh IndexError.
        """
        recent = conv.get("recent_phone_numbers") or []
        if recent and isinstance(recent[0], dict):
            # Pancake có lúc dùng key phone_number
            return recent[0].get("phone_number") or recent[0].get("phone") or "N/A"
        return "N/A"

    # =========================
    # API calls
    # =========================
    def fetch_pages(self):
        """Lấy danh sách các Fanpage/OA đang hoạt động"""
        resp = requests.get(
            f"{self.api_v1}/pages",
            params={"access_token": self.user_token},
            timeout=30
        )
        if resp.status_code == 200:
            cat = resp.json().get("categorized", {})
            return cat.get("activated", []) + cat.get("inactivated", [])
        return []

    def get_token(self, page_id):
        """
        Tạo Token truy cập cho từng trang
        - Fix params: chỉ cần access_token (page_id đã nằm trên URL)
        - In debug khi fail để bạn biết lý do
        """
        raw_page_id = self._normalize_page_id(str(page_id))

        url = f"{self.api_v1}/pages/{raw_page_id}/generate_page_access_token"
        try:
            resp = requests.post(
                url,
                params={"access_token": self.user_token},
                timeout=30
            )
        except Exception as e:
            print(f"[PANCAKE] get_token EXCEPTION for page_id={page_id}: {repr(e)}")
            return None

        if resp.status_code != 200:
            # debug rõ lý do fail (token sai, page không quyền, bị rate limit, ...)
            try:
                print(f"[PANCAKE] get_token FAILED for page_id={page_id} "
                      f"(raw={raw_page_id}) status={resp.status_code} body={resp.text[:300]}")
            except Exception:
                print(f"[PANCAKE] get_token FAILED for page_id={page_id} status={resp.status_code}")
            return None

        return resp.json().get("page_access_token")

    def get_all_leads(self, page_id, p_token, page_username=None):
        """
        Lấy khách hàng và ID hội thoại tương ứng + page_username để build link hội thoại
        Trả về list dict:
          - name
          - psid
          - conversation_id
          - phone
          - sector
          - status
          - page_username
        """
        raw_page_id = self._normalize_page_id(str(page_id))

        # 1) load tag map
        tag_map = {}
        tag_resp = requests.get(
            f"{self.public_v1}/pages/{raw_page_id}/tags",
            params={"page_access_token": p_token},
            timeout=30
        )
        if tag_resp.status_code == 200:
            for t in tag_resp.json().get("tags", []):
                tag_map[t.get("id")] = t.get("text")

        # 2) load conversations
        resp = requests.get(
            f"{self.public_v2}/pages/{raw_page_id}/conversations",
            params={"page_access_token": p_token, "type": "INBOX"},
            timeout=30
        )

        leads = []
        if resp.status_code == 200:
            for conv in resp.json().get("conversations", []):
                cust_data = conv.get("customers", [])
                if not cust_data:
                    continue

                # default
                sector, status = None, "Khách Mới"

                # parse tags
                for item in conv.get("tags", []):
                    tag_text = item.get("text") if isinstance(item, dict) else tag_map.get(item)
                    if not tag_text or not isinstance(tag_text, str):
                        continue

                    # Sector tag
                    if tag_text.startswith("1-"):
                        if "Pod/Drop" in tag_text:
                            sector = "Pod_Drop"
                        elif "Express" in tag_text:
                            sector = "Express"
                        elif "Warehouse" in tag_text:
                            sector = "Warehouse"

                    # Status tag
                    if tag_text.startswith("2-"):
                        raw_status = tag_text.split("- ", 1)[-1].strip().lower()
                        if raw_status == "khách mới":
                            status = "Khách Mới"
                        elif raw_status == "khách chốt":
                            status = "Khách hàng tiềm năng"
                        elif raw_status == "khách vip":
                            status = "Khách Vip"

                # ✅ FIX QUAN TRỌNG: không còn lọc mất khách thiếu sector tag
                if not sector:
                    # bạn có thể đổi thành "Unknown" nếu muốn lọc riêng nhóm chưa gắn tag
                    sector = "Pod_Drop"

                leads.append({
                    "name": cust_data[0].get("name", "Khách hàng"),
                    "psid": cust_data[0].get("id"),
                    "conversation_id": conv.get("id"),
                    "phone": self._safe_phone(conv),
                    "sector": sector,
                    "status": status,
                    "page_username": page_username
                })

        else:
            # debug nếu conversations fail (token hết hạn, sai token...)
            try:
                print(f"[PANCAKE] get_all_leads FAILED page_id={page_id} (raw={raw_page_id}) "
                      f"status={resp.status_code} body={resp.text[:300]}")
            except Exception:
                print(f"[PANCAKE] get_all_leads FAILED page_id={page_id} status={resp.status_code}")

        return leads
