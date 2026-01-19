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
        DB có thể lưu page_id dạng pzl_, tl_, ...
        API Pancake cần RAW page_id
        """
        if not page_id:
            return page_id
        for prefix in ("pzl_", "tl_", "pfb_", "pig_"):
            if isinstance(page_id, str) and page_id.startswith(prefix):
                return page_id[len(prefix):]
        return page_id

    def _safe_phone(self, conv: dict) -> str:
        recent = conv.get("recent_phone_numbers") or []
        if recent and isinstance(recent[0], dict):
            return recent[0].get("phone_number") or recent[0].get("phone") or "N/A"
        return "N/A"

    # =========================
    # Pages
    # =========================
    def fetch_pages(self):
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
        raw_page_id = self._normalize_page_id(str(page_id))
        url = f"{self.api_v1}/pages/{raw_page_id}/generate_page_access_token"

        try:
            resp = requests.post(
                url,
                params={"access_token": self.user_token},
                timeout=30
            )
        except Exception as e:
            print(f"[PANCAKE] get_token EXCEPTION page_id={page_id}: {e}")
            return None

        if resp.status_code != 200:
            print(f"[PANCAKE] get_token FAILED page_id={page_id} "
                  f"status={resp.status_code} body={resp.text[:200]}")
            return None

        return resp.json().get("page_access_token")

    # =========================
    # Leads / Conversations
    # =========================
    def get_all_leads(self, page_id, p_token, page_username=None):
        raw_page_id = self._normalize_page_id(str(page_id))

        tag_map = {}
        tag_resp = requests.get(
            f"{self.public_v1}/pages/{raw_page_id}/tags",
            params={"page_access_token": p_token},
            timeout=30
        )
        if tag_resp.status_code == 200:
            for t in tag_resp.json().get("tags", []):
                tag_map[t.get("id")] = t.get("text")

        resp = requests.get(
            f"{self.public_v2}/pages/{raw_page_id}/conversations",
            params={"page_access_token": p_token, "type": "INBOX"},
            timeout=30
        )

        leads = []
        if resp.status_code != 200:
            print(f"[PANCAKE] get_all_leads FAILED page_id={page_id} "
                  f"status={resp.status_code}")
            return leads

        for conv in resp.json().get("conversations", []):
            cust_data = conv.get("customers", [])
            if not cust_data:
                continue

            sector, status = "Pod_Drop", "Khách Mới"

            for item in conv.get("tags", []):
                tag_text = item.get("text") if isinstance(item, dict) else tag_map.get(item)
                if not tag_text:
                    continue

                if tag_text.startswith("1-"):
                    if "Express" in tag_text:
                        sector = "Express"
                    elif "Warehouse" in tag_text:
                        sector = "Warehouse"

                if tag_text.startswith("2-"):
                    raw = tag_text.split("- ", 1)[-1].lower()
                    if raw == "khách chốt":
                        status = "Khách hàng tiềm năng"
                    elif raw == "khách vip":
                        status = "Khách Vip"

            leads.append({
                "name": cust_data[0].get("name", "Khách hàng"),
                "psid": cust_data[0].get("id"),
                "conversation_id": conv.get("id"),
                "phone": self._safe_phone(conv),
                "sector": sector,
                "status": status,
                "page_username": page_username
            })

        return leads

    # =========================
    # SEND MESSAGE (FIX CHUẨN API)
    # =========================
    def send_message(
        self,
        page_id: str,
        conversation_id: str,
        access_token: str,
        message: str = None,
        content_ids: list = None
    ):
        """
        POST /pages/{page_id}/conversations/{conversation_id}/messages
        """
        raw_page_id = self._normalize_page_id(str(page_id))

        url = (
            f"{self.public_v1}/pages/"
            f"{raw_page_id}/conversations/"
            f"{conversation_id}/messages"
        )

        payload = {
            "action": "reply_inbox"
        }

        if message:
            payload["message"] = message

        if content_ids:
            payload["content_ids"] = content_ids

        resp = requests.post(
            url,
            params={"page_access_token": access_token},
            json=payload,
            timeout=30
        )

        if resp.status_code not in (200, 201):
            raise Exception(
                f"Pancake send_message failed "
                f"(status={resp.status_code}) {resp.text}"
            )

        return resp.json()