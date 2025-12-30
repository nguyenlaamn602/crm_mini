import requests
import json
import os
from dotenv import load_dotenv

# Tải cấu hình từ file .env
load_dotenv()

def test_pancake_api():
    user_token = os.getenv("PANCAKE_USER_TOKEN")
    api_v1 = "https://pages.fm/api/v1"
    public_api_v2 = "https://pages.fm/api/public_api/v2"

    if not user_token:
        print("❌ Lỗi: Chưa cấu hình PANCAKE_USER_TOKEN trong file .env")
        return

    result = {
        "pages": [],
        "filtered_customers": []
    }

    print("🚀 Đang kết nối Pancake.ai để lấy Username và Platform...")

    # 1. Lấy danh sách Pages
    pages_resp = requests.get(f"{api_v1}/pages", params={"access_token": user_token})
    if pages_resp.status_code != 200:
        print(f"❌ Không thể lấy danh sách page. Mã lỗi: {pages_resp.status_code}")
        return

    pages_data = pages_resp.json().get("categorized", {})
    all_pages = pages_data.get("activated", []) + pages_data.get("inactivated", [])

    for page in all_pages:
        p_id = str(page.get("id"))
        p_name = page.get("name")
        p_platform = page.get("platform")
        # Lấy username (thường dùng cho Facebook/Telegram) hoặc slug
        p_username = page.get("username") or page.get("slug") or "N/A"
        
        result["pages"].append({
            "id": p_id,
            "name": p_name,
            "username": p_username, # THÊM MỚI TRƯỜNG NÀY
            "platform": p_platform
        })

        # 2. Lấy Page Access Token
        tk_url = f"{api_v1}/pages/{p_id}/generate_page_access_token"
        tk_resp = requests.post(tk_url, params={"page_id": p_id, "access_token": user_token})
        page_token = tk_resp.json().get("page_access_token") if tk_resp.status_code == 200 else None

        if not page_token:
            continue

        # 3. Lấy hội thoại và lọc theo Tag 1-
        conv_url = f"{public_api_v2}/pages/{p_id}/conversations"
        conv_resp = requests.get(conv_url, params={"page_access_token": page_token, "type": "INBOX"})
        
        if conv_resp.status_code == 200:
            conversations = conv_resp.json().get("conversations", [])
            for conv in conversations:
                # Kiểm tra Tag sector (1-)
                has_tag = False
                tags = conv.get("tags", [])
                for tag in tags:
                    tag_text = tag.get("text", "") if isinstance(tag, dict) else ""
                    if tag_text.startswith("1-"):
                        has_tag = True
                        break
                
                if has_tag:
                    customers = conv.get("customers", [])
                    if customers:
                        result["filtered_customers"].append({
                            "page_id": p_id,
                            "page_name": p_name,
                            "page_username": p_username, # Để bạn biết link sẽ dùng gì
                            "platform": p_platform,
                            "customer_name": customers[0].get("name"),
                            "psid": customers[0].get("id"),
                            "conversation_id": conv.get("id")
                        })

    # Xuất kết quả JSON
    print("\n--- KẾT QUẢ TEST API (JSON) ---")
    print(json.dumps(result, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    test_pancake_api()