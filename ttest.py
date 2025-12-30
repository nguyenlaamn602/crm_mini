import requests
import json

# --- CẤU HÌNH ---
USER_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiVEhHIEZ1bGZpbGwiLCJleHAiOjE3NzI0MjMyNTYsImFwcGxpY2F0aW9uIjoxLCJ1aWQiOiI0ZWJjZDNkOC04ZjQ4LTQwYzUtOTMxZC0wNDNkNzkwMTgwODYiLCJzZXNzaW9uX2lkIjoiNzNkNmE1MGUtZDZmOC00MzhmLWExOGMtODMwYzRjMzk5ZDQwIiwiaWF0IjoxNzY0NjQ3MjU2LCJmYl9pZCI6IjE1NjgwMDQ1NTUwMjEwMCIsImxvZ2luX3Nlc3Npb24iOm51bGwsImZiX25hbWUiOiJUSEcgRnVsZmlsbCJ9.KsHVnDMNvy8ldjyNQLMR0CJk0HFczp5w0wrUaS4LQeA"
TARGET_TAG = "2- Khách mới"

def run_final_api_test():
    print(f"🎯 ĐANG TRÍCH XUẤT SỐ ĐIỆN THOẠI SẠCH: '{TARGET_TAG}'\n")

    url_pages = "https://pages.fm/api/v1/pages"
    pages = requests.get(url_pages, params={"access_token": USER_TOKEN}).json().get("categorized", {}).get("activated", [])

    for p in pages:
        p_id = p.get("id")
        url_gen = f"https://pages.fm/api/v1/pages/{p_id}/generate_page_access_token"
        p_token = requests.post(url_gen, params={"page_id": p_id, "access_token": USER_TOKEN}).json().get("page_access_token")
        
        if not p_token: continue

        url_tags = f"https://pages.fm/api/public_api/v1/pages/{p_id}/tags"
        tags = requests.get(url_tags, params={"page_access_token": p_token}).json().get("tags", [])
        tag_id = next((t.get("id") for t in tags if TARGET_TAG.lower() in t.get("text", "").lower()), None)

        if tag_id is not None:
            url_convs = f"https://pages.fm/api/public_api/v2/pages/{p_id}/conversations"
            convs = requests.get(url_convs, params={"page_access_token": p_token, "tags": tag_id, "type": "INBOX"}).json().get("conversations", [])

            for conv in convs:
                customers_data = conv.get("customers", [])
                # Lấy danh sách số điện thoại thô
                raw_phones = conv.get("recent_phone_numbers", [])
                
                if customers_data:
                    customer = customers_data[0]
                    name = customer.get("name", "Khách hàng ẩn danh")
                    
                    # LOGIC MỚI: Chỉ lấy chuỗi phone_number sạch
                    clean_phone = "Chưa có SĐT"
                    if raw_phones and isinstance(raw_phones[0], dict):
                        # Trích xuất phím 'phone_number' từ Object đầu tiên
                        clean_phone = raw_phones[0].get("phone_number", "Chưa có SĐT")
                    elif raw_phones and isinstance(raw_phones[0], str):
                        clean_phone = raw_phones[0]

                    print(f"      👤 Tên: {name}")
                    print(f"      📞 SĐT: {clean_phone}")
                    print("      " + "-"*20)

if __name__ == "__main__":
    run_final_api_test()