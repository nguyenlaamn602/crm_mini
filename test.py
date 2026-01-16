import requests
import json
import os
import time
from dotenv import load_dotenv

# Tải cấu hình từ file .env
load_dotenv()

class PancakeScanner:
    def __init__(self):
        self.user_token = os.getenv("PANCAKE_USER_TOKEN")
        self.api_v1 = "https://pages.fm/api/v1"
        self.public_v1 = "https://pages.fm/api/public_api/v1"
        self.public_v2 = "https://pages.fm/api/public_api/v2"
        
        if not self.user_token:
            raise ValueError("❌ Lỗi: Chưa cấu hình PANCAKE_USER_TOKEN trong file .env")

    def get_pages(self):
        """Lấy danh sách toàn bộ các trang"""
        resp = requests.get(f"{self.api_v1}/pages", params={"access_token": self.user_token})
        if resp.status_code != 200:
            return []
        data = resp.json().get("categorized", {})
        return data.get("activated", []) + data.get("inactivated", [])

    def get_page_token(self, page_id):
        """Tạo Page Access Token"""
        url = f"{self.api_v1}/pages/{page_id}/generate_page_access_token"
        resp = requests.post(url, params={"page_id": page_id, "access_token": self.user_token})
        return resp.json().get("page_access_token") if resp.status_code == 200 else None

    def get_tag_map(self, page_id, page_token):
        """Lấy danh sách tag để đối chiếu ID và Text"""
        tag_map = {}
        url = f"{self.public_v1}/pages/{page_id}/tags"
        resp = requests.get(url, params={"page_access_token": page_token})
        if resp.status_code == 200:
            for t in resp.json().get("tags", []):
                tag_map[str(t.get("id"))] = t.get("text")
        return tag_map

    def fetch_all_conversations(self, page_id, page_token):
        """
        Lấy TOÀN BỘ hội thoại bằng cách lặp qua last_conversation_id
        (GIỮ NGUYÊN LOGIC CŨ)
        """
        all_convs = []
        last_id = None
        
        while True:
            params = {
                "page_access_token": page_token,
                "type": "INBOX"
            }
            if last_id:
                params["last_conversation_id"] = last_id  # Sử dụng để lấy 60 bản ghi tiếp theo

            url = f"{self.public_v2}/pages/{page_id}/conversations"
            resp = requests.get(url, params=params)
            
            if resp.status_code != 200:
                break
                
            data = resp.json().get("conversations", [])
            if not data:
                break
            
            all_convs.extend(data)
            
            # Lấy ID của hội thoại cuối cùng trong danh sách để làm mốc cho lần gọi tới
            last_id = data[-1].get("id")
            
            # Tạm nghỉ để tránh bị giới hạn rate limit nếu dữ liệu quá lớn
            time.sleep(0.2) 
            
            # Nếu trả về ít hơn 60, nghĩa là đã hết dữ liệu
            if len(data) < 60:
                break
                
        return all_convs


def main():
    scanner = PancakeScanner()
    
    result = {
        "summary": {
            "total_pages": 0,
            "total_conversations_scanned": 0,
            "total_leads_found": 0
        },
        "details": []
    }

    print("🚀 Bắt đầu quét toàn bộ dữ liệu từ Pancake...")
    pages = scanner.get_pages()
    result["summary"]["total_pages"] = len(pages)

    for page in pages:
        p_id = str(page.get("id"))
        p_name = page.get("name")
        print(f"--- Đang xử lý Page: {p_name} ({p_id}) ---")

        token = scanner.get_page_token(p_id)
        if not token:
            print(f"  ⚠️ Không lấy được token cho {p_name}")
            continue

        tag_map = scanner.get_tag_map(p_id, token)
        conversations = scanner.fetch_all_conversations(p_id, token)
        
        page_conv_count = len(conversations)
        page_lead_count = 0
        result["summary"]["total_conversations_scanned"] += page_conv_count

        for conv in conversations:
            conv_tags = conv.get("tags", [])

            # ===== LOGIC FILTER TAG GIỐNG pancake.py (support cả dict và id) =====
            is_lead = False
            sector = None
            status = "Khách Mới"

            processed_tags = []

            for item in conv_tags:
                # Pancake v2 có thể trả tags dạng dict {"id":..,"text":..} hoặc chỉ id
                if isinstance(item, dict):
                    tag_text = item.get("text")
                else:
                    tag_text = tag_map.get(str(item))

                if not tag_text:
                    continue

                processed_tags.append(tag_text)

                # TAG NHÓM 1 → SECTOR
                if tag_text.startswith("1-"):
                    is_lead = True
                    if "Express" in tag_text:
                        sector = "Express"
                    elif "Warehouse" in tag_text:
                        sector = "Warehouse"
                    else:
                        sector = "Pod_Drop"

                # TAG NHÓM 2 → STATUS
                if tag_text.startswith("2-"):
                    raw = tag_text.split("-", 1)[-1].strip().lower()
                    if raw == "khách chốt":
                        status = "Khách hàng tiềm năng"
                    elif raw == "khách vip":
                        status = "Khách Vip"

            # Giữ đúng rule: chỉ coi là lead khi có tag 1-*
            if not is_lead:
                continue

            page_lead_count += 1
            customers = conv.get("customers", [])
            customer_name = customers[0].get("name") if customers else "N/A"

            result["details"].append({
                "page_name": p_name,
                "page_id": p_id,
                "customer_name": customer_name,
                "conversation_id": conv.get("id"),
                "sector": sector,
                "status": status,
                "tags": processed_tags,
                "updated_at": conv.get("updated_at")
            })

        result["summary"]["total_leads_found"] += page_lead_count
        print(f"  ✅ Đã quét {page_conv_count} hội thoại. Tìm thấy {page_lead_count} leads.")

    # Xuất kết quả
    output_file = "full_scan_result.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print("\n" + "="*30)
    print("HOÀN THÀNH QUÉT DỮ LIỆU")
    print(f"Tổng số Page: {result['summary']['total_pages']}")
    print(f"Tổng số hội thoại đã kiểm tra: {result['summary']['total_conversations_scanned']}")
    print(f"Tổng số Lead thỏa điều kiện (1-): {result['summary']['total_leads_found']}")
    print(f"Dữ liệu chi tiết đã lưu tại: {output_file}")


if __name__ == "__main__":
    main()
