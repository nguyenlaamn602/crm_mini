import streamlit as st
import requests

# Cấu hình các đầu mục API từ tài liệu
BASE_URL = "https://pages.fm/api/v1"
PUBLIC_V1 = "https://pages.fm/api/public_api/v1"
PUBLIC_V2 = "https://pages.fm/api/public_api/v2"

st.set_page_config(page_title="Pancake CRM Lite", layout="wide")

st.title("🔌 Pancake CRM Connector")
st.markdown("---")

# --- SIDEBAR: Quản lý Token ---
st.sidebar.header("Xác thực")
user_token = st.sidebar.text_input("Nhập User Access Token", type="password", help="Lấy từ Account -> Personal Settings")

# --- LOGIC CHÍNH ---
if user_token:
    # 1. Lấy danh sách Page
    try:
        pages_resp = requests.get(f"{BASE_URL}/pages", params={"access_token": user_token})
        
        if pages_resp.status_code == 200:
            pages_data = pages_resp.json().get("pages", [])
            if not pages_data:
                # Một số trường hợp API trả về cấu trúc 'categorized'
                cat = pages_resp.json().get("categorized", {})
                pages_data = cat.get("activated", []) + cat.get("inactivated", [])

            if pages_data:
                page_map = {p['name']: p['id'] for p in pages_data}
                selected_page_name = st.selectbox("1. Chọn Fanpage", list(page_map.keys()))
                page_id = page_map[selected_page_name]

                # 2. Tự động lấy Page Access Token
                # Lưu ý: Phải gửi page_id trong query params theo đúng tài liệu
                token_res = requests.post(
                    f"{BASE_URL}/pages/{page_id}/generate_page_access_token",
                    params={"access_token": user_token, "page_id": page_id}
                )

                if token_res.status_code == 200:
                    page_token = token_res.json().get("page_access_token")
                    st.sidebar.success(f"Đã kết nối: {selected_page_name}")
                    
                    # 3. Lấy danh sách hội thoại
                    st.subheader("👥 Danh sách khách hàng mới nhất")
                    conv_resp = requests.get(
                        f"{PUBLIC_V2}/pages/{page_id}/conversations",
                        params={"page_access_token": page_token, "page_id": page_id, "type": "INBOX"}
                    )

                    if conv_resp.status_code == 200:
                        conversations = conv_resp.json().get("conversations", [])
                        if conversations:
                            # Hiển thị danh sách để chọn
                            customer_list = {}
                            for c in conversations:
                                name = c.get("participants", [{}])[0].get("name", "Khách hàng")
                                customer_list[f"{name} (ID: {c['id']})"] = c['id']

                            selected_customer = st.selectbox("2. Chọn khách hàng", list(customer_list.keys()))
                            conv_id = customer_list[selected_customer]

                            # 4. Soạn và gửi tin nhắn
                            st.markdown("---")
                            st.subheader(f"💬 Gửi tin nhắn đến: {selected_customer}")
                            msg_content = st.text_area("Nội dung tin nhắn")

                            if st.button("Gửi Inbox ngay"):
                                if msg_content:
                                    send_res = requests.post(
                                        f"{PUBLIC_V1}/pages/{page_id}/conversations/{conv_id}/messages",
                                        params={"page_access_token": page_token},
                                        json={"action": "reply_inbox", "message": msg_content}
                                    )
                                    
                                    if send_res.status_code == 200:
                                        st.success("✅ Gửi tin nhắn thành công!")
                                    else:
                                        st.error(f"❌ Lỗi gửi tin: {send_res.text}")
                                else:
                                    st.warning("Vui lòng nhập nội dung.")
                        else:
                            st.info("Không có hội thoại nào gần đây.")
                    else:
                        st.error("Không thể lấy danh sách hội thoại. Kiểm tra lại quyền của Page Token.")
                else:
                    st.error(f"Không thể tạo Page Token. Chi tiết: {token_res.text}")
            else:
                st.warning("Tài khoản này không quản lý Page nào.")
        else:
            st.error(f"Lỗi xác thực User Token: {pages_resp.status_code}")
            
    except Exception as e:
        st.error(f"Lỗi hệ thống: {str(e)}")
else:
    st.info("Vui lòng nhập User Access Token ở thanh bên trái để bắt đầu.")