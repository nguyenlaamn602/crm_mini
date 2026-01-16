import streamlit as st
import requests
import os
import time
import pandas as pd
from dotenv import load_dotenv

# 1. Load cấu hình từ file .env
load_dotenv()
env_token = os.getenv("PANCAKE_USER_TOKEN", "")

# Cấu hình API
BASE_URL = "https://pages.fm/api/v1"
PUBLIC_V1 = "https://pages.fm/api/public_api/v1"
PUBLIC_V2 = "https://pages.fm/api/public_api/v2"

st.set_page_config(page_title="Pancake CRM Pro Table", layout="wide")
st.title("🔌 Pancake CRM Connector (Table View)")

# --- KHỞI TẠO BỘ NHỚ TẠM (SESSION STATE) ---
if 'conversations' not in st.session_state:
    st.session_state.conversations = []
if 'page_token' not in st.session_state:
    st.session_state.page_token = ""
if 'master_selected_ids' not in st.session_state:
    st.session_state.master_selected_ids = set() # Lưu trữ ID đã chọn

# --- HÀM CACHE DANH SÁCH PAGE ---
@st.cache_data(ttl=3600)
def get_pages_list(token):
    try:
        resp = requests.get(f"{BASE_URL}/pages", params={"access_token": token}, timeout=10)
        if resp.status_code == 200:
            data = resp.json().get("pages", [])
            if not data:
                cat = resp.json().get("categorized", {})
                data = cat.get("activated", []) + cat.get("inactivated", [])
            return data, 200
        return [], resp.status_code
    except Exception:
        return [], 500

# --- SIDEBAR ---
st.sidebar.header("Xác thực")
user_token = st.sidebar.text_input("User Access Token", value=env_token, type="password")

if st.sidebar.button("Clear Cache & Selection"):
    st.cache_data.clear()
    st.session_state.conversations = []
    st.session_state.master_selected_ids = set()
    st.rerun()

# --- LOGIC CHÍNH ---
if user_token:
    pages_data, status = get_pages_list(user_token)
    
    if status == 200 and pages_data:
        page_map = {p['name']: p['id'] for p in pages_data}
        col_p1, col_p2 = st.columns([3, 1])
        with col_p1:
            selected_page_name = st.selectbox("1. Chọn Fanpage", list(page_map.keys()))
            page_id = page_map[selected_page_name]
        
        with col_p2:
            st.write(" ")
            if st.button("🔄 Tải dữ liệu khách"):
                with st.spinner("Đang đồng bộ..."):
                    t_res = requests.post(f"{BASE_URL}/pages/{page_id}/generate_page_access_token", 
                                        params={"access_token": user_token, "page_id": page_id})
                    if t_res.status_code == 200:
                        st.session_state.page_token = t_res.json().get("page_access_token")
                        c_res = requests.get(f"{PUBLIC_V2}/pages/{page_id}/conversations",
                                            params={"page_access_token": st.session_state.page_token, "page_id": page_id, "type": "INBOX"})
                        if c_res.status_code == 200:
                            st.session_state.conversations = c_res.json().get("conversations", [])
                            st.success("Đã tải danh sách!")
                        else:
                            st.error(f"Lỗi: {c_res.status_code}")

        # HIỂN THỊ DẠNG BẢNG
        if st.session_state.conversations:
            st.subheader("👥 Quản lý danh sách khách hàng")
            
            # Chuẩn bị dữ liệu cho bảng
            rows = []
            for c in st.session_state.conversations:
                cust_data = c.get("customers", [])
                part_data = c.get("participants", [])
                name = "Ẩn danh"
                if cust_data: name = cust_data[0].get("name") or name
                elif part_data: name = part_data[0].get("name") or name
                
                rows.append({
                    "Chọn": c['id'] in st.session_state.master_selected_ids,
                    "Tên khách hàng": name,
                    "ID Hội thoại": c['id'],
                    "Thời gian": c.get("inserted_at", "")
                })
            
            df = pd.DataFrame(rows)

            # Bộ lọc tên
            search_query = st.text_input("🔍 Lọc nhanh theo tên (Không làm mất các mục đã tick)", "")
            filtered_df = df[df["Tên khách hàng"].str.contains(search_query, case=False)] if search_query else df

            # Hiển thị bảng
            edited_df = st.data_editor(
                filtered_df,
                column_config={
                    "Chọn": st.column_config.CheckboxColumn(help="Tick để chọn gửi bulk"),
                    "ID Hội thoại": st.column_config.TextColumn(disabled=True),
                    "Tên khách hàng": st.column_config.TextColumn(disabled=True),
                    "Thời gian": st.column_config.TextColumn(disabled=True),
                },
                disabled=["Tên khách hàng", "ID Hội thoại", "Thời gian"],
                hide_index=True,
                use_container_width=True,
                key="customer_table"
            )

            # CẬP NHẬT MASTER SELECTION
            for index, row in edited_df.iterrows():
                if row["Chọn"]:
                    st.session_state.master_selected_ids.add(row["ID Hội thoại"])
                else:
                    if row["ID Hội thoại"] in st.session_state.master_selected_ids:
                        st.session_state.master_selected_ids.remove(row["ID Hội thoại"])

            # HIỂN THỊ TỔNG HỢP GỬI TIN
            num_selected = len(st.session_state.master_selected_ids)
            st.markdown(f"### 💬 Đang chọn: `{num_selected}` khách hàng")
            
            if num_selected > 0:
                # --- LOGIC CẬP NHẬT: Hiển thị Tên thay vì ID ---
                with st.expander("📝 Xem danh sách Tên khách hàng đã chọn"):
                    selected_names = []
                    for c in st.session_state.conversations:
                        if c['id'] in st.session_state.master_selected_ids:
                            c_data = c.get("customers", [])
                            p_data = c.get("participants", [])
                            c_name = "Ẩn danh"
                            if c_data: c_name = c_data[0].get("name") or c_name
                            elif p_data: c_name = p_data[0].get("name") or c_name
                            selected_names.append(c_name)
                    
                    # Hiển thị danh sách tên gọn gàng
                    st.write(", ".join(selected_names))

                msg_text = st.text_area("Nội dung tin nhắn")
                img_file = st.file_uploader("Đính kèm hình ảnh", type=["jpg", "png"])

                if st.button("🚀 Bắt đầu gửi hàng loạt"):
                    success = 0
                    prog = st.progress(0)
                    
                    cid = None
                    if img_file:
                        f = {"file": (img_file.name, img_file.getvalue(), img_file.type)}
                        u = requests.post(f"{PUBLIC_V1}/pages/{page_id}/upload_contents", 
                                        params={"page_access_token": st.session_state.page_token}, files=f)
                        if u.status_code == 200: cid = u.json().get("id")

                    selected_list = list(st.session_state.master_selected_ids)
                    for i, cv_id in enumerate(selected_list):
                        payload = {"action": "reply_inbox", "message": msg_text}
                        if cid: payload.update({"content_ids": [cid], "attachment_type": "PHOTO"})
                        
                        s = requests.post(f"{PUBLIC_V1}/pages/{page_id}/conversations/{cv_id}/messages",
                                        params={"page_access_token": st.session_state.page_token}, json=payload)
                        if s.status_code == 200: success += 1
                        elif s.status_code == 429: #
                            st.error("Bị chặn 429! Dừng lại ngay.")
                            break
                        time.sleep(1.2) # Nghỉ an toàn chống 429
                        prog.progress((i+1)/len(selected_list))
                    
                    st.success(f"Hoàn thành gửi {success}/{num_selected} khách hàng.")
            else:
                st.info("Hãy tick chọn khách hàng trong bảng trên để bắt đầu soạn tin nhắn.")

    else:
        st.error("Không thể kết nối Pancake. Vui lòng kiểm tra Token hoặc chờ 5 phút.")
else:
    st.info("Nhập Token vào Sidebar để bắt đầu.")