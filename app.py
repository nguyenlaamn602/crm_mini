from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_apscheduler import APScheduler
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import User, PricingHistory
from services.pancake import PancakeService
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson.objectid import ObjectId
import urllib.parse
import requests, time, random, string, re
import uuid
import os
import sys
import paramiko
import pandas as pd
import io
import zipfile
import xml.etree.ElementTree as ET
from sshtunnel import SSHTunnelForwarder
from dotenv import load_dotenv
load_dotenv()

# --- FIX LỖI DSSKey (MONKEYPATCH) ---
# Đoạn này cực kỳ quan trọng để không bị crash trên Windows
if not hasattr(paramiko, 'DSSKey'):
    paramiko.DSSKey = paramiko.PKey

def get_db():
    """
    Tạo kết nối Database. Nếu ở Local sẽ dựng SSH Tunnel.
    """
    # 1. Lấy thông số SSH (Để mở đường hầm)
    ssh_host = os.getenv("SSH_HOST")
    ssh_user = os.getenv("SSH_USER", "root")
    ssh_pass = os.getenv("SSH_PASSWORD")
    
    # 2. Lấy thông số MongoDB (Để đăng nhập Database)
    db_user = os.getenv("MONGO_USER", "THGfulfill")
    db_pass = os.getenv("MONGO_PASS")
    db_name = os.getenv("MONGO_DB", "CRM_Production")
    
    # Mã hóa mật khẩu DB (vì pass DB nằm trong URI nên cần quote_plus)
    # Ký tự đặc biệt trong pass SSH thì KHÔNG cần mã hóa
    encoded_db_pass = urllib.parse.quote_plus(db_pass) if db_pass else ""

    if ssh_host:
        print(f"🛠  Đang dựng SSH Tunnel tới {ssh_host}...")
        try:
            # Dựng đường hầm SSH
            tunnel = SSHTunnelForwarder(
                (ssh_host, 22),
                ssh_username=ssh_user,
                ssh_password=ssh_pass, # Gửi pass SSH nguyên bản
                remote_bind_address=('127.0.0.1', 27017),
                local_bind_address=('127.0.0.1', 27017),
                host_pkey_directories=[],
                allow_agent=False
            )
            tunnel.start()
            print("🚀 SSH Tunnel OK!")

            # Kết nối tới MongoDB qua cổng 27017 của đường hầm
            uri = f"mongodb://{db_user}:{encoded_db_pass}@127.0.0.1:27017/{db_name}?authSource=admin"
            client = MongoClient(uri, serverSelectionTimeoutMS=5000)
            
            # Kiểm tra "sức khỏe" kết nối
            client.admin.command('ping')
            print(f"✅ Đã kết nối Database: {db_name}")
            return client, client[db_name], tunnel

        except Exception as e:
            print(f"❌ Lỗi kết nối: {e}")
            raise e
    else:
        # Chế độ chạy trên Server (dùng MONGO_URI trực tiếp)
        print("🔌 Đang kết nối Database trực tiếp...")
        uri = os.getenv("MONGO_URI")
        client = MongoClient(uri)
        client.admin.command('ping')
        db_name = os.getenv("MONGO_DB", "CRM_Production")
        print(f"✅ Đã kết nối Database: {db_name}")
        return client, client[db_name], None

# --- THIRD PARTY CONFIG ---
# Load Config from .env
PANCAKE_USER_TOKEN = os.getenv("PANCAKE_USER_TOKEN")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

BASE_URL = "https://pages.fm/api/v1"
PUBLIC_V1 = "https://pages.fm/api/public_api/v1"
PUBLIC_V2 = "https://pages.fm/api/public_api/v2"

TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

app = Flask(__name__)

# --- APP CONFIG ---
try:
    client, db, tunnel = get_db()
except Exception as e:
    print(f"FATAL: Không thể kết nối tới Database. App sẽ thoát. Lỗi: {e}")
    sys.exit(1)
app.config['SECRET_KEY'] = 'crm_thg_ultimate_2025_secure_final_v5'
pricing_history = PricingHistory(db)

# --- UPLOAD CONFIG ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ✅ CONFIG LOG FILE
DEBUG_LOG_FILE = 'debug_n8n.log'

login_manager = LoginManager()
login_manager.user_loader(lambda uid: User(db.users.find_one({"_id": ObjectId(uid)})) if db.users.find_one({"_id": ObjectId(uid)}) else None)
login_manager.login_view = 'login'
login_manager.login_message = None
login_manager.init_app(app)

# ✅ CONTEXT PROCESSOR: Pass utility functions to all templates
@app.context_processor
def utility_processor():
    return {
        'now_dt': now_dt
    }

# --- LARK CONFIG ---
LARK_APP_ID, LARK_APP_SECRET = "cli_a87a40a3d6b85010", "wFMNBqGMhcuZsyNDZVAnYgOv6XuZyAqn"
LARK_APP_TOKEN, LARK_TABLE_ID = "Vqfqbm1Lda7vdVsvABQlk8KSgog", "tblEUCxBUVUUDt4R"
LARK_TASK_APP_TOKEN, LARK_TASK_TABLE_ID = "Ajhqblaj9aT34JsuQ8PlTi7xgZe", "tblKknj4Pp8HStO9"

scheduler = APScheduler()
LAST_SYNC_TIMESTAMP = time.time()

# ---------------------------
# CONSTANTS: Departments + Status
# ---------------------------
USER_DEPARTMENTS = ["Sale", "Customer Services", "Operation", "Finance", "HR", "Marketing", "Quotation & Foreign Affairs"]
CORP_DEPARTMENTS = ["Sale", "Customer Services", "Operation", "Finance", "HR", "Marketing", "Quotation & Foreign Affairs"]
DEPARTMENT_TASK_DEPARTMENTS = ["Sale", "Customer Services", "Operation", "Finance", "HR", "Marketing", "Quotation & Foreign Affairs"]

# ✅ UNIFIED STATUSES (Gộp status) - Thứ tự: todo, doing, waiting, done, overdue, cancelled
UNIFIED_STATUSES = ["todo", "doing", "waiting", "done", "overdue", "cancelled"]

# ✅ NEW: Customer Request Constants
REQUEST_STATUSES = ["Request", "Thanh toán", "Lên đơn", "Trouble"]
BUSINESS_TYPES = ["POD/Dropship", "Warehouse", "Express", "New"]

# ✅ NEW: Roles
SUPERADMIN_ROLE = "superadmin"

# ---------------------------
# HELPERS
# ---------------------------
def now_dt():
    # ✅ FIX TIME: Ép buộc giờ Việt Nam (UTC+7)
    utc_now = datetime.now(timezone.utc)
    vn_time = utc_now + timedelta(hours=7)
    return vn_time.replace(tzinfo=None) 

def log_to_file(msg):
    """✅ Ghi log ra file để xem trên web"""
    try:
        timestamp = now_dt().strftime("%Y-%m-%d %H:%M:%S")
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg}\n")
    except Exception as e:
        print(f"Log Error: {e}", file=sys.stderr)

def parse_due_at(raw: str):
    if not raw: return None
    try:
        if "T" in raw: return datetime.strptime(raw, "%Y-%m-%dT%H:%M")
        return datetime.strptime(raw, "%Y-%m-%d %H:%M")
    except: return None

def save_uploaded_file(file_obj):
    if file_obj and file_obj.filename:
        original_filename = secure_filename(file_obj.filename)
        unique_filename = f"{uuid.uuid4().hex}_{original_filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        try:
            file_obj.save(file_path)
            return unique_filename
        except Exception as e:
            log_to_file(f"Error saving file: {e}")
            return None
    return None

# ==========================================
# ✅ NATIVE XLSX READERS & PRICING HELPERS (from test.py & app1.py)
# ==========================================
def col_str_to_int(col_str):
    """Convert column letter to 0-based index (e.g., 'A'->0, 'Z'->25, 'AA'->26)"""
    expn = 0
    col_num = 0
    for char in reversed(col_str):
        col_num += (ord(char) - ord('A') + 1) * (26 ** expn)
        expn += 1
    return col_num - 1

def get_sheet_mapping_native(file_path):
    """Trả về dict map tên sheet sang đường dẫn file XML bên trong file zip XLSX."""
    mapping = {}
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            workbook_xml = z.read('xl/workbook.xml')
            root = ET.fromstring(workbook_xml)
            sheet_ids = {} 
            ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main',
                  'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
            
            for sheet in root.findall('.//ns:sheet', ns):
                name = sheet.get('name')
                r_id = sheet.get(f"{{{ns['r']}}}id")
                if name and r_id: sheet_ids[r_id] = name
            
            if 'xl/_rels/workbook.xml.rels' in z.namelist():
                rels_xml = z.read('xl/_rels/workbook.xml.rels')
                rels_root = ET.fromstring(rels_xml)
                ns_rels = {'ns': 'http://schemas.openxmlformats.org/package/2006/relationships'}
                
                for rel in rels_root.findall('.//ns:Relationship', ns_rels):
                    r_id = rel.get('Id')
                    target = rel.get('Target')
                    if r_id in sheet_ids:
                        if target.startswith('/'): target = target[1:]
                        else: target = 'xl/' + target
                        mapping[sheet_ids[r_id]] = target
    except Exception as e:
        log_to_file(f"Native Sheet Mapping Error: {e}")
    return mapping

def read_xlsx_sheet_native(file_path, sheet_xml_path):
    """Đọc dữ liệu từ sheet XML với xử lý toạ độ cột chính xác"""
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            # 1. Read Shared Strings
            shared_strings = []
            if 'xl/sharedStrings.xml' in z.namelist():
                with z.open('xl/sharedStrings.xml') as f:
                    tree = ET.parse(f)
                    root = tree.getroot()
                    ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                    for si in root.findall('.//ns:si', ns):
                        text = ""
                        for t in si.findall('.//ns:t', ns):
                            if t.text: text += t.text
                        shared_strings.append(text)
            
            # 2. Parse Sheet Data
            if sheet_xml_path not in z.namelist(): return pd.DataFrame()
            
            rows_dict = {} 
            max_col = 0
            
            with z.open(sheet_xml_path) as f:
                ns = {'ns': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                context = ET.iterparse(f, events=('end',))
                
                for event, elem in context:
                    if elem.tag.endswith('c'): 
                        r_attr = elem.get('r') 
                        if not r_attr: continue
                        
                        match = re.match(r"([A-Z]+)([0-9]+)", r_attr)
                        if not match: continue
                        
                        col_str, row_str = match.groups()
                        col_idx = col_str_to_int(col_str)
                        row_idx = int(row_str) - 1
                        
                        if col_idx > max_col: max_col = col_idx
                        
                        val = ""
                        ctype = elem.get('t')
                        v_tag = elem.find('ns:v', ns)
                        
                        if v_tag is not None and v_tag.text:
                            val = v_tag.text
                            if ctype == 's': 
                                try: val = shared_strings[int(val)]
                                except: pass
                            elif ctype == 'b': 
                                val = bool(int(val))
                        
                        is_tag = elem.find('ns:is', ns)
                        if is_tag is not None:
                            t_tag = is_tag.find('.//ns:t', ns)
                            if t_tag is not None and t_tag.text: val = t_tag.text
                        
                        if row_idx not in rows_dict: rows_dict[row_idx] = {}
                        rows_dict[row_idx][col_idx] = val
                        
                        elem.clear() 

            # 3. Convert to List of Lists
            data = []
            if not rows_dict: return pd.DataFrame()
            
            sorted_rows = sorted(rows_dict.keys())
            max_row = sorted_rows[-1]
            
            for r in range(max_row + 1):
                row_data = []
                if r in rows_dict:
                    for c in range(max_col + 1):
                        row_data.append(rows_dict[r].get(c, ""))
                else:
                    row_data = [""] * (max_col + 1)
                data.append(row_data)
            
            return pd.DataFrame(data)

    except Exception as e:
        log_to_file(f"Native XLSX Parse Error: {e}")
        return pd.DataFrame()

def get_xlsx_sheet_names_native(file_path):
    mapping = get_sheet_mapping_native(file_path)
    return list(mapping.keys()) if mapping else ['Sheet1']

# --- COUNTRY MAPPING (Code -> Chinese) ---
COUNTRY_MAP = {
    'US': '美国', 'GB': '英国', 'DE': '德国', 'FR': '法国', 'IT': '意大利', 'ES': '西班牙',
    'AU': '澳大利亚', 'CA': '加拿大', 'JP': '日本', 'KR': '韩国', 'SG': '新加坡',
    'MY': '马来西亚', 'TH': '泰国', 'VN': '越南', 'PH': '菲律宾', 'ID': '印度尼西亚',
    'BR': '巴西', 'MX': '墨西哥', 'CL': '智利', 'RU': '俄罗斯', 'NL': '荷兰',
    'BE': '比利时', 'AT': '奥地利', 'PL': '波兰', 'CZ': '捷克', 'DK': '丹麦',
    'FI': '芬兰', 'NO': '挪威', 'SE': '瑞典', 'CH': '瑞士', 'IE': '爱尔兰',
    'PT': '葡萄牙', 'GR': '希腊', 'HU': '匈牙利', 'RO': '罗马尼亚', 'SK': '斯洛伐克',
    'SI': '斯洛文尼亚', 'HR': '克罗地亚', 'EE': '爱沙尼亚', 'LV': '拉脱维aj', 'LT': '立陶宛',
    'BG': '保加利亚', 'CY': '塞浦路斯', 'MT': '马耳他', 'LU': '卢森堡'
}

VN_REGION_MAP = {
    'US': 'USA', 'AU': 'AU', 'CA': 'CA', 'GB': 'UK', 'UK': 'UK',
    'HK': 'HK', 'SG': 'SG', 'JP': 'JP', 'NZ': 'NZ', 'MX': 'MX',
    'BR': 'BR', 'CH': 'CH', 'CL': 'CL', 'AE': 'AE', 'SA': 'SA'
}

def normalize_country(code_or_name):
    """Normalize US -> 美国, or keep 美国 if already Chinese"""
    if not code_or_name: return ""
    code_or_name = str(code_or_name).strip().upper()
    return COUNTRY_MAP.get(code_or_name, code_or_name) 

# --- LOGIC: Indexing Price Table ---
def index_price_table(file_path):
    """
    Quét qua tất cả các sheet.
    Tìm ô chứa '运输代码:XYZ' hoặc 'Product Code:XYZ'.
    Trả về dict: {'XYZ': {'sheet_xml': 'path/to/xml', 'sheet_name': 'Name'}}
    """
    mapping = get_sheet_mapping_native(file_path)
    index = {}
    
    for sheet_name, xml_path in mapping.items():
        df = read_xlsx_sheet_native(file_path, xml_path)
        if df.empty: continue
        
        found_code = None
        for r in range(min(20, len(df))):
            row_vals = df.iloc[r].astype(str).values
            row_str = " ".join(row_vals)
            # ✅ UPDATED REGEX: Add Product Code for VN sheets
            match = re.search(r'(?:运输代码|Transport Code|Product Code)[:：]\s*([A-Za-z0-9\-\_]+)', row_str, re.IGNORECASE)
            if match:
                found_code = match.group(1).strip()
                break
        
        if found_code:
            index[found_code] = {'sheet_xml': xml_path, 'sheet_name': sheet_name}
            
    return index

# --- LOGIC: Checking Weight ---
def check_weight_rule(weight_val, rule_str):
    """
    Parse rule like '0<W<=0.1' or '0.1<W≤0.2'
    """
    try:
        w = float(weight_val)
        rule_str = str(rule_str).replace(" ", "").upper()
        
        match = re.search(r'([\d\.]+)[<＜]W[<＜≤<=]([\d\.]+)', rule_str)
        if match:
            min_w = float(match.group(1))
            max_w = float(match.group(2))
            if min_w < w <= max_w: return True
            return False
        
        # Fallback exact match or range with dash
        if '-' in rule_str:
            parts = rule_str.split('-')
            if float(parts[0]) <= w <= float(parts[1]): return True
        
        # Fallback if rule_str is just a number (Exact weight step in matrix)
        try:
            step_w = float(rule_str)
            if w == step_w: return True
        except: pass
            
    except: pass
    return False

# --- LOGIC: Calculate Single Row ---
def calculate_price_for_row(row_data, price_df):
    """
    Tìm giá trong DataFrame của 1 sheet cụ thể.
    Hỗ trợ 2 dạng: 
    1. Dọc (CN-WW): Cột Country, Cột Weight, Cột Price...
    2. Ngang/Matrix (VN-WW): Header chứa tên vùng, nhiều cột Weight...
    """
    try:
        # 1. Identify Header Row
        header_idx = -1
        for r in range(min(20, len(price_df))): 
            row_vals = [str(x).strip() for x in price_df.iloc[r].values]
            # Dấu hiệu bảng Dọc hoặc Ngang
            if any('国家' in x or 'Country' in x or 'Weight' in x for x in row_vals):
                header_idx = r
                break
        
        if header_idx == -1: return "Lỗi Header", "Lỗi Header"
        
        headers = [str(x).strip() for x in price_df.iloc[header_idx].values]
        df = price_df.iloc[header_idx+1:].copy()
        df.columns = headers
        
        raw_country_input = str(row_data.get('Quốc gia', '')).strip().upper()
        target_weight = float(row_data.get('Cân nặng', 0))

        # ✅ CHECK IF MATRIX STRUCTURE (VN-WW Style)
        # Nếu có đơn vị (VND) hoặc nhiều cột Weight (KG)
        is_matrix = headers.count('Weight (KG)') > 1 or any('(VND)' in h or '（VND）' in h for h in headers)

        if is_matrix:
            # MATRIX LOGIC
            # Bước 1: Tìm cột khớp với vùng
            matched_col_idx = -1
            # Thử map code (US -> USA)
            vn_region_name = VN_REGION_MAP.get(raw_country_input, raw_country_input)
            
            for i, h in enumerate(headers):
                h_clean = h.replace('\n', ' ').upper()
                if vn_region_name in h_clean:
                    matched_col_idx = i
                    break
            
            if matched_col_idx == -1: return "Vùng không khớp", 0
            
            # Bước 2: Tìm cột Weight (KG) tương ứng (gần nhất bên trái cột matched_col_idx)
            weight_col_idx = -1
            for i in range(matched_col_idx, -1, -1):
                if 'Weight' in headers[i]:
                    weight_col_idx = i
                    break
            
            if weight_col_idx == -1: return "Thiếu cột KL", 0
            
            # Bước 3: Tìm dòng khớp cân nặng
            for _, p_row in df.iterrows():
                rule = str(p_row.iloc[weight_col_idx]).strip()
                if check_weight_rule(target_weight, rule):
                    val = p_row.iloc[matched_col_idx]
                    try:
                        return int(round(float(val))), 0 # VN-WW: VND nên làm tròn đến hàng đơn vị
                    except: return "Lỗi Giá", 0
            
            return "Không tìm thấy bước KL", 0

        else:
            # VERTICAL LOGIC (Bản cũ CN-WW)
            col_country = next((c for c in headers if '国家' in c or 'Country' in c), None)
            col_zone = next((c for c in headers if '分区' in c or 'Zone' in c), None)
            col_weight = next((c for c in headers if '重量' in c or 'Weight' in c), None)
            col_price = next((c for c in headers if '运费' in c or 'Freight' in c), None)
            col_fee = next((c for c in headers if '挂号费' in c or 'Fee' in c or 'RMB/票' in c), None)
            
            if not col_country or not col_price: return "Thiếu Cột", "Thiếu Cột"
            
            target_zone_num = None
            if '-' in raw_country_input:
                parts = raw_country_input.split('-')
                target_country = normalize_country(parts[0].strip())
                zm = re.search(r'(\d+)', parts[1])
                if zm: target_zone_num = zm.group(1)
            else:
                target_country = normalize_country(raw_country_input)

            for _, p_row in df.iterrows():
                curr_country = str(p_row[col_country]).strip()
                supported_countries = [c.strip() for c in re.split(r'[,，、;]', curr_country)]
                if target_country not in supported_countries: continue
                
                if col_zone and target_zone_num:
                    if target_zone_num not in str(p_row[col_zone]).strip(): continue
                    
                weight_rule = str(p_row[col_weight]).strip()
                if check_weight_rule(target_weight, weight_rule):
                    try:
                        unit_price = float(p_row[col_price])
                        fee = float(p_row[col_fee]) if col_fee and str(p_row[col_fee]).strip() and str(p_row[col_fee]).strip() != 'nan' else 0
                        return round(unit_price, 2), round(fee, 2)
                    except: return "Lỗi Value", "Lỗi Value"
                    
            return "Không tìm thấy vùng", "N/A"

    except Exception as e:
        return f"Err: {str(e)}", "Err"

# ✅ NEW: Transit Time Helper for CN Price Tables (Column C: 参考时效)
def get_transit_time_cn(price_df, target_country):
    """Extract transit time from CN price table. Column C contains 参考时效, Column B contains Country."""
    try:
        # Find header row
        header_idx = -1
        for r in range(min(20, len(price_df))):
            row_vals = [str(x).strip() for x in price_df.iloc[r].values]
            if any('国家' in x or '参考时效' in x for x in row_vals):
                header_idx = r
                break
        
        if header_idx == -1:
            return None
            
        headers = [str(x).strip() for x in price_df.iloc[header_idx].values]
        df = price_df.iloc[header_idx+1:].copy()
        df.columns = headers
        
        # Find transit time column (参考时效)
        transit_col = next((c for c in headers if '时效' in c or 'Transit' in c), None)
        country_col = next((c for c in headers if '国家' in c or 'Country' in c), None)
        
        if not transit_col or not country_col:
            return None
        
        # Normalize input country
        target_cn = normalize_country(str(target_country).strip().upper())
        
        for _, row in df.iterrows():
            curr_country = str(row[country_col]).strip()
            # Split by comma/semicolon for countries like "美国,加拿大"
            countries = [c.strip() for c in re.split(r'[,，、;]', curr_country)]
            if target_cn in countries:
                return str(row[transit_col]).strip()
        
        return None
    except:
        return None

# ✅ NEW: Transit Time Helper for VN Price Tables (Transit time section)
VN_TRANSIT_TIME_MAP = {
    # Default mapping based on VN price table Transit time section
    'EU': '5-12 BSD', 'US': '5-12 BSD', 'USA': '5-12 BSD',
    'MX': '5-12 BSD', 'CA': '5-12 BSD', 'AE': '5-12 BSD', 
    'NZ': '5-12 BSD', 'AU': '5-12 BSD', 'GB': '5-12 BSD',
    'UK': '5-12 BSD', 'DE': '5-12 BSD', 'FR': '5-12 BSD',
    'IT': '5-12 BSD', 'ES': '5-12 BSD', 'NL': '5-12 BSD',
    'HK': '3-5 BSD', 'MY': '3-5 BSD', 'SG': '3-5 BSD',
    'JP': '5-10 BSD', 'KR': '5-10 BSD',
}

def get_transit_time_vn(price_df, target_country):
    """Extract transit time from VN price table, fallback to default if not found."""
    try:
        # Try to find Transit Time header in price table
        header_idx = -1
        for r in range(min(30, len(price_df))):
            row_vals = [str(x).strip().lower() for x in price_df.iloc[r].values]
            if any('transit' in x or 'time' in x or 'delivery' in x for x in row_vals):
                header_idx = r
                break
        
        if header_idx != -1:
            headers = [str(x).strip() for x in price_df.iloc[header_idx].values]
            df = price_df.iloc[header_idx+1:].copy()
            df.columns = headers
            
            # Find transit time column
            transit_col = next((c for c in headers if 'transit' in c.lower() or 'time' in c.lower()), None)
            country_col = next((c for c in headers if 'country' in c.lower() or 'region' in c.lower() or 'zone' in c.lower()), None)
            
            if transit_col and country_col:
                code = str(target_country).strip().upper()
                for _, row in df.iterrows():
                    curr_region = str(row[country_col]).strip().upper()
                    if code in curr_region or curr_region in code:
                        tt = str(row[transit_col]).strip()
                        if tt and tt.lower() != 'nan':
                            # Normalize to BSD
                            tt = tt.replace('working days', 'BSD').replace('days', 'BSD').replace('day', 'BSD')
                            return tt
    except:
        pass
    
    # Fallback to default mapping
    code = str(target_country).strip().upper()
    return VN_TRANSIT_TIME_MAP.get(code, '5-12 BSD')

# ✅ TELEGRAM HELPER BASIC
def send_telegram_notification(chat_id, text):
    if not chat_id or not TELEGRAM_BOT_TOKEN: 
        return False
    try:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        requests.post(TELEGRAM_API_URL, json=payload, timeout=5)
        return True
    except Exception as e:
        log_to_file(f"[TELEGRAM] Error: {e}")
        return False

# ✅ NEW: NOTIFY CREATOR ON STATUS CHANGE
def send_status_change_notification(task_doc, new_status, task_type="Task"):
    try:
        creator = None
        if task_type == "Corp Task" or task_type == "Department Task":
            creator_name = task_doc.get("assigned_by")
            if creator_name:
                creator = db.users.find_one({"username": creator_name})
        else:
            user_id = task_doc.get("user_id")
            if user_id:
                creator = db.users.find_one({"_id": user_id})

        if creator and creator.get("telegram_chat_id"):
            creator_id_str = str(creator['_id'])
            current_user_id_str = str(current_user.id)
            
            if creator_id_str != current_user_id_str:
                title = task_doc.get("todo_content") or task_doc.get("title") or "No Content"
                msg = (
                    f"🔄 <b>STATUS UPDATE: {task_type}</b>\n\n"
                    f"📝 <b>Task:</b> {title}\n"
                    f"📊 <b>New Status:</b> {new_status}\n"
                    f"👤 <b>Updated by:</b> {current_user.username}\n"
                    f"⏰ <b>Time:</b> {now_dt().strftime('%H:%M %d/%m')}"
                )
                send_telegram_notification(creator.get("telegram_chat_id"), msg)
    except Exception as e:
        log_to_file(f"[TELEGRAM] Status notify error: {e}")

def find_any_task(tid):
    t = db.tasks.find_one({"id": tid})
    if t: return t, 'tasks'
    t = db.corp_tasks.find_one({"id": tid})
    if t: return t, 'corp_tasks'
    t = db.personal_tasks.find_one({"id": tid})
    if t: return t, 'personal_tasks'
    t = db.department_tasks.find_one({"id": tid}) # ✅ NEW: Department Tasks
    if t: return t, 'department_tasks'
    t = db.customer_requests.find_one({"id": tid})
    if t: return t, 'customer_requests'
    return None, None

# --- Logic Helpers ---
def is_overdue(task_doc):
    due = task_doc.get("due_at")
    return bool(due and isinstance(due, datetime) and due < now_dt())

def mark_missed(task_id: str, reason: str = "auto"):
    t = db.tasks.find_one({"id": task_id})
    if not t: return
    if t.get("status") == "done": return
    db.tasks.update_one({"id": task_id}, {
        "$set": {
            "status": "overdue", "missed_at": now_dt(), "updated_at": now_dt(),
            "miss_reason": reason, "missed_notify_pending": True
        }
    })

# ✅ UPDATED: Logic tìm khách hàng thông minh hơn
def link_customer_for_task(raw_name: str):
    if not raw_name: return None, None
    clean_name = re.sub(r'\s*\[.*\]', '', raw_name).strip()
    if not clean_name: return None, raw_name

    lead = db.leads.find_one({"full_name": {"$regex": f"^{re.escape(clean_name)}$", "$options": "i"}})
    if lead: return lead.get("psid"), lead.get("full_name")
    
    lead = db.leads.find_one({"full_name": {"$regex": re.escape(clean_name), "$options": "i"}}, sort=[("updated_at", -1)])
    if lead: return lead.get("psid"), lead.get("full_name")
    
    return None, clean_name

def can_user_quick_update(task_doc):
    if current_user.role in [SUPERADMIN_ROLE, "admin"]: return True
    me = ObjectId(current_user.id)
    return task_doc.get("user_id") == me or task_doc.get("assigned_to") == me

def allowed_next_status(task_doc):
    if is_overdue(task_doc) and task_doc.get("status") != "done": return "overdue"
    if task_doc.get("status") == "todo": return "waiting"
    if task_doc.get("status") == "waiting": return "doing"
    if task_doc.get("status") == "doing": return "done"
    return "todo" # Default or cycle back

def next_personal_status(cur):
    if cur == "todo": return "waiting"
    if cur == "waiting": return "doing"
    if cur == "doing": return "done"
    return "todo"

def get_next_status(cur):
    if cur == "todo": return "waiting"
    if cur == "waiting": return "doing"
    if cur == "doing": return "done"
    return "todo"

def can_update_corp_status(corp_task): # ✅ Updated for superadmin
    if current_user.role in [SUPERADMIN_ROLE, "admin"]: return True
    assigned = corp_task.get("assigned_to")
    if isinstance(assigned, ObjectId): return ObjectId(current_user.id) == assigned
    if isinstance(assigned, list): return ObjectId(current_user.id) in assigned
    return False

def can_edit_corp_task(corp_task): # ✅ Updated for superadmin
    if current_user.role in [SUPERADMIN_ROLE, "admin"]: return True
    assigned = corp_task.get("assigned_to", [])
    if isinstance(assigned, list): return ObjectId(current_user.id) in assigned
    return ObjectId(current_user.id) == assigned

def validate_corp_status_change(new_status: str, corp_task):
    if new_status not in UNIFIED_STATUSES: return False, "Invalid status"
    # ✅ FIX: Allow Superadmin AND Admin to cancel
    if new_status == "Cancelled" and current_user.role not in [SUPERADMIN_ROLE, "admin"]: 
        return False, "Only admin/superadmin can cancel"
    return True, ""

# ---------------------------
# SYNC LOGIC
# ---------------------------
def get_lark_token():
    try:
        res = requests.post("https://open.larksuite.com/open-apis/auth/v3/tenant_access_token/internal", 
                            json={"app_id": LARK_APP_ID, "app_secret": LARK_APP_SECRET}, timeout=30)
        return res.json().get("tenant_access_token")
    except: return None

def classify_sector(fields):
    k = str(fields.get('Dịch vụ', '')).upper()
    if "POD" in k or "DROPSHIP" in k: return "Pod_Drop"
    elif "WAREHOUSE" in k: return "Warehouse"
    return "Express"

def init_pancake_pages(force_refresh=True):
    service = PancakeService()
    try: pages = service.fetch_pages()
    except: return
    if not pages: return

    for p in pages:
        p_id = str(p.get('id') or '')
        if not p_id: continue
        p_username = p.get('username') or p.get('slug') or p_id
        if p.get('platform') == 'zalo' and not str(p_username).startswith('pzl_'): p_username = f"pzl_{p_username}"
        elif p.get('platform') == 'telegram' and not str(p_username).startswith('tl_'): p_username = f"tl_{p_username}"

        existing = db.pages.find_one({"id": p_id})
        access_token = existing.get("access_token") if existing else None
        if force_refresh or not access_token:
            try: access_token = service.get_token(p_id)
            except: pass
        
        db.pages.update_one({"id": p_id}, {
            "$set": {
                "id": p_id, "name": p.get('name'), "platform": p.get('platform'),
                "username": p_username, "access_token": access_token, "updated_at": now_dt()
            }}, upsert=True)

def sync_all_lark_task():
    global LAST_SYNC_TIMESTAMP
    tk = get_lark_token()
    if not tk: return
    try:
        res = requests.get(f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_APP_TOKEN}/tables/{LARK_TABLE_ID}/records", 
                           headers={"Authorization": f"Bearer {tk}"}, params={"page_size": 500}, timeout=60).json()
        for item in res.get('data', {}).get('items', []):
            f = item.get('fields', {})
            db.leads.update_one({"psid": item.get('record_id')}, {
                "$set": {
                    "full_name": f.get('Tên khách hàng'), "phone_number": f.get('Link FB/username tele'),
                    "sector": classify_sector(f), "status": f.get('Trạng thái', 'Khách Mới'),
                    "page_id": "LARK_AUTO", "source_platform": "Lark"
                },
                "$setOnInsert": {"updated_at": now_dt()}  # ✅ Only set on new records
            }, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except: pass

def sync_lark_tasks_task():
    global LAST_SYNC_TIMESTAMP
    tk = get_lark_token()
    if not tk: return
    try:
        res = requests.get(f"https://open.larksuite.com/open-apis/bitable/v1/apps/{LARK_TASK_APP_TOKEN}/tables/{LARK_TASK_TABLE_ID}/records", 
                           headers={"Authorization": f"Bearer {tk}"}, timeout=60).json()
        for item in res.get('data', {}).get('items', []):
            f = item.get('fields', {})
            assignee = f.get('Chịu trách nhiệm', [])[0].get('name', '---') if f.get('Chịu trách nhiệm') else '---'
            u_id = None
            lu = db.users.find_one({"username": assignee})
            if lu: u_id = lu['_id']
            
            raw = f.get('Time') or f.get('Deadline')
            due_at = parse_due_at(raw) if isinstance(raw, str) else None
            
            db.tasks.update_one({"id": item.get('record_id')}, {"$set": {
                "todo_content": f.get('Nội Dung Todo', ''), "status": f.get('Tình trạng', 'Not_yet'),
                "assignee": assignee, "assigned_to": u_id, "customer_name": f.get('Tên Nhóm Khách/Khách mới', ''),
                "due_at": due_at, "updated_at": now_dt()
            }}, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except: pass

def pancake_sync_task():
    global LAST_SYNC_TIMESTAMP
    service = PancakeService()
    try:
        init_pancake_pages(True)
        for p in db.pages.find({}, {"id": 1, "access_token": 1, "username": 1}):
            if not p.get("id") or not p.get("access_token"): continue
            for l in service.get_all_leads(p["id"], p["access_token"]):
                db.leads.update_one({"psid": l['psid']}, {
                    "$set": {
                        "full_name": l['name'], "phone_number": l['phone'], "sector": l['sector'],
                        "status": l['status'], "page_id": p["id"], "page_username": p["username"],
                        "conversation_id": l.get('conversation_id'), "source_platform": "Pancake"
                    },
                    "$setOnInsert": {"updated_at": now_dt()}  # ✅ Only set on new records
                }, upsert=True)
        LAST_SYNC_TIMESTAMP = time.time()
    except: pass

def sync_pancake_conversation_for_customer(customer):
    service = PancakeService()
    pages = service.fetch_pages()
    for page in pages:
        conversations = service.fetch_conversations(page["id"])
        for c in conversations:
            if c.get("psid") == customer.get("psid"):
                return {"page_id": page["id"], "page_username": page["username"], "conversation_id": c["id"]}
    return None

# ✅ UNIFIED AUTO OVERDUE LOGIC (Replacing individual functions)
def auto_scan_overdue_tasks():
    now = now_dt()
    active_statuses = ["todo", "waiting", "doing", "Not_yet"]
    
    # 1. Normal Tasks (Customer Tasks)
    db.tasks.update_many(
        {"status": {"$in": active_statuses}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "missed_at": now, "updated_at": now, "missed_notify_pending": True}}
    )
    
    # 2. Corp Tasks
    db.corp_tasks.update_many(
        {"status": {"$in": ["todo", "waiting", "doing"]}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "updated_at": now}}
    )
    
    # 3. Personal Tasks
    db.personal_tasks.update_many(
        {"status": {"$in": ["todo", "waiting", "doing"]}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "updated_at": now, "missed_notify_pending": True}}
    )
    
    # 4. Department Tasks
    db.department_tasks.update_many(
        {"status": {"$in": ["todo", "waiting", "doing"]}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "updated_at": now}}
    )
    
    # 5. Customer Requests
    db.customer_requests.update_many(
        {"status": {"$in": ["todo", "waiting", "doing"]}, "due_at": {"$lt": now}}, # Note: Requests usually have no due_at, but if added
        {"$set": {"status": "overdue", "updated_at": now}}
    )

# ---------------------------
# ROUTES: AUTH
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p, depts = request.form.get('username'), request.form.get('password'), request.form.getlist('department')
        if db.users.find_one({"username": u}): # ✅ Check for existing username
            flash('Username exists!', 'danger')
            return redirect(url_for('register'))
        role = SUPERADMIN_ROLE if db.users.count_documents({}) == 0 else 'user' # ✅ First user is superadmin
        db.users.insert_one({"username": u, "password_hash": generate_password_hash(p), "role": role, "departments": depts, "created_at": now_dt()})
        return redirect(url_for('login'))
    return render_template('register.html', departments=USER_DEPARTMENTS) # Assumes register.html has multi-select

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        user = db.users.find_one({"username": u})
        if user and check_password_hash(user['password_hash'], p):
            login_user(User(user))
            return redirect(url_for('index'))
        flash('Sai thông tin đăng nhập', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------------------------
# ROUTES: DASHBOARD & USER SETTINGS
# ---------------------------
@app.route('/')
@login_required
def index():
    stats = {
        "pod_drop": db.leads.count_documents({"sector": "Pod_Drop"}),
        "express": db.leads.count_documents({"sector": "Express"}),
        "warehouse": db.leads.count_documents({"sector": "Warehouse"}),
        "total_staff": db.users.count_documents({}),
        "personal_tasks": db.personal_tasks.count_documents({"user_id": ObjectId(current_user.id),"status": {"$ne": "done"}})
    }

    # ✅ FILTER: Calculate stats based on role
    user_query = {}
    if current_user.role == 'admin':
        # Admin: Only get users in their department
        user_query["departments"] = {"$in": current_user.departments}
    # Superadmin gets all. User gets nothing/their own (filtered in UI)

    user_task_stats = []
    
    # If user is just 'user', we can optimize by skipping this heavy calc or just doing for self
    if current_user.role in [SUPERADMIN_ROLE, 'admin']:
        all_users = list(db.users.find(user_query, {"username": 1, "_id": 1, "departments": 1}))
        
        for u in all_users:
            uid = u["_id"]
            uid_str = str(uid)
            
            cus_done = db.tasks.count_documents({"assigned_to": {"$in": [uid, uid_str]}, "status": "done"})
            cus_not = db.tasks.count_documents({"assigned_to": {"$in": [uid, uid_str]}, "status": {"$ne": "done"}})
            
            corp_done = db.corp_tasks.count_documents({"assigned_to": {"$in": [uid, uid_str]}, "status": "done"})
            corp_not = db.corp_tasks.count_documents({
                "assigned_to": {"$in": [uid, uid_str]}, 
                "status": {"$nin": ["done", "cancelled"]}
            })
            # ✅ NEW: Department Task counts
            dept_done = db.department_tasks.count_documents({"assigned_to": {"$in": [uid, uid_str]}, "status": "done"})
            dept_not = db.department_tasks.count_documents({
                "$or": [{"assigned_to": {"$in": [uid, uid_str]}}, {"department": {"$in": u.get("departments", [])}}],
                "status": {"$nin": ["done", "cancelled"]}
            })
            
            user_task_stats.append({
                "id": str(uid),
                "username": u.get("username", "Unknown"),
                "department": ", ".join(u.get("departments", []) or ["Other"]),
                "cus_done": int(cus_done),
                "cus_not": int(cus_not),
                "corp_done": int(corp_done),
                "corp_not": int(corp_not), # ✅ Add dept task counts
                "dept_done": int(dept_done),
                "dept_not": int(dept_not),
                "done": int(cus_done + corp_done),
                "not_done": int(cus_not + corp_not)
            })

    return render_template('pages.html', stats=stats, user_task_stats=user_task_stats, departments=USER_DEPARTMENTS)

@app.route('/user/update-telegram', methods=['POST'])
@login_required
def update_telegram_self():
    tid = (request.form.get('telegram_id') or '').strip()
    if tid:
        db.users.update_one({"_id": ObjectId(current_user.id)}, {"$set": {"telegram_chat_id": tid}})
        flash("Đã cập nhật Telegram Chat ID thành công!", "success")
    else:
        flash("Vui lòng nhập ID hợp lệ", "warning")
    return redirect(url_for('index'))

# ---------------------------
# ROUTES: CRM (Leads)
# ---------------------------
@app.route('/sector/<name>')
@login_required
def view_sector(name):
    q = {"sector": name}
    if request.args.get('search'): q["full_name"] = {"$regex": request.args.get('search'), "$options": "i"}
    if request.args.get('status'): q["status"] = request.args.get('status')
    
    if request.args.get('mode') == 'mine': # ✅ Only show leads assigned to current user
        q["assigned_to"] = ObjectId(current_user.id)
        
    leads = list(db.leads.find(q).sort("updated_at", -1))
    users_list = []
    if current_user.role == 'admin':
        users_list = list(db.users.find({}, {"username": 1, "_id": 1}))

    user_map = {u['_id']: u['username'] for u in db.users.find({}, {"username": 1, "_id": 1})}
    
    return render_template('leads.html', sector_name=name, sector_id=name, leads=leads, user_map=user_map, users_list=users_list)

@app.route('/customer/assign/<psid>', methods=['POST'])
@login_required
def assign_lead(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead:
        return jsonify({"status": "error", "message": "Lead not found"}), 404
        
    new_assignee_id = request.form.get('assigned_user_id')
    action_ok = False
    
    if current_user.role in [SUPERADMIN_ROLE, 'admin']: # ✅ Admin/Superadmin can assign/unassign
        if new_assignee_id:
            db.leads.update_one({"psid": psid}, {"$set": {"assigned_to": ObjectId(new_assignee_id), "updated_at": now_dt()}})
        else:
             db.leads.update_one({"psid": psid}, {"$unset": {"assigned_to": ""}, "$set": {"updated_at": now_dt()}})
        action_ok = True
        
    elif current_user.department in ['Customer Services', 'Sale'] or current_user.role == 'user':
        if new_assignee_id == str(current_user.id):
            db.leads.update_one({"psid": psid}, {"$set": {"assigned_to": ObjectId(current_user.id), "updated_at": now_dt()}})
            action_ok = True
        elif not new_assignee_id and str(lead.get('assigned_to')) == str(current_user.id):
            db.leads.update_one({"psid": psid}, {"$unset": {"assigned_to": ""}, "$set": {"updated_at": now_dt()}})
            action_ok = True
            
    if action_ok:
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"status": "success"})
        return redirect(request.referrer or url_for('index'))
    else:
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

@app.route('/customer/<psid>')
@login_required
def view_customer_detail(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead: return "Not Found", 404
    t_q = {"$or": [{"customer_psid": psid}, {"customer_name": lead.get("full_name")}]}
    n_q = {"customer_psid": psid} # ✅ Notes are user-specific
    if current_user.role != 'admin':
        t_q = {"$and": [t_q, {"$or": [{"user_id": ObjectId(current_user.id)}, {"assigned_to": ObjectId(current_user.id)}]}]}
        n_q["user_id"] = ObjectId(current_user.id)
    
    users_list = list(db.users.find({}, {"username": 1, "_id": 1}))
    return render_template('customer.html', lead=lead, tasks=list(db.tasks.find(t_q).sort("created_at", -1)), notes=list(db.notes.find(n_q).sort("created_at", -1)), users_list=users_list)

@app.route('/customer/update/<psid>', methods=['POST'])
@login_required
def update_customer(psid):
    upd = {k: v for k, v in request.form.items() if v}
    upd['updated_at'] = now_dt()
    if 'assigned_to' in upd and isinstance(upd['assigned_to'], str):
         if upd['assigned_to']:
             upd['assigned_to'] = ObjectId(upd['assigned_to'])
         else:
             pass 
    db.leads.update_one({"psid": psid}, {"$set": upd})
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest': return jsonify({"status": "success"})
    return redirect(url_for('view_customer_detail', psid=psid))

@app.route('/customer/add', methods=['POST'])
@login_required
def add_customer():
    full_name = request.form.get("full_name")
    if not full_name:
        flash("Thiếu tên khách hàng", "danger")
        return redirect(request.referrer or url_for("index"))

    db.leads.insert_one({
        "psid": str(uuid.uuid4()),
        "full_name": full_name,
        "phone_number": request.form.get("phone_number", "N/A"),
        "sector": request.form.get("sector") or "Pod_Drop",
        "status": request.form.get("status") or "Khách Mới",
        "page_id": "MANUAL",
        "source_platform": "Manual",
        "updated_at": now_dt(),
        "created_at": now_dt(),
    })
    return redirect(url_for("view_sector", name=request.form.get("sector") or "Pod_Drop"))

@app.route('/customer/<cid>/sync-pancake', methods=['POST'])
@login_required
def sync_customer_pancake(cid):
    customer = db.customers.find_one({"_id": ObjectId(cid)})
    if not customer: return jsonify({"status": "not_found"}), 404
    if not customer.get("psid"): return jsonify({"status": "missing_psid"}), 400

    result = sync_pancake_conversation_for_customer(customer)
    if not result: return jsonify({"status": "not_found_conversation"})

    db.customers.update_one({"_id": customer["_id"]}, {"$set": result})
    return jsonify({"status": "success"})

@app.route('/customer/delete/<psid>', methods=['POST'])
@login_required
def delete_customer(psid):
    if current_user.role == 'admin':
        db.leads.delete_one({"psid": psid})
    return redirect(url_for('index'))

@app.route('/customer/note/add/<psid>', methods=['POST'])
@login_required
def add_customer_note(psid):
    content = (request.form.get("content") or "").strip()
    if content:
        db.notes.insert_one({
            "content": content,
            "customer_psid": psid,
            "user_id": ObjectId(current_user.id),
            "created_at": now_dt()
        })
    return redirect(url_for("view_customer_detail", psid=psid))

@app.route('/customer/activity/add/<psid>', methods=['POST'])
@login_required
def add_customer_activity(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead: return redirect(url_for("index"))

    tid = 'act_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    todo_content = (request.form.get("todo_content") or "").strip()
    status = request.form.get("status") or "todo" # ✅ Default to unified status
    
    raw_deadline = request.form.get("deadline") or request.form.get("time_log")
    due_at = parse_due_at(raw_deadline) if (raw_deadline and "T" in raw_deadline) else None
    legacy_time_log = raw_deadline if not due_at else None

    assigned_to_oid = ObjectId(current_user.id)
    assignee_name = current_user.username

    if current_user.role in [SUPERADMIN_ROLE, "admin"]: # ✅ Admin/Superadmin can assign
        assigned_user_id = request.form.get("assigned_user_id")
        if assigned_user_id:
            u = db.users.find_one({"_id": ObjectId(assigned_user_id)})
            if u:
                assigned_to_oid = u["_id"]
                assignee_name = u.get("username", assignee_name)

    created_by_oid = ObjectId(current_user.id)

    db.tasks.insert_one({
        "id": tid,
        "todo_content": todo_content,
        "customer_name": lead.get("full_name"),
        "customer_psid": psid,
        "assignee": assignee_name,
        "assigned_to": assigned_to_oid,
        "status": status,
        "due_at": due_at,
        "time_log": legacy_time_log,
        "user_id": created_by_oid,
        "created_at": now_dt(),
        "updated_at": now_dt(),
        "assigned_by": current_user.username,
        "assigned_by_role": current_user.role,
        "assigned_at": now_dt() if assigned_to_oid != created_by_oid else None,
        "notify_pending": True if assigned_to_oid != created_by_oid else False,
        "missed_notify_pending": False
    })
    return redirect(url_for("view_customer_detail", psid=psid))

# ---------------------------
# ROUTES: NORMAL TASKS
# ---------------------------
@app.route('/tasks')
@login_required
def view_tasks():
    # --- 1. GATHER FILTERS ---
    filter_type = request.args.get('type')
    filter_status = request.args.get('status')
    search = request.args.get('search', '').strip().lower()
    filter_department = request.args.get('department')
    date_filter = request.args.get('date_filter')
    custom_start = request.args.get('start_date')
    custom_end = request.args.get('end_date')
    
    # --- 2. PREPARE DATE QUERY ---
    date_q = {}
    if date_filter:
        now = now_dt()
        today = now.date()
        start_dt, end_dt = None, None
        if date_filter == 'yesterday':
            yesterday = today - timedelta(days=1)
            start_dt = datetime.combine(yesterday, datetime.min.time())
            end_dt = datetime.combine(yesterday, datetime.max.time())
        elif date_filter == 'this_week':
            start_dt = datetime.combine(today - timedelta(days=today.weekday()), datetime.min.time())
            end_dt = now
        elif date_filter == 'last_week':
            last_week_start = today - timedelta(days=today.weekday() + 7)
            last_week_end = last_week_start + timedelta(days=6)
            start_dt = datetime.combine(last_week_start, datetime.min.time())
            end_dt = datetime.combine(last_week_end, datetime.max.time())
        elif date_filter == 'this_month':
            start_dt = datetime.combine(today.replace(day=1), datetime.min.time())
            end_dt = now
        elif date_filter == 'last_month':
            last_month_end = today.replace(day=1) - timedelta(days=1)
            last_month_start = last_month_end.replace(day=1)
            start_dt = datetime.combine(last_month_start, datetime.min.time())
            end_dt = datetime.combine(last_month_end, datetime.max.time())
        elif date_filter == 'custom' and custom_start and custom_end:
            try:
                start_dt = datetime.strptime(custom_start, "%Y-%m-%d")
                end_dt = datetime.strptime(custom_end, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
            except: pass
        if start_dt and end_dt:
            date_q = {"created_at": {"$gte": start_dt, "$lte": end_dt}}

    # --- 3. DYNAMIC QUERY BUILDER ---
    me = ObjectId(current_user.id)

    def build_query(collection_name, include_status=True):
        conditions = []
        # Role-based filters
        if current_user.role not in [SUPERADMIN_ROLE, 'admin']:
            if collection_name == 'tasks': conditions.append({"$or": [{"user_id": me}, {"assigned_to": me}]})
            elif collection_name == 'corp_tasks': conditions.append({"assigned_to": {"$in": [me]}})
            elif collection_name == 'department_tasks': conditions.append({"$or": [{"assigned_to": {"$in": [me]}}, {"department": {"$in": current_user.departments or []}}]})
            elif collection_name == 'customer_requests': conditions.append({"$or": [{"sender_name": current_user.username}, {"assigned_to": me}, {"assigned_to": {"$in": [me]}}, {"assignee": current_user.username}]})
        if collection_name == 'personal_tasks': conditions.append({"user_id": me})

        # Common filters - only include status if requested
        if include_status and filter_status: conditions.append({"status": filter_status})
        if date_q: conditions.append(date_q)

        # Department filter
        if filter_department and collection_name in ['corp_tasks', 'department_tasks']:
            if collection_name == 'corp_tasks': conditions.append({"$or": [{"department": filter_department}, {"departments": filter_department}]})
            else: conditions.append({"department": filter_department})

        # Search filter
        if search:
            search_regex = {"$regex": search, "$options": "i"}
            if collection_name == 'tasks': conditions.append({"$or": [{"todo_content": search_regex}, {"customer_name": search_regex}]})
            elif collection_name in ['corp_tasks', 'department_tasks']: conditions.append({"$or": [{"title": search_regex}, {"department": search_regex}]})
            elif collection_name == 'personal_tasks': conditions.append({"title": search_regex})
            elif collection_name == 'customer_requests': conditions.append({"$or": [{"content": search_regex}, {"customer_name": search_regex}]})
        
        return {"$and": conditions} if conditions else {}

    # --- 4. BUILD QUERIES & CALCULATE COUNTS ---
    final_queries = {
        'customer': build_query('tasks'),
        'corp': build_query('corp_tasks'),
        'personal': build_query('personal_tasks'),
        'department': build_query('department_tasks'),
        'request': build_query('customer_requests')
    }
    task_counts = {
        'customer': db.tasks.count_documents(final_queries['customer']),
        'corp': db.corp_tasks.count_documents(final_queries['corp']),
        'personal': db.personal_tasks.count_documents(final_queries['personal']),
        'department': db.department_tasks.count_documents(final_queries['department']),
        'request': db.customer_requests.count_documents(final_queries['request']),
    }
    task_counts['all'] = sum(task_counts.values())

    # ✅ FIX: Calculate status counts WITHOUT status filter (use include_status=False)
    status_counts = {'all': 0}
    # Build base queries WITHOUT status filter
    base_q_customer = build_query('tasks', include_status=False)
    base_q_corp = build_query('corp_tasks', include_status=False)
    base_q_personal = build_query('personal_tasks', include_status=False)
    base_q_dept = build_query('department_tasks', include_status=False)
    base_q_request = build_query('customer_requests', include_status=False)
    
    # Add status filter for each specific status
    def add_status_filter(q, status):
        if q:
            return {"$and": [q, {"status": status}]}
        return {"status": status}
    
    for s in UNIFIED_STATUSES:
        count = 0
        if not filter_type or filter_type == 'customer':
            count += db.tasks.count_documents(add_status_filter(base_q_customer, s))
        if not filter_type or filter_type == 'corp':
            count += db.corp_tasks.count_documents(add_status_filter(base_q_corp, s))
        if not filter_type or filter_type == 'personal':
            count += db.personal_tasks.count_documents(add_status_filter(base_q_personal, s))
        if not filter_type or filter_type == 'department':
            count += db.department_tasks.count_documents(add_status_filter(base_q_dept, s))
        if not filter_type or filter_type == 'request':
            count += db.customer_requests.count_documents(add_status_filter(base_q_request, s))
        
        status_counts[s] = count
        status_counts['all'] += count

    # --- 5. FETCH DATA FOR DISPLAY ---
    all_items = []
    if not filter_type or filter_type == 'customer':
        for t in db.tasks.find(final_queries['customer']):
            t['kind'] = 'customer'
            all_items.append(t)
    if not filter_type or filter_type == 'corp':
        for t in db.corp_tasks.find(final_queries['corp']):
            t.update({'kind': 'corp', 'todo_content': t.get('title')})
            if 'assignees' not in t: t['assignees'] = [t.get('assignee')] if t.get('assignee') else []
            t['assignee'] = t['assignees'][0] if t['assignees'] else '---'
            all_items.append(t)
    if not filter_type or filter_type == 'personal':
        for t in db.personal_tasks.find(final_queries['personal']):
            t.update({'kind': 'personal', 'todo_content': t.get('title'), 'assignee': 'Me'})
            all_items.append(t)
    if not filter_type or filter_type == 'department':
        for t in db.department_tasks.find(final_queries['department']):
            t.update({'kind': 'department', 'todo_content': t.get('title'), 'customer_name': None})
            if 'assignees' not in t: t['assignees'] = [t.get('assignee')] if t.get('assignee') else []
            t['assignee'] = t['assignees'][0] if t['assignees'] else '---'
            all_items.append(t)
    if not filter_type or filter_type == 'request':
        for r in db.customer_requests.find(final_queries['request']):
            r.update({'kind': 'request', 'todo_content': r.get('content'), 'due_at': None})
            if 'assignees' not in r: r['assignees'] = [r.get('assignee')] if r.get('assignee') else []
            if not r['assignees']: r['assignees'] = [r.get('sender_name')] if r.get('sender_name') else []
            r['assignee'] = r['assignees'][0] if r['assignees'] else '---'
            if r.get('status') in REQUEST_STATUSES:
                r['note'] = r.get('status')
                r['status'] = 'todo'
            else:
                r['note'] = r.get('note', '')
            all_items.append(r)

    # --- 6. SORT RESULTS ---
    # ✅ UPDATED SORT LOGIC: Priority User's Created/Assigned Tasks
    def get_is_mine(t):
        if t.get('kind') == 'personal': return True
        assigned = t.get('assigned_to')
        if (isinstance(assigned, list) and me in assigned) or (assigned == me): return True
        if t.get('user_id') == me: return True
        if t.get('assigned_by') == current_user.username: return True
        if t.get('sender_name') == current_user.username: return True
        return False

    all_items.sort(key=lambda x: x.get('updated_at') or datetime.min, reverse=True)
    all_items.sort(key=lambda x: x.get('status') in ['done', 'cancelled'])
    all_items.sort(key=lambda x: x.get('status') == 'overdue', reverse=True)
    all_items.sort(key=lambda x: get_is_mine(x), reverse=True)
    
    # --- 7. RENDER TEMPLATE ---
    users_list = list(db.users.find({}, {"username": 1, "_id": 1, "departments": 1}))

    return render_template(
        'tasks.html', 
        tasks=all_items, 
        users_list=users_list, 
        statuses=UNIFIED_STATUSES, 
        corp_departments=CORP_DEPARTMENTS,
        department_task_departments=DEPARTMENT_TASK_DEPARTMENTS,
        request_statuses=REQUEST_STATUSES,
        business_types=BUSINESS_TYPES,
        task_counts=task_counts,
        status_counts=status_counts  # ✅ NEW: For horizontal status tabs
    )

@app.route('/task/add', methods=['POST'])
@login_required
def add_task():
    aid = request.form.get('assigned_user_id') or current_user.id
    target = db.users.find_one({"_id": ObjectId(aid)})
    
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))
    customer_psid, norm_name = link_customer_for_task(request.form.get('customer_name'))
    
    assigned_to_oid = ObjectId(aid) # ✅ Assigned to user selected in modal
    is_assigned = assigned_to_oid != ObjectId(current_user.id)
    
    db.tasks.insert_one({
        "id": 'task_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),
        "todo_content": request.form.get('todo_content'), "customer_name": norm_name or request.form.get('customer_name'),
        "customer_psid": customer_psid, "assignee": target['username'] if target else '---', "assigned_to": assigned_to_oid,
        "status": "todo", "due_at": due_at, "deadline": due_at, "user_id": ObjectId(current_user.id),
        "created_at": now_dt(), "updated_at": now_dt(), "notify_pending": is_assigned,
        "assigned_by": current_user.username, "assigned_by_role": current_user.role,
        "assigned_at": now_dt() if is_assigned else None, "missed_notify_pending": False,
        "attachment": save_uploaded_file(request.files.get('attachment'))
        # ✅ Add note field
        , "note": request.form.get('note', '')
    })
    
    # ✅ AUTO SEND TELEGRAM (Notify Assignee)
    if is_assigned and target:
        msg_text = (
            f"🔔 <b>NEW TASK ASSIGNED</b>\n\n"
            f"📝 <b>Content:</b> {request.form.get('todo_content')}\n"
            f"👤 <b>Customer:</b> {norm_name or request.form.get('customer_name') or 'N/A'}\n"
            f"👤 <b>By:</b> {current_user.username}\n"
            f"📅 <b>Deadline:</b> {due_at.strftime('%H:%M %d/%m/%Y') if due_at else 'None'}"
        )
        if target.get("telegram_chat_id"):
            send_telegram_notification(target.get("telegram_chat_id"), msg_text)
            
    return redirect(url_for('view_tasks'))

# ✅ UNIFIED MANUAL SEND TELEGRAM
@app.route('/task/send-telegram/<id>', methods=['POST'])
@login_required
def task_manual_send_telegram(id):
    """Gửi Telegram thủ công cho bất kỳ loại task/request nào"""
    t, col = find_any_task(id)
    if not t: return jsonify({"status": "not_found"}), 404
    
    # Lấy danh sách người nhận (Hỗ trợ cả mảng OID và OID đơn lẻ)
    assigned_to = t.get("assigned_to", [])
    if isinstance(assigned_to, ObjectId): assigned_to = [assigned_to]
    
    # Nếu không có assigned_to, thử dùng user_id (cho personal task)
    if not assigned_to and t.get("user_id"): assigned_to = [t.get("user_id")]
    
    users = list(db.users.find({"_id": {"$in": assigned_to}}))
    
    # Nội dung thông báo linh động
    title = t.get('todo_content') or t.get('title') or t.get('content') or 'N/A'
    context = t.get('customer_name') or t.get('department') or 'System'
    by_user = t.get('assigned_by') or t.get('sender_name') or 'Admin'
    due_at = t.get('due_at')
    
    msg_text = (
        f"🔔 <b>TASK REMINDER</b>\n\n"
        f"📝 <b>Nội dung:</b> {title}\n"
        f"👤 <b>Bối cảnh:</b> {context}\n"
        f"👤 <b>Người giao:</b> {by_user}\n"
        f"📅 <b>Hạn chót:</b> {due_at.strftime('%H:%M %d/%m/%Y') if due_at else 'N/A'}"
    )
    
    count = 0
    for u in users:
        if u.get("telegram_chat_id"):
            if send_telegram_notification(u.get("telegram_chat_id"), msg_text):
                count += 1
    
    if count > 0:
        flash(f"Đã gửi thông báo đến {count} người.", "success")
    else:
        flash("Người nhận chưa cập nhật Telegram ID hoặc lỗi Bot.", "warning")
        
    return redirect(request.referrer or url_for('view_tasks'))

@app.route('/task/update/<id>', methods=['POST'])
@login_required
def update_task_detail(id):
    task, col_name = find_any_task(id)
    if not task:
        if request.is_json: return jsonify({"status": "error", "message": "Task not found"}), 404
        return redirect(url_for('view_tasks'))

    # ✅ Permission Check for Update (Safety)
    me = ObjectId(current_user.id)
    has_perm = False
    if col_name == 'personal_tasks':
         if task.get('user_id') == me: has_perm = True
    elif current_user.role in [SUPERADMIN_ROLE, 'admin']: has_perm = True
    elif col_name == 'tasks' and (task.get('user_id') == me or task.get('assigned_to') == me): has_perm = True
    elif col_name == 'corp_tasks':
        assigned = task.get('assigned_to', [])
        if isinstance(assigned, list) and me in assigned: has_perm = True
        elif assigned == me: has_perm = True
    elif col_name == 'department_tasks':
        assigned = task.get('assigned_to', [])
        if isinstance(assigned, list) and me in assigned: has_perm = True
        elif assigned == me: has_perm = True
    elif col_name == 'customer_requests': has_perm = True
    
    if not has_perm:
         if request.is_json: return jsonify({"status": "error", "message": "Forbidden"}), 403
         return redirect(url_for('view_tasks'))


    if request.is_json:
        data = request.get_json()
        upd = {"updated_at": now_dt()}
        # ✅ FIX: Only update fields that are ACTUALLY provided in data (not None)
        if col_name == 'tasks':
            if 'todo_content' in data and data.get('todo_content') is not None:
                upd["todo_content"] = data.get('todo_content')
            if 'customer_name' in data and data.get('customer_name') is not None:
                upd["customer_name"] = data.get('customer_name')
        elif col_name in ['corp_tasks', 'department_tasks']:
            # ✅ FIX: Only update title if provided
            if 'todo_content' in data and data.get('todo_content') is not None:
                upd["title"] = data.get('todo_content')
        elif col_name == 'personal_tasks':
            if 'todo_content' in data and data.get('todo_content') is not None:
                upd["title"] = data.get('todo_content')
        
        if 'due_at' in data: upd['due_at'] = parse_due_at(data['due_at'])
        
        if 'note' in data: upd['note'] = data['note'] # ✅ Update note field

        # ✅ NEW: Handle Assignee Updates for Corp/Department Tasks
        if 'assigned_user_ids' in data and col_name in ['corp_tasks', 'department_tasks']:
            ids = data['assigned_user_ids']
            if isinstance(ids, list):
                try:
                    users = list(db.users.find({"_id": {"$in": [ObjectId(uid) for uid in ids]}}))
                    upd['assigned_to'] = [u["_id"] for u in users]
                    upd['assignees'] = [u["username"] for u in users]
                    upd['assignee'] = users[0]["username"] if users else '---'
                except: pass

        db[col_name].update_one({"id": id}, {"$set": upd})
        return jsonify({"status": "success"})

    upd = {"status": request.form.get('status'), "due_at": parse_due_at(request.form.get('due_at')), "updated_at": now_dt()}
    
    if col_name == 'tasks':
        upd.update({"todo_content": request.form.get('todo_content'), "customer_name": request.form.get('customer_name')})
        # ✅ FIX: SUPERADMIN CAN REASSIGN TOO
        if current_user.role in [SUPERADMIN_ROLE, 'admin'] and request.form.get('assigned_user_id'):
            u = db.users.find_one({"_id": ObjectId(request.form.get('assigned_user_id'))})
            if u: upd.update({"assigned_to": u["_id"], "assignee": u["username"]})
    elif col_name in ['corp_tasks', 'personal_tasks']:
        upd["title"] = request.form.get('todo_content')

    if 'attachment' in request.files:
        f = save_uploaded_file(request.files['attachment'])
        if f: upd["attachment"] = f

    db[col_name].update_one({"id": id}, {"$set": upd})
    if 'detail' in request.form.get('source_page', ''): return redirect(url_for('view_task_detail_page', id=id))
    return redirect(url_for('view_tasks' if col_name == 'tasks' else ('view_corp_tasks' if col_name == 'corp_tasks' else 'view_personal_tasks')))

# ✅ Unified quick update for all task types
@app.route('/task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_task(id):
    t, col = find_any_task(id)
    if not t: return jsonify({"status": "error"}), 404
    
    # ✅ Permission Check for quick update
    has_perm = False
    me = ObjectId(current_user.id)
    
    # 1. Personal Task: STRICT OWNER ONLY
    if col == 'personal_tasks':
        if t.get('user_id') == me: has_perm = True
        
    # 2. Other Tasks: Admin/Superadmin OK
    elif current_user.role in [SUPERADMIN_ROLE, 'admin']: has_perm = True
    elif col == 'tasks' and (t.get('user_id') == me or t.get('assigned_to') == me): has_perm = True
    elif col == 'corp_tasks':
         assigned = t.get("assigned_to", [])
         if isinstance(assigned, ObjectId) and assigned == me: has_perm = True
         elif isinstance(assigned, list) and me in assigned: has_perm = True
    elif col == 'department_tasks': # ✅ NEW: Department task permission
         assigned = t.get("assigned_to", [])
         if isinstance(assigned, ObjectId) and assigned == me: has_perm = True
         elif isinstance(assigned, list) and me in assigned: has_perm = True
    elif col == 'customer_requests': has_perm = True # Allow all to update requests for now
    
    if not has_perm: return jsonify({"status": "error", "message": "Forbidden"}), 403

    req_status = request.form.get('status')
    nst = req_status if req_status else get_next_status(t.get('status', 'todo'))
    
    upd = {"status": nst, "updated_at": now_dt()}
    
    # ✅ Preserve Old Status as Note if transitioning from Request Status
    if col == 'customer_requests':
        current_s = t.get('status')
        if current_s in REQUEST_STATUSES and not t.get('note'):
            upd['note'] = current_s

    # Special logic for requests if needed (no overdue logic usually)
    if nst == "overdue": upd.update({"missed_at": now_dt(), "missed_notify_pending": True})
    
    db[col].update_one({"id": id}, {"$set": upd})
    send_status_change_notification(t, nst, "Task")
    
    return jsonify({"status": "success", "next": nst})

# ✅ NEW: Route for Task Type Conversion
@app.route('/task/convert/<id>', methods=['POST'])
@login_required
def convert_personal_task(id):
    t, col = find_any_task(id)
    if not t or col != 'personal_tasks': 
        return redirect(url_for('view_tasks'))

    # Only owner can convert
    if t.get('user_id') != ObjectId(current_user.id):
        flash('Unauthorized', 'danger')
        return redirect(url_for('view_tasks'))

    target_type = request.form.get('target_type')
    
    # Common fields override from Form
    new_title = request.form.get('todo_content') or t.get("title")
    new_due_at = parse_due_at(request.form.get('due_at')) or t.get("due_at")
    new_note = request.form.get('note', '')
    
    new_data = {
        "created_at": t.get("created_at"),
        "updated_at": now_dt(),
        "status": "todo",
        "due_at": new_due_at,
        "attachment": t.get("attachment"), # Keep old attachment
        "note": new_note
    }

    # Handle new file upload if provided
    if 'attachment' in request.files:
        f = save_uploaded_file(request.files['attachment'])
        if f: new_data['attachment'] = f

    # ✅ PROCESS ASSIGNEES FOR CONVERSION
    assigned_user_ids = request.form.getlist('assigned_user_ids')
    assigned_to_oids = []
    assignees_names = []
    
    # Defaults to Current User if none selected
    if not assigned_user_ids:
        assigned_to_oids = [ObjectId(current_user.id)]
        assignees_names = [current_user.username]
    else:
        try:
            # Filter valid users
            users = list(db.users.find({"_id": {"$in": [ObjectId(uid) for uid in assigned_user_ids]}}))
            assigned_to_oids = [u["_id"] for u in users]
            assignees_names = [u.get("username", "user") for u in users]
        except:
            # Fallback
            assigned_to_oids = [ObjectId(current_user.id)]
            assignees_names = [current_user.username]

    # Helper for single assignee (Customer Task)
    primary_assignee_name = assignees_names[0] if assignees_names else current_user.username
    primary_assignee_oid = assigned_to_oids[0] if assigned_to_oids else ObjectId(current_user.id)


    if target_type == 'customer':
        new_id = 'task_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        customer_name = request.form.get('customer_name') or 'Converted Task'
        customer_psid, norm_name = link_customer_for_task(customer_name)
        new_data.update({
            "id": new_id,
            "todo_content": new_title,
            "customer_name": norm_name or customer_name,
            "customer_psid": customer_psid,
            "assignee": primary_assignee_name, # ✅ Single Assignee Name
            "assigned_to": primary_assignee_oid, # ✅ Single OID
            "user_id": ObjectId(current_user.id),
            "assigned_by": current_user.username
        })
        db.tasks.insert_one(new_data)
        
    elif target_type == 'corp':
        new_id = 'corp_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        # Handle multiple departments
        depts = request.form.getlist('departments')
        if not depts and request.form.get('department'): depts = [request.form.get('department')]
        if not depts:
            depts = current_user.departments
        dept_display = ", ".join(depts)

        new_data.update({
            "id": new_id,
            "title": new_title,
            "departments": depts,
            "department": dept_display,
            "assigned_to": assigned_to_oids, # ✅ List OIDs
            "assignees": assignees_names,     # ✅ List Names
            "assignee": primary_assignee_name,
            "assigned_by": current_user.username
        })
        db.corp_tasks.insert_one(new_data)

    elif target_type == 'department':
        new_id = 'dept_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        dept = request.form.get('department')
        if not dept:
            dept = current_user.departments[0] if current_user.departments else None
        if not dept:
            flash("Department is required for Department Task conversion.", "danger")
            return redirect(url_for('view_task_detail_page', id=id))
        new_data.update({
            "id": new_id,
            "title": new_title,
            "department": dept,
            "assigned_to": assigned_to_oids, # ✅ List OIDs
            "assignees": assignees_names,     # ✅ List Names
            "assignee": primary_assignee_name,
            "assigned_by": current_user.username
        })
        db.department_tasks.insert_one(new_data)

    elif target_type == 'request':
        new_id = 'req_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        req_content = request.form.get('content') or new_title
        c_name = request.form.get('customer_name') or 'Converted'
        c_psid, c_norm = link_customer_for_task(c_name)
        req_status_note = request.form.get('request_status_note') # Special field
        
        new_data.update({
            "id": new_id,
            "content": req_content,
            "customer_name": c_norm or c_name,
            "customer_psid": c_psid,
            "app": "Manual",
            "status": "todo",
            "note": req_status_note, 
            "business_type": request.form.get('business_type', 'New'),
            "assigned_by": current_user.username,
            "sender_name": current_user.username,
            "assigned_to": assigned_to_oids, # ✅ List OIDs
            "assignees": assignees_names,     # ✅ List Names
            "assignee": primary_assignee_name
        })
        db.customer_requests.insert_one(new_data)

    else:
        flash('Invalid target type', 'danger')
        return redirect(url_for('view_task_detail_page', id=id))

    # Delete old task
    db.personal_tasks.delete_one({"id": id})
    flash('Task converted successfully', 'success')
    return redirect(url_for('view_tasks'))

@app.route('/task/detail/<id>')
@login_required
def view_task_detail_page(id):
    task, col_name = find_any_task(id)
    if not task: return redirect(url_for('view_tasks'))
    
    # ✅ Redirect to Request Detail if it's a request (uses request_detail.html)
    if col_name == 'customer_requests':
        return redirect(url_for('view_customer_request_detail', id=id))

    task['is_normal_task'] = (col_name == 'tasks')
    if col_name == 'tasks':
        task['kind'] = 'customer' # ✅ Explicitly set kind
    elif col_name == 'corp_tasks':
        task['kind'] = 'corp' # ✅ Explicitly set kind
        task.update({'todo_content': task.get('title'), 'customer_name': task.get('department','Corp'), 'assignee': ", ".join(task.get('assignees', [])) or "---"})
    elif col_name == 'department_tasks': # ✅ NEW: Department task detail mapping
        task['kind'] = 'department' # ✅ Explicitly set kind
        task['is_department_task'] = True
        task.update({'todo_content': task.get('title'), 'customer_name': task.get('department','Corp'), 'assignee': ", ".join(task.get('assignees', [])) or "---"})
    elif col_name == 'personal_tasks':
        task['kind'] = 'personal' # ✅ Explicitly set kind
        task.update({'todo_content': task.get('title'), 'customer_name': "Personal Task", 'assignee': "Me"})
    
    # Permission Check
    me = ObjectId(current_user.id)
    has_perm = False
    
    # 1. Personal Task: STRICT OWNER ONLY
    if col_name == 'personal_tasks':
        if task.get('user_id') == me: has_perm = True
        
    # 2. Other Tasks: Admin/Superadmin OK
    elif current_user.role in [SUPERADMIN_ROLE, 'admin']: has_perm = True
    elif col_name == 'tasks' and (task.get('user_id') == me or task.get('assigned_to') == me): has_perm = True
    elif col_name == 'corp_tasks':
        assigned = task.get('assigned_to', [])
        if isinstance(assigned, list) and me in assigned: has_perm = True
        elif assigned == me: has_perm = True
    elif col_name == 'department_tasks': # ✅ NEW: Department task detail permission logic
        assigned = task.get('assigned_to', [])
        if isinstance(assigned, list) and me in assigned: has_perm = True
        elif assigned == me: has_perm = True
        # ✅ NEW: Allow members of the same department to view detail (Context: Team Visibility)
        elif current_user.role in ['admin', 'user'] and task.get('department') in current_user.departments: has_perm = True
            
    if not has_perm: return redirect(url_for('view_tasks'))
    
    # ✅ PASS ALL CONSTANTS AND USERS FOR CONVERT MODAL
    users_list = list(db.users.find({}, {"username": 1, "_id": 1, "departments": 1}))
    return render_template('task_detail.html', task=task, statuses=UNIFIED_STATUSES, departments=USER_DEPARTMENTS,
                           corp_departments=CORP_DEPARTMENTS, 
                           department_task_departments=DEPARTMENT_TASK_DEPARTMENTS,
                           request_statuses=REQUEST_STATUSES,
                           business_types=BUSINESS_TYPES,
                           users_list=users_list) # ✅ Pass users_list

@app.route('/task/detail/upload/<id>', methods=['POST'])
@login_required
def upload_task_file_detail(id):
    task, col_name = find_any_task(id)
    if task and 'attachment' in request.files:
        f = save_uploaded_file(request.files['attachment'])
        if f: db[col_name].update_one({"id": id}, {"$set": {"attachment": f, "updated_at": now_dt()}})
    
    # Redirect based on type
    if col_name == 'customer_requests':
         return redirect(url_for('view_customer_request_detail', id=id))
    return redirect(url_for('view_task_detail_page', id=id))

@app.route('/task/delete/<id>', methods=['POST'])
@login_required
def delete_task(id):
    t, col = find_any_task(id)
    if not t: return redirect(url_for('view_tasks'))

    # Generic Delete Logic
    can_delete = False
    me = ObjectId(current_user.id)

    # 1. Personal Task: STRICT OWNER ONLY
    if col == 'personal_tasks': 
        if t.get('user_id') == me:
            can_delete = True
            
    # 2. Other Tasks: Admin/Superadmin OK
    elif current_user.role in [SUPERADMIN_ROLE, "admin"]: 
        can_delete = True
    elif col == 'tasks':
        # Normal task: creator can delete unless assigned by admin
        if t.get("user_id") == me and t.get("assigned_by_role") != "admin":
            can_delete = True
    elif col == 'customer_requests':
        # Only admin deletes requests usually, or maybe creator? Let's stick to admin for now based on requests_customer.html
        pass 

    if can_delete:
        db[col].delete_one({"id": id})
        
        # ✅ FIX: Redirect to main tasks list with correct type filter
        redirect_type = ''
        if col == 'tasks': redirect_type = 'customer'
        elif col == 'corp_tasks': redirect_type = 'corp'
        elif col == 'personal_tasks': redirect_type = 'personal'
        elif col == 'department_tasks': redirect_type = 'department'
        elif col == 'customer_requests': redirect_type = 'request'
        
        return redirect(url_for('view_tasks', type=redirect_type))
    else:
        flash("Bạn không có quyền xoá task này.", "danger")

    return redirect(url_for('view_tasks'))

# ✅ NEW: Route for Generic Request Delete (Popup -> Telegram)
@app.route('/task/request-delete-generic/<id>', methods=['POST'])
@login_required
def request_task_delete_generic(id):
    t, col = find_any_task(id)
    if not t: return jsonify({"status": "not_found"}), 404
    
    reason = request.form.get('reason', 'No reason provided')
    
    # Find Admin/Superadmin to notify
    admins = list(db.users.find({"role": {"$in": [SUPERADMIN_ROLE, 'admin']}}))
    
    msg_text = (
        f"🚨 <b>DELETE REQUEST</b>\n\n"
        f"👤 <b>User:</b> {current_user.username}\n"
        f"📝 <b>Task:</b> {t.get('todo_content') or t.get('title')}\n"
        f"📂 <b>Type:</b> {col}\n"
        f"❓ <b>Reason:</b> {reason}\n"
    )
    
    count = 0
    for a in admins:
        if a.get("telegram_chat_id"):
            send_telegram_notification(a.get("telegram_chat_id"), msg_text)
            count += 1
            
    if count > 0:
        flash("Đã gửi yêu cầu xóa tới Admin.", "success")
    else:
        flash("Không tìm thấy Admin để gửi yêu cầu. Vui lòng liên hệ trực tiếp.", "warning")
        
    return redirect(request.referrer or url_for('view_tasks'))

# ---------------------------
# ROUTES: PERSONAL TASKS
# ---------------------------
@app.route('/personal-tasks')
@login_required
def view_personal_tasks():
    return redirect(url_for('view_tasks', type='personal'))

@app.route('/personal-task/add', methods=['POST'])
@login_required
def add_personal_task():
    title = (request.form.get("title") or "").strip()
    if not title: return redirect(url_for("view_tasks"))
    db.personal_tasks.insert_one({ # ✅ Add note field
        "id": 'ptask_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),
        "title": title, "description": request.form.get("description"), "status": "todo",
        "due_at": parse_due_at(request.form.get("due_at")), "user_id": ObjectId(current_user.id),
        "created_at": now_dt(), "updated_at": now_dt(), "notify_pending": False, "missed_notify_pending": False,
        "attachment": save_uploaded_file(request.files.get('attachment'))
    })
    return redirect(url_for("view_tasks"))

@app.route('/personal-task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_personal_task(id):
    t = db.personal_tasks.find_one({"id": id, "user_id": ObjectId(current_user.id)}) # ✅ Only creator can update
    if not t: return jsonify({"status": "not_found"}), 404
    nst = next_personal_status(t.get("status", "Not_yet"))
    upd = {"status": nst, "updated_at": now_dt()}
    if nst == "Missed": upd["missed_notify_pending"] = True
    db.personal_tasks.update_one({"id": id}, {"$set": upd})
    return jsonify({"status": "success", "next": nst})

@app.route('/personal-task/delete/<id>', methods=['POST'])
@login_required
def delete_personal_task(id):
    db.personal_tasks.delete_one({
        "id": id,
        "user_id": ObjectId(current_user.id)
    })
    return redirect(url_for("view_personal_tasks"))


# ---------------------------
# ✅ Task Tổng công ty
# ---------------------------
@app.route('/corp-tasks')
@login_required # ✅ Redirect to unified view
def view_corp_tasks():
    return redirect(url_for('view_tasks', type='corp'))


@app.route('/corp-task/add', methods=['POST'])
@login_required
def add_corp_task():
    # ✅ FIX: Allow all roles to create Corp Tasks
    # Không còn chặn User/Admin nữa

    # Tạo ID ngẫu nhiên cho task
    cid = 'corp_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    title = (request.form.get('title') or '').strip()
    
    # ✅ FIX: Handle Multiple Departments
    departments = request.form.getlist('departments')
    
    # If using select (old UI fallback or single choice), get 'department' string
    single_dept = request.form.get('department')
    if not departments and single_dept:
        departments = [single_dept]
        
    # Join for display compatibility: "Vận Hành, Marketing"
    department_display = ", ".join(departments)
    
    # LẤY DANH SÁCH NGƯỜI ĐƯỢC GÁN (Mở cho tất cả các Role)
    assigned_user_ids = request.form.getlist('assigned_user_ids') # ✅ Can be empty
    
    # ✅ NEW: Default assignment logic if none selected
    if not assigned_user_ids:
        # If user didn't select anyone, default to themselves
        assigned_user_ids = [str(current_user.id)]

    # Parse thời hạn
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    # Kiểm tra dữ liệu đầu vào
    if not title or not departments or not due_at:
        flash('Thiếu thông tin hoặc phòng ban không hợp lệ', 'danger')
        return redirect(url_for('view_tasks'))

    # Xử lý OID và lấy tên hiển thị
    try:
        # Chuyển string ID thành ObjectId, bọc trong try-except để tránh crash nếu ID lỗi. If empty, it will be empty list.
        user_oids = [ObjectId(uid) for uid in assigned_user_ids]
        users = list(db.users.find({"_id": {"$in": user_oids}}))
        
        assignees = [u.get("username", "user") for u in users]
    except Exception as e:
        flash('Lỗi định dạng người dùng', 'danger')
        return redirect(url_for('view_tasks'))
    
    # Handle file upload
    attachment_filename = None
    if 'attachment' in request.files:
        attachment_filename = save_uploaded_file(request.files['attachment'])

    # Lưu vào Database
    db.corp_tasks.insert_one({
        "id": cid,
        "title": title,
        "departments": departments,       # ✅ Array for filtering
        "department": department_display, # ✅ String for display compatibility
        "assigned_to": [u["_id"] for u in users], # Lưu mảng OID
        "assignees": assignees,                   # Lưu mảng tên để hiển thị nhanh
        "assignee": assignees[0] if assignees else '---', # Primary assignee for display
        "status": "todo",
        "due_at": due_at,
        "created_at": now_dt(),
        "updated_at": now_dt(),
        "assigned_by": current_user.username,
        "assigned_by_role": current_user.role,
        "assigned_at": now_dt(),
        "notify_pending": True,
        "admin_request": None, # For admin approval flow
        "note": request.form.get('note', ''), # ✅ Add note field
        "attachment": attachment_filename
    })

    # ✅ AUTO SEND TELEGRAM
    msg_text = (
        f"🔔 <b>NEW TASK ASSIGNED</b>\n\n"
        f"📝 <b>Content:</b> {title}\n"
        f"🏢 <b>Depts:</b> {department_display}\n"
        f"👤 <b>By:</b> {current_user.username}\n"
        f"📅 <b>Deadline:</b> {due_at.strftime('%H:%M %d/%m/%Y')}"
    )
    for u in users: # Notify all assignees
        chat_id = u.get("telegram_chat_id")
        if chat_id:
            send_telegram_notification(chat_id, msg_text)

    flash('Đã tạo task công ty thành công', 'success')
    return redirect(url_for('view_tasks'))

# ✅ MANUAL SEND TELEGRAM (Corp) - Pointing to unified logic
@app.route('/corp-task/send-telegram/<id>', methods=['POST'])
@login_required
def corp_manual_send_telegram(id):
    return task_manual_send_telegram(id)

@app.route('/corp-task/request-action/<id>', methods=['POST'])
@login_required
def request_corp_action(id):
    action_type = request.form.get('action_type') # 'edit' hoặc 'delete'
    reason = request.form.get('reason', '')
    
    if action_type not in ['edit', 'delete']:
        return jsonify({"status": "error", "message": "Invalid action"}), 400
        
    db.corp_tasks.update_one(
        {"id": id},
        {"$set": {
            "admin_request": action_type,
            "request_reason": reason,
            "request_by": current_user.username,
            "updated_at": now_dt()
        }}
    )
    flash(f"Đã gửi yêu cầu {action_type} tới Admin", "info")
    return redirect(url_for('view_tasks'))

@app.route('/corp-task/update/<id>', methods=['POST'])
@login_required
def update_corp_task(id):
    t = db.corp_tasks.find_one({"id": id}) # ✅ Find task
    if not t or not can_edit_corp_task(t):
        flash("Bạn không có quyền chỉnh sửa task này", "danger")
        return redirect(url_for('view_tasks'))

    title = (request.form.get('title') or '').strip()
    
    # ✅ FIX: Handle Multiple Departments for Update
    departments = request.form.getlist('departments')
    single_dept = request.form.get('department')
    if not departments and single_dept:
        departments = [single_dept]
    department_display = ", ".join(departments)

    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    # ✅ NEW: Assignment logic based on role for updates
    assigned_to_oids = t.get("assigned_to", [])
    assignees = t.get("assignees", [])

    if current_user.role == SUPERADMIN_ROLE:
        # Superadmin can change assignees
        assigned_user_ids = request.form.getlist('assigned_user_ids')
        # If no assignees selected, clear them
        assigned_user_ids = request.form.getlist('assigned_user_ids')
        try:
            users = list(db.users.find({"_id": {"$in": [ObjectId(u) for u in assigned_user_ids]}}))
            assigned_to_oids = [u["_id"] for u in users]
            assignees = [u.get("username", "user") for u in users]
        except:
            assigned_to_oids = []
            assignees = []
    elif current_user.role == 'admin':
        # Admin cannot change assignees for corp tasks, only view
        pass
    else: # Regular user
        # Regular user cannot change assignees for corp tasks, only view
        pass

    upd = {
        "title": title,
        "departments": departments,       # ✅ Array
        "department": department_display, # ✅ String
        "assigned_to": assigned_to_oids,
        "assignees": assignees,
        "due_at": due_at,
        "updated_at": now_dt(),
        "admin_request": None, # Xóa trạng thái pending nếu có sau khi sửa
        "note": request.form.get('note', '') # ✅ Update note field
    }

    # Handle file upload
    if 'attachment' in request.files:
        f = request.files['attachment']
        if f.filename:
            filename = save_uploaded_file(f)
            if filename:
                upd["attachment"] = filename

    db.corp_tasks.update_one({"id": id}, {"$set": upd})
    flash("Cập nhật task thành công", "success")
    return redirect(url_for('view_tasks'))

@app.route('/corp-task/status/<id>', methods=['POST'])
@login_required
def update_corp_status(id):
    t = db.corp_tasks.find_one({"id": id})
    if not t:
        return jsonify({"status": "not_found"}), 404
    if not can_update_corp_status(t): # ✅ Check permission
        return jsonify({"status": "forbidden", "message": "No permission"}), 403

    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status")

    ok, msg = validate_corp_status_change(new_status, t)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400

    db.corp_tasks.update_one({"id": id}, {"$set": {"status": new_status, "updated_at": now_dt()}}) # ✅ Update status
    
    # ✅ SEND TELEGRAM NOTIFICATION TO CREATOR
    send_status_change_notification(t, new_status, "Corp Task")
    
    return jsonify({"status": "success"})

@app.route('/corp-task/delete/<id>', methods=['POST'])
@login_required
def delete_corp_task(id):
    if current_user.role in [SUPERADMIN_ROLE, "admin"]: db.corp_tasks.delete_one({"id": id}) # ✅ Admin/Superadmin can delete
    return redirect(url_for("view_tasks"))

@app.route('/corp-task/request-delete/<id>', methods=['POST'])
@login_required
def request_corp_delete(id):
    # This is legacy route, redirected to generic now if needed, but kept for compatibility
    return request_task_delete_generic(id)

# ---------------------------
# ✅ NEW: Department Tasks
# ---------------------------
@app.route('/department-task/add', methods=['POST'])
@login_required
def add_department_task():
    did = 'dept_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    title = (request.form.get('title') or '').strip()
    department = request.form.get('department')
    assigned_user_ids = request.form.getlist('assigned_user_ids')

    # ✅ Assignment logic for department tasks
    if current_user.role == SUPERADMIN_ROLE:
        # Superadmin can assign to anyone
        pass # No validation needed
    elif current_user.role in ['admin', 'user']:
        # Admin AND User can only create for their own department
        if department not in current_user.departments:
            flash(f"Bạn chỉ có thể tạo task cho các phòng ban của mình ({', '.join(current_user.departments)}).", "danger")
            return redirect(url_for('view_tasks'))
        
        # VALIDATE: All assignees must be in same department
        if assigned_user_ids:
            try:
                user_oids = [ObjectId(uid) for uid in assigned_user_ids]
                # Check if all assignees are in the target department
                assignee_users = list(db.users.find({"_id": {"$in": user_oids}}))
                for user in assignee_users:
                    if department not in user.get('departments', []):
                        flash(f"User {user.get('username')} không thuộc phòng ban {department}.", "danger")
                        return redirect(url_for('view_tasks'))
            except: pass

        # If no assignees selected, default to self
        if not assigned_user_ids: assigned_user_ids = [str(current_user.id)]

    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    if not title or department not in DEPARTMENT_TASK_DEPARTMENTS or not due_at:
        flash('Thiếu thông tin hoặc phòng ban không hợp lệ', 'danger')
        return redirect(url_for('view_tasks'))

    try:
        user_oids = [ObjectId(uid) for uid in assigned_user_ids]
        users = list(db.users.find({"_id": {"$in": user_oids}}))
        assignees = [u.get("username", "user") for u in users]
    except Exception as e:
        flash('Lỗi định dạng người dùng', 'danger')
        return redirect(url_for('view_tasks'))
    
    db.department_tasks.insert_one({
        "id": did,
        "title": title,
        "department": department,
        "assigned_to": [u["_id"] for u in users],
        "assignees": assignees,
        "assignee": assignees[0] if assignees else '---',
        "status": "todo",
        "due_at": due_at,
        "created_at": now_dt(),
        "updated_at": now_dt(),
        "assigned_by": current_user.username,
        "assigned_by_role": current_user.role,
        "assigned_at": now_dt(),
        "notify_pending": True,
        "note": request.form.get('note', ''),
        "attachment": save_uploaded_file(request.files.get('attachment'))
    })

    msg_text = (
        f"🔔 <b>NEW DEPARTMENT TASK</b>\n\n"
        f"📝 <b>Content:</b> {title}\n"
        f"🏢 <b>Dept:</b> {department}\n"
        f"👤 <b>By:</b> {current_user.username}\n"
        f"📅 <b>Deadline:</b> {due_at.strftime('%H:%M %d/%m/%Y')}"
    )
    for u in users:
        chat_id = u.get("telegram_chat_id")
        if chat_id:
            send_telegram_notification(chat_id, msg_text)

    flash('Đã tạo task phòng ban thành công', 'success')
    return redirect(url_for('view_tasks'))

# ✅ NEW: Department Task Telegram Notification - Pointing to unified logic
@app.route('/department-task/send-telegram/<id>', methods=['POST'])
@login_required
def department_manual_send_telegram(id):
    return task_manual_send_telegram(id)

@app.route('/department-task/update/<id>', methods=['POST'])
@login_required
def update_department_task(id):
    # This will be handled by the generic /task/update/<id> route
    pass

@app.route('/department-task/delete/<id>', methods=['POST'])
@login_required
def delete_department_task(id):
    if current_user.role in [SUPERADMIN_ROLE, "admin"]: # ✅ Admin/Superadmin can delete
        db.department_tasks.delete_one({"id": id})
    return redirect(url_for("view_tasks"))

# ---------------------------
# ✅ ROUTES: REQUESTS CUSTOMER (NEW FEATURE)
# ---------------------------
@app.route('/requests/customer')
@login_required
def view_customer_requests():
    """Giao diện danh sách yêu cầu n8n"""
    q = {}
    if request.args.get('search'):
        q["$or"] = [
            {"content": {"$regex": request.args.get('search'), "$options": "i"}},
            {"customer_name": {"$regex": request.args.get('search'), "$options": "i"}}
        ]
    requests_list = list(db.customer_requests.find(q).sort("created_at", -1)) # ✅ Filtered by current user in view_tasks
    
    # ✅ Pass Constants to Template for Dropdowns
    return render_template(
        'requests_customer.html', 
        requests=requests_list,
        request_statuses=REQUEST_STATUSES,
        business_types=BUSINESS_TYPES
    )

@app.route('/request/customer/add', methods=['POST'])
@login_required
def add_customer_request():
    """Thêm yêu cầu khách hàng thủ công"""
    content = (request.form.get("content") or "").strip()
    customer_name = (request.form.get("customer_name") or "").strip()
    
    # ✅ Get Full Fields
    note_val = request.form.get("note") or request.form.get("status") or "Request"
    business_type_form = request.form.get("business_type")
    
    if not content:
        flash("Nội dung không được để trống", "danger")
        return redirect(url_for("view_customer_requests"))

    customer_psid, norm_name = link_customer_for_task(customer_name)
    
    # ✅ Logic Business Type: Prefer Form > Auto-Detect > Default "New"
    business_type = "New"
    if business_type_form and business_type_form != "New":
        business_type = business_type_form
    elif customer_psid:
        lead = db.leads.find_one({"psid": customer_psid})
        if lead and lead.get('sector'):
            s = lead.get('sector')
            if s == 'Pod_Drop': business_type = "POD/Dropship"
            elif s == 'Warehouse': business_type = "Warehouse"
            elif s == 'Express': business_type = "Express"

    # ✅ NEW: Handle Assignee Checklist
    assigned_user_ids = request.form.getlist('assigned_user_ids')
    assigned_to = []
    assignees = []
    
    if assigned_user_ids:
        try:
            users = list(db.users.find({"_id": {"$in": [ObjectId(uid) for uid in assigned_user_ids]}}))
            assigned_to = [u["_id"] for u in users]
            assignees = [u.get("username", "user") for u in users]
        except: pass

    rid = 'req_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    db.customer_requests.insert_one({
        "id": rid,
        "content": content,
        "customer_name": norm_name or customer_name,
        "customer_psid": customer_psid,
        "app": "Manual",
        "status": "todo", # ✅ Default unified status
        "note": note_val, # ✅ Store old status as Note
        "business_type": business_type,
        "created_at": now_dt(),
        "assigned_by": current_user.username,
        "sender_name": current_user.username,
        "assigned_to": assigned_to, # ✅ List[ObjectId]
        "assignees": assignees,      # ✅ List[str]
        "assignee": assignees[0] if assignees else None,
        "attachment": save_uploaded_file(request.files.get('attachment')) # ✅ Add Attachment
    })
    
    # ✅ AUTO SEND TELEGRAM (Notify Assignees)
    if assigned_to:
        msg_text = (
            f"🔔 <b>NEW REQUEST ASSIGNED</b>\n\n"
            f"📝 <b>Content:</b> {content}\n"
            f"👤 <b>Customer:</b> {norm_name or customer_name or 'N/A'}\n"
            f"👤 <b>By:</b> {current_user.username}\n"
            f"📋 <b>Type:</b> {business_type}"
        )
        users = list(db.users.find({"_id": {"$in": assigned_to}}))
        for u in users:
            if u.get("telegram_chat_id"):
                send_telegram_notification(u.get("telegram_chat_id"), msg_text)
    
    flash("Request created successfully", "success")
    return redirect(url_for("view_tasks", type='request')) # ✅ Redirect to tasks view

@app.route('/request/customer/detail/<id>')
@login_required
def view_customer_request_detail(id):
    """Xem chi tiết và chỉnh sửa Customer Request (giống Task Detail)"""
    req = db.customer_requests.find_one({"id": id})
    if not req:
        flash("Request not found", "danger")
        return redirect(url_for("view_customer_requests"))
        
    # ✅ FIX: Pass full user objects for checklist, not just names
    users_list = list(db.users.find({}, {"username": 1, "_id": 1}))
    
    return render_template(
        'request_detail.html', 
        req=req,
        request_statuses=REQUEST_STATUSES,
        business_types=BUSINESS_TYPES,
        statuses=UNIFIED_STATUSES,
        users_list=users_list # ✅ Pass list of user dicts
    )

@app.route('/request/customer/update/<id>', methods=['POST'])
@login_required
def update_customer_request(id):
    """API update thông tin request (JSON)"""
    req = db.customer_requests.find_one({"id": id})
    if not req: return jsonify({"status": "not_found"}), 404
    
    data = request.get_json()
    upd = {"updated_at": now_dt()}
    
    if 'content' in data: upd['content'] = data['content']
    if 'customer_name' in data: 
        # Nếu đổi tên khách hàng, thử link lại PSID
        c_name = data['customer_name']
        upd['customer_name'] = c_name
        customer_psid, _ = link_customer_for_task(c_name)
        if customer_psid: upd['customer_psid'] = customer_psid
        
    if 'status' in data:
        if data['status'] in UNIFIED_STATUSES:
            upd['status'] = data['status']

    if 'note' in data:
        upd['note'] = data['note']

    if 'business_type' in data:
        if data['business_type'] in BUSINESS_TYPES:
            upd['business_type'] = data['business_type']
            
    # ✅ NEW: Update Result
    if 'result' in data:
        upd['result'] = data['result']

    # ✅ NEW: Update Assignee (Checklist List)
    if 'assigned_user_ids' in data:
        ids = data['assigned_user_ids']
        if isinstance(ids, list):
            try:
                users = list(db.users.find({"_id": {"$in": [ObjectId(uid) for uid in ids]}}))
                upd['assigned_to'] = [u["_id"] for u in users]
                upd['assignees'] = [u["username"] for u in users]
                # Fallback single assignee for legacy compat
                upd['assignee'] = users[0]["username"] if users else None
            except: pass

    db.customer_requests.update_one({"id": id}, {"$set": upd})
    return jsonify({"status": "success"})

@app.route('/request/customer/delete/<id>', methods=['POST'])
@login_required
def delete_customer_request(id):
    """Xóa yêu cầu (Chỉ Admin/Superadmin)"""
    # ✅ FIX: Allow Superadmin to delete
    if current_user.role in [SUPERADMIN_ROLE, 'admin']:
        db.customer_requests.delete_one({"id": id})
    return redirect(url_for('view_tasks', type='request')) # ✅ Redirect to unified view with 'request' filter

# ---------------------------
# ✅ API: EXTERNAL (n8n Integration)
# ---------------------------
@app.route('/api/external/task', methods=['POST'])
def add_external_task():
    """API cho n8n bắn dữ liệu về - Lưu vào Customer Requests HOẶC Personal Tasks"""
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {app.config['SECRET_KEY']}":
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    # ✅ SAFETY 1: Force Parse JSON
    data = request.get_json(force=True, silent=True) or {}
    if not data: 
        return jsonify({"status": "error", "message": "No data"}), 400

    content = data.get('content', '')
    raw_customer_name = data.get('customer_name', '')
    sender_name = str(data.get('sender_name') or 'Unknown').strip()
    
    # ✅ LOGIC MAPPING 2 CHIỀU: INT & STR
    sender_id_raw = data.get('sender_id')
    
    source_app = data.get('app', 'Tele')
    internal_user = None

    if source_app == 'Tele' and sender_id_raw:
        # Case 1: Thử tìm theo String (Chuẩn mới)
        try:
            sid_str = str(sender_id_raw).strip()
            if sid_str and sid_str.lower() != 'none':
                internal_user = db.users.find_one({"telegram_chat_id": sid_str})
        except Exception:
            pass

        # Case 2: Nếu chưa thấy, thử tìm theo Integer (Chuẩn cũ/Lỗi n8n)
        if not internal_user:
            try:
                sid_int = int(sender_id_raw)
                internal_user = db.users.find_one({"telegram_chat_id": sid_int})
            except Exception:
                pass
    
    # ✅ Case 3: Fallback - Tìm theo Username (Nếu ID không khớp hoặc chưa cập nhật)
    if not internal_user and sender_name and sender_name != 'Unknown':
        # Tìm chính xác username (case-insensitive)
        internal_user = db.users.find_one({"username": {"$regex": f"^{re.escape(sender_name)}$", "$options": "i"}})

    # ✅ TÍNH NĂNG MỚI: Nếu map được User -> Tạo Personal Task
    if internal_user:
        ptid = 'ptask_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        db.personal_tasks.insert_one({
            "id": ptid,
            "title": content, # Content từ Tele -> Title của task
            "description": f"Auto-created from Telegram ({sender_name}). Customer: {raw_customer_name}",
            "status": "todo",
            "due_at": None, # Chưa có deadline
            "user_id": internal_user["_id"], # Assign cho chính user đó
            "created_at": now_dt(),
            "updated_at": now_dt(),
            "notify_pending": False,
            "missed_notify_pending": False,
            "source": "telegram" # Đánh dấu nguồn
        })
        return jsonify({"status": "success", "type": "personal_task", "id": ptid})

    # Nếu không map được User -> Tạo Customer Request như cũ
    customer_psid, norm_name = link_customer_for_task(raw_customer_name)
    
    # ✅ Auto-detect Business Type (Loại hình kinh doanh)
    business_type = "New"
    if customer_psid:
        lead = db.leads.find_one({"psid": customer_psid})
        if lead and lead.get('sector'):
            s = lead.get('sector')
            if s == 'Pod_Drop': business_type = "POD/Dropship"
            elif s == 'Warehouse': business_type = "Warehouse"
            elif s == 'Express': business_type = "Express"

    rid = 'req_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    db.customer_requests.insert_one({
        "id": rid,
        "content": content,
        "customer_name": norm_name or raw_customer_name,
        "customer_psid": customer_psid,
        "app": source_app,
        "status": "Request", # Default status
        "business_type": business_type, # New field
        "created_at": now_dt(),
        "assigned_by": f"{sender_name} ({source_app})",
        "sender_name": sender_name
    })
    
    return jsonify({
        "status": "success", 
        "type": "customer_request",
        "id": rid
    })

# ---------------------------
# ROUTES: ADMIN USER MANAGEMENT
# ---------------------------
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role not in [SUPERADMIN_ROLE, 'admin']: # ✅ Only admin/superadmin can view
        return redirect(url_for('index'))

    # ✅ FILTER: Admin only sees users in their own department
    query = {}
    if current_user.role == 'admin':
        query["departments"] = {"$in": current_user.departments}

    users = []
    for u in db.users.find(query):
        uo = User(u) # This now has .departments
        uid = u["_id"]
        p1 = db.tasks.count_documents({"assigned_to": uid, "status": {"$ne": "Done"}})
        p2 = db.personal_tasks.count_documents({"user_id": uid, "status": {"$ne": "done"}})
        p4 = db.department_tasks.count_documents({"assigned_to": {"$in": [uid]}, "status": {"$ne": "done"}}) # ✅ NEW: Department task count
        p3 = db.corp_tasks.count_documents({"assigned_to": {"$in": [uid]}, "status": {"$ne": "Done"}})
        uo.pending_tasks = p1 + p2 + p3 + p4 # ✅ Sum all task types
        users.append(uo)

    return render_template('user.html', users=users, departments=USER_DEPARTMENTS)

@app.route('/admin/user/add', methods=['POST'])
@login_required
def admin_add_user():
    # ✅ FIX: Allow Superadmin to add users
    if current_user.role not in [SUPERADMIN_ROLE, 'admin']:
        return redirect(url_for('index'))
        
    u = request.form.get('username')
    p = request.form.get('password')
    depts = request.form.getlist('departments')
    
    # ✅ VALIDATE: Admin can only add users to their department
    if current_user.role == 'admin' and not set(depts).issubset(set(current_user.departments)):
        flash(f'Admin chỉ được tạo user trong các phòng ban mình quản lý.', 'danger')
        return redirect(url_for('admin_users'))

    if not u or not p:
        flash('Thiếu username hoặc password', 'danger')
        return redirect(url_for('admin_users'))
        
    if db.users.find_one({"username": u}):
        flash('Username đã tồn tại!', 'danger')
        return redirect(url_for('admin_users'))
        
    db.users.insert_one({ # ✅ Default role is 'user'
        "username": u,
        "password_hash": generate_password_hash(p),
        "role": "user",
        "departments": depts,
        "created_at": now_dt()
    })
    flash(f'Tạo user {u} thành công', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/detail/<user_id>')
@login_required
def admin_user_detail(user_id):
    if current_user.role not in [SUPERADMIN_ROLE, 'admin']: # ✅ Only admin/superadmin can view
        return redirect(url_for('index'))

    uid = ObjectId(user_id)
    u = db.users.find_one({"_id": uid})
    if not u:
        return redirect(url_for('admin_users'))
    
    # ✅ VALIDATE: Admin can only see details of their dept users
    if current_user.role == 'admin' and not set(u.get('departments', [])).intersection(set(current_user.departments)):
        flash("Bạn không có quyền xem user này (không chung phòng ban).", "danger")
        return redirect(url_for('admin_users'))

    task_q = {"assigned_to": uid}
    tasks = list(db.tasks.find(task_q).sort("updated_at", -1))
    
    # ✅ STRICT PRIVACY: Only show personal tasks if viewing own profile
    personal_tasks = []
    if uid == ObjectId(current_user.id):
         ptask_q = {"user_id": uid}
         personal_tasks = list(db.personal_tasks.find(ptask_q).sort("updated_at", -1))
    
    corp_q = {"assigned_to": {"$in": [uid]}}
    corp_tasks = list(db.corp_tasks.find(corp_q).sort("updated_at", -1))
    
    dept_q = {"$or": [{"assigned_to": {"$in": [uid]}}, {"department": {"$in": u.get("departments", [])}}]} # ✅ NEW: Department tasks for user
    department_tasks = list(db.department_tasks.find(dept_q).sort("updated_at", -1))

    # Calculate Breakdown Stats for Display & Chart
    stats_tasks = {
        "total": len(tasks),
        "done": sum(1 for t in tasks if t.get('status') == 'done'),
        "not_yet": sum(1 for t in tasks if t.get('status') not in ['done', 'cancelled']),
        "overdue": sum(1 for t in tasks if t.get('status') == 'overdue')
    }
    
    stats_personal = {
        "total": len(personal_tasks),
        "done": sum(1 for t in personal_tasks if t.get('status') == 'done'),
        "not_yet": sum(1 for t in personal_tasks if t.get('status') not in ['done', 'cancelled']),
        "overdue": sum(1 for t in personal_tasks if t.get('status') == 'overdue')
    }
    
    stats_corp = {
        "total": len(corp_tasks),
        "done": sum(1 for t in corp_tasks if t.get('status') == 'done'),
        "not_yet": sum(1 for t in corp_tasks if t.get('status') not in ['done', 'cancelled']),
        "overdue": sum(1 for t in corp_tasks if t.get('status') == 'overdue')
    }
    # ✅ NEW: Department task stats
    stats_department = {
        "total": len(department_tasks),
        "done": sum(1 for t in department_tasks if t.get('status') == 'done'),
        "not_yet": sum(1 for t in department_tasks if t.get('status') not in ['done', 'cancelled']),
        "overdue": sum(1 for t in department_tasks if t.get('status') == 'overdue')
    }

    # Consolidated Chart Data
    chart_data = {
        "breakdown": [stats_tasks['total'], stats_corp['total'], stats_personal['total'], stats_department['total']], # ✅ Add department to breakdown
        "status": [
            stats_tasks['done'] + stats_personal['done'] + stats_corp['done'] + stats_department['done'],
            (stats_tasks['not_yet'] + stats_personal['not_yet'] + stats_corp['not_yet'] + stats_department['not_yet']),
            (stats_tasks['overdue'] + stats_personal['overdue'] + stats_corp['overdue'] + stats_department['overdue'])
        ]
    }

    stats = {
        "total": stats_tasks["total"] + stats_personal["total"] + stats_corp["total"],
        "done": stats_tasks["done"] + stats_personal["done"] + stats_corp["done"],
        "not_yet": stats_tasks["not_yet"] + stats_personal["not_yet"] + stats_corp["not_yet"],
        "overdue": stats_tasks["overdue"] + stats_personal["overdue"] + stats_corp["overdue"] + stats_department["overdue"],
    }

    task_breakdown = {
        "customer": stats_tasks,
        "department": stats_department, # ✅ NEW: Department task breakdown
        "personal": stats_personal,
        "corp": stats_corp
    }

    return render_template(
        'user_detail.html',
        staff=u,
        stats=stats,
        tasks=tasks,
        department_tasks=department_tasks, # ✅ Pass department tasks
        personal_tasks=personal_tasks,
        corp_tasks=corp_tasks,
        task_breakdown=task_breakdown,
        departments=USER_DEPARTMENTS,
        chart_data=chart_data
    )


@app.route('/admin/user/update_role/<user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != SUPERADMIN_ROLE: # ✅ Only superadmin can change roles
        return redirect(url_for('index'))

    # prevent self role change if needed (optional)
    if ObjectId(user_id) == ObjectId(current_user.id):
        return redirect(url_for('admin_users'))

    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": request.form.get('role')}})
    return redirect(url_for('admin_users'))

@app.route('/admin/user/update_departments/<user_id>', methods=['POST'])
@login_required
def update_user_departments(user_id):
    # ✅ RESTRICT: ONLY SUPERADMIN CAN UPDATE DEPARTMENT
    if current_user.role != SUPERADMIN_ROLE: 
        flash("Chỉ Superadmin mới có quyền đổi phòng ban.", "danger")
        return redirect(url_for('admin_users'))

    new_depts = request.form.getlist('departments')
    db.users.update_one(
        {"_id": ObjectId(user_id)}, 
        {"$set": {"departments": new_depts}}
    )
    flash(f"Đã cập nhật phòng ban cho user.", "success")
    return redirect(url_for('admin_user_detail', user_id=user_id))

# ✅ NEW: Admin Update Telegram ID
@app.route('/admin/user/update-telegram/<user_id>', methods=['POST'])
@login_required
def admin_update_user_telegram(user_id):
    if current_user.role not in [SUPERADMIN_ROLE, 'admin']: return redirect(url_for('index')) # ✅ Only admin/superadmin
    tid = (request.form.get('telegram_id') or '').strip()
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"telegram_chat_id": tid}})
    flash("Cập nhật Telegram ID thành công", "success")
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role not in [SUPERADMIN_ROLE, 'admin']: # ✅ Only admin/superadmin
        return redirect(url_for('index'))

    if ObjectId(user_id) != ObjectId(current_user.id):
        db.users.delete_one({"_id": ObjectId(user_id)})
    return redirect(url_for('admin_users'))

# ---------------------------
# ROUTES: UTILITIES
# ---------------------------
@app.route('/api/notifications')
@login_required
def api_notifications():
    me = ObjectId(current_user.id)
    t1 = list(db.tasks.find({"assigned_to": me, "notify_pending": True, "status": {"$ne": "done"}}).sort("assigned_at", -1).limit(10))
    t2 = list(db.corp_tasks.find({"assigned_to": me, "notify_pending": True, "status": {"$ne": "done"}}).sort("assigned_at", -1).limit(10))
    t3 = list(db.personal_tasks.find({"user_id": me, "notify_pending": True, "status": {"$ne": "done"}}).sort("created_at", -1).limit(5))
    t4 = list(db.department_tasks.find({"assigned_to": me, "notify_pending": True, "status": {"$ne": "done"}}).sort("assigned_at", -1).limit(5)) # ✅ NEW: Department task notifications
    
    res = []
    for x in t1: res.append({"id": x.get("id"), "kind": "task", "todo_content": x.get("todo_content"), "customer_name": x.get("customer_name"), "assigned_by": x.get("assigned_by"), "assigned_at": x.get("assigned_at").strftime("%d/%m %H:%M") if x.get("assigned_at") else "", "due_at": x.get("due_at").strftime("%d/%m %H:%M") if x.get("due_at") else ""})
    for x in t2: res.append({"id": x.get("id"), "kind": "corp", "todo_content": f"[{x.get('department')}] {x.get('title')}", "customer_name": "", "assigned_by": x.get("assigned_by"), "assigned_at": x.get("assigned_at").strftime("%d/%m %H:%M") if x.get("assigned_at") else "", "due_at": x.get("due_at").strftime("%d/%m %H:%M") if x.get("due_at") else ""})
    for x in t3: res.append({"id": x.get("id"), "kind": "personal", "todo_content": x.get("title"), "customer_name": "", "assigned_by": "Self", "assigned_at": x.get("created_at").strftime("%d/%m %H:%M"), "due_at": x.get("due_at").strftime("%d/%m %H:%M") if x.get("due_at") else ""})
    
    return jsonify({"items": res})

@app.route('/api/notifications/ack', methods=['POST'])
@login_required
def api_notifications_ack():
    ids = request.get_json().get("ids", [])
    if not ids: return jsonify({"status": "no_ids"})
    me = ObjectId(current_user.id)
    now = now_dt()
    db.tasks.update_many({"id": {"$in": ids}, "assigned_to": me}, {"$set": {"notify_pending": False, "notified_at": now}})
    db.corp_tasks.update_many({"id": {"$in": ids}, "assigned_to": me}, {"$set": {"notify_pending": False, "notified_at": now}})
    db.personal_tasks.update_many({"id": {"$in": ids}, "user_id": me}, {"$set": {"notify_pending": False}}) # ✅ Acknowledge personal tasks
    db.department_tasks.update_many({"id": {"$in": ids}, "assigned_to": me}, {"$set": {"notify_pending": False, "notified_at": now}}) # ✅ Acknowledge department tasks
    return jsonify({"status": "success"})

@app.route('/api/admin/missed')
@login_required
def api_admin_missed():
    if current_user.role not in [SUPERADMIN_ROLE, "admin"]: return jsonify({"items": []}) # ✅ Admin/Superadmin can view
    items = list(db.tasks.find({"status": "Missed", "missed_notify_pending": True}).sort("missed_at", -1).limit(20))
    return jsonify({"items": [{"id": x.get("id"), "todo_content": x.get("todo_content"), "assignee": x.get("assignee"), "due_at": x.get("due_at").strftime("%d/%m %H:%M") if x.get("due_at") else ""} for x in items]})

@app.route('/api/admin/missed/ack', methods=['POST'])
@login_required
def api_admin_missed_ack():
    # ✅ FIX: SUPERADMIN CAN ACK
    if current_user.role not in [SUPERADMIN_ROLE, "admin"]: return jsonify({"status": "forbidden"})
    db.tasks.update_many({"id": {"$in": request.get_json().get("ids", [])}}, {"$set": {"missed_notify_pending": False, "missed_notified_at": now_dt()}})
    return jsonify({"status": "success"})

@app.route('/api/admin/corp-requests')
@login_required
def api_admin_corp_requests(): # ✅ Admin/Superadmin can view
    # ✅ FIX: SUPERADMIN CAN VIEW REQUESTS
    if current_user.role not in [SUPERADMIN_ROLE, 'admin']: return jsonify({"items": []})
    reqs = list(db.corp_tasks.find({"admin_request": {"$ne": None}}))
    return jsonify({"items": [{"id": r.get("id"), "title": r.get("title"), "request_type": r.get("admin_request"), "reason": r.get("request_reason"), "user": r.get("request_by")} for r in reqs]})

@app.route('/sync-status')
@login_required
def sync_status(): return jsonify({"last_sync": LAST_SYNC_TIMESTAMP})

@app.route('/sync-now')
@login_required
def sync_now():
    init_pancake_pages(True)
    pancake_sync_task()
    sync_all_lark_task()
    sync_lark_tasks_task()
    return redirect(request.referrer)

@app.route('/webhook/lark', methods=['POST'])
def lark_webhook():
    d = request.json
    return jsonify({"challenge": d.get("challenge")}) if d and "challenge" in d else jsonify({"status": "ok"})

@app.route('/broadcast')
@login_required
def broadcast_page(): return render_template('broadcast.html')

@app.route('/api/broadcast/pages')
@login_required
def api_broadcast_pages():
    """Lấy danh sách Pages từ Pancake - sử dụng đúng cấu trúc API response"""
    try:
        res = requests.get(f"{BASE_URL}/pages", params={"access_token": PANCAKE_USER_TOKEN}, timeout=30)
        if res.status_code == 200:
            # ✅ FIX: Pancake trả về categorized.activated + categorized.inactivated, không phải pages
            cat = res.json().get("categorized", {})
            pages = cat.get("activated", []) + cat.get("inactivated", [])
            return jsonify({"pages": pages})
        else:
            log_to_file(f"[BROADCAST] Failed to fetch pages: {res.status_code} - {res.text[:200]}")
            return jsonify({"error": "Failed to fetch pages", "status": res.status_code}), 400
    except Exception as e:
        log_to_file(f"[BROADCAST] Exception fetching pages: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/broadcast/conversations/<page_id>')
@login_required
def api_broadcast_conversations(page_id):
    """Lấy danh sách conversations từ một Page để broadcast"""
    try:
        # 1. Lấy page access token 
        tr = requests.post(
            f"{BASE_URL}/pages/{page_id}/generate_page_access_token", 
            params={"access_token": PANCAKE_USER_TOKEN}, 
            timeout=30
        )
        if tr.status_code != 200:
            log_to_file(f"[BROADCAST] Token failed for page {page_id}: {tr.status_code}")
            return jsonify({"error": "Token failed", "detail": tr.text[:200]}), 400
            
        ptk = tr.json().get("page_access_token")
        if not ptk:
            return jsonify({"error": "No page_access_token in response"}), 400
        
        # 2. Lấy conversations
        cr = requests.get(
            f"{PUBLIC_V2}/pages/{page_id}/conversations", 
            params={"page_access_token": ptk, "type": "INBOX"},
            timeout=30
        )
        if cr.status_code != 200:
            log_to_file(f"[BROADCAST] Conversations failed for page {page_id}: {cr.status_code}")
            return jsonify({"error": "Conv failed", "detail": cr.text[:200]}), 400
            
        return jsonify({
            "conversations": cr.json().get("conversations", []), 
            "page_token": ptk
        })
    except Exception as e:
        log_to_file(f"[BROADCAST] Exception in conversations: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/broadcast/send', methods=['POST'])
@login_required
def api_broadcast_send():
    pid, ptk, cids, msg = request.form.get('page_id'), request.form.get('page_token'), request.form.getlist('ids[]'), request.form.get('message')
    img = request.files.get('image')
    c_ids = []
    if img:
        ur = requests.post(f"{PUBLIC_V1}/pages/{pid}/upload_contents", params={"page_access_token": ptk}, files={"file": (img.filename, img.read(), img.content_type)})
        if ur.status_code == 200: c_ids = [ur.json().get("id")]
    
    cnt = 0
    for cid in cids:
        pl = {"action": "reply_inbox", "message": msg}
        if c_ids: pl.update({"content_ids": c_ids, "attachment_type": "PHOTO"})
        if requests.post(f"{PUBLIC_V1}/pages/{pid}/conversations/{cid}/messages", params={"page_access_token": ptk}, json=pl).status_code == 200: cnt += 1
        time.sleep(1)
    return jsonify({"success": cnt, "total": len(cids)})

# ---------------------------
# ROUTES: TOOLS (PRICING LOGIC)
# ---------------------------
@app.route('/tools/pricing')
@login_required
def view_pricing_tool():
    """Giao diện Pricing Tool"""
    return render_template('pricing.html')

@app.route('/tools/pricing/calculate_all', methods=['POST'])
@login_required
def pricing_calculate_all():
    """Tính cước cho toàn bộ danh sách import"""
    try:
        data = request.json.get('data', [])
        mode = request.json.get('mode', '')  # ✅ Get mode from frontend
        if not data: return jsonify({"status": "error", "message": "No data"}), 400
        
        # 1. Lấy file bảng giá mới nhất
        latest_pt = db.price_tables.find_one(sort=[("uploaded_at", -1)])
        if not latest_pt:
            return jsonify({"status": "error", "message": "Missing Price Table"}), 404
            
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], latest_pt['filename'])
        if not os.path.exists(file_path):
            return jsonify({"status": "error", "message": "Price Table File Lost"}), 404

        # ✅ Detect mode if not provided (check if CN characters in filename)
        is_cn_mode = 'china' in mode.lower() or 'cn' in mode.lower() or '云途' in latest_pt.get('filename', '')
        
        # 2. Build Index: Scan ALL sheets for Transport Code
        sheet_index = index_price_table(file_path)
        sheet_cache = {} 
        results = []
        
        for row in data:
            # ✅ Clean up and get input values
            clean_row = {str(k).strip(): v for k, v in row.items()}
            
            # Get simplified input columns (Service, Country, Weight)
            service_val = str(clean_row.get('Service', '')).strip()
            country_val = str(clean_row.get('Country', clean_row.get('Quốc gia', ''))).strip()
            weight_val = clean_row.get('Weight', clean_row.get('Cân nặng', 0))
            
            # ✅ AUTO-GENERATE SERVICE CODE: Service-Country-Weight
            generated_service_code = f"{service_val}-{country_val}-{weight_val}"
            
            # ✅ Use 'Service' column to lookup price sheet
            service_code = service_val
            
            row_normalized = {
                'Quốc gia': country_val,
                'Cân nặng': weight_val,
                'SERVICE CODE': service_code
            }
            
            freight = "N/A"
            reg_fee = "N/A"
            transit_time = "N/A"
            
            # Find Sheet Info from Index
            sheet_info = sheet_index.get(service_code)
            
            if sheet_info:
                xml_path = sheet_info['sheet_xml']
                sheet_name = sheet_info['sheet_name']
                
                # Load Sheet Data (Cached)
                if sheet_name not in sheet_cache:
                    df = read_xlsx_sheet_native(file_path, xml_path)
                    sheet_cache[sheet_name] = df
                
                df = sheet_cache[sheet_name]
                if not df.empty:
                    # Calculate Price
                    freight, reg_fee = calculate_price_for_row(row_normalized, df)
                    
                    # ✅ Get Transit Time based on mode
                    if is_cn_mode:
                        tt = get_transit_time_cn(df, country_val)
                        if tt:
                            # ✅ Normalize Chinese -> BSD
                            transit_time = tt.replace('工作日', ' BSD').replace('天', ' BSD')
                        else:
                            transit_time = "N/A"
                    else:
                        transit_time = get_transit_time_vn(df, country_val)
                else:
                    freight = "Lỗi Sheet"
            else:
                freight = "Mã DV không khớp"
                log_to_file(f"Code '{service_code}' not found in index. Available keys: {list(sheet_index.keys())[:5]}...")
            
            # ✅ Build result row with all required columns
            new_row = {
                'Service': service_val,
                'Country': country_val,
                'Weight': weight_val,
                'SERVICE CODE': generated_service_code,
                'Transit Time': transit_time,
                'Cước chính': freight,
                'Phí đăng ký': reg_fee
            }
            
            # ✅ Preserve extra columns BUT exclude legacy/duplicate ones
            exclude_keys = [
                'Service', 'Country', 'Weight', 'SERVICE CODE', 'Transit Time', 'Cước chính', 'Phí đăng ký', # Standard keys
                'Quốc gia', 'Cân nặng', 'Tg vận chuyển' # Legacy keys to remove
            ]
            
            for k, v in row.items():
                if k not in exclude_keys:
                    new_row[k] = v
            results.append(new_row)
        
        return jsonify({"status": "success", "data": results})
        
    except Exception as e:
        log_to_file(f"Pricing Calculation Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tools/pricing/export', methods=['POST'])
@login_required
def export_pricing_results():
    """Xuất danh sách đã tính toán ra file Excel/CSV"""
    try:
        data = request.json.get('data', [])
        if not data: return jsonify({"status": "error", "message": "No data"}), 400
        
        df = pd.DataFrame(data)

        df.insert(0, 'STT', range(1, 1 + len(df)))

        desired_cols = [
            'STT', 'Service', 'Country', 'Weight', 'SERVICE CODE',
            'Transit Time', 'Cước chính', 'Phí đăng ký'
        ]

        final_cols = [col for col in desired_cols if col in df.columns]
        other_cols = [col for col in df.columns if col not in final_cols]
        
        df_export = df[final_cols + other_cols]
        
        output = io.BytesIO()
        df_export.to_csv(output, index=False, encoding='utf-8-sig')
        output.seek(0)
        
        return send_file(
            output, 
            download_name=f"Pricing_Results_{now_dt().strftime('%Y%m%d_%H%M')}.csv", 
            as_attachment=True, 
            mimetype='text/csv'
        )
    except Exception as e:
        log_to_file(f"Pricing Export Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tools/pricing/history')
@login_required
def get_pricing_history():
    """API để lấy danh sách lịch sử tính giá."""
    try:
        items = pricing_history.list_latest(limit=50)
        for item in items:
            item['_id'] = str(item['_id'])
            if 'created_by' in item and item['created_by']:
                item['created_by'] = str(item['created_by'])
            if item.get('created_at'):
                item['created_at'] = item['created_at'].isoformat()
        return jsonify({"status": "success", "items": items})
    except Exception as e:
        log_to_file(f"Pricing History Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tools/pricing/history/<history_id>')
@login_required
def get_pricing_history_detail(history_id):
    """API để lấy chi tiết một lần tính giá."""
    try:
        item = pricing_history.get_by_id(history_id)
        if not item:
            return jsonify({"status": "error", "message": "History not found"}), 404
        
        item['_id'] = str(item['_id'])
        if item.get('created_by'):
            item['created_by'] = str(item['created_by'])
        if item.get('created_at'):
            item['created_at'] = item['created_at'].isoformat()

        return jsonify({"status": "success", "item": item})
    except Exception as e:
        log_to_file(f"Pricing History Detail Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tools/pricing/history/save', methods=['POST'])
@login_required
def save_pricing_history():
    """API để người dùng chủ động lưu kết quả vào lịch sử."""
    try:
        data = request.json.get('data', [])
        mode = request.json.get('mode', 'Unknown')
        name = request.json.get('name')
        if not data:
            return jsonify({"status": "error", "message": "No data to save"}), 400
        
        pricing_history.create(
            data=data, 
            mode=mode,
            user_id=ObjectId(current_user.id),
            name=name
        )
        return jsonify({"status": "success", "message": "Saved to history."})
    except Exception as e:
        log_to_file(f"Pricing History Save Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tools/pricing/formulas')
@login_required
def get_pricing_formulas():
    formulas = list(db.pricing_formulas.find({}))
    for f in formulas:
        f['_id'] = str(f['_id'])
        if 'user_id' in f and f.get('user_id'):
            f['user_id'] = str(f['user_id'])
        if 'updated_at' in f and isinstance(f.get('updated_at'), datetime):
            f['updated_at'] = f['updated_at'].isoformat()
    return jsonify({"status": "success", "formulas": formulas})

@app.route('/tools/pricing/formulas/save', methods=['POST'])
@login_required
def save_pricing_formula():
    data = request.json
    name = data.get('name')
    formula_str = data.get('formula')
    if not name or not formula_str:
        return jsonify({"status": "error", "message": "Name and formula are required"}), 400
    
    db.pricing_formulas.update_one(
        {"name": name},
        {"$set": {
            "name": name,
            "formula": formula_str,
            "user_id": ObjectId(current_user.id),
            "updated_at": now_dt()
        }},
        upsert=True
    )
    return jsonify({"status": "success", "message": "Formula saved"})

@app.route('/tools/pricing/formulas/delete/<formula_id>', methods=['POST'])
@login_required
def delete_pricing_formula(formula_id):
    result = db.pricing_formulas.delete_one({"_id": ObjectId(formula_id)})
    return jsonify({"status": "success"}) if result.deleted_count > 0 else (jsonify({"status": "error"}), 404)

@app.route('/tools/pricing/history/delete/<history_id>', methods=['POST'])
@login_required
def delete_pricing_history(history_id):
    try:
        success = pricing_history.delete_by_id(history_id)
        if success:
            return jsonify({"status": "success", "message": "History deleted."})
        else:
            return jsonify({"status": "error", "message": "History not found or could not be deleted."}), 404
    except Exception as e:
        log_to_file(f"Pricing History Delete Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/tools/pricing/download-template')
@login_required
def download_template():
    df = pd.DataFrame(columns=['Service', 'Country', 'Weight'])
    df.loc[0] = ['YTYCPREG', 'US', '0.5']
    
    output = io.BytesIO()
    df.to_csv(output, index=False, encoding='utf-8-sig')
    output.seek(0)
    
    return send_file(
        output, 
        download_name='pricing_template.csv', 
        as_attachment=True, 
        mimetype='text/csv'
    )

@app.route('/upload_data', methods=['POST'])
@login_required
def upload_data():
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file uploaded"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"}), 400
        
    if file:
        filename = save_uploaded_file(file)
        if not filename:
            return jsonify({"success": False, "message": "Save file failed"}), 500
            
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            if filename.lower().endswith('.csv'):
                try:
                    df = pd.read_csv(filepath, encoding='utf-8-sig')
                except UnicodeDecodeError:
                    try:
                        df = pd.read_csv(filepath, encoding='utf-8')
                    except UnicodeDecodeError:
                        df = pd.read_csv(filepath, encoding='latin1')
                except Exception as e:
                     return jsonify({"success": False, "message": f"Lỗi đọc CSV: {str(e)}"}), 400
            else:
                try:
                    df = pd.read_excel(filepath)
                except Exception:
                    mapping = get_sheet_mapping_native(filepath)
                    if mapping:
                        first_sheet = list(mapping.values())[0]
                        df = read_xlsx_sheet_native(filepath, first_sheet)
                        
                        if not df.empty and len(df) > 0:
                            df.columns = df.iloc[0].astype(str).str.strip()
                            df = df[1:].reset_index(drop=True)
                    else:
                        df = None
                        
                    if df is None or df.empty:
                         return jsonify({"success": False, "message": "Không thể đọc file Excel (Lỗi thư viện). Vui lòng thử lại với file .CSV."}), 400
            
            df.columns = df.columns.str.strip()
            df = df.fillna('')
            data = df.to_dict('records')
            return jsonify({"success": True, "data": data})
        except Exception as e:
            return jsonify({"success": False, "message": f"Lỗi xử lý file: {str(e)}"}), 500
            
    return jsonify({"success": False, "message": "Unknown error"}), 500

@app.route('/upload_price_table', methods=['POST'])
@login_required
def upload_price_table():
    if 'file' not in request.files: return jsonify({"success": False, "message": "No file"}), 400
    file = request.files['file']
    if file.filename == '': return jsonify({"success": False, "message": "No name"}), 400
    
    filename = save_uploaded_file(file)
    if not filename: return jsonify({"success": False, "message": "Save failed"}), 500

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        if filename.lower().endswith('.csv'):
             xl = None
             sheet_names = ['Main']
        else:
            try:
                xl = pd.ExcelFile(filepath)
                sheet_names = xl.sheet_names
            except Exception:
                sheet_names = get_xlsx_sheet_names_native(filepath)
        
        db.price_tables.insert_one({
            "filename": filename,
            "original_name": file.filename,
            "uploaded_by": current_user.username,
            "uploaded_at": now_dt(),
            "sheets": sheet_names
        })
        
        return jsonify({"success": True, "message": "Upload thành công", "sheets": sheet_names})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    if db.users.count_documents({"username": "admin"}) == 0:
        db.users.insert_one({
            "username": "admin",
            "password_hash": generate_password_hash('admin123'),
            "role": SUPERADMIN_ROLE, # ✅ First user is superadmin
            "department": "Vận Hành", 
            "created_at": now_dt()
        })
    
    # ✅ Auto-create specific superadmin user
    if db.users.count_documents({"username": "superadmin"}) == 0:
        db.users.insert_one({
            "username": "superadmin",
            "password_hash": generate_password_hash('supaeradmin123'),
            "role": SUPERADMIN_ROLE,
            "department": "Vận Hành",
            "created_at": now_dt()
        })
        print("Created superadmin/superadmin123")

    init_pancake_pages(True)

    if not scheduler.running:
        scheduler.add_job(id='p_sync', func=pancake_sync_task, trigger='interval', hours=24)  # ✅ Changed to daily
        scheduler.add_job(id='l_leads', func=sync_all_lark_task, trigger='interval', hours=24)  # ✅ Changed to daily
        # scheduler.add_job(id='l_tasks', func=sync_lark_tasks_task, trigger='interval', seconds=60)
        
        # ✅ Unified auto overdue scheduler
        scheduler.add_job(id='auto_overdue', func=auto_scan_overdue_tasks, trigger='interval', seconds=60)
        
        scheduler.start()
        
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)