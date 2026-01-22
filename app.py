from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_apscheduler import APScheduler
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import User
from services.pancake import PancakeService
from datetime import datetime
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests, time, random, string, re
import uuid
import os
from dotenv import load_dotenv
load_dotenv()

# --- THIRD PARTY CONFIG ---
# Load Config from .env
PANCAKE_USER_TOKEN = os.getenv("PANCAKE_USER_TOKEN")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

BASE_URL = "https://pages.fm/api/v1"
PUBLIC_V1 = "https://pages.fm/api/public_api/v1"
PUBLIC_V2 = "https://pages.fm/api/public_api/v2"

# ✅ TELEGRAM API URL
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

app = Flask(__name__)

# --- APP CONFIG ---
MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"
client = MongoClient(MONGO_URI)
db = client.CRM_Production
app.config['SECRET_KEY'] = 'crm_thg_ultimate_2025_secure_final_v5'

# --- UPLOAD CONFIG ---
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

login_manager = LoginManager()
login_manager.user_loader(lambda uid: User(db.users.find_one({"_id": ObjectId(uid)})) if db.users.find_one({"_id": ObjectId(uid)}) else None)
login_manager.login_view = 'login'
login_manager.login_message = None
login_manager.init_app(app)

# --- LARK CONFIG ---
LARK_APP_ID, LARK_APP_SECRET = "cli_a87a40a3d6b85010", "wFMNBqGMhcuZsyNDZVAnYgOv6XuZyAqn"
LARK_APP_TOKEN, LARK_TABLE_ID = "Vqfqbm1Lda7vdVsvABQlk8KSgog", "tblEUCxBUVUUDt4R"
LARK_TASK_APP_TOKEN, LARK_TASK_TABLE_ID = "Ajhqblaj9aT34JsuQ8PlTi7xgZe", "tblKknj4Pp8HStO9"

scheduler = APScheduler()
LAST_SYNC_TIMESTAMP = time.time()

# ---------------------------
# CONSTANTS: Departments + Status
# ---------------------------
USER_DEPARTMENTS = ["Vận Hành", "Marketing", "Kế toán", "CSKH/Sale", "Nhân sự"]
CORP_DEPARTMENTS = ["Vận Hành", "Marketing", "Kế toán", "Nhân sự", "CSKH/Sale", "Ngoại giao"]

CORP_STATUSES = ["Unreceived", "Received", "In_progress", "Pending_approval", "Done", "Cancelled"]
CORP_STATUS_LABELS = {
    "Unreceived": "Chưa nhận task",
    "Received": "Đã nhận task",
    "In_progress": "Đang làm",
    "Pending_approval": "Đang chờ duyệt",
    "Done": "Done",
    "Cancelled": "Cancelled",
}

# ---------------------------
# HELPERS
# ---------------------------
def now_dt():
    return datetime.now()

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
            print(f"Error saving file: {e}")
            return None
    return None

# ✅ TELEGRAM HELPER BASIC
def send_telegram_notification(chat_id, text):
    if not chat_id or not TELEGRAM_BOT_TOKEN: 
        return False
    try:
        payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
        requests.post(TELEGRAM_API_URL, json=payload, timeout=5)
        return True
    except Exception as e:
        print(f"[TELEGRAM] Error: {e}")
        return False

# ✅ NEW: NOTIFY CREATOR ON STATUS CHANGE
def send_status_change_notification(task_doc, new_status, task_type="Task"):
    """Gửi thông báo cho người tạo khi status thay đổi (nếu người sửa khác người tạo)"""
    try:
        creator = None
        # Xác định người tạo dựa trên loại task
        if task_type == "Corp Task":
            # Corp task lưu username người tạo trong assigned_by (string) hoặc tìm theo logic cũ
            creator_name = task_doc.get("assigned_by")
            if creator_name:
                creator = db.users.find_one({"username": creator_name})
        else:
            # Normal task lưu user_id (ObjectId) là người tạo
            user_id = task_doc.get("user_id")
            if user_id:
                creator = db.users.find_one({"_id": user_id})

        # Chỉ gửi nếu tìm thấy creator, có chat_id và người sửa KHÁC người tạo
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
        print(f"[TELEGRAM] Status notify error: {e}")

def find_any_task(tid):
    t = db.tasks.find_one({"id": tid})
    if t: return t, 'tasks'
    t = db.corp_tasks.find_one({"id": tid})
    if t: return t, 'corp_tasks'
    t = db.personal_tasks.find_one({"id": tid})
    if t: return t, 'personal_tasks'
    return None, None

# --- Logic Helpers ---
def is_overdue(task_doc):
    due = task_doc.get("due_at")
    return bool(due and isinstance(due, datetime) and due < now_dt())

def mark_missed(task_id: str, reason: str = "auto"):
    t = db.tasks.find_one({"id": task_id})
    if not t: return
    if t.get("status") == "Done": return
    db.tasks.update_one({"id": task_id}, {
        "$set": {
            "status": "Missed", "missed_at": now_dt(), "updated_at": now_dt(),
            "miss_reason": reason, "missed_notify_pending": True
        }
    })

def link_customer_for_task(customer_name: str):
    if not customer_name: return None, None
    name = customer_name.strip()
    if not name: return None, None
    lead = db.leads.find_one({"full_name": {"$regex": f"^{re.escape(name)}$", "$options": "i"}})
    if lead: return lead.get("psid"), lead.get("full_name")
    lead = db.leads.find_one({"full_name": {"$regex": re.escape(name), "$options": "i"}}, sort=[("updated_at", -1)])
    if lead: return lead.get("psid"), lead.get("full_name")
    return None, None

def can_user_quick_update(task_doc):
    if current_user.role == "admin": return True
    me = ObjectId(current_user.id)
    return task_doc.get("user_id") == me or task_doc.get("assigned_to") == me

def allowed_next_status(task_doc):
    if is_overdue(task_doc) and task_doc.get("status") != "Done": return "Missed"
    if task_doc.get("status") == "Not_yet": return "Done"
    return "Not_yet" # Toggle back

def next_personal_status(cur):
    if cur == "Not_yet": return "Done"
    if cur == "Done": return "Missed"
    return "Not_yet"

def auto_mark_personal_tasks():
    now = now_dt()
    overdue = db.personal_tasks.find({"status": "Not_yet", "due_at": {"$ne": None, "$lt": now}})
    for t in overdue:
        db.personal_tasks.update_one({"id": t["id"]}, {"$set": {"status": "Missed", "updated_at": now, "missed_notify_pending": True}})

def can_update_corp_status(corp_task):
    if current_user.role == "admin": return True
    assigned = corp_task.get("assigned_to")
    if isinstance(assigned, ObjectId): return ObjectId(current_user.id) == assigned
    if isinstance(assigned, list): return ObjectId(current_user.id) in assigned
    return False

def can_edit_corp_task(corp_task):
    if current_user.role == "admin": return True
    assigned = corp_task.get("assigned_to", [])
    if isinstance(assigned, list): return ObjectId(current_user.id) in assigned
    return ObjectId(current_user.id) == assigned

def validate_corp_status_change(new_status: str, corp_task):
    if new_status not in CORP_STATUSES: return False, "Invalid status"
    if new_status == "Cancelled" and current_user.role != "admin": return False, "Only admin can cancel"
    return True, ""

# ---------------------------
# SYNC LOGIC (Pancake & Lark)
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
            db.leads.update_one({"psid": item.get('record_id')}, {"$set": {
                "full_name": f.get('Tên khách hàng'), "phone_number": f.get('Link FB/username tele'),
                "sector": classify_sector(f), "status": f.get('Trạng thái', 'Khách Mới'),
                "page_id": "LARK_AUTO", "source_platform": "Lark", "updated_at": now_dt()
            }}, upsert=True)
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
                db.leads.update_one({"psid": l['psid']}, {"$set": {
                    "full_name": l['name'], "phone_number": l['phone'], "sector": l['sector'],
                    "status": l['status'], "page_id": p["id"], "page_username": p["username"],
                    "conversation_id": l.get('conversation_id'), "source_platform": "Pancake", "updated_at": now_dt()
                }}, upsert=True)
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

def auto_mark_missed_tasks():
    now = now_dt()
    overdue = list(db.tasks.find({"status": "Not_yet", "due_at": {"$ne": None, "$lt": now}}, {"id": 1}))
    for t in overdue: mark_missed(t.get("id"), reason="auto_deadline")

# ---------------------------
# ROUTES: AUTH
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p, dept = request.form.get('username'), request.form.get('password'), request.form.get('department')
        if db.users.find_one({"username": u}):
            flash('Username exists!', 'danger')
            return redirect(url_for('register'))
        role = 'admin' if db.users.count_documents({}) == 0 else 'user'
        db.users.insert_one({"username": u, "password_hash": generate_password_hash(p), "role": role, "department": dept, "created_at": now_dt()})
        return redirect(url_for('login'))
    return render_template('register.html', departments=USER_DEPARTMENTS)

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
        "personal_tasks": db.personal_tasks.count_documents({"user_id": ObjectId(current_user.id),"status": {"$ne": "Done"}})
    }

    # ✅ NEW: Calculate Tasks per User (For Graph)
    # Tổng hợp từ bảng tasks (Customer Task) và corp_tasks (Company Task)
    user_task_stats = []
    # ✅ Lấy thêm trường department
    all_users = list(db.users.find({}, {"username": 1, "_id": 1, "department": 1}))
    
    for u in all_users:
        uid = u["_id"]
        uid_str = str(uid)
        
        # ✅ FIX MẠNH: Truy vấn bằng cả ObjectId VÀ String
        # Để đảm bảo bắt dính dù lưu kiểu gì
        
        # 1. Normal Tasks (Customer Tasks)
        cus_done = db.tasks.count_documents({"assigned_to": {"$in": [uid, uid_str]}, "status": "Done"})
        cus_not = db.tasks.count_documents({"assigned_to": {"$in": [uid, uid_str]}, "status": {"$ne": "Done"}})
        
        # 2. Corp Tasks (Company Tasks) - assigned_to có thể là mảng
        # Lưu ý: $in hoạt động tốt với mảng, nó sẽ check xem assigned_to (dù là đơn hay mảng) có chứa uid/uid_str không
        corp_done = db.corp_tasks.count_documents({"assigned_to": {"$in": [uid, uid_str]}, "status": "Done"})
        # ✅ FIX: Đếm tất cả trạng thái KHÔNG PHẢI Done và KHÔNG PHẢI Cancelled
        corp_not = db.corp_tasks.count_documents({
            "assigned_to": {"$in": [uid, uid_str]}, 
            "status": {"$nin": ["Done", "Cancelled"]}
        })
        
        # ✅ IMPORTANT: TRẢ VỀ CÁC KEY RIÊNG BIỆT CHO CHART
        # ✅ Force ép kiểu int để JSON serialize không bị lỗi
        user_task_stats.append({
            "id": str(uid),
            "username": u.get("username", "Unknown"),
            "department": u.get("department", "Other"),
            "cus_done": int(cus_done),
            "cus_not": int(cus_not),
            "corp_done": int(corp_done),
            "corp_not": int(corp_not),
            "done": int(cus_done + corp_done),
            "not_done": int(cus_not + corp_not)
        })

    # ✅ DEBUG LOG: In ra console server để kiểm tra dữ liệu
    print(f"📊 [DEBUG CHART DATA] Count: {len(user_task_stats)}")
    for x in user_task_stats:
        # Chỉ in ra nếu có dữ liệu để tránh spam log
        if x['cus_done'] > 0 or x['cus_not'] > 0 or x['corp_done'] > 0 or x['corp_not'] > 0:
            print(f"User: {x['username']} | CusDone: {x['cus_done']} | CusNot: {x['cus_not']} | CorpDone: {x['corp_done']}")

    # ✅ Truyền danh sách phòng ban cho filter
    return render_template('pages.html', stats=stats, user_task_stats=user_task_stats, departments=USER_DEPARTMENTS)

# ✅ User tự update Telegram ID
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
    
    # ✅ MODE: VIEW MY LEADS (User Role Filter)
    if request.args.get('mode') == 'mine':
        q["assigned_to"] = ObjectId(current_user.id)
        
    leads = list(db.leads.find(q).sort("updated_at", -1))

    # ✅ PREPARE DATA FOR ASSIGNMENT DROPDOWNS
    users_list = []
    if current_user.role == 'admin':
        users_list = list(db.users.find({}, {"username": 1, "_id": 1}))

    # ✅ USER MAP FOR DISPLAY
    user_map = {u['_id']: u['username'] for u in db.users.find({}, {"username": 1, "_id": 1})}
    
    return render_template('leads.html', sector_name=name, sector_id=name, leads=leads, user_map=user_map, users_list=users_list)

# ✅ NEW: API Gán Lead (Cho Admin & User tự nhận/hủy)
@app.route('/customer/assign/<psid>', methods=['POST'])
@login_required
def assign_lead(psid):
    lead = db.leads.find_one({"psid": psid})
    if not lead:
        return jsonify({"status": "error", "message": "Lead not found"}), 404
        
    new_assignee_id = request.form.get('assigned_user_id')
    
    # LOGIC:
    # 1. Admin can assign to anyone.
    # 2. CSKH/Sale can claim (assign to self) if unassigned, or if allowed.
    
    action_ok = False
    
    if current_user.role == 'admin':
        if new_assignee_id:
            db.leads.update_one({"psid": psid}, {"$set": {"assigned_to": ObjectId(new_assignee_id), "updated_at": now_dt()}})
        else:
            # Unassign
             db.leads.update_one({"psid": psid}, {"$unset": {"assigned_to": ""}, "$set": {"updated_at": now_dt()}})
        action_ok = True
        
    elif current_user.department == 'CSKH/Sale' or current_user.role == 'user':
        # Self claim
        if new_assignee_id == str(current_user.id):
            db.leads.update_one({"psid": psid}, {"$set": {"assigned_to": ObjectId(current_user.id), "updated_at": now_dt()}})
            action_ok = True
        # ✅ NEW: Self unclaim (Cancel Claim)
        # Chỉ cho phép hủy nếu lead đang được gán cho chính user này
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
    n_q = {"customer_psid": psid}
    if current_user.role != 'admin':
        t_q = {"$and": [t_q, {"$or": [{"user_id": ObjectId(current_user.id)}, {"assigned_to": ObjectId(current_user.id)}]}]}
        n_q["user_id"] = ObjectId(current_user.id)
    
    # ✅ PASS USERS LIST FOR ASSIGNMENT (Admin & All)
    # We pass it to all because we might want to show names or allow claim
    users_list = list(db.users.find({}, {"username": 1, "_id": 1}))
        
    return render_template('customer.html', lead=lead, tasks=list(db.tasks.find(t_q).sort("created_at", -1)), notes=list(db.notes.find(n_q).sort("created_at", -1)), users_list=users_list)

@app.route('/customer/update/<psid>', methods=['POST'])
@login_required
def update_customer(psid):
    upd = {k: v for k, v in request.form.items() if v}
    upd['updated_at'] = now_dt()
    
    # Handle 'assigned_to' update from Customer Detail
    if 'assigned_to' in upd:
        val = upd['assigned_to']
        if val:
            upd['assigned_to'] = ObjectId(val)
        else:
            # If empty string passed, unset it (need special handling for update_one logic or just ignore if standard form)
            # The standard logic below will set assigned_to="" if using form loop, which is bad for ObjectId.
            # Specialized handling:
            pass 
            
    # Fix ObjectId for assigned_to if it came from the loop above as string
    if 'assigned_to' in upd and isinstance(upd['assigned_to'], str):
         upd['assigned_to'] = ObjectId(upd['assigned_to'])
         
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
    status = request.form.get("status") or "Not_yet"
    
    raw_deadline = request.form.get("deadline") or request.form.get("time_log")
    due_at = parse_due_at(raw_deadline) if (raw_deadline and "T" in raw_deadline) else None
    legacy_time_log = raw_deadline if not due_at else None

    assigned_to_oid = ObjectId(current_user.id)
    assignee_name = current_user.username

    if current_user.role == "admin":
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
    q = {} if current_user.role == 'admin' else {"$or": [{"user_id": ObjectId(current_user.id)}, {"assigned_to": ObjectId(current_user.id)}]}
    if request.args.get('search'): q["$or"] = [{"todo_content": {"$regex": request.args.get('search'), "$options": "i"}}, {"customer_name": {"$regex": request.args.get('search'), "$options": "i"}}]
    if request.args.get('status'): q["status"] = request.args.get('status')
    return render_template('tasks.html', tasks=list(db.tasks.find(q).sort("updated_at", -1)), users_list=list(db.users.find({}, {"username": 1, "_id": 1})) if current_user.role == 'admin' else [])

@app.route('/task/add', methods=['POST'])
@login_required
def add_task():
    aid = request.form.get('assigned_user_id') or current_user.id
    target = db.users.find_one({"_id": ObjectId(aid)})
    
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))
    customer_psid, norm_name = link_customer_for_task(request.form.get('customer_name'))
    
    assigned_to_oid = ObjectId(aid)
    is_assigned = assigned_to_oid != ObjectId(current_user.id)
    
    db.tasks.insert_one({
        "id": 'task_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),
        "todo_content": request.form.get('todo_content'), "customer_name": norm_name or request.form.get('customer_name'),
        "customer_psid": customer_psid, "assignee": target['username'] if target else '---', "assigned_to": assigned_to_oid,
        "status": "Not_yet", "due_at": due_at, "deadline": due_at, "user_id": ObjectId(current_user.id),
        "created_at": now_dt(), "updated_at": now_dt(), "notify_pending": is_assigned,
        "assigned_by": current_user.username, "assigned_by_role": current_user.role,
        "assigned_at": now_dt() if is_assigned else None, "missed_notify_pending": False,
        "attachment": save_uploaded_file(request.files.get('attachment'))
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

# ✅ NEW: Route gửi Telegram thủ công cho Normal Task
@app.route('/task/send-telegram/<id>', methods=['POST'])
@login_required
def task_manual_send_telegram(id):
    t = db.tasks.find_one({"id": id})
    if not t: return jsonify({"status": "not_found"}), 404
    
    assigned_to = t.get("assigned_to")
    target_user = None
    
    if assigned_to:
        target_user = db.users.find_one({"_id": assigned_to})

    if target_user and target_user.get("telegram_chat_id"):
        msg_text = (
            f"🔔 <b>TASK REMINDER</b>\n\n"
            f"📝 <b>Content:</b> {t.get('todo_content')}\n"
            f"👤 <b>Customer:</b> {t.get('customer_name') or 'N/A'}\n"
            f"👤 <b>By:</b> {t.get('assigned_by') or 'Unknown'}\n"
            f"📅 <b>Deadline:</b> {t.get('due_at').strftime('%H:%M %d/%m/%Y') if t.get('due_at') else 'None'}"
        )
        if send_telegram_notification(target_user.get("telegram_chat_id"), msg_text):
            flash(f"Đã gửi thông báo đến {target_user.get('username')}.", "success")
        else:
            flash("Gửi thất bại. Kiểm tra Bot.", "danger")
    else:
        flash("Người được giao chưa cập nhật Telegram ID.", "warning")
        
    return redirect(url_for('view_tasks'))

@app.route('/task/update/<id>', methods=['POST'])
@login_required
def update_task_detail(id):
    task, col_name = find_any_task(id)
    if not task:
        if request.is_json: return jsonify({"status": "error", "message": "Task not found"}), 404
        return redirect(url_for('view_tasks'))
    
    if request.is_json:
        data = request.get_json()
        upd = {"updated_at": now_dt()}
        if col_name == 'tasks':
            upd.update({"todo_content": data.get('todo_content'), "customer_name": data.get('customer_name')})
        elif col_name in ['corp_tasks', 'personal_tasks']:
            upd["title"] = data.get('todo_content')
        if 'due_at' in data: upd['due_at'] = parse_due_at(data['due_at'])
        db[col_name].update_one({"id": id}, {"$set": upd})
        return jsonify({"status": "success"})

    upd = {"status": request.form.get('status'), "due_at": parse_due_at(request.form.get('due_at')), "updated_at": now_dt()}
    
    if col_name == 'tasks':
        upd.update({"todo_content": request.form.get('todo_content'), "customer_name": request.form.get('customer_name')})
        if current_user.role == 'admin' and request.form.get('assigned_user_id'):
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

@app.route('/task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_task(id):
    t = db.tasks.find_one({"id": id})
    if not t or not can_user_quick_update(t): return jsonify({"status": "error"}), 403
    nst = allowed_next_status(t)
    upd = {"status": nst, "updated_at": now_dt()}
    if nst == "Missed": upd.update({"missed_at": now_dt(), "missed_notify_pending": True})
    db.tasks.update_one({"id": id}, {"$set": upd})
    
    # ✅ SEND TELEGRAM NOTIFICATION TO CREATOR
    send_status_change_notification(t, nst, "Customer Task")
    
    return jsonify({"status": "success", "next": nst})

@app.route('/task/detail/<id>')
@login_required
def view_task_detail_page(id):
    task, col_name = find_any_task(id)
    if not task: return redirect(url_for('view_tasks'))
    
    task['is_normal_task'] = (col_name == 'tasks')
    if col_name == 'corp_tasks':
        task.update({'todo_content': task.get('title'), 'customer_name': task.get('department','Corp'), 'assignee': ", ".join(task.get('assignees', [])) or "---"})
    elif col_name == 'personal_tasks':
        task.update({'todo_content': task.get('title'), 'customer_name': "Personal Task", 'assignee': "Me"})
    
    # Permission Check
    me = ObjectId(current_user.id)
    has_perm = False
    if current_user.role == 'admin': has_perm = True
    elif col_name == 'tasks' and (task.get('user_id') == me or task.get('assigned_to') == me): has_perm = True
    elif col_name == 'personal_tasks' and task.get('user_id') == me: has_perm = True
    elif col_name == 'corp_tasks':
        assigned = task.get('assigned_to', [])
        if isinstance(assigned, list) and me in assigned: has_perm = True
        elif assigned == me: has_perm = True
            
    if not has_perm: return redirect(url_for('view_tasks'))
    return render_template('task_detail.html', task=task)

@app.route('/task/detail/upload/<id>', methods=['POST'])
@login_required
def upload_task_file_detail(id):
    task, col_name = find_any_task(id)
    if task and 'attachment' in request.files:
        f = save_uploaded_file(request.files['attachment'])
        if f: db[col_name].update_one({"id": id}, {"$set": {"attachment": f, "updated_at": now_dt()}})
    return redirect(url_for('view_task_detail_page', id=id))

@app.route('/task/delete/<id>', methods=['POST'])
@login_required
def delete_task(id):
    t = db.tasks.find_one({"id": id})
    if not t:
        return redirect(url_for('view_tasks'))

    if current_user.role == "admin":
        db.tasks.delete_one({"id": id})
        return redirect(request.referrer or url_for('view_tasks'))

    # user rule:
    # - allow delete only if user is creator
    # - but forbid if task was assigned by admin
    me = ObjectId(current_user.id)
    if t.get("user_id") != me:
        return redirect(request.referrer or url_for('view_tasks'))

    if t.get("assigned_by_role") == "admin":
        flash("Bạn không thể xoá task do admin phân bổ.", "danger")
        return redirect(request.referrer or url_for('view_tasks'))

    db.tasks.delete_one({"id": id})
    return redirect(request.referrer or url_for('view_tasks'))

# ---------------------------
# ROUTES: PERSONAL TASKS
# ---------------------------
@app.route('/personal-tasks')
@login_required
def view_personal_tasks():
    q = {"user_id": ObjectId(current_user.id)}
    if request.args.get('status'): q["status"] = request.args.get('status')
    if request.args.get('search'): q["title"] = {"$regex": request.args.get('search'), "$options": "i"}
    return render_template("personal_tasks.html", tasks=list(db.personal_tasks.find(q).sort("updated_at", -1)))

@app.route('/personal-task/add', methods=['POST'])
@login_required
def add_personal_task():
    title = (request.form.get("title") or "").strip()
    if not title: return redirect(url_for("view_personal_tasks"))
    db.personal_tasks.insert_one({
        "id": 'ptask_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8)),
        "title": title, "description": request.form.get("description"), "status": "Not_yet",
        "due_at": parse_due_at(request.form.get("due_at")), "user_id": ObjectId(current_user.id),
        "created_at": now_dt(), "updated_at": now_dt(), "notify_pending": False, "missed_notify_pending": False,
        "attachment": save_uploaded_file(request.files.get('attachment'))
    })
    return redirect(url_for("view_personal_tasks"))

@app.route('/personal-task/quick-update/<id>', methods=['POST'])
@login_required
def quick_update_personal_task(id):
    t = db.personal_tasks.find_one({"id": id, "user_id": ObjectId(current_user.id)})
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
@login_required
def view_corp_tasks():
    dept = request.args.get('dept', '').strip()
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()

    q = {}
    if current_user.role != 'admin':
        q["assigned_to"] = {"$in": [ObjectId(current_user.id)]}

    if dept:
        q["department"] = dept
    if status:
        q["status"] = status
    if search:
        q["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"assignees": {"$regex": search, "$options": "i"}},
            {"department": {"$regex": search, "$options": "i"}}
        ]

    corp_tasks = list(db.corp_tasks.find(q).sort("updated_at", -1))

    # ===== NORMALIZE TASK DATA (UI) =====
    for t in corp_tasks:
        if isinstance(t.get("assigned_to"), ObjectId):
            t["assigned_to"] = [t["assigned_to"]]

        if "assignees" not in t:
            t["assignees"] = [t["assignee"]] if t.get("assignee") else []

    users_list = list(db.users.find({}, {"username": 1, "_id": 1}))

    # ===== SERIALIZE FOR CHART (NO ObjectId) =====
    corp_tasks_chart = []
    for t in corp_tasks:
        corp_tasks_chart.append({
            "id": t.get("id"),
            "title": t.get("title"),
            "department": t.get("department"),
            "status": t.get("status"),
        })

    return render_template(
        'corp_tasks.html',
        corp_tasks=corp_tasks,                
        corp_tasks_chart=corp_tasks_chart,     
        corp_departments=CORP_DEPARTMENTS,
        corp_statuses=CORP_STATUSES,
        corp_status_labels=CORP_STATUS_LABELS,
        users_list=users_list
    )


@app.route('/corp-task/add', methods=['POST'])
@login_required
def add_corp_task():
    # Tạo ID ngẫu nhiên cho task
    cid = 'corp_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    title = (request.form.get('title') or '').strip()
    department = request.form.get('department')
    
    # LẤY DANH SÁCH NGƯỜI ĐƯỢC GÁN (Mở cho tất cả các Role)
    assigned_user_ids = request.form.getlist('assigned_user_ids')
    
    # Nếu là User thường mà không chọn ai, thì mặc định tự gán cho mình
    if not assigned_user_ids:
        assigned_user_ids = [str(current_user.id)]

    # Parse thời hạn
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    # Kiểm tra dữ liệu đầu vào
    if not title or department not in CORP_DEPARTMENTS or not due_at:
        flash('Thiếu thông tin hoặc phòng ban không hợp lệ', 'danger')
        return redirect(url_for('view_corp_tasks'))

    # Xử lý OID và lấy tên hiển thị
    try:
        # Chuyển string ID thành ObjectId, bọc trong try-except để tránh crash nếu ID lỗi
        user_oids = [ObjectId(uid) for uid in assigned_user_ids]
        users = list(db.users.find({"_id": {"$in": user_oids}}))
        
        assignees = [u.get("username", "user") for u in users]
    except Exception as e:
        flash('Lỗi định dạng người dùng', 'danger')
        return redirect(url_for('view_corp_tasks'))
    
    # Handle file upload
    attachment_filename = None
    if 'attachment' in request.files:
        attachment_filename = save_uploaded_file(request.files['attachment'])

    # Lưu vào Database
    db.corp_tasks.insert_one({
        "id": cid,
        "title": title,
        "department": department,
        "assigned_to": [u["_id"] for u in users], # Lưu mảng OID
        "assignees": assignees,                   # Lưu mảng tên để hiển thị nhanh
        "assignee": assignees[0] if assignees else '---',
        "status": "Unreceived",
        "due_at": due_at,
        "created_at": now_dt(),
        "updated_at": now_dt(),
        "assigned_by": current_user.username,
        "assigned_by_role": current_user.role,
        "assigned_at": now_dt(),
        "notify_pending": True,
        "admin_request": None,
        "attachment": attachment_filename
    })

    # ✅ AUTO SEND TELEGRAM
    msg_text = (
        f"🔔 <b>NEW TASK ASSIGNED</b>\n\n"
        f"📝 <b>Content:</b> {title}\n"
        f"🏢 <b>Dept:</b> {department}\n"
        f"👤 <b>By:</b> {current_user.username}\n"
        f"📅 <b>Deadline:</b> {due_at.strftime('%H:%M %d/%m/%Y')}"
    )
    for u in users:
        chat_id = u.get("telegram_chat_id")
        if chat_id:
            send_telegram_notification(chat_id, msg_text)

    flash('Đã tạo task công ty thành công', 'success')
    return redirect(url_for('view_corp_tasks'))

# ✅ MANUAL SEND TELEGRAM (Corp)
@app.route('/corp-task/send-telegram/<id>', methods=['POST'])
@login_required
def corp_manual_send_telegram(id):
    t = db.corp_tasks.find_one({"id": id})
    if not t: return jsonify({"status": "not_found"}), 404
    
    assigned_to = t.get("assigned_to", [])
    if isinstance(assigned_to, ObjectId): assigned_to = [assigned_to]
    
    users = list(db.users.find({"_id": {"$in": assigned_to}}))
    count = 0
    msg_text = (
        f"🔔 <b>TASK REMINDER</b>\n\n"
        f"📝 <b>Content:</b> {t.get('title')}\n"
        f"🏢 <b>Dept:</b> {t.get('department')}\n"
        f"👤 <b>By:</b> {t.get('assigned_by')}\n"
        f"📅 <b>Deadline:</b> {t.get('due_at').strftime('%H:%M %d/%m/%Y') if t.get('due_at') else 'None'}"
    )
    
    for u in users:
        if u.get("telegram_chat_id"):
            if send_telegram_notification(u.get("telegram_chat_id"), msg_text): count += 1
    
    if count > 0: flash(f"Đã gửi thông báo đến {count} người.", "success")
    else: flash("Không tìm thấy Telegram ID của người nhận.", "warning")
    return redirect(url_for('view_corp_tasks'))

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
    return redirect(url_for('view_corp_tasks'))

@app.route('/corp-task/update/<id>', methods=['POST'])
@login_required
def update_corp_task(id):
    t = db.corp_tasks.find_one({"id": id})
    if not t or not can_edit_corp_task(t):
        flash("Bạn không có quyền chỉnh sửa task này", "danger")
        return redirect(url_for('view_corp_tasks'))

    title = (request.form.get('title') or '').strip()
    department = request.form.get('department')
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    # ✅ FIXED: Correct variable naming (assigned_user_ids instead of uids)
    if current_user.role == 'admin':
        assigned_user_ids = request.form.getlist('assigned_user_ids')
        try:
            users = list(db.users.find({"_id": {"$in": [ObjectId(u) for u in assigned_user_ids]}}))
            assigned_to_oids = [u["_id"] for u in users]
            assignees = [u.get("username", "user") for u in users]
        except:
            assigned_to_oids = []
            assignees = []
    else:
        assigned_to_oids = t.get("assigned_to")
        assignees = t.get("assignees")

    upd = {
        "title": title,
        "department": department,
        "assigned_to": assigned_to_oids,
        "assignees": assignees,
        "due_at": due_at,
        "updated_at": now_dt(),
        "admin_request": None # Xóa trạng thái pending nếu có sau khi sửa
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
    return redirect(url_for('view_corp_tasks'))

@app.route('/corp-task/status/<id>', methods=['POST'])
@login_required
def update_corp_status(id):
    t = db.corp_tasks.find_one({"id": id})
    if not t:
        return jsonify({"status": "not_found"}), 404
    if not can_update_corp_status(t):
        return jsonify({"status": "forbidden", "message": "No permission"}), 403

    payload = request.get_json(silent=True) or {}
    new_status = payload.get("status")

    ok, msg = validate_corp_status_change(new_status, t)
    if not ok:
        return jsonify({"status": "error", "message": msg}), 400

    db.corp_tasks.update_one({"id": id}, {"$set": {"status": new_status, "updated_at": now_dt()}})
    
    # ✅ SEND TELEGRAM NOTIFICATION TO CREATOR
    send_status_change_notification(t, new_status, "Corp Task")
    
    return jsonify({"status": "success"})

@app.route('/corp-task/delete/<id>', methods=['POST'])
@login_required
def delete_corp_task(id):
    if current_user.role == "admin": db.corp_tasks.delete_one({"id": id})
    return redirect(url_for("view_corp_tasks"))

@app.route('/corp-task/request-delete/<id>', methods=['POST'])
@login_required
def request_corp_delete(id):
    db.corp_tasks.update_one({"id": id}, {"$set": {"admin_request": "delete", "request_reason": request.form.get('reason'), "request_by": current_user.username, "updated_at": now_dt()}})
    flash("Đã gửi yêu cầu xóa", "info")
    return redirect(url_for('view_corp_tasks'))

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
    requests_list = list(db.customer_requests.find(q).sort("created_at", -1))
    return render_template('requests_customer.html', requests=requests_list)

@app.route('/request/customer/delete/<id>', methods=['POST'])
@login_required
def delete_customer_request(id):
    """Xóa yêu cầu (Chỉ Admin)"""
    if current_user.role == 'admin':
        db.customer_requests.delete_one({"id": id})
    return redirect(url_for('view_customer_requests'))

# ---------------------------
# ✅ API: EXTERNAL (n8n Integration)
# ---------------------------
@app.route('/api/external/task', methods=['POST'])
def add_external_task():
    """API cho n8n bắn dữ liệu về - Lưu vào Customer Requests"""
    auth_header = request.headers.get('Authorization')
    if auth_header != f"Bearer {app.config['SECRET_KEY']}":
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    
    data = request.json
    if not data: return jsonify({"status": "error", "message": "No data"}), 400
    
    content = data.get('content', '')
    raw_customer_name = data.get('customer_name', '')
    source_app = data.get('app', 'Tele')
    
    customer_psid, norm_name = link_customer_for_task(raw_customer_name)
    rid = 'req_' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    db.customer_requests.insert_one({
        "id": rid,
        "content": content,
        "customer_name": norm_name or raw_customer_name,
        "customer_psid": customer_psid,
        "app": source_app,
        "created_at": now_dt(),
        "assigned_by": f"n8n ({source_app})"
    })
    return jsonify({"status": "success", "id": rid})

# ---------------------------
# ROUTES: ADMIN USER MANAGEMENT
# ---------------------------
@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    users = []
    for u in db.users.find():
        uo = User(u)
        uid = u["_id"]
        p1 = db.tasks.count_documents({"assigned_to": uid, "status": {"$ne": "Done"}})
        p2 = db.personal_tasks.count_documents({"user_id": uid, "status": {"$ne": "Done"}})
        p3 = db.corp_tasks.count_documents({"assigned_to": {"$in": [uid]}, "status": {"$ne": "Done"}})
        uo.pending_tasks = p1 + p2 + p3
        users.append(uo)

    return render_template('user.html', users=users, departments=USER_DEPARTMENTS)

@app.route('/admin/user/add', methods=['POST'])
@login_required
def admin_add_user():
    if current_user.role != 'admin':
        return redirect(url_for('index'))
        
    u = request.form.get('username')
    p = request.form.get('password')
    dept = request.form.get('department')
    
    if not u or not p:
        flash('Thiếu username hoặc password', 'danger')
        return redirect(url_for('admin_users'))
        
    if db.users.find_one({"username": u}):
        flash('Username đã tồn tại!', 'danger')
        return redirect(url_for('admin_users'))
        
    db.users.insert_one({
        "username": u,
        "password_hash": generate_password_hash(p),
        "role": "user",
        "department": dept, # ✅ Fix: d -> dept
        "created_at": now_dt()
    })
    flash(f'Tạo user {u} thành công', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/detail/<user_id>')
@login_required
def admin_user_detail(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    uid = ObjectId(user_id)
    u = db.users.find_one({"_id": uid})
    if not u:
        return redirect(url_for('admin_users'))

    task_q = {"assigned_to": uid}
    tasks = list(db.tasks.find(task_q).sort("updated_at", -1))
    
    ptask_q = {"user_id": uid}
    personal_tasks = list(db.personal_tasks.find(ptask_q).sort("updated_at", -1))
    
    corp_q = {"assigned_to": {"$in": [uid]}}
    corp_tasks = list(db.corp_tasks.find(corp_q).sort("updated_at", -1))

    # Calculate Breakdown Stats for Display & Chart
    stats_tasks = {
        "total": len(tasks),
        "done": sum(1 for t in tasks if t.get('status') == 'Done'),
        "not_yet": sum(1 for t in tasks if t.get('status') == 'Not_yet'),
        "missed": sum(1 for t in tasks if t.get('status') == 'Missed')
    }
    
    stats_personal = {
        "total": len(personal_tasks),
        "done": sum(1 for t in personal_tasks if t.get('status') == 'Done'),
        "not_yet": sum(1 for t in personal_tasks if t.get('status') == 'Not_yet'),
        "missed": sum(1 for t in personal_tasks if t.get('status') == 'Missed')
    }
    
    stats_corp = {
        "total": len(corp_tasks),
        "done": sum(1 for t in corp_tasks if t.get('status') == 'Done'),
        "not_yet": sum(1 for t in corp_tasks if t.get('status') not in ['Done', 'Cancelled']),
        "missed": 0
    }

    # Consolidated Chart Data
    chart_data = {
        "breakdown": [stats_tasks['total'], stats_corp['total'], stats_personal['total']],
        "status": [
            stats_tasks['done'] + stats_personal['done'] + stats_corp['done'],
            stats_tasks['not_yet'] + stats_personal['not_yet'] + stats_corp['not_yet'],
            stats_tasks['missed'] + stats_personal['missed'] + stats_corp['missed']
        ]
    }

    stats = {
        "total": stats_tasks["total"] + stats_personal["total"] + stats_corp["total"],
        "done": stats_tasks["done"] + stats_personal["done"] + stats_corp["done"],
        "not_yet": stats_tasks["not_yet"] + stats_personal["not_yet"] + stats_corp["not_yet"],
        "missed": stats_tasks["missed"] + stats_personal["missed"],
    }

    task_breakdown = {
        "customer": stats_tasks,
        "personal": stats_personal,
        "corp": stats_corp
    }

    return render_template(
        'user_detail.html',
        staff=u,
        stats=stats,
        tasks=tasks,
        personal_tasks=personal_tasks,
        corp_tasks=corp_tasks,
        task_breakdown=task_breakdown,
        departments=USER_DEPARTMENTS,
        chart_data=chart_data
    )


@app.route('/admin/user/update_role/<user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    # prevent self role change if needed (optional)
    if ObjectId(user_id) == ObjectId(current_user.id):
        return redirect(url_for('admin_users'))

    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"role": request.form.get('role')}})
    return redirect(url_for('admin_users'))

@app.route('/admin/user/update_department/<user_id>', methods=['POST'])
@login_required
def update_user_department(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('index'))

    target_user = db.users.find_one({"_id": ObjectId(user_id)})
    if not target_user:
        return redirect(url_for('admin_users'))

    new_dept = request.form.get('department')

    # Logic: Nếu user đã có department, không cho phép set về rỗng
    if target_user.get('department') and not new_dept:
        flash(f"User {target_user.get('username')} đã có phòng ban, không thể hủy bỏ!", "warning")
    elif new_dept:
        db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"department": new_dept}})
        flash(f"Đã cập nhật phòng ban cho {target_user.get('username')}", "success") # ✅ Fix: u -> target_user

    return redirect(url_for('admin_users'))

# ✅ NEW: Admin Update Telegram ID
@app.route('/admin/user/update-telegram/<user_id>', methods=['POST'])
@login_required
def admin_update_user_telegram(user_id):
    if current_user.role != 'admin': return redirect(url_for('index'))
    tid = (request.form.get('telegram_id') or '').strip()
    db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"telegram_chat_id": tid}})
    flash("Cập nhật Telegram ID thành công", "success")
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/user/delete/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
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
    t1 = list(db.tasks.find({"assigned_to": me, "notify_pending": True, "status": {"$ne": "Done"}}).sort("assigned_at", -1).limit(10))
    t2 = list(db.corp_tasks.find({"assigned_to": me, "notify_pending": True, "status": {"$ne": "Done"}}).sort("assigned_at", -1).limit(10))
    t3 = list(db.personal_tasks.find({"user_id": me, "notify_pending": True, "status": {"$ne": "Done"}}).sort("created_at", -1).limit(5))
    
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
    db.personal_tasks.update_many({"id": {"$in": ids}, "user_id": me}, {"$set": {"notify_pending": False}})
    return jsonify({"status": "success"})

@app.route('/api/admin/missed')
@login_required
def api_admin_missed():
    if current_user.role != "admin": return jsonify({"items": []})
    items = list(db.tasks.find({"status": "Missed", "missed_notify_pending": True}).sort("missed_at", -1).limit(20))
    return jsonify({"items": [{"id": x.get("id"), "todo_content": x.get("todo_content"), "assignee": x.get("assignee"), "due_at": x.get("due_at").strftime("%d/%m %H:%M") if x.get("due_at") else ""} for x in items]})

@app.route('/api/admin/missed/ack', methods=['POST'])
@login_required
def api_admin_missed_ack():
    if current_user.role != "admin": return jsonify({"status": "forbidden"})
    db.tasks.update_many({"id": {"$in": request.get_json().get("ids", [])}}, {"$set": {"missed_notify_pending": False, "missed_notified_at": now_dt()}})
    return jsonify({"status": "success"})

@app.route('/api/admin/corp-requests')
@login_required
def api_admin_corp_requests():
    if current_user.role != "admin": return jsonify({"items": []})
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
    res = requests.get(f"{BASE_URL}/pages", params={"access_token": PANCAKE_USER_TOKEN})
    return jsonify({"pages": res.json().get("pages", [])}) if res.status_code == 200 else (jsonify({"error": "Failed"}), 400)

@app.route('/api/broadcast/conversations/<page_id>')
@login_required
def api_broadcast_conversations(page_id):
    tr = requests.post(f"{BASE_URL}/pages/{page_id}/generate_page_access_token", params={"access_token": PANCAKE_USER_TOKEN, "page_id": page_id})
    if tr.status_code != 200: return jsonify({"error": "Token failed"}), 400
    ptk = tr.json().get("page_access_token")
    cr = requests.get(f"{PUBLIC_V2}/pages/{page_id}/conversations", params={"page_access_token": ptk, "page_id": page_id, "type": "INBOX"})
    return jsonify({"conversations": cr.json().get("conversations", []), "page_token": ptk}) if cr.status_code == 200 else (jsonify({"error": "Conv failed"}), 400)

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


if __name__ == '__main__':
    if db.users.count_documents({"username": "admin"}) == 0:
        db.users.insert_one({
            "username": "admin",
            "password_hash": generate_password_hash('admin123'),
            "role": "admin",
            "department": "Vận Hành", # Mặc định Admin thuộc Vận Hành
            "created_at": now_dt()
        })

    init_pancake_pages(True)

    if not scheduler.running:
        scheduler.add_job(id='p_sync', func=pancake_sync_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_leads', func=sync_all_lark_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_tasks', func=sync_lark_tasks_task, trigger='interval', seconds=60)
        scheduler.add_job(id='auto_missed', func=auto_mark_missed_tasks, trigger='interval', seconds=60)
        scheduler.add_job(id='auto_missed_personal', func=auto_mark_personal_tasks, trigger='interval', seconds=60)
        scheduler.start()
        
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)