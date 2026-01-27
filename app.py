from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_apscheduler import APScheduler
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from models import User
from services.pancake import PancakeService
from datetime import datetime, timedelta, timezone
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests, time, random, string, re
import uuid
import os
import sys
from dotenv import load_dotenv
load_dotenv()

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
MONGO_URI = "mongodb://admin:admin123@45.76.188.143:27017/test?authSource=admin"
client = MongoClient(MONGO_URI)
db = client.CRM_Production
app.config['SECRET_KEY'] = 'crm_thg_ultimate_2025_secure_final_v5'

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
DEPARTMENT_TASK_DEPARTMENTS = ["Vận Hành", "Marketing", "Kế toán", "Nhân sự", "CSKH/Sale", "Ngoại giao"] # Same as corp for now

# ✅ UNIFIED STATUSES (Gộp status)
UNIFIED_STATUSES = ["todo", "doing", "done", "overdue", "cancelled"]

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
    if task_doc.get("status") == "todo": return "doing"
    if task_doc.get("status") == "doing": return "done"
    return "todo" # Default or cycle back

def next_personal_status(cur):
    if cur == "todo": return "doing"
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

# ✅ UNIFIED AUTO OVERDUE LOGIC (Replacing individual functions)
def auto_scan_overdue_tasks():
    now = now_dt()
    
    # 1. Normal Tasks (Customer Tasks)
    db.tasks.update_many(
        {"status": {"$in": ["todo", "doing", "Not_yet"]}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "missed_at": now, "updated_at": now, "missed_notify_pending": True}}
    )
    
    # 2. Corp Tasks
    db.corp_tasks.update_many(
        {"status": {"$in": ["todo", "doing"]}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "updated_at": now}}
    )
    
    # 3. Personal Tasks
    db.personal_tasks.update_many(
        {"status": {"$in": ["todo", "doing"]}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "updated_at": now, "missed_notify_pending": True}}
    )
    
    # 4. Department Tasks
    db.department_tasks.update_many(
        {"status": {"$in": ["todo", "doing"]}, "due_at": {"$lt": now}},
        {"$set": {"status": "overdue", "updated_at": now}}
    )
    
    # 5. Customer Requests
    db.customer_requests.update_many(
        {"status": {"$in": ["todo", "doing"]}, "due_at": {"$lt": now}}, # Note: Requests usually have no due_at, but if added
        {"$set": {"status": "overdue", "updated_at": now}}
    )

# ---------------------------
# ROUTES: AUTH
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u, p, dept = request.form.get('username'), request.form.get('password'), request.form.get('department')
        if db.users.find_one({"username": u}): # ✅ Check for existing username
            flash('Username exists!', 'danger')
            return redirect(url_for('register'))
        role = SUPERADMIN_ROLE if db.users.count_documents({}) == 0 else 'user' # ✅ First user is superadmin
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
        "personal_tasks": db.personal_tasks.count_documents({"user_id": ObjectId(current_user.id),"status": {"$ne": "done"}})
    }

    user_task_stats = []
    all_users = list(db.users.find({}, {"username": 1, "_id": 1, "department": 1}))
    
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
            "$or": [{"assigned_to": {"$in": [uid, uid_str]}}, {"department": u.get("department")}],
            "status": {"$nin": ["done", "cancelled"]}
        })
        
        user_task_stats.append({
            "id": str(uid),
            "username": u.get("username", "Unknown"),
            "department": u.get("department", "Other"),
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
        
    elif current_user.department == 'CSKH/Sale' or current_user.role == 'user':
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
    filter_type = request.args.get('type') # customer, corp, personal, department, request
    filter_status = request.args.get('status')
    search = request.args.get('search', '').lower()
    filter_department = request.args.get('department') # For department tasks


    all_items = []
    me = ObjectId(current_user.id)

    # 1. Customer Tasks
    if not filter_type or filter_type == 'customer':
        q = {}
        # ✅ User can only see their own customer tasks
        if current_user.role not in [SUPERADMIN_ROLE, 'admin']:
            q["$or"] = [{"user_id": me}, {"assigned_to": me}]
        if filter_status: q["status"] = filter_status
        tasks = list(db.tasks.find(q))
        for t in tasks:
            if search and not (search in (t.get('todo_content') or '').lower() or search in (t.get('customer_name') or '').lower()): continue
            t['kind'] = 'customer'
            t['context_label'] = t.get('customer_name')
            all_items.append(t)

    # 2. Corp Tasks
    if not filter_type or filter_type == 'corp':
        q = {}
        # ✅ User can only see their own corp tasks
        if current_user.role not in [SUPERADMIN_ROLE, 'admin']:
            q["assigned_to"] = {"$in": [me]}
        if filter_status: q["status"] = filter_status
        # ✅ FIX: Enable department filter for Corp Tasks
        if filter_department: q["department"] = filter_department
        ctasks = list(db.corp_tasks.find(q))
        for t in ctasks:
            if search and not (search in (t.get('title') or '').lower() or search in (t.get('department') or '').lower()): continue
            t['kind'] = 'corp'
            t['todo_content'] = t.get('title')
            t['context_label'] = t.get('department')
            if 'assignees' not in t: t['assignees'] = [t.get('assignee')] if t.get('assignee') else []
            t['assignee'] = t['assignees'][0] if t['assignees'] else '---'
            all_items.append(t)

    # 3. Personal Tasks
    if not filter_type or filter_type == 'personal':
         q = {}
         if current_user.role not in [SUPERADMIN_ROLE, 'admin']: q["user_id"] = me # ✅ Personal tasks are always user-specific
         if filter_status: q["status"] = filter_status
         ptasks = list(db.personal_tasks.find(q))
         for t in ptasks:
            if search and not (search in (t.get('title') or '').lower()): continue
            t['kind'] = 'personal'
            t['todo_content'] = t.get('title')
            t['context_label'] = 'Personal'
            t['assignee'] = 'Me'
            all_items.append(t)

    # ✅ NEW: 4. Department Tasks
    if not filter_type or filter_type == 'department':
        q = {}
        # ✅ Department tasks are filtered by user's department or assigned_to
        if current_user.role not in [SUPERADMIN_ROLE, 'admin']:
            q["$or"] = [
                {"assigned_to": {"$in": [me]}},
                {"department": current_user.department}
            ]
        if filter_department: q["department"] = filter_department
        if filter_status: q["status"] = filter_status
        dtasks = list(db.department_tasks.find(q))
        for t in dtasks:
            if search and not (search in (t.get('title') or '').lower() or search in (t.get('department') or '').lower()): continue
            t['kind'] = 'department'
            t['todo_content'] = t.get('title')
            t['customer_name'] = None # No customer for department tasks
            t['department'] = t.get('department')
            if 'assignees' not in t: t['assignees'] = [t.get('assignee')] if t.get('assignee') else []
            t['assignee'] = t['assignees'][0] if t['assignees'] else '---'
            all_items.append(t)


    # 4. Customer Requests (Merged)
    if not filter_type or filter_type == 'request':
        q = {}
        if search:
             q["$or"] = [
                {"content": {"$regex": search, "$options": "i"}},
                {"customer_name": {"$regex": search, "$options": "i"}}
            ]
        if filter_status: q["status"] = filter_status
        # ✅ User can only see requests they sent or are assigned to (if requests had assignees)
        if current_user.role not in [SUPERADMIN_ROLE, 'admin']:
            q["sender_name"] = current_user.username # Assuming sender_name is current_user.username
        reqs = list(db.customer_requests.find(q))
        for r in reqs:
            r['kind'] = 'request'
            r['todo_content'] = r.get('content')
            r['context_label'] = r.get('customer_name')
            r['assignee'] = r.get('sender_name')
            r['due_at'] = None
            
            # ✅ Migration Logic for Display: Old Status -> Note
            if r.get('status') in REQUEST_STATUSES:
                r['note'] = r.get('status')
                r['status'] = 'todo' # Default unified status
            else:
                r['note'] = r.get('note', '')

            all_items.append(r)

    # Sort Logic
    def get_is_mine(t):
        if t.get('kind') == 'personal': return True
        assigned = t.get('assigned_to')
        if not assigned: return False
        if isinstance(assigned, list): return me in assigned
        return assigned == me

    all_items.sort(key=lambda x: x.get('updated_at') or datetime.min, reverse=True)
    all_items.sort(key=lambda x: not get_is_mine(x))
    all_items.sort(key=lambda x: x.get('status') in ['done', 'cancelled'])
    all_items.sort(key=lambda x: x.get('status') == 'overdue', reverse=True) # Overdue first
    
    # ✅ FIX: Include Department in users_list for frontend validation
    users_list = list(db.users.find({}, {"username": 1, "_id": 1, "department": 1}))

    return render_template(
        'tasks.html', 
        tasks=all_items, 
        users_list=users_list, 
        statuses=UNIFIED_STATUSES, 
        corp_departments=CORP_DEPARTMENTS, # For corp task modal
        department_task_departments=DEPARTMENT_TASK_DEPARTMENTS, # For department task modal
        request_statuses=REQUEST_STATUSES,
        business_types=BUSINESS_TYPES)

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
        # ✅ Generic content update based on task kind
        if col_name == 'tasks':
            upd.update({"todo_content": data.get('todo_content'), "customer_name": data.get('customer_name')})
        elif col_name in ['corp_tasks', 'personal_tasks']:
            upd["title"] = data.get('todo_content')
        if 'due_at' in data: upd['due_at'] = parse_due_at(data['due_at'])
        
        if 'note' in data: upd['note'] = data['note'] # ✅ Update note field

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
    if current_user.role in [SUPERADMIN_ROLE, 'admin']: has_perm = True
    elif col == 'personal_tasks' and t.get('user_id') == ObjectId(current_user.id): has_perm = True
    elif col == 'tasks' and (t.get('user_id') == ObjectId(current_user.id) or t.get('assigned_to') == ObjectId(current_user.id)): has_perm = True
    elif col == 'corp_tasks':
         assigned = t.get("assigned_to", [])
         if isinstance(assigned, ObjectId) and assigned == ObjectId(current_user.id): has_perm = True
         elif isinstance(assigned, list) and ObjectId(current_user.id) in assigned: has_perm = True
    elif col == 'department_tasks': # ✅ NEW: Department task permission
         if isinstance(assigned, ObjectId) and assigned == ObjectId(current_user.id): has_perm = True
         elif isinstance(assigned, list) and ObjectId(current_user.id) in assigned: has_perm = True
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

@app.route('/task/detail/<id>')
@login_required
def view_task_detail_page(id):
    task, col_name = find_any_task(id)
    if not task: return redirect(url_for('view_tasks'))
    
    # ✅ Redirect to Request Detail if it's a request (uses request_detail.html)
    if col_name == 'customer_requests':
        return render_template('request_detail.html', req=task, request_statuses=REQUEST_STATUSES, business_types=BUSINESS_TYPES, statuses=UNIFIED_STATUSES)

    task['is_normal_task'] = (col_name == 'tasks')
    if col_name == 'corp_tasks':
        task.update({'todo_content': task.get('title'), 'customer_name': task.get('department','Corp'), 'assignee': ", ".join(task.get('assignees', [])) or "---"})
    elif col_name == 'department_tasks': # ✅ NEW: Department task detail mapping
        task['is_department_task'] = True
        task.update({'todo_content': task.get('title'), 'customer_name': task.get('department','Corp'), 'assignee': ", ".join(task.get('assignees', [])) or "---"})
    elif col_name == 'personal_tasks':
        task.update({'todo_content': task.get('title'), 'customer_name': "Personal Task", 'assignee': "Me"})
    
    # Permission Check
    me = ObjectId(current_user.id)
    has_perm = False
    if current_user.role in [SUPERADMIN_ROLE, 'admin']: has_perm = True
    elif col_name == 'tasks' and (task.get('user_id') == me or task.get('assigned_to') == me): has_perm = True
    elif col_name == 'personal_tasks' and task.get('user_id') == me: has_perm = True
    elif col_name == 'corp_tasks':
        assigned = task.get('assigned_to', [])
        if isinstance(assigned, list) and me in assigned: has_perm = True
        elif assigned == me: has_perm = True
    elif col_name == 'department_tasks': # ✅ NEW: Department task detail permission
        assigned = task.get('assigned_to', [])
        if isinstance(assigned, list) and me in assigned: has_perm = True
        elif assigned == me: has_perm = True
            
    if not has_perm: return redirect(url_for('view_tasks'))
    return render_template('task_detail.html', task=task, statuses=UNIFIED_STATUSES)

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
    t, col = find_any_task(id)
    if not t: return redirect(url_for('view_tasks'))

    # Generic Delete Logic
    can_delete = False
    if current_user.role in [SUPERADMIN_ROLE, "admin"]: 
        can_delete = True
    elif col == 'personal_tasks': 
        can_delete = True
    elif col == 'tasks':
        # Normal task: creator can delete unless assigned by admin
        if t.get("user_id") == ObjectId(current_user.id) and t.get("assigned_by_role") != "admin":
            can_delete = True
    elif col == 'customer_requests':
        # Only admin deletes requests usually, or maybe creator? Let's stick to admin for now based on requests_customer.html
        pass 

    if can_delete:
        db[col].delete_one({"id": id})
    else:
        flash("Bạn không có quyền xoá task này.", "danger")

    return redirect(request.referrer or url_for('view_tasks'))

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
    department = request.form.get('department')
    
    # LẤY DANH SÁCH NGƯỜI ĐƯỢC GÁN (Mở cho tất cả các Role)
    assigned_user_ids = request.form.getlist('assigned_user_ids') # ✅ Can be empty
    
    # ✅ NEW: Default assignment logic if none selected
    if not assigned_user_ids:
        # If user didn't select anyone, default to themselves
        assigned_user_ids = [str(current_user.id)]

    # Parse thời hạn
    due_at = parse_due_at(request.form.get('due_at') or request.form.get('deadline'))

    # Kiểm tra dữ liệu đầu vào
    if not title or department not in CORP_DEPARTMENTS or not due_at:
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
        "department": department,
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
        f"🏢 <b>Dept:</b> {department}\n"
        f"👤 <b>By:</b> {current_user.username}\n"
        f"📅 <b>Deadline:</b> {due_at.strftime('%H:%M %d/%m/%Y')}"
    )
    for u in users: # Notify all assignees
        chat_id = u.get("telegram_chat_id")
        if chat_id:
            send_telegram_notification(chat_id, msg_text)

    flash('Đã tạo task công ty thành công', 'success')
    return redirect(url_for('view_tasks'))

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
    return redirect(url_for('view_tasks'))

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
    department = request.form.get('department')
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
        "department": department,
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
        pass
    elif current_user.role in ['admin', 'user']:
        # Admin AND User can only create for their own department
        if department != current_user.department:
            flash(f"Bạn chỉ có thể tạo task cho phòng ban của mình ({current_user.department}).", "danger")
            return redirect(url_for('view_tasks'))
        
        # VALIDATE: All assignees must be in same department
        if assigned_user_ids:
            try:
                user_oids = [ObjectId(uid) for uid in assigned_user_ids]
                invalid_users = db.users.count_documents({"_id": {"$in": user_oids}, "department": {"$ne": current_user.department}})
                if invalid_users > 0:
                    flash("Bạn chỉ được giao task cho nhân viên trong phòng ban của mình.", "danger")
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
        "sender_name": current_user.username
    })
    
    flash("Đã tạo yêu cầu mới", "success")
    return redirect(url_for("view_customer_requests"))

@app.route('/request/customer/detail/<id>')
@login_required
def view_customer_request_detail(id):
    """Xem chi tiết và chỉnh sửa Customer Request (giống Task Detail)"""
    req = db.customer_requests.find_one({"id": id})
    if not req:
        flash("Request not found", "danger")
        return redirect(url_for("view_customer_requests"))
        
    return render_template(
        'request_detail.html', 
        req=req,
        request_statuses=REQUEST_STATUSES,
        business_types=BUSINESS_TYPES,
        statuses=UNIFIED_STATUSES
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

    db.customer_requests.update_one({"id": id}, {"$set": upd})
    return jsonify({"status": "success"})

@app.route('/request/customer/delete/<id>', methods=['POST'])
@login_required
def delete_customer_request(id):
    """Xóa yêu cầu (Chỉ Admin/Superadmin)"""
    # ✅ FIX: Allow Superadmin to delete
    if current_user.role in [SUPERADMIN_ROLE, 'admin']:
        db.customer_requests.delete_one({"id": id})
    return redirect(url_for('view_customer_requests'))

# ---------------------------
# ROUTES: TOOLS (NEW PRICING)
# ---------------------------
@app.route('/tools/pricing')
@login_required
def view_pricing_tool():
    """Giao diện Pricing Tool"""
    return render_template('pricing.html')

@app.route('/tools/pricing/calculate', methods=['POST'])
@login_required
def pricing_calculate():
    """API tính toán giá cước (Mock Logic)"""
    try:
        data = request.json or request.form
        weight = float(data.get('weight', 0))
        service = data.get('service', 'Express')
        country = data.get('country', 'VN')
        
        # Simple Mock Formula (Thay thế bằng logic thực tế sau này)
        base_price = 30000 if service == 'Express' else 15000
        rate_per_kg = 20000
        
        # Surcharges mock
        fuel_surcharge = 0.15 # 15%
        
        subtotal = base_price + (weight * rate_per_kg)
        total = subtotal * (1 + fuel_surcharge)
        
        return jsonify({
            "status": "success",
            "data": {
                "weight": weight,
                "service": service,
                "country": country,
                "subtotal": round(subtotal, 0),
                "total_price": round(total, 0),
                "currency": "VND"
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# ---------------------------
# ✅ API: EXTERNAL (n8n Integration)
# ---------------------------
@app.route('/api/external/task', methods=['POST'])
def add_external_task():
    """API cho n8n bắn dữ liệu về - Lưu vào Customer Requests"""
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
    
    # Nếu tìm thấy User nội bộ -> Lấy Username chuẩn
    if internal_user:
        u_name = internal_user.get('username')
        if u_name and str(u_name).strip():
            sender_name = str(u_name).strip()

    # Final check: Đảm bảo không bao giờ lưu rỗng
    if not sender_name or sender_name == 'None':
        sender_name = 'Unknown'

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
        query["department"] = current_user.department

    users = []
    for u in db.users.find(query):
        uo = User(u)
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
    dept = request.form.get('department')
    
    # ✅ VALIDATE: Admin can only add users to their department
    if current_user.role == 'admin' and dept != current_user.department:
        flash(f'Admin chỉ được tạo user trong phòng ban {current_user.department}', 'danger')
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
        "department": dept, # ✅ Fix: d -> dept
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
    if current_user.role == 'admin' and u.get('department') != current_user.department:
        flash("Bạn không có quyền xem user này.", "danger")
        return redirect(url_for('admin_users'))

    task_q = {"assigned_to": uid}
    tasks = list(db.tasks.find(task_q).sort("updated_at", -1))
    
    ptask_q = {"user_id": uid}
    personal_tasks = list(db.personal_tasks.find(ptask_q).sort("updated_at", -1))
    
    corp_q = {"assigned_to": {"$in": [uid]}}
    corp_tasks = list(db.corp_tasks.find(corp_q).sort("updated_at", -1))
    
    dept_q = {"$or": [{"assigned_to": {"$in": [uid]}}, {"department": u.get("department")}]} # ✅ NEW: Department tasks for user
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

@app.route('/admin/user/update_department/<user_id>', methods=['POST'])
@login_required
def update_user_department(user_id):
    # ✅ RESTRICT: ONLY SUPERADMIN CAN UPDATE DEPARTMENT
    if current_user.role != SUPERADMIN_ROLE: 
        flash("Chỉ Superadmin mới có quyền đổi phòng ban.", "danger")
        return redirect(url_for('admin_users'))

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
    if current_user.role not in [SUPERADMIN_ROLE, "admin"]: return jsonify({"items": []})
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
            "role": SUPERADMIN_ROLE, # ✅ First user is superadmin
            "department": "Vận Hành", 
            "created_at": now_dt()
        })
    
    # ✅ Auto-create specific superadmin user
    if db.users.count_documents({"username": "superadmin"}) == 0:
        db.users.insert_one({
            "username": "superadmin",
            "password_hash": generate_password_hash('superadmin123'),
            "role": SUPERADMIN_ROLE,
            "department": "Vận Hành",
            "created_at": now_dt()
        })
        print("Created superadmin/superadmin123")

    init_pancake_pages(True)

    if not scheduler.running:
        scheduler.add_job(id='p_sync', func=pancake_sync_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_leads', func=sync_all_lark_task, trigger='interval', seconds=60)
        scheduler.add_job(id='l_tasks', func=sync_lark_tasks_task, trigger='interval', seconds=60)
        
        # ✅ Unified auto overdue scheduler
        scheduler.add_job(id='auto_overdue', func=auto_scan_overdue_tasks, trigger='interval', seconds=60)
        
        scheduler.start()
        
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)